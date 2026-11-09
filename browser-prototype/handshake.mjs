import nacl from 'tweetnacl';
import { channelBinding, splitKeys, verifyHostFingerprint } from './authentication.mjs';

const concat = (...arrays) => { const n=arrays.reduce((x,a)=>x+a.length,0), out=new Uint8Array(n); let i=0; for(const a of arrays){out.set(a,i);i+=a.length;} return out; };
function varint(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid protobuf integer');
  const bytes=[]; do { let n=value%128; value=Math.floor(value/128); if(value)n|=128; bytes.push(n); } while(value);
  return new Uint8Array(bytes);
}
export const bytesField = (field, value) => concat(varint(field*8+2), varint(value.length), value);
export const intField = (field, value) => concat(varint(field*8), varint(value));
export const wireMessage = (...fields) => concat(...fields);

function fields(input) {
  let at=0; const result=new Map();
  const read=()=>{let n=0,m=1;for(let i=0;i<8;i++){if(at>=input.length)throw new Error('Truncated protobuf');const b=input[at++];n+=(b&127)*m;if(!Number.isSafeInteger(n))throw new Error('Oversized protobuf integer');if(!(b&128))return n;m*=128;}throw new Error('Invalid protobuf integer');};
  while(at<input.length){
    const key=read(), number=Math.floor(key/8), type=key%8; if(!number)throw new Error('Invalid protobuf field');
    let value;
    if(type===0)value=read();
    else if(type===2){const len=read();if(len>input.length-at)throw new Error('Truncated protobuf');value=input.slice(at,at+len);at+=len;}
    else if(type===1||type===5){const len=type===1?8:4;if(len>input.length-at)throw new Error('Truncated protobuf');at+=len;continue;}
    else throw new Error('Unsupported protobuf field');
    if(result.has(number))throw new Error('Duplicate protobuf field');
    result.set(number,value);
  }
  return result;
}

const bytes = (map, field) => { const v=map.get(field); if(!(v instanceof Uint8Array))throw new Error('Missing protobuf bytes'); return v; };
const nonce = n => { const out=new Uint8Array(24); new DataView(out.buffer).setBigUint64(0,n,true); return out; };

export class SessionCipher {
  constructor(sendKey, receiveKey) { this.sendKey=sendKey; this.receiveKey=receiveKey; this.sendCounter=0n; this.receiveCounter=0n; }
  seal(data) { if(this.sendCounter===0xffffffffffffffffn)throw new Error('Session counter exhausted'); return nacl.secretbox(data,nonce(++this.sendCounter),this.sendKey); }
  open(data) { if(data.length<=1)return data; if(this.receiveCounter===0xffffffffffffffffn)throw new Error('Session counter exhausted'); const out=nacl.secretbox.open(data,nonce(++this.receiveCounter),this.receiveKey);if(!out)throw new Error('Session decryption failed');return out; }
  destroy() { this.sendKey.fill(0); this.receiveKey.fill(0); }
}

// Transport is an ordered binary-message stream with async next() and send().
export async function authenticateHost(transport, expectedFingerprint) {
  const envelope=fields(await transport.next());
  if(envelope.size!==1 || !envelope.has(3))throw new Error('Missing host identity');
  const signed=fields(bytes(envelope,3));
  const host=bytes(signed,2), signedTranscript=bytes(signed,1);
  verifyHostFingerprint(host,expectedFingerprint);
  const opened=nacl.sign.open(signedTranscript,host);
  if(!opened)throw new Error('Invalid host signature');
  const transcript=fields(opened), responder=bytes(transcript,2);
  if(responder.length!==32 || transcript.get(4)!==1 || (transcript.has(3) && bytes(transcript,3).length))throw new Error('Unsupported host key exchange');
  const initiator=nacl.box.keyPair(), shared=nacl.randomBytes(32);
  try {
    const sealed=nacl.box(shared,new Uint8Array(24),responder,initiator.secretKey);
    const binding=channelBinding(host,initiator.publicKey,responder);
    const keys=splitKeys(shared,initiator.publicKey,responder);
    const cipher=new SessionCipher(keys.send,keys.receive);
    try {
      transport.send(bytesField(4,wireMessage(bytesField(1,initiator.publicKey),bytesField(2,sealed),intField(3,1))));
      const confirmation=fields(cipher.open(await transport.next()));
      if(confirmation.size!==1 || !confirmation.has(35))throw new Error('Missing host key confirmation');
      const received=bytes(fields(bytes(confirmation,35)),1);
      if(received.length!==32 || !nacl.verify(received,binding))throw new Error('Host key confirmation mismatch');
      return { binding, cipher, hostKey: host };
    } catch(error) { cipher.destroy(); throw error; }
  } finally { initiator.secretKey.fill(0); shared.fill(0); }
}

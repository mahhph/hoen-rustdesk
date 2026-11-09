import { once } from 'node:events';
import WebSocket from 'ws';
import { createGateway } from './gateway.mjs';
import { authenticateHost } from './handshake.mjs';

const host=process.env.DESKTOP_HOST, pin=process.env.DESKTOP_HOST_FINGERPRINT;
if(!host || !/^[a-fA-F0-9]{64}$/.test(pin || ''))throw new Error('Supply the reviewed host address and SHA-256 fingerprint.');
const gateway=createGateway({destinationHost:host,destinationPort:Number(process.env.DESKTOP_HOST_PORT || 42830)});
const address=await gateway.listen();
const ws=new WebSocket(`ws://127.0.0.1:${address.port}`);
try {
  const opened=once(ws,'open');
  const queue=[]; let waiter;
  ws.on('message',(data,binary)=>{if(!binary){ws.close();return;}const value=new Uint8Array(data);if(waiter){const w=waiter;waiter=null;w(value);}else queue.push(value);});
  await opened;
  const transport={send:data=>ws.send(data),next:()=>queue.length?Promise.resolve(queue.shift()):new Promise((resolve,reject)=>{const timer=setTimeout(()=>{waiter=null;reject(new Error('Host handshake timed out'));},10000);waiter=value=>{clearTimeout(timer);resolve(value);};})};
  const session=await authenticateHost(transport,new Uint8Array(Buffer.from(pin,'hex')));
  session.cipher.destroy();
  console.log('Authenticated host handshake and key confirmation passed; no login grant or desktop session was sent.');
} finally { ws.terminate(); await gateway.close(); }

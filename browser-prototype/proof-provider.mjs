import https from 'node:https';
import tls from 'node:tls';
import { createHash, timingSafeEqual } from 'node:crypto';
import nacl from 'tweetnacl';
import { createViewerProof } from './authentication.mjs';

function canonical32(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('Invalid 32-byte value');
  const bytes=Buffer.from(value,'base64url');
  if(bytes.length!==32 || bytes.toString('base64url')!==value)throw new Error('Invalid 32-byte value');
  return bytes;
}

function mailboxRequest(config, route, method='GET', payload) {
  const url=new URL(config.mailboxUrl), target=new URL(route,url);
  if(url.protocol!=='https:' || url.username || url.password || url.pathname!=='/' || url.search || url.hash || target.origin!==url.origin) throw new Error('Invalid mailbox URL');
  const expected=Buffer.from(config.mailboxFingerprint,'hex');
  if(expected.length!==32)throw new Error('Invalid mailbox certificate fingerprint');
  const agent=new https.Agent({ca:config.mailboxCaPem,rejectUnauthorized:true,checkServerIdentity:(host,certificate)=>{
    const failure=tls.checkServerIdentity(host,certificate); if(failure)return failure;
    const actual=createHash('sha256').update(certificate.raw).digest();
    if(!timingSafeEqual(actual,expected))return new Error('Mailbox certificate fingerprint mismatch');
  }});
  const body=payload===undefined?null:Buffer.from(JSON.stringify(payload));
  return new Promise((resolve,reject)=>{
    const req=https.request(target,{method,agent,headers:{Authorization:`Bearer ${config.accessToken}`,...(body?{'Content-Type':'application/json','Content-Length':body.length}:{})}},res=>{
      const chunks=[];let length=0;
      res.on('data',chunk=>{length+=chunk.length;if(length>65536)res.destroy(new Error('Mailbox response too large'));else chunks.push(chunk);});
      res.on('end',()=>{agent.destroy();if(res.statusCode<200||res.statusCode>=300)return reject(new Error(`Mailbox request failed (${res.statusCode})`));try{resolve(JSON.parse(Buffer.concat(chunks).toString()));}catch{reject(new Error('Invalid mailbox response'));}});
      res.on('error',reject);
    });
    req.setTimeout(10000,()=>req.destroy(new Error('Mailbox request timed out')));
    req.on('error',error=>{agent.destroy();reject(error);});req.end(body);
  });
}

export function createProofProvider(config, request=mailboxRequest) {
  for(const name of ['viewerIdentity','hostIdentity']) if(!/^[a-z][a-z0-9-]{0,63}$/.test(config[name] || ''))throw new Error('Invalid viewer or host identity');
  if(typeof config.mailboxCaPem!=='string'||!config.mailboxCaPem.includes('BEGIN CERTIFICATE'))throw new Error('Mailbox certificate is required');
  if(!/^[0-9a-f]{64}$/i.test(config.mailboxFingerprint || ''))throw new Error('Mailbox fingerprint is required');
  canonical32(config.accessToken);
  const seed=canonical32(config.viewerSeed);
  const pair=nacl.sign.keyPair.fromSeed(seed);
  const viewerFingerprint=createHash('sha256').update(pair.publicKey).digest('hex');
  seed.fill(0);
  async function registered() {
    const result=await request(config,'/v1/remote-machines');
    if(!Array.isArray(result.machines))throw new Error('Invalid machine directory');
    const viewer=result.machines.find(m=>m.identity===config.viewerIdentity);
    const host=result.machines.find(m=>m.identity===config.hostIdentity && m.hostingEnabled);
    if(!viewer || viewer.publicKeyFingerprint!==viewerFingerprint || !host || !/^[0-9a-f]{64}$/.test(host.publicKeyFingerprint || ''))throw new Error('Prototype viewer or host is not registered with the expected key');
    return host;
  }
  return {
    async info(){const host=await registered();return {host:host.identity,displayName:host.displayName,hostFingerprint:host.publicKeyFingerprint};},
    async issue(host,binding){
      if(host!==config.hostIdentity || typeof binding!=='string' || !/^[0-9a-f]{64}$/.test(binding))throw new Error('Invalid proof request');
      await registered();
      const grant=await request(config,'/v1/remote-grants','POST',{host,channelBinding:binding});
      const token=canonical32(grant.token);
      try { const proof=createViewerProof(new Uint8Array(Buffer.from(binding,'hex')),new Uint8Array(token),pair.secretKey); return {viewerKey:Buffer.from(proof.viewerKey).toString('base64url'),grantToken:Buffer.from(proof.grantToken).toString('base64url'),signature:Buffer.from(proof.signature).toString('base64url')}; }
      finally {token.fill(0);}
    },
    destroy(){pair.secretKey.fill(0);},
  };
}

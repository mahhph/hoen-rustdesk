import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import { createProofProvider } from './proof-provider.mjs';

test('issues a proof only for the registered prototype viewer and selected host', async () => {
  const seed=Buffer.alloc(32,7), pair=nacl.sign.keyPair.fromSeed(seed);
  const config={viewerIdentity:'browser-test',hostIdentity:'windows',mailboxUrl:'https://example.test/',mailboxFingerprint:'a'.repeat(64),mailboxCaPem:'-----BEGIN CERTIFICATE-----',accessToken:Buffer.alloc(32,9).toString('base64url'),viewerSeed:seed.toString('base64url')};
  const viewerFingerprint=createHash('sha256').update(pair.publicKey).digest('hex');
  const calls=[];
  const request=async (_config,route,method,payload)=>{
    calls.push({route,method,payload});
    if(route==='/v1/remote-machines')return {machines:[{identity:'browser-test',publicKeyFingerprint:viewerFingerprint},{identity:'windows',displayName:'Area51',hostingEnabled:true,publicKeyFingerprint:'b'.repeat(64)},{identity:'mac',displayName:'Mac',hostingEnabled:true,publicKeyFingerprint:'d'.repeat(64),endpoint:{address:'192.168.1.9',port:42830}},{identity:'disabled',hostingEnabled:false,publicKeyFingerprint:'e'.repeat(64)}]};
    return {token:Buffer.alloc(32,3).toString('base64url')};
  };
  const provider=createProofProvider(config,request);
  assert.equal((await provider.info()).host,'windows');
  const proof=await provider.issue('windows','c'.repeat(64));
  assert.equal(Buffer.from(proof.viewerKey,'base64url').toString('hex'),Buffer.from(pair.publicKey).toString('hex'));
  assert.equal(Buffer.from(proof.signature,'base64url').length,64);
  assert.deepEqual(calls.at(-1).payload,{host:'windows',channelBinding:'c'.repeat(64)});
  assert.deepEqual((await provider.list()).map(m=>m.host),['windows','mac']);
  assert.equal((await provider.info('mac')).hostFingerprint,'d'.repeat(64));
  assert.deepEqual(await provider.resolve('mac'),{address:'192.168.1.9',port:42830});
  await provider.issue('mac','c'.repeat(64));
  assert.equal(calls.at(-1).payload.host,'mac');
  await assert.rejects(provider.issue('other','c'.repeat(64)),/Host is not registered/);
  await assert.rejects(provider.issue('disabled','c'.repeat(64)),/Host is not registered/);
  provider.destroy();
  const routed=createProofProvider({...config,transportOverrides:{mac:{address:'127.0.0.1',port:42833}}},request);
  assert.deepEqual(await routed.resolve('mac'),{address:'127.0.0.1',port:42833});
  assert.equal((await routed.info('mac')).hostFingerprint,'d'.repeat(64));
  await assert.rejects(routed.resolve('other'),/Host is not registered/);
  await routed.issue('mac','c'.repeat(64));assert.equal(calls.at(-1).payload.host,'mac');
  routed.destroy();
  assert.throws(()=>createProofProvider({...config,transportOverrides:{mac:{address:'evil.invalid',port:42833}}},request),/Invalid transport override/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import { sha256 } from '@noble/hashes/sha256';
import { authenticateHost, bytesField, intField, wireMessage, SessionCipher } from './handshake.mjs';
import { channelBinding, splitKeys } from './authentication.mjs';

function simulatedHost({ wrongConfirmation=false }={}) {
  const host=nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(7)), box=nacl.box.keyPair();
  const transcript=wireMessage(bytesField(2,box.publicKey),intField(4,1));
  const identity=bytesField(3,wireMessage(bytesField(1,nacl.sign(transcript,host.secretKey)),bytesField(2,host.publicKey)));
  let sent;
  return {
    host,
    async next() {
      if(!sent)return identity;
      // The outgoing public-key message contains short, length-delimited fields in a stable order.
      const inner=sent.slice(2), initiator=inner.slice(2,34), sealed=inner.slice(36,84);
      const shared=nacl.box.open(sealed,new Uint8Array(24),initiator,box.secretKey);
      assert.ok(shared);
      const binding=channelBinding(host.publicKey,initiator,box.publicKey);
      const keys=splitKeys(shared,initiator,box.publicKey);
      const cipher=new SessionCipher(keys.receive,keys.send);
      return cipher.seal(bytesField(35,bytesField(1,wrongConfirmation?new Uint8Array(32):binding)));
    },
    send(data){sent=data;},
  };
}

test('authenticates a native-compatible signed host and encrypted key confirmation', async () => {
  const host=simulatedHost();
  const session=await authenticateHost(host,sha256(host.host.publicKey));
  assert.equal(session.binding.length,32);
  session.cipher.destroy();
});

test('rejects a wrong host fingerprint or key confirmation', async () => {
  const host=simulatedHost();
  await assert.rejects(authenticateHost(host,new Uint8Array(32)),/fingerprint mismatch/);
  const bad=simulatedHost({wrongConfirmation:true});
  await assert.rejects(authenticateHost(bad,sha256(bad.host.publicKey)),/confirmation mismatch/);
});

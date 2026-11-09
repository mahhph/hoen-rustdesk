import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha256';
import nacl from 'tweetnacl';
import { channelBinding, splitKeys, verifyHostFingerprint, createViewerProof } from './authentication.mjs';

const filled = n => new Uint8Array(32).fill(n);
const hex = x => Buffer.from(x).toString('hex');

test('channel binding and directional keys match native Rust fixed vectors', () => {
  assert.equal(hex(channelBinding(filled(1), filled(2), filled(3))), 'f6935b12fd0e89aeea832a54c81e55231adae30d47851b990846303a168237fd');
  const keys = splitKeys(filled(0x11), filled(0x22), filled(0x33));
  assert.equal(hex(keys.send), 'c189ec6e1935c0751cfc85a0f075405cae507d7925bb19687caf56cbb54e0ecf');
  assert.equal(hex(keys.receive), '8a62648e9195cb10ea900c0a24d2a166c1e982347a2dc6833c3e756bf5715d36');
  assert.throws(() => channelBinding(filled(1), filled(2), filled(3), 2, 1), /Unsupported/);
});

test('host fingerprints and viewer proofs use the enrolled keys and connection binding', () => {
  const pair = nacl.sign.keyPair.fromSeed(filled(7));
  verifyHostFingerprint(pair.publicKey, sha256(pair.publicKey));
  assert.throws(() => verifyHostFingerprint(pair.publicKey, filled(0)), /mismatch/);
  const binding = filled(1), token = filled(2);
  const proof = createViewerProof(binding, token, pair.secretKey);
  const domain = new TextEncoder().encode('hoen-mailbox-viewer-proof/v1\0');
  const signed = new Uint8Array(domain.length + 64);
  signed.set(domain); signed.set(binding, domain.length); signed.set(sha256(token), domain.length + 32);
  assert.ok(nacl.sign.detached.verify(signed, proof.signature, proof.viewerKey));
  signed[domain.length] ^= 1;
  assert.equal(nacl.sign.detached.verify(signed, proof.signature, proof.viewerKey), false);
});

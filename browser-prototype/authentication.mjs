import { blake2b } from '@noble/hashes/blake2';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils';
import nacl from 'tweetnacl';

const bytes32 = (v, name) => {
  if (!(v instanceof Uint8Array) || v.length !== 32) throw new Error(`${name} must contain 32 bytes`);
  return v;
};
const equal = (a, b) => a.length === b.length && nacl.verify(a, b);
const version = (n, littleEndian) => { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, n, littleEndian); return out; };

export function channelBinding(host, initiator, responder, advertised = 1, selected = 1) {
  if (advertised !== 1 || selected !== 1) throw new Error('Unsupported key exchange version');
  return sha256(concatBytes(utf8ToBytes('hoen-mailbox-channel/v1'), new Uint8Array([0]),
    bytes32(host, 'host key'), bytes32(initiator, 'initiator key'), bytes32(responder, 'responder key'),
    version(advertised, false), version(selected, false)));
}

export function splitKeys(sharedKey, initiator, responder, advertised = 1, selected = 1) {
  bytes32(sharedKey, 'shared key'); bytes32(initiator, 'initiator key'); bytes32(responder, 'responder key');
  if (advertised !== 1 || selected !== 1) throw new Error('Unsupported key exchange version');
  const derive = direction => blake2b(concatBytes(utf8ToBytes('rdkx-spl'), new Uint8Array([direction]),
    version(advertised, true), version(selected, true), initiator, responder), { dkLen: 32, key: sharedKey });
  return { send: derive(1), receive: derive(2) };
}

export function verifyHostFingerprint(publicKey, fingerprint) {
  if (!equal(sha256(bytes32(publicKey, 'host key')), bytes32(fingerprint, 'host fingerprint'))) throw new Error('Host fingerprint mismatch');
}

export function createViewerProof(binding, token, secretKey) {
  bytes32(binding, 'channel binding'); bytes32(token, 'grant token');
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== nacl.sign.secretKeyLength) throw new Error('Invalid viewer signing key');
  const message = concatBytes(utf8ToBytes('hoen-mailbox-viewer-proof/v1'), new Uint8Array([0]), binding, sha256(token));
  return { viewerKey: nacl.sign.keyPair.fromSecretKey(secretKey).publicKey, grantToken: token, signature: nacl.sign.detached(message, secretKey) };
}

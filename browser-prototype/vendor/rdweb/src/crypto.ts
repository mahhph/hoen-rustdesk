// Session cryptography: peer authentication, key exchange, stream cipher and
// the password challenge, compatible with RustDesk peers.
//
// Trust chain: the server's Ed25519 key (configured, out of band) signs
// IdPk{id, pk = peer's long-term Ed25519 key} which hbbs hands us in the
// RelayResponse; the peer then signs IdPk{id, pk = ephemeral Curve25519 key}
// with that long-term key and sends it as SignedId over the relay. Only after
// both signatures check out (and both ids match the peer we asked for) do we
// seal a fresh symmetric key to the ephemeral key.

import nacl from "tweetnacl";
import { fromBinary } from "@bufbuild/protobuf";
import { IdPkSchema } from "./proto/session_pb.js";

const utf8 = new TextEncoder();
const ZERO_NONCE = new Uint8Array(24);

export class HandshakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeError";
  }
}

export function decodeBase64(s: string): Uint8Array {
  const bin = atob(s.trim().replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function encodeBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

/** Parses the server public key (base64 Ed25519, as in id_ed25519.pub). */
export function parseServerKey(key: string): Uint8Array {
  let raw: Uint8Array;
  try {
    raw = decodeBase64(key);
  } catch {
    throw new HandshakeError("server key is not valid base64");
  }
  if (raw.length !== nacl.sign.publicKeyLength) {
    throw new HandshakeError(`server key must be ${nacl.sign.publicKeyLength} bytes, got ${raw.length}`);
  }
  return raw;
}

/**
 * Opens a crypto_sign combined message (signature || IdPk) with `signer` and
 * returns the embedded key if the signature is valid and the id matches.
 */
export function openSignedIdPk(signed: Uint8Array, signer: Uint8Array, expectedId: string): Uint8Array {
  const opened = nacl.sign.open(signed, signer);
  if (!opened) throw new HandshakeError("signature verification failed");
  let idpk;
  try {
    idpk = fromBinary(IdPkSchema, opened);
  } catch {
    throw new HandshakeError("malformed signed identity");
  }
  if (idpk.id !== expectedId) {
    throw new HandshakeError(`signed identity is for "${idpk.id}", expected "${expectedId}"`);
  }
  return idpk.pk;
}

/** Verifies hbbs' signature over the peer's long-term key; returns that key. */
export function verifyPeerLongTermKey(signedByServer: Uint8Array, serverKey: Uint8Array, peerId: string): Uint8Array {
  const pk = openSignedIdPk(signedByServer, serverKey, peerId);
  if (pk.length !== nacl.sign.publicKeyLength) throw new HandshakeError("peer key has wrong length");
  return pk;
}

/** Verifies the peer's SignedId with its long-term key; returns the ephemeral box key. */
export function verifyPeerEphemeralKey(signedId: Uint8Array, peerLongTermKey: Uint8Array, peerId: string): Uint8Array {
  const pk = openSignedIdPk(signedId, peerLongTermKey, peerId);
  if (pk.length !== nacl.box.publicKeyLength) throw new HandshakeError("peer session key has wrong length");
  return pk;
}

export interface KeyExchange {
  /** Our ephemeral Curve25519 public key (PublicKey.asymmetric_value). */
  ourPublicKey: Uint8Array;
  /** The symmetric key boxed to the peer (PublicKey.symmetric_value). */
  sealedKey: Uint8Array;
  /** The symmetric key for the stream cipher. */
  key: Uint8Array;
}

export function createKeyExchange(peerBoxKey: Uint8Array): KeyExchange {
  const key = nacl.randomBytes(nacl.secretbox.keyLength);
  const eph = nacl.box.keyPair();
  const sealedKey = nacl.box(key, ZERO_NONCE, peerBoxKey, eph.secretKey);
  eph.secretKey.fill(0);
  return { ourPublicKey: eph.publicKey, sealedKey, key };
}

function nonceFor(seq: bigint): Uint8Array {
  const n = new Uint8Array(24);
  new DataView(n.buffer).setBigUint64(0, seq, true);
  return n;
}

/**
 * secretbox stream cipher with independent little-endian sequence counters
 * per direction (the counter is incremented before each message).
 */
export class StreamCipher {
  private sendSeq = 0n;
  private recvSeq = 0n;

  constructor(private readonly key: Uint8Array) {}

  seal(plain: Uint8Array): Uint8Array {
    this.sendSeq++;
    return nacl.secretbox(plain, nonceFor(this.sendSeq), this.key);
  }

  open(sealed: Uint8Array): Uint8Array {
    // Frames of 0 or 1 byte are never encrypted by peers (keep-alives).
    if (sealed.length <= 1) return sealed;
    this.recvSeq++;
    const plain = nacl.secretbox.open(sealed, nonceFor(this.recvSeq), this.key);
    if (!plain) throw new HandshakeError(`decryption failed at message ${this.recvSeq}`);
    return plain;
  }

  destroy(): void {
    this.key.fill(0);
  }
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  let len = 0;
  for (const p of parts) len += p.length;
  const buf = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

/**
 * The salted password hash a peer stores for "remember password":
 * SHA256(password || salt). It is password-equivalent for that peer, so treat
 * it as a secret, but it does not reveal the password itself.
 */
export function rememberedPasswordHash(password: string, salt: string): Promise<Uint8Array> {
  return sha256(utf8.encode(password), utf8.encode(salt));
}

/** The login proof for a challenge: SHA256(SHA256(password || salt) || challenge). */
export function loginProof(saltedHash: Uint8Array, challenge: string): Promise<Uint8Array> {
  return sha256(saltedHash, utf8.encode(challenge));
}

// Rendezvous (hbbs) step: ask the server to introduce us to the peer and wait
// until the peer has joined a relay for us.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  ConnType,
  NatType,
  PunchHoleResponse_Failure,
  RendezvousMessageSchema,
  type RelayResponse,
} from "./proto/rendezvous_pb.js";
import { TransportError, WsTransport } from "./transport.js";

export class RendezvousError extends Error {
  constructor(
    message: string,
    /** unreachable: the WebSocket to the ID or relay server could not be opened at all. */
    readonly code: "offline" | "not-found" | "key-mismatch" | "refused" | "login-required" | "timeout" | "network" | "unreachable",
  ) {
    super(message);
    this.name = "RendezvousError";
  }
}

export interface RelayTicket {
  uuid: string;
  /** host:port of the relay the peer joined, as announced by hbbs. */
  relayServer: string;
  /** IdPk of the peer signed by the server key; empty if the server sent none. */
  signedPeerKey: Uint8Array;
  peerVersion: string;
}

export interface RendezvousOptions {
  url: string;
  peerId: string;
  licenceKey: string;
  token?: string;
  connType?: ConnType;
  version: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export async function requestRelay(opts: RendezvousOptions): Promise<RelayTicket> {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  let t: WsTransport;
  try {
    t = await WsTransport.open(opts.url, { timeoutMs: 10_000, signal: opts.signal });
  } catch (e) {
    if (e instanceof TransportError && e.code === "aborted") throw e;
    throw new RendezvousError(`cannot reach the ID server: ${(e as Error).message}`, "unreachable");
  }
  try {
    const req = create(RendezvousMessageSchema, {
      union: {
        case: "punchHoleRequest",
        value: {
          id: opts.peerId,
          // A browser cannot accept a hole-punched connection: report a
          // symmetric NAT so the peer meets us on a relay.
          natType: NatType.SYMMETRIC,
          licenceKey: opts.licenceKey,
          connType: opts.connType ?? ConnType.DEFAULT_CONN,
          token: opts.token ?? "",
          version: opts.version,
          forceRelay: true,
        },
      },
    });
    t.send(toBinary(RendezvousMessageSchema, req));

    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const left = deadline - Date.now();
      if (left <= 0) throw new RendezvousError("the remote device did not answer", "timeout");
      let raw: Uint8Array;
      try {
        raw = await t.next(left, opts.signal);
      } catch (e) {
        if (e instanceof TransportError && e.code === "timeout") {
          throw new RendezvousError("the remote device did not answer", "timeout");
        }
        throw new RendezvousError(`ID server connection failed: ${(e as Error).message}`, "network");
      }
      let msg;
      try {
        msg = fromBinary(RendezvousMessageSchema, raw);
      } catch {
        continue;
      }
      const u = msg.union;
      if (u.case === "punchHoleResponse") {
        const r = u.value;
        if (r.otherFailure) {
          const lower = r.otherFailure.toLowerCase();
          const code = lower.includes("login") || lower.includes("token") ? "login-required" : "refused";
          throw new RendezvousError(r.otherFailure, code);
        }
        switch (r.failure) {
          case PunchHoleResponse_Failure.OFFLINE:
            throw new RendezvousError("the remote device is offline", "offline");
          case PunchHoleResponse_Failure.LICENSE_MISMATCH:
            throw new RendezvousError("the server key does not match", "key-mismatch");
          case PunchHoleResponse_Failure.LICENSE_OVERUSE:
            throw new RendezvousError("the server refused the connection (licence overuse)", "refused");
          case PunchHoleResponse_Failure.ID_NOT_EXIST:
            if (r.socketAddr.length === 0 && !r.relayServer) {
              throw new RendezvousError("the ID does not exist", "not-found");
            }
            break;
        }
        // A punch-hole answer with an address means the peer wants a direct
        // connection, which a browser cannot do; keep waiting for the relay.
        continue;
      }
      if (u.case === "relayResponse") {
        return ticketFrom(u.value);
      }
    }
  } finally {
    t.close("rendezvous done");
  }
}

function ticketFrom(r: RelayResponse): RelayTicket {
  if (r.refuseReason) throw new RendezvousError(r.refuseReason, "refused");
  if (!r.uuid) throw new RendezvousError("the server sent a relay answer without a session id", "refused");
  return {
    uuid: r.uuid,
    relayServer: r.relayServer,
    signedPeerKey: r.union.case === "pk" ? r.union.value : new Uint8Array(0),
    peerVersion: r.version,
  };
}

/** Joins the relay pair for `uuid`; resolves once hbbr accepted the request. */
export async function joinRelay(
  url: string,
  uuid: string,
  peerId: string,
  licenceKey: string,
  signal?: AbortSignal,
  connType: ConnType = ConnType.DEFAULT_CONN,
): Promise<WsTransport> {
  let t: WsTransport;
  try {
    t = await WsTransport.open(url, { timeoutMs: 10_000, signal });
  } catch (e) {
    if (e instanceof TransportError && e.code === "aborted") throw e;
    throw new RendezvousError(`cannot reach the relay server: ${(e as Error).message}`, "unreachable");
  }
  const req = create(RendezvousMessageSchema, {
    union: {
      case: "requestRelay",
      value: { id: peerId, uuid, licenceKey, secure: true, connType },
    },
  });
  t.send(toBinary(RendezvousMessageSchema, req));
  return t;
}

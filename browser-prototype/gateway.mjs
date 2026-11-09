import http from 'node:http';
import net from 'node:net';
import { pathToFileURL } from 'node:url';
import { WebSocket, WebSocketServer } from 'ws';
import { encodeFrame, FrameDecoder, MAX_FRAME } from './framing.mjs';

// A fixed destination keeps the initial prototype focused on one configured host.
export function createGateway({ destinationHost, destinationPort, listenHost = '127.0.0.1', listenPort = 0 }) {
  if (!destinationHost || !Number.isInteger(destinationPort) || destinationPort < 1 || destinationPort > 65535) throw new Error('A destination host and port are required');
  const httpServer = http.createServer((_req, res) => { res.writeHead(404); res.end(); });
  const wss = new WebSocketServer({ server: httpServer, maxPayload: MAX_FRAME });
  wss.on('connection', ws => {
    const socket = net.createConnection({ host: destinationHost, port: destinationPort });
    const decoder = new FrameDecoder();
    let closed = false;
    const close = () => { if (closed) return; closed = true; socket.destroy(); if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close(); };
    ws.on('message', (data, binary) => {
      if (!binary) return close();
      try { if (socket.writableLength > MAX_FRAME * 2) return close(); socket.write(encodeFrame(data)); } catch { close(); }
    });
    socket.on('data', chunk => {
      try {
        for (const frame of decoder.push(chunk)) {
          if (ws.readyState !== WebSocket.OPEN || ws.bufferedAmount > MAX_FRAME * 2) return close();
          ws.send(frame, { binary: true });
        }
      } catch { close(); }
    });
    socket.on('error', close); socket.on('close', close);
    ws.on('error', close); ws.on('close', close);
  });
  return {
    listen: () => new Promise((resolve, reject) => { httpServer.once('error', reject); httpServer.listen(listenPort, listenHost, () => resolve(httpServer.address())); }),
    close: () => new Promise(resolve => { for (const client of wss.clients) client.terminate(); wss.close(() => httpServer.close(resolve)); }),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.DESKTOP_HOST_PORT || 42830);
  const gateway = createGateway({ destinationHost: process.env.DESKTOP_HOST, destinationPort: port, listenHost: process.env.LISTEN_HOST || '127.0.0.1', listenPort: Number(process.env.LISTEN_PORT || 8080) });
  console.log('Gateway listening:', await gateway.listen());
}

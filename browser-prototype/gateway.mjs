import http from 'node:http';
import net from 'node:net';
import { readFile, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { WebSocket, WebSocketServer } from 'ws';
import { encodeFrame, FrameDecoder, MAX_FRAME } from './framing.mjs';
import { createProofProvider } from './proof-provider.mjs';

// A fixed destination keeps the initial prototype focused on one configured host.
export function createGateway({ destinationHost, destinationPort, listenHost = '127.0.0.1', listenPort = 0, provider = null, staticDir = null }) {
  if (!destinationHost || !Number.isInteger(destinationPort) || destinationPort < 1 || destinationPort > 65535) throw new Error('A destination host and port are required');
  const respond=(res,code,value)=>{res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(value));};
  const httpServer = http.createServer(async (req,res) => {
    try {
      const pathname=new URL(req.url,'http://localhost').pathname;
      if(pathname==='/api/config' && req.method==='GET') return provider?respond(res,200,await provider.info()):respond(res,503,{error:'Viewer is not configured'});
      if(pathname==='/api/proof' && req.method==='POST') {
        if(!provider)return respond(res,503,{error:'Viewer is not configured'});
        let body='';for await(const chunk of req){body+=chunk;if(body.length>4096)throw new Error('Request too large');}
        const data=JSON.parse(body);return respond(res,200,await provider.issue(data.host,data.binding));
      }
      if(req.method!=='GET' || !staticDir)return respond(res,404,{error:'Not found'});
      const base=path.resolve(staticDir), relative=pathname==='/'?'index.html':decodeURIComponent(pathname).replace(/^\//,'');
      const file=path.resolve(base,relative);
      if(!file.startsWith(base+path.sep))return respond(res,404,{error:'Not found'});
      readFile(file,(error,data)=>{if(error)return respond(res,404,{error:'Not found'});const ext=path.extname(file);const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.wasm':'application/wasm'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream'});res.end(data);});
    } catch { if(!res.headersSent)respond(res,400,{error:'Request could not be completed'});else res.destroy(); }
  });
  const wss = new WebSocketServer({ server: httpServer, path: '/desktop', maxPayload: MAX_FRAME });
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
  let provider=null;
  if(process.env.PROTOTYPE_VIEWER_CONFIG){
    const file=process.env.PROTOTYPE_VIEWER_CONFIG, stat=statSync(file);
    if(process.platform!=='win32' && (stat.mode & 0o077)!==0)throw new Error('Viewer configuration must be private to its owner');
    provider=createProofProvider(JSON.parse(readFileSync(file,'utf8')));
  }
  const gateway = createGateway({ destinationHost: process.env.DESKTOP_HOST, destinationPort: port, listenHost: process.env.LISTEN_HOST || '127.0.0.1', listenPort: Number(process.env.LISTEN_PORT || 8080), provider, staticDir: path.resolve('dist') });
  console.log('Gateway listening:', await gateway.listen());
}

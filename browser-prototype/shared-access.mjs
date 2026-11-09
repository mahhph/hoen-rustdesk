import https from 'node:https';
import http from 'node:http';
import {readFileSync} from 'node:fs';
import {randomBytes,scryptSync,timingSafeEqual} from 'node:crypto';

// Private operator-provisioned config; never served to the browser.
const config=JSON.parse(readFileSync(process.env.SHARED_ACCESS_CONFIG,'utf8'));
const origin=new URL(config.origin).origin;
const sessions=new Map();
const login=`<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Remote Desktop sign in</title><style>body{font:17px system-ui;background:#101827;color:#eef2ff;max-width:360px;margin:12vh auto;padding:24px}input,button{box-sizing:border-box;width:100%;font:inherit;padding:14px;margin-top:16px;border-radius:8px}button{background:#2866e6;color:white;border:0}</style><h1>Remote Desktop</h1><p>Sign in to connect to Area51.</p><form method="post" action="/login"><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button>Sign in</button></form></html>`;
const cookie=req=>/\bdesktop_session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie||'')?.[1];
const authorized=req=>{const expires=sessions.get(cookie(req));return expires!==undefined&&expires>Date.now();};
const validOrigin=req=>req.headers.host===new URL(origin).host&&(!req.headers.origin||req.headers.origin===origin);
function headers(req){const h={...req.headers,host:'127.0.0.1:42840'};delete h.cookie;delete h.authorization;if(h.origin)h.origin='http://127.0.0.1:42840';return h;}
function deny(res,status,text){res.writeHead(status,{'Content-Type':'text/plain','Cache-Control':'no-store'});res.end(text);}
let failures=0,blockedUntil=0;
const server=https.createServer({key:readFileSync(config.keyFile),cert:readFileSync(config.certFile),minVersion:'TLSv1.2'},async(req,res)=>{
 try{
  if(!validOrigin(req))return deny(res,403,'Invalid origin');
  if(req.method==='POST'&&req.url==='/login'){
   if(Date.now()<blockedUntil)return deny(res,429,'Please wait one minute before trying again.');
   let body='';for await(const chunk of req){body+=chunk;if(body.length>2048)return deny(res,413,'Request too large');}
   const supplied=new URLSearchParams(body).get('password')||'';
   const actual=scryptSync(supplied,config.salt,32),expected=Buffer.from(config.passwordHash,'hex');
   if(expected.length!==actual.length||!timingSafeEqual(actual,expected)){if(++failures>=10){blockedUntil=Date.now()+60000;failures=0;}return deny(res,401,'Incorrect password. Go back to try again.');}
   failures=0;for(const [id,expires] of sessions)if(expires<Date.now())sessions.delete(id);
   const id=randomBytes(32).toString('hex');sessions.set(id,Date.now()+8*3600000);
   res.writeHead(303,{Location:'/', 'Cache-Control':'no-store','Set-Cookie':`desktop_session=${id}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`});return res.end();
  }
  if(!authorized(req)){if(req.method!=='GET'||req.url!=='/')return deny(res,401,'Sign in required');res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});return res.end(login);}
  const upstream=http.request({hostname:'127.0.0.1',port:42840,path:req.url,method:req.method,headers:headers(req)},reply=>{res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);});
  upstream.on('error',()=>{if(!res.headersSent)deny(res,502,'Desktop service unavailable');else res.destroy();});req.pipe(upstream);
 }catch{if(!res.headersSent)deny(res,400,'Request failed');else res.destroy();}
});
server.on('upgrade',(req,socket,head)=>{
 if(!validOrigin(req)||req.headers.origin!==origin||!authorized(req)||new URL(req.url,origin).pathname!=='/desktop'){socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return;}
 const upstream=http.request({hostname:'127.0.0.1',port:42840,path:req.url,headers:headers(req)});
 upstream.on('upgrade',(res,remote,remoteHead)=>{socket.write('HTTP/1.1 101 Switching Protocols\r\n'+Object.entries(res.headers).map(([k,v])=>`${k}: ${v}`).join('\r\n')+'\r\n\r\n');if(head.length)remote.write(head);if(remoteHead.length)socket.write(remoteHead);socket.pipe(remote).pipe(socket);socket.on('error',()=>remote.destroy());remote.on('error',()=>socket.destroy());socket.on('close',()=>remote.destroy());remote.on('close',()=>socket.destroy());});
 upstream.on('response',()=>socket.destroy());upstream.on('error',()=>socket.destroy());upstream.end();
});
server.requestTimeout=30000;server.headersTimeout=15000;
server.listen(42841,'127.0.0.1',()=>console.log('Shared HTTPS sign-in listening on loopback port 42841'));

import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import WebSocket from 'ws';
import { createGateway } from './gateway.mjs';
import { FrameDecoder, encodeFrame } from './framing.mjs';

test('translates real WebSocket messages to and from native TCP frames', async t => {
  const received = [];
  const server = net.createServer(socket => {
    const decoder = new FrameDecoder();
    socket.on('data', chunk => {
      for (const frame of decoder.push(chunk)) {
        received.push(frame.toString());
        const reply = encodeFrame(Buffer.from(`reply:${frame}`));
        socket.write(reply.subarray(0, 1));
        socket.write(reply.subarray(1));
      }
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const gateway = createGateway({ destinationHost: '127.0.0.1', destinationPort: server.address().port });
  const address = await gateway.listen();
  t.after(async () => { await gateway.close(); await new Promise(resolve => server.close(resolve)); });
  const ws = new WebSocket(`ws://127.0.0.1:${address.port}/desktop`);
  await once(ws, 'open');
  const reply = once(ws, 'message');
  ws.send(Buffer.from('actual-frame'));
  const [data, binary] = await reply;
  assert.equal(binary, true);
  assert.equal(data.toString(), 'reply:actual-frame');
  assert.deepEqual(received, ['actual-frame']);
  ws.close();
  await once(ws, 'close');
});

test('browser configuration and proof endpoints use the configured provider', async t => {
  const gateway=createGateway({destinationHost:'127.0.0.1',destinationPort:12345,provider:{info:async()=>({host:'windows',hostFingerprint:'a'.repeat(64)}),issue:async(host,binding)=>({host,binding})}});
  const address=await gateway.listen();
  t.after(()=>gateway.close());
  const base=`http://127.0.0.1:${address.port}`;
  assert.equal((await (await fetch(`${base}/api/config`)).json()).host,'windows');
  const response=await fetch(`${base}/api/proof`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:'windows',binding:'b'.repeat(64)})});
  assert.equal((await response.json()).binding,'b'.repeat(64));
});

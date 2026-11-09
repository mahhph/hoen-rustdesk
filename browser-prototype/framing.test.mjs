import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeFrame, FrameDecoder } from './framing.mjs';

test('round-trips native frame boundary sizes across fragmented and coalesced input', () => {
  const lengths = [0, 1, 63, 64, 16383, 16384, 4194303, 4194304];
  const expected = lengths.map(n => Buffer.alloc(n, n % 251));
  const wire = Buffer.concat(expected.map(x => encodeFrame(x)));
  const decoder = new FrameDecoder();
  const actual = [];
  for (let i = 0; i < wire.length; i += 32749) actual.push(...decoder.push(wire.subarray(i, i + 32749)));
  assert.deepEqual(actual, expected);
});

test('rejects oversized frames before waiting for their content', () => {
  assert.throws(() => encodeFrame(Buffer.alloc(11), 10), /exceeds/);
  assert.throws(() => new FrameDecoder(10).push(encodeFrame(Buffer.alloc(11))), /exceeds/);
});

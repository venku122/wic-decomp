import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectPEBuffer } from './inspect-pe.mjs';

// Entirely synthetic fixture; no game or Microsoft executable bytes.
function fakePE({ machine = 0x014c, rich = true, pe32plus = false } = {}) {
  const b = Buffer.alloc(1024);
  b.writeUInt16LE(0x5a4d, 0);
  b.writeUInt32LE(0x100, 0x3c);
  if (rich) {
    const start = 0x40;
    const key = 0x12345678;
    b.writeUInt32LE((0x536e6144 ^ key) >>> 0, start);
    for (let i = 4; i < 16; i += 4) b.writeUInt32LE(key, start + i);
    b.writeUInt32LE((((92 << 16) | 50727) ^ key) >>> 0, start + 16);
    b.writeUInt32LE((3 ^ key) >>> 0, start + 20);
    b.write('Rich', start + 24, 'ascii');
    b.writeUInt32LE(key, start + 28);
  }
  b.write('PE\0\0', 0x100, 'latin1');
  b.writeUInt16LE(machine, 0x104);
  b.writeUInt16LE(1, 0x106);
  b.writeUInt32LE(1700000000, 0x108);
  b.writeUInt16LE(0xe0, 0x114);
  const opt = 0x118;
  b.writeUInt16LE(pe32plus ? 0x20b : 0x10b, opt);
  b.writeUInt8(8, opt + 2);
  b.writeUInt8(0, opt + 3);
  b.writeUInt32LE(0x1234, opt + 16);
  const section = opt + 0xe0;
  b.write('.text', section, 'ascii');
  b.writeUInt32LE(0x1000, section + 12);
  b.writeUInt32LE(0x200, section + 16);
  b.writeUInt32LE(0x400, section + 20);
  return b;
}

test('parses synthetic PE32/x86 safely and returns compiler hints without asserting provenance', () => {
  const r = inspectPEBuffer(fakePE());
  assert.equal(r.machine, '0x014c');
  assert.equal(r.arch, 'x86');
  assert.equal(r.pe_format, 'PE32');
  assert.equal(r.image_linker_major, 8);
  assert.equal(r.rich_header.record_count, 1);
  assert.deepEqual(r.rich_header.records[0], { product_id: 92, build: 50727, count: 3 });
  assert.equal(r.matches_prior_recorded_wic_build, false);
  assert.equal(r.sections[0].name, '.text');
});

test('handles missing Rich header without failure', () => {
  assert.equal(inspectPEBuffer(fakePE({ rich: false })).rich_header, null);
});

test('distinguishes synthetic x64/PE32+ as non-target architecture', () => {
  const r = inspectPEBuffer(fakePE({ machine: 0x8664, pe32plus: true }));
  assert.equal(r.arch, 'x64');
  assert.equal(r.pe_format, 'PE32+');
});

test('rejects invalid or truncated PE safely', () => {
  assert.throws(() => inspectPEBuffer(Buffer.alloc(10)), /out of bounds/);
  const invalid = fakePE();
  invalid.writeUInt32LE(0xffffffff, 0x3c);
  assert.throws(() => inspectPEBuffer(invalid), /out of bounds/);
  const wrong = fakePE();
  wrong.write('ZZ\0\0', 0x100, 'latin1');
  assert.throws(() => inspectPEBuffer(wrong), /Missing PE signature/);
});

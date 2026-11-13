import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { compareFunction } from './verify-function.mjs';

function fixture({ targetRelocation = 0, objectRelocation = 0, change = false } = {}) {
  const target = Buffer.alloc(0x600);
  target.write('MZ');
  target.writeUInt32LE(0x80, 0x3c);
  target.write('PE\0\0', 0x80, 'latin1');
  target.writeUInt16LE(0x14c, 0x84);
  target.writeUInt16LE(2, 0x86);
  target.writeUInt16LE(0xe0, 0x94);
  target.writeUInt16LE(0x10b, 0x98);
  target.writeUInt32LE(0x400000, 0xb4);
  target.writeUInt32LE(16, 0xf4);
  const text = 0x178;
  target.write('.text', text);
  target.writeUInt32LE(0x100, text + 8);
  target.writeUInt32LE(0x1000, text + 12);
  target.writeUInt32LE(0x200, text + 16);
  target.writeUInt32LE(0x200, text + 20);
  target.writeUInt32LE(0x60000020, text + 36);
  target.write('.reloc', text + 40);
  target.writeUInt32LE(0x100, text + 48);
  target.writeUInt32LE(0x2000, text + 52);
  target.writeUInt32LE(0x200, text + 56);
  target.writeUInt32LE(0x400, text + 60);
  target.writeUInt32LE(0x42000040, text + 76);
  const code = Buffer.from([0xb8, 0, 0, 0, 0, 0xc3]);
  if (targetRelocation) {
    target.writeUInt32LE(0x2000, 0x120);
    target.writeUInt32LE(12, 0x124);
    target.writeUInt32LE(0x1000, 0x400);
    target.writeUInt32LE(12, 0x404);
    target.writeUInt16LE((targetRelocation << 12) | 1, 0x408);
    code.writeUInt32LE(0x401080, 1);
  }
  if (objectRelocation === 0x14 && !targetRelocation) {
    code[0] = 0xe8;
    code.writeInt32LE(0x1080 - 0x1005, 1);
  }
  code.copy(target, 0x200);
  const object = Buffer.alloc(146);
  object.writeUInt16LE(0x14c);
  object.writeUInt16LE(1, 2);
  object.writeUInt32LE(70, 8);
  object.writeUInt32LE(4, 12);
  object.write('.text$x', 20);
  object.writeUInt32LE(code.length, 36);
  object.writeUInt32LE(60, 40);
  object.writeUInt32LE(60 + code.length, 44);
  object.writeUInt16LE(objectRelocation ? 1 : 0, 52);
  object.writeUInt32LE(0x60501020, 56);
  code.copy(object, 60);
  if (change) object[60] = 0xb9;
  if (objectRelocation) {
    object.writeUInt32LE(0, 61);
    // Relocations follow the text section, before the symbol table.
    object.writeUInt32LE(1, 66);
    object.writeUInt32LE(3, 70);
    object.writeUInt16LE(objectRelocation, 74);
  }
  // Move the symbol table beyond the relocation record.
  object.writeUInt32LE(76, 8);
  const table = Buffer.alloc(152);
  object.copy(table, 0, 0, 76);
  table.write('.text$x', 76);
  table.writeUInt16LE(1, 88);
  table[92] = 3;
  table[93] = 1;
  table.writeUInt32LE(code.length, 94);
  table.writeUInt16LE(objectRelocation ? 1 : 0, 98);
  table[108] = 1; // IMAGE_COMDAT_SELECT_NODUPLICATES
  table.write('_sample', 112);
  table.writeUInt16LE(1, 124);
  table.writeUInt16LE(0x20, 126);
  table[128] = 2;
  table.write('_global', 130);
  table[146] = 2;
  table.writeUInt32LE(4, 148);
  const spec = {
    targetSha256: createHash('sha256').update(target).digest('hex'),
    rva: 0x1000,
    endRva: 0x1006,
    symbol: '_sample',
    absoluteSymbols: { _global: 0x1080 },
    relativeSymbols: { _global: 0x1080 },
  };
  return { target, object: table, spec };
}

function compare({ target, object, spec }) {
  return compareFunction(target, object, spec);
}

test('compares a full synthetic function exactly and reports no private data', () => {
  const result = compare(fixture());
  assert.equal(result.status, 'locally_matched');
  assert.equal(result.comparison, 'exact');
  assert.equal(result.byte_count_compared, 6);
  assert.equal(result.independent_verification, false);
  assert.doesNotMatch(JSON.stringify(result), /_sample|_global|b800000000c3/);
});

test('different code generation is a mismatch', () => {
  assert.equal(compare(fixture({ change: true })).status, 'mismatch');
});

test('a wrong end boundary cannot match a common prefix', () => {
  const data = fixture();
  data.spec.endRva--;
  assert.equal(compare(data).status, 'mismatch');
});

test('rejects wrong build and truncated COFF', () => {
  const data = fixture();
  const truncated = { ...data, object: data.object.subarray(0, 100) };
  assert.equal(compare(truncated).status, 'unverifiable');
  data.target[0x210] ^= 1;
  assert.equal(compare(data).reason, 'target_identity');
});

test('paired DIR32 and HIGHLOW require the same resolved address', () => {
  const data = fixture({ targetRelocation: 3, objectRelocation: 6 });
  assert.equal(compare(data).comparison, 'relocation_adjusted');
  data.spec.absoluteSymbols._global++;
  assert.equal(compare(data).status, 'mismatch');
});

test('identical bytes do not override unsupported, unpaired or crossing fixups', () => {
  for (const data of [
    fixture({ targetRelocation: 3 }),
    fixture({ targetRelocation: 3, objectRelocation: 0x14 }),
    fixture({ targetRelocation: 5, objectRelocation: 6 }),
  ]) {
    assert.equal(compare(data).status, 'unverifiable');
  }
  const crossing = fixture({ targetRelocation: 3, objectRelocation: 6 });
  crossing.spec.rva += 2;
  assert.equal(compare(crossing).status, 'unverifiable');
});


test('resolves REL32 without wildcarding the displacement', () => {
  const data = fixture({ objectRelocation: 0x14 });
  assert.equal(compare(data).comparison, 'relocation_adjusted');
  data.spec.relativeSymbols._global++;
  assert.equal(compare(data).status, 'mismatch');
  data.spec.relativeSymbols._global = 0x2000;
  assert.equal(compare(data).status, 'unverifiable');
});

test('rejects an overlapping relocation site in the target', () => {
  const data = fixture({ targetRelocation: 3, objectRelocation: 6 });
  data.target.writeUInt16LE(0x3002, 0x40a);
  data.spec.targetSha256 = createHash('sha256').update(data.target).digest('hex');
  assert.equal(compare(data).reason, 'overlapping_pe_relocations');
});

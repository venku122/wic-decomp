#!/usr/bin/env node
/**
 * Minimal read-only PE inspector for locally owned executables.
 * Does not run, modify, transmit, or embed game contents.
 * Rich-header records are forensic hints, not proof of compiler provenance.
 */
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const CANONICAL_WIC_SHA256 = '86807eb0d9d60abe7263b69d7f53d2089ee791f9407bd5a7c737c3f7b3f1588a';
const MINIMUM_DOS_HEADER = 0x40;
const MAX_SECTIONS = 96;

function requireRange(buffer, offset, length, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > buffer.length) {
    throw new Error(`Truncated or invalid PE: ${label} is out of bounds`);
  }
}

function richHeader(buffer, peOffset) {
  // Rich header is stored inside the DOS stub and obfuscated by an XOR key.
  // Missing or malformed records must not invalidate an otherwise valid PE.
  const end = buffer.lastIndexOf(Buffer.from('Rich'), peOffset - 8);
  if (end < MINIMUM_DOS_HEADER || end + 8 > peOffset) return null;
  const key = buffer.readUInt32LE(end + 4);
  let start = -1;
  for (let i = end - 4; i >= MINIMUM_DOS_HEADER; i -= 4) {
    if (((buffer.readUInt32LE(i) ^ key) >>> 0) === 0x536e6144) { // 'DanS' little-endian
      start = i;
      break;
    }
  }
  if (start < 0 || start + 16 > end || (end - start - 16) % 8 !== 0) return null;
  for (let i = start + 4; i < start + 16; i += 4) {
    if (((buffer.readUInt32LE(i) ^ key) >>> 0) !== 0) return null;
  }
  const records = [];
  for (let i = start + 16; i + 8 <= end; i += 8) {
    const compId = (buffer.readUInt32LE(i) ^ key) >>> 0;
    const useCount = (buffer.readUInt32LE(i + 4) ^ key) >>> 0;
    if (useCount === 0) continue;
    records.push({ product_id: compId >>> 16, build: compId & 0xffff, count: useCount });
  }
  return { offset: start, record_count: records.length, records };
}

export function inspectPEBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Expected a Buffer');
  requireRange(buffer, 0, MINIMUM_DOS_HEADER, 'DOS header');
  if (buffer.readUInt16LE(0) !== 0x5a4d) throw new Error('Not a DOS MZ executable');
  const peOffset = buffer.readUInt32LE(0x3c);
  requireRange(buffer, peOffset, 24, 'PE signature and COFF header');
  if (buffer.toString('latin1', peOffset, peOffset + 4) !== 'PE\0\0') throw new Error('Missing PE signature');

  const coff = peOffset + 4;
  const machine = buffer.readUInt16LE(coff);
  const numberOfSections = buffer.readUInt16LE(coff + 2);
  const timestamp = buffer.readUInt32LE(coff + 4);
  const optionalSize = buffer.readUInt16LE(coff + 16);
  if (numberOfSections > MAX_SECTIONS) throw new Error(`Unreasonable section count: ${numberOfSections}`);
  const optional = coff + 20;
  requireRange(buffer, optional, optionalSize, 'optional header');
  if (optionalSize < 20) throw new Error('Optional header too small');
  const magic = buffer.readUInt16LE(optional);
  if (magic !== 0x10b && magic !== 0x20b) throw new Error('Not a PE32 or PE32+ image');
  const table = optional + optionalSize;
  requireRange(buffer, table, numberOfSections * 40, 'section headers');

  const sections = [];
  for (let n = 0; n < numberOfSections; n++) {
    const base = table + n * 40;
    sections.push({
      name: buffer.subarray(base, base + 8).toString('latin1').replace(/\0.*$/, ''),
      rva: `0x${buffer.readUInt32LE(base + 12).toString(16)}`,
      raw_offset: buffer.readUInt32LE(base + 20),
      raw_size: buffer.readUInt32LE(base + 16),
    });
  }

  const sha256 = createHash('sha256').update(buffer).digest('hex');
  const rich = richHeader(buffer, peOffset);
  return {
    sha256,
    matches_prior_recorded_wic_build: sha256 === CANONICAL_WIC_SHA256,
    file_size_bytes: buffer.length,
    machine: `0x${machine.toString(16).padStart(4, '0')}`,
    arch: machine === 0x14c ? 'x86' : machine === 0x8664 ? 'x64' : 'other',
    pe_format: magic === 0x10b ? 'PE32' : 'PE32+',
    image_linker_major: buffer.readUInt8(optional + 2),
    image_linker_minor: buffer.readUInt8(optional + 3),
    coff_timestamp_unix: timestamp,
    coff_timestamp_utc: timestamp ? new Date(timestamp * 1000).toISOString() : null,
    entry_point_rva: `0x${buffer.readUInt32LE(optional + 16).toString(16)}`,
    number_of_sections: numberOfSections,
    sections,
    rich_header: rich,
    caveat: 'Metadata is not compiler-build proof. Source/toolchain flags and independent byte matching remain unverified.',
  };
}

async function main() {
  const arg = process.argv[2];
  if (!arg || ['-h', '--help'].includes(arg)) {
    console.log('Usage: node scripts/inspect-pe.mjs <path-to-locally-owned-executable>');
    console.log('Reads file locally; prints only derived PE metadata and SHA-256. Never executes it.');
    process.exitCode = arg ? 0 : 2;
    return;
  }
  const result = inspectPEBuffer(await readFile(arg));
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch(error => {
    console.error(`PE inspection failed: ${error.message}`);
    process.exitCode = 1;
  });
}

#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import {
  readTargetFunction, readObjectFunction, requireEvidence, VerificationError,
} from './x86-function-code.mjs';

const uint32 = value => Number.isInteger(value) && value >= 0 && value <= 0xffffffff;

export function compareFunction(image, object, spec) {
  const result = {
    schema_version: 1,
    checker_version: 'x86-coff-v1',
    independent_verification: false,
    byte_count_compared: 0,
    mismatch_count: 0,
  };
  try {
    requireEvidence(typeof spec?.targetSha256 === 'string' && /^[0-9a-f]{64}$/.test(spec.targetSha256),
      'invalid_target_identity');
    requireEvidence(uint32(spec.rva) && uint32(spec.endRva) && spec.endRva > spec.rva &&
      typeof spec.symbol === 'string' && spec.symbol.length > 0, 'invalid_function_scope');
    const target = readTargetFunction(image, spec);
    const candidate = readObjectFunction(object, spec.symbol);
    const relocated = Buffer.from(candidate.bytes);
    const paired = new Set();
    for (const { offset, type, name } of candidate.relocations) {
      const symbols = type === 0x06 ? spec.absoluteSymbols : spec.relativeSymbols;
      requireEvidence(symbols && Object.hasOwn(symbols, name) && uint32(symbols[name]),
        'unresolved_coff_reference');
      const addend = relocated.readInt32LE(offset);
      requireEvidence(target.containsRva(symbols[name], type === 0x14) &&
        target.containsRva(symbols[name] + addend, type === 0x14), 'invalid_symbol_binding');
      if (type === 0x06) {
        requireEvidence(target.relocations.has(offset), 'unpaired_pe_relocation');
        const value = target.imageBase + symbols[name] + addend;
        requireEvidence(uint32(value), 'invalid_resolved_address');
        relocated.writeUInt32LE(value, offset);
        paired.add(offset);
      } else {
        const displacement = symbols[name] + addend - (spec.rva + offset + 4);
        requireEvidence(displacement >= -0x80000000 && displacement <= 0x7fffffff,
          'invalid_resolved_address');
        relocated.writeInt32LE(displacement, offset);
      }
    }
    requireEvidence(paired.size === target.relocations.size, 'unpaired_pe_relocation');
    const compared = Math.min(target.bytes.length, relocated.length);
    let mismatches = Math.abs(target.bytes.length - relocated.length);
    for (let offset = 0; offset < compared; offset++) {
      if (target.bytes[offset] !== relocated[offset]) mismatches++;
    }
    return {
      ...result,
      status: mismatches ? 'mismatch' : 'locally_matched',
      comparison: candidate.relocations.length ? 'relocation_adjusted' : 'exact',
      byte_count_compared: compared,
      target_byte_count: target.bytes.length,
      candidate_byte_count: relocated.length,
      mismatch_count: mismatches,
      relocation_count: candidate.relocations.length,
    };
  } catch (error) {
    if (!(error instanceof VerificationError)) throw error;
    return { ...result, status: 'unverifiable', reason: error.reason };
  }
}

export function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

async function main(args) {
  if (args.length !== 3) {
    console.error('Usage: node scripts/verify-function.mjs <target.exe> <candidate.obj> <private-scope.json>');
    return 2;
  }
  const [image, object, json] = await Promise.all(args.map(path => readFile(path)));
  const result = compareFunction(image, object, JSON.parse(json));
  console.log(JSON.stringify(result, null, 2));
  return result.status === 'locally_matched' ? 0 : result.status === 'mismatch' ? 1 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then(code => {
    process.exitCode = code;
  }).catch(() => {
    console.error('Verification failed to read or process local inputs.');
    process.exitCode = 2;
  });
}

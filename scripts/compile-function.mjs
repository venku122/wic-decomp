#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve, join, dirname, basename } from 'node:path';
import { compareFunction, sha256 } from './verify-function.mjs';
import { readTargetFunction } from './x86-function-code.mjs';

// Keep output locations and the actual compiler invocation under the checker's control.
const supportedFlag = /^\/(?:O[12dxtsy]|Oy-?|Ob[012]|GS-?|GR-?|EHsc|arch:SSE2?|fp:(?:precise|strict|fast))$/;
const digest = /^[0-9a-f]{64}$/;
const components = ['cl.exe', 'c1xx.dll', 'c2.dll'];

async function compileAndCompare(spec) {
  if (!Array.isArray(spec.flags) || !spec.flags.every(flag =>
    typeof flag === 'string' && supportedFlag.test(flag))) {
    throw new Error('unsupported_compile_flags');
  }
  if (typeof spec.boundaryEvidence !== 'string' || !spec.boundaryEvidence.trim()) {
    throw new Error('missing_boundary_evidence');
  }
  const compiler = resolve(spec.compiler);
  if (basename(compiler).toLowerCase() !== 'cl.exe') throw new Error('unsupported_compiler');
  const hashes = {};
  for (const component of components) {
    const expected = spec.toolchainSha256?.[component];
    if (typeof expected !== 'string' || !digest.test(expected)) throw new Error('missing_toolchain_identity');
    hashes[component] = sha256(await readFile(join(dirname(compiler), component)));
    if (hashes[component] !== expected) throw new Error('toolchain_identity');
  }

  const image = await readFile(resolve(spec.target));
  if (!Number.isInteger(spec.rva) || !Number.isInteger(spec.endRva) ||
      spec.rva < 0 || spec.endRva > 0xffffffff || spec.endRva <= spec.rva) {
    throw new Error('invalid_function_scope');
  }
  readTargetFunction(image, spec);
  let boundaryDigest;
  if (spec.boundaryIndex) {
    const boundaryBytes = await readFile(resolve(spec.boundaryIndex));
    boundaryDigest = sha256(boundaryBytes);
    if (boundaryDigest !== spec.boundaryIndexSha256) throw new Error('boundary_index_identity');
    const matches = boundaryBytes.toString('utf8').split(/\r?\n/).filter(line => line.trim())
      .map(line => JSON.parse(line)).filter(row => Number(row.rva) === spec.rva);
    if (matches.length !== 1 || Number(matches[0].endRvaExclusive) !== spec.endRva ||
        matches[0].length !== spec.endRva - spec.rva) {
      throw new Error('boundary_index_scope');
    }
  }
  const source = await readFile(resolve(spec.source));
  const workspace = await mkdtemp(join(resolve(spec.workDir), 'wic-verify-'));
  const args = ['/nologo', '/c', '/TP', '/Gy', '/X', ...spec.flags, '/Focandidate.obj', 'candidate.cpp'];
  try {
    await writeFile(join(workspace, 'candidate.cpp'), source);
    // Strip compiler options and search paths injected by the calling shell.
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      !['CL', '_CL_', 'INCLUDE', 'LIB', 'LIBPATH'].includes(key.toUpperCase())));
    const run = spawnSync(compiler, args, { cwd: workspace, env, windowsHide: true, timeout: 30000 });
    if (run.error || run.status !== 0) throw new Error('compile_failed');
    if (/\b(?:D9002|D9025)\b/.test(String(run.stderr) + String(run.stdout))) {
      throw new Error('compiler_rejected_flags');
    }
    const object = await readFile(join(workspace, 'candidate.obj'));
    const result = compareFunction(image, object, spec);
    return {
      result,
      evidence: {
        ...result,
        target_sha256: spec.targetSha256,
        source_sha256: sha256(source),
        object_sha256: sha256(object),
        toolchain_sha256: hashes,
        command: [compiler, ...args],
        boundary_index_sha256: boundaryDigest,
        scope: {
          rva: spec.rva,
          endRva: spec.endRva,
          boundaryEvidence: spec.boundaryEvidence,
          symbol: spec.symbol,
          absoluteSymbols: spec.absoluteSymbols,
          relativeSymbols: spec.relativeSymbols,
        },
      },
    };
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

const reportedErrors = new Set([
  'unsupported_compile_flags', 'missing_boundary_evidence', 'unsupported_compiler',
  'missing_toolchain_identity', 'toolchain_identity', 'target_identity', 'compile_failed',
  'compiler_rejected_flags', 'invalid_function_scope', 'invalid_pe', 'unsupported_pe', 'target_boundary', 'truncated_pe',
  'invalid_pe_relocations', 'unsupported_pe_relocation', 'crossing_pe_relocation',
  'overlapping_pe_relocations', 'boundary_index_identity', 'boundary_index_scope',
]);

async function main() {
  const [config, evidencePath, ...extra] = process.argv.slice(2);
  if (!config || !evidencePath || extra.length) {
    console.error('Usage: node scripts/compile-function.mjs <private-config.json> <new-private-evidence.json>');
    return 2;
  }
  try {
    const spec = JSON.parse(await readFile(config, 'utf8'));
    const { result, evidence } = await compileAndCompare(spec);
    await writeFile(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify(result, null, 2));
    return result.status === 'locally_matched' ? 0 : result.status === 'mismatch' ? 1 : 2;
  } catch (error) {
    const reason = reportedErrors.has(error.message) ? error.message : 'local_input_or_output_error';
    console.log(JSON.stringify({
      schema_version: 1, status: 'unverifiable', reason, independent_verification: false,
    }, null, 2));
    return 2;
  }
}

process.exitCode = await main();

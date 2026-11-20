import { inspectPEBuffer } from './inspect-pe.mjs';

const EXECUTABLE_CODE = 0x20000020;
const X86 = 0x14c;

export class VerificationError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

export function requireEvidence(condition, reason) {
  if (!condition) throw new VerificationError(reason);
}

function slice(buffer, offset, size, reason) {
  requireEvidence(offset >= 0 && size >= 0 && offset + size <= buffer.length, reason);
  return buffer.subarray(offset, offset + size);
}

export function readTargetFunction(image, spec) {
  let info;
  try {
    info = inspectPEBuffer(image);
  } catch {
    throw new VerificationError('invalid_pe');
  }
  requireEvidence(info.sha256 === spec.targetSha256, 'target_identity');
  requireEvidence(info.arch === 'x86' && info.pe_format === 'PE32', 'unsupported_pe');
  const pe = image.readUInt32LE(0x3c);
  const optional = pe + 24;
  const optionalSize = image.readUInt16LE(pe + 20);
  requireEvidence(optionalSize >= 96, 'invalid_pe');
  const directoryCount = image.readUInt32LE(optional + 92);
  requireEvidence(directoryCount <= Math.floor((optionalSize - 96) / 8), 'invalid_pe');
  const imageBase = image.readUInt32LE(optional + 28);
  const sections = info.sections.map((section, index) => {
    const header = optional + optionalSize + index * 40;
    const virtualSize = image.readUInt32LE(header + 8);
    return {
      start: Number(section.rva),
      size: Math.min(virtualSize || section.raw_size, section.raw_size),
      offset: section.raw_offset,
      virtualSize: virtualSize || section.raw_size,
      executable: (image.readUInt32LE(header + 36) & EXECUTABLE_CODE) === EXECUTABLE_CODE,
    };
  });
  function bytesAt(rva, length, code) {
    const overlaps = sections.filter(section =>
      rva < section.start + section.size && rva + length > section.start);
    const [section] = overlaps;
    requireEvidence(overlaps.length === 1 && (!code || section.executable) &&
      rva >= section.start && rva + length <= section.start + section.size,
    code ? 'target_boundary' : 'invalid_pe_relocations');
    return slice(image, section.offset + rva - section.start, length, 'truncated_pe');
  }
  const { rva, endRva } = spec;
  const bytes = bytesAt(rva, endRva - rva, true);
  const relocations = new Set();
  function containsRva(address, executable) {
    const containing = sections.filter(section =>
      address >= section.start && address < section.start + section.virtualSize);
    return containing.length === 1 && (!executable || containing[0].executable);
  }
  if (directoryCount <= 5) return { bytes, imageBase, relocations, containsRva };
  const relocRva = image.readUInt32LE(optional + 136);
  const relocSize = image.readUInt32LE(optional + 140);
  requireEvidence(Boolean(relocRva) === Boolean(relocSize), 'invalid_pe_relocations');
  if (!relocSize) return { bytes, imageBase, relocations, containsRva };
  const table = bytesAt(relocRva, relocSize, false);
  for (let block = 0; block < table.length;) {
    slice(table, block, 8, 'invalid_pe_relocations');
    const page = table.readUInt32LE(block);
    const size = table.readUInt32LE(block + 4);
    requireEvidence(page % 4096 === 0 && size >= 8 && size % 4 === 0, 'invalid_pe_relocations');
    const records = slice(table, block + 8, size - 8, 'invalid_pe_relocations');
    for (let index = 0; index < records.length; index += 2) {
      const record = records.readUInt16LE(index);
      const type = record >>> 12;
      if (type === 0) continue; // ABSOLUTE is block padding.
      const address = page + (record & 0xfff);
      const width = type === 1 || type === 2 || type === 4 ? 2 : type === 3 ? 4 : 8;
      if (address < endRva && address + width > rva) {
        requireEvidence(type === 3, 'unsupported_pe_relocation');
        requireEvidence(address >= rva && address + 4 <= endRva, 'crossing_pe_relocation');
        requireEvidence(![...relocations].some(offset => Math.abs(address - rva - offset) < 4),
          'overlapping_pe_relocations');
        relocations.add(address - rva);
      }
      if (type === 4) { // HIGHADJ consumes the following word.
        index += 2;
        requireEvidence(index < records.length, 'invalid_pe_relocations');
      }
    }
    block += size;
  }
  return { bytes, imageBase, relocations, containsRva };
}

function readObjectScope(object, symbol) {
  slice(object, 0, 20, 'invalid_coff');
  requireEvidence(object.readUInt16LE(0) === X86 && object.readUInt16LE(16) === 0, 'unsupported_coff');
  const count = object.readUInt16LE(2);
  const headers = slice(object, 20, count * 40, 'invalid_coff_sections');
  const tableOffset = object.readUInt32LE(8);
  const symbolCount = object.readUInt32LE(12);
  requireEvidence(tableOffset >= 20 + headers.length && symbolCount > 0, 'invalid_coff_symbols');
  const table = slice(object, tableOffset, symbolCount * 18, 'invalid_coff_symbols');
  const stringsOffset = tableOffset + table.length;
  slice(object, stringsOffset, 4, 'invalid_coff_strings');
  const strings = slice(object, stringsOffset, object.readUInt32LE(stringsOffset), 'invalid_coff_strings');
  requireEvidence(strings.length >= 4, 'invalid_coff_strings');

  function nameAt(row) {
    if (table.readUInt32LE(row) !== 0) {
      return table.subarray(row, row + 8).toString('utf8').split('\0', 1)[0];
    }
    const offset = table.readUInt32LE(row + 4);
    const end = strings.indexOf(0, offset);
    requireEvidence(offset >= 4 && end > offset, 'invalid_coff_strings');
    return strings.toString('utf8', offset, end);
  }

  const symbols = new Map();
  for (let index = 0; index < symbolCount;) {
    const row = index * 18;
    const auxiliary = table[row + 17];
    requireEvidence(index + auxiliary < symbolCount, 'invalid_coff_symbols');
    symbols.set(index, {
      index,
      name: nameAt(row),
      value: table.readUInt32LE(row + 8),
      section: table.readInt16LE(row + 12),
      type: table.readUInt16LE(row + 14),
      storage: table[row + 16],
      auxiliary: table.subarray(row + 18, row + 18 * (1 + auxiliary)),
    });
    index += 1 + auxiliary;
  }
  const entries = [...symbols.values()];
  const matches = entries.filter(entry => entry.name === symbol);
  const [entry] = matches;
  requireEvidence(matches.length === 1 && entry.type === 0x20 && entry.storage === 2 &&
    entry.section >= 1 && entry.section <= count && entry.value === 0, 'coff_function_symbol');
  const header = (entry.section - 1) * 40;
  const flags = headers.readUInt32LE(header + 36);
  // A single-function COMDAT (MSVC /Gy) supplies an independent extent.
  requireEvidence((flags & 0x20001020) === 0x20001020 && (flags & 0x01000000) === 0,
    'unsupported_coff_section');
  const definitions = entries.filter(candidate =>
    candidate.section === entry.section && candidate.storage === 3 && candidate.type === 0 &&
    candidate.value === 0 && candidate.auxiliary.length === 18 && candidate.auxiliary[14] !== 0);
  const [definition] = definitions;
  const length = headers.readUInt32LE(header + 16);
  const relocationCount = headers.readUInt16LE(header + 32);
  requireEvidence(definitions.length === 1 && length > 0 &&
    definition.auxiliary.readUInt32LE(0) === length &&
    definition.auxiliary.readUInt16LE(4) === relocationCount &&
    entries.every(other => other === entry || other.section !== entry.section || other.type !== 0x20),
  'coff_function_boundary');

  const rawOffset = headers.readUInt32LE(header + 20);
  requireEvidence(rawOffset >= 20 + headers.length && rawOffset + length <= tableOffset,
    'invalid_coff_code');
  const bytes = slice(object, rawOffset, length, 'invalid_coff_code');
  const relocations = [];
  const relocationOffset = headers.readUInt32LE(header + 24);
  if (relocationCount) {
    requireEvidence(relocationOffset >= rawOffset + length &&
      relocationOffset + relocationCount * 10 <= tableOffset, 'invalid_coff_relocations');
  }
  const records = slice(object, relocationCount ? relocationOffset : 0, relocationCount * 10,
    'invalid_coff_relocations');
  for (let index = 0; index < records.length; index += 10) {
    const offset = records.readUInt32LE(index);
    const type = records.readUInt16LE(index + 8);
    const reference = symbols.get(records.readUInt32LE(index + 4));
    requireEvidence(type === 0x06 || type === 0x14, 'unsupported_coff_relocation');
    requireEvidence(offset + 4 <= length, 'crossing_coff_relocation');
    requireEvidence(reference?.storage === 2 && reference.section === 0 && reference.value === 0,
      'unsupported_coff_reference');
    relocations.push({ offset, type, name: reference.name });
  }
  relocations.sort((a, b) => a.offset - b.offset);
  requireEvidence(relocations.every(({ offset }, index) =>
    index === 0 || offset >= relocations[index - 1].offset + 4), 'overlapping_coff_relocations');
  return { bytes, relocations, count, headers, header, rawOffset, relocationOffset, relocationCount,
    tableOffset, symbolCount, symbols, table, strings, stringsOffset, definition };
}

export function readObjectFunction(object, symbol) {
  const { bytes, relocations } = readObjectScope(object, symbol);
  return { bytes, relocations };
}

/**
 * Return a new x86 COFF object with one caller-identified DIR32 operand.
 * The caller must establish the instruction boundary and expected address.
 */
export function bindObjectAbsoluteOperand(object, symbol, { offset, expectedAddress, externalSymbol }) {
  const scope = readObjectScope(object, symbol);
  requireEvidence(Number.isSafeInteger(offset) && offset >= 0 && offset + 4 <= scope.bytes.length,
    'coff_operand_bounds');
  requireEvidence(Number.isSafeInteger(expectedAddress) && expectedAddress >= 0 &&
    expectedAddress <= 0xffffffff && scope.bytes.readUInt32LE(offset) === expectedAddress,
  'coff_operand_value');
  requireEvidence(!scope.relocations.some(row => row.offset < offset + 4 && row.offset + 4 > offset),
    'overlapping_coff_relocation');
  requireEvidence(typeof externalSymbol === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(externalSymbol),
    'invalid_coff_binding_name');
  const matches = [...scope.symbols.values()].filter(row => row.name === externalSymbol);
  requireEvidence(matches.length === 0 || (matches.length === 1 && matches[0].storage === 2 &&
    matches[0].section === 0 && matches[0].value === 0), 'unsupported_coff_reference');

  // All bytes after the old symbol table must belong to its string table.
  // Keep every original symbol index and leave other sections at their old file offsets.
  requireEvidence(scope.relocationCount < 0xfffe && scope.stringsOffset + scope.strings.length === object.length,
    'unsupported_coff_layout');
  for (let index = 0; index < scope.count; index++) {
    const header = index * 40;
    const raw = scope.headers.readUInt32LE(header + 20);
    const size = scope.headers.readUInt32LE(header + 16);
    const reloc = scope.headers.readUInt32LE(header + 24);
    const count = scope.headers.readUInt16LE(header + 32);
    requireEvidence((raw === 0 || raw + size <= scope.tableOffset) &&
      (count === 0 || reloc + count * 10 <= scope.tableOffset) &&
      (scope.headers.readUInt32LE(header + 36) & 0x01000000) === 0 &&
      scope.headers.readUInt32LE(header + 28) === 0 && scope.headers.readUInt16LE(header + 34) === 0,
    'unsupported_coff_layout');
  }

  const relocations = Array.from({ length: scope.relocationCount }, (_, index) =>
    object.subarray(scope.relocationOffset + index * 10, scope.relocationOffset + index * 10 + 10));
  const binding = Buffer.alloc(10);
  binding.writeUInt32LE(offset, 0);
  binding.writeUInt32LE(matches[0]?.index ?? scope.symbolCount, 4);
  binding.writeUInt16LE(0x06, 8);
  relocations.push(binding);
  relocations.sort((a, b) => a.readUInt32LE(0) - b.readUInt32LE(0));

  const prefix = Buffer.from(object.subarray(0, scope.tableOffset));
  const symbols = Buffer.from(scope.table);
  const section = 20 + scope.header;
  prefix.writeUInt32LE(0, scope.rawOffset + offset);
  prefix.writeUInt32LE(scope.tableOffset, section + 24);
  prefix.writeUInt16LE(relocations.length, section + 32);
  prefix.writeUInt32LE(scope.tableOffset + relocations.length * 10, 8);
  symbols.writeUInt16LE(relocations.length, scope.definition.index * 18 + 22);
  if (matches.length) return Buffer.concat([prefix, ...relocations, symbols, scope.strings]);

  const external = Buffer.alloc(18);
  external.writeUInt32LE(scope.strings.length, 4);
  external[16] = 2;
  const strings = Buffer.concat([scope.strings, Buffer.from(externalSymbol + '\0', 'ascii')]);
  strings.writeUInt32LE(strings.length, 0);
  prefix.writeUInt32LE(scope.symbolCount + 1, 12);
  return Buffer.concat([prefix, ...relocations, symbols, external, strings]);
}

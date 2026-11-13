# Local x86 function verifier

Use an offline directory outside the checkout for the target, source, compiler, scope, and evidence. Confirm that the analyzed bytes and boundaries describe the exact file identified by SHA-256. A stock executable and an initialized analysis image have separate identities.

## Compile and compare

Run on Windows with Node.js 20+ and a local MSVC x86 toolchain.

    node scripts/compile-function.mjs <private-config.json> <new-private-evidence.json>

The private configuration includes:

- `target` and its independently recorded lowercase `targetSha256`
- `rva` and exclusive `endRva` as JSON integers
- `boundaryEvidence` identifying the checked analysis record
- Optional `boundaryIndex` and `boundaryIndexSha256` pin a local NDJSON export. The unique row for the start must agree on `rva`, `endRvaExclusive`, and `length`. The first two fields may be hex strings.
- `source`, a self-contained local C++ translation unit
- `symbol`, the exact decorated COFF external symbol
- `compiler`, the full path to `cl.exe`
- `toolchainSha256`, lowercase SHA-256 pins for `cl.exe`, `c1xx.dll`, and `c2.dll`
- `flags`, e.g. `["/O2", "/GS-"]`
- `workDir`, an existing private directory for a fresh temporary build

The checker compiles with `/nologo /c /TP /Gy /X`, the supplied allowlisted options, and fixed source and object names. It clears inherited `CL`, `_CL_`, and include/library variables. The private JSON captures compiler component pins, command, source and object hashes, and scope. The stdout JSON contains comparison status and counts. Keep private evidence private. Object hashes may reflect compiler metadata such as timestamps even when function bytes match.

For a prebuilt object:

    node scripts/verify-function.mjs <target.exe> <candidate.obj> <private-scope.json>

This entry point takes the target digest, RVA bounds, and decorated symbol. Its result describes the supplied artifacts. Source and compiler provenance require a separate record. Exit codes are 0 for a match, 1 for a mismatch, and 2 for unverifiable or invalid input.

## Comparison scope

Establish contiguous, instruction-complete target bounds from trusted local analysis. Ghidra inventory `size` counts addresses and cannot establish contiguity. The checker requires one file-backed executable PE32/x86 section. The candidate must be a standard x86 COFF external function at offset zero in a single-function code COMDAT with consistent section and auxiliary lengths. Padding stays in scope. A short or long candidate counts as a mismatch even when the common prefix is identical.

Every byte is compared. The supported object fixups reference external symbols:

- `DIR32` requires a PE `HIGHLOW` at the same offset and a separately established symbol RVA in private `absoluteSymbols`. The compared field is target image base + symbol RVA + object addend.
- `REL32` requires a separately established executable symbol RVA in private `relativeSymbols`. The compared field is symbol RVA + object addend − RVA immediately after the field. The PE base relocation table omits ordinary PC-relative calls.

Establish mappings independently from symbol or cross-reference evidence. A value derived from the target operand under comparison is circular evidence. An adjusted match is conditional on these reviewed bindings. Missing bindings, unsupported references or relocation types within scope, overlaps, and partially covered sites are unverifiable. Fixed-base images can contain address-dependent fields absent from the PE relocation table. A `DIR32` without a matching PE relocation is unverifiable in this version.

An exact result means the checked scopes matched as stored with zero object fixups. LTCG objects, linker rewrites, split functions, and inferred padding are outside this version’s scope. The checker leaves independent verification false. A trusted verifier should reproduce the same scope and retain separate evidence.

## Tests

    npm test
    node --test scripts/verify-function.test.mjs

All repository fixtures are synthetic and require no Microsoft compiler.

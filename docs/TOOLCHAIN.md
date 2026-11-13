# Compiler identification and matching oracle

**Status:** research hypothesis, not validated against the target executable.

## Evidence and candidate builds

- Historic _World in Conflict_ diagnostics reportedly identify compiler **1400** (Visual C++ 2005). This is evidence for the *family*, not the exact patch level used in the canonical Steam build.
- `_MSC_VER=1400` corresponds to Visual Studio 2005 / MSVC 8.0: [Microsoft compiler versions](https://learn.microsoft.com/en-us/cpp/overview/compiler-versions).
- **Primary candidate:** Visual C++ 2005 SP1 (`cl.exe` 14.00.50727.762). **Alternative:** the VS 2005 RTM-era toolchain (including 14.00.50727.42); investigate other hotfixes or mixed-object toolchains as evidence requires.
- [Official Microsoft Windows SDK for Vista, February 2007 Update](https://www.microsoft.com/en-us/download/details.aspx?id=14477) explicitly states that its C++ compilers are the same as Visual Studio 2005 SP1. Obtain it from Microsoft and respect its licence. **Do not redistribute the ISO or extracted compiler binaries.**
- Different object files in a linked executable may have different compiler versions; the linker build is not a global proof.

## Proposed canonical target

Private 2026-08 engineering records identify a Steam Windows x86 `wic.exe`, Steam BuildID `11300`, SHA-256:

```text
86807eb0d9d60abe7263b69d7f53d2089ee791f9407bd5a7c737c3f7b3f1588a
```

This repository has **not** independently examined or validated that executable. A different build hash must be researched under a separate identity, not silently merged into the same inventory.

## Local binary preflight

```bash
npm test
node scripts/inspect-pe.mjs "C:/path/to/your/wic.exe"
```

Collect SHA-256, PE architecture/format, COFF timestamp, PE linker-version fields and parseable Rich-header records. Treat Rich records as hints, not conclusive identification: they may refer to tools/objects other than the code under inspection, may be missing, or may be forged. Record provenance of every tool and every local sample.

## Experimental procedure for the compiler oracle

1. Verify the **exact executable SHA**, architecture, and loading assumptions locally; never upload the file.
2. Investigate Rich-header product/build IDs, import table, compiler-generated idioms, RTTI, EH tables, and linker characteristics.
3. Install isolated, legitimate candidate toolchains. Record `cl.exe /Bv`, `link.exe` version, hashes, installation source and licence constraints; keep binaries offline and untracked.
4. Select five nontrivial functions with trustworthy boundaries and minimal external dependencies. Avoid counting tiny thunks or simple returns as the only evidence.
5. Reconstruct or devise C++ candidates locally. Enumerate plausible `/O2`, `/Ox`, `/Ob`, `/GS`, `/GR`, `/EH`, `/arch`, alignment, calling convention, floating-point and codegen flags, as appropriate to MSVC 8.0. Never assume all switches are actually supported by a given compiler.
6. Compile deterministically, disassemble **local** outputs, account explicitly for relocation fixups, symbol addresses, padding, inlining, and link-time transforms; test source alternatives.
7. Produce an evidence report containing function identity, target hash, compiler identity, flags, comparison scope, mismatch counts and local test command. **Do not publish binary snippets or reconstructed game source.**
8. Independently repeat the match under the same toolchain/target identity before raising its status.

## Acceptance gates

- **Compiler-family hypothesis:** multiple clues, not a match.
- **Locally matched:** full justified byte comparison for a function, with only documented relocation-address treatment. Masks must not erase meaningful instructions.
- **Independently verified:** a separate trusted run recreates the same function result with the same target hash and accepted rules.
- **Milestone complete:** at least five nontrivial independently verified functions plus a reproducible, safe checker.

No commercial/legacy compiler, Windows licence, or Ubisoft licence is granted by this project.

# WiC Decomp

**A community-driven, agent-friendly reverse-engineering and matching-decompilation research project for _World in Conflict_ (2007).**

> **Status: bootstrap / compiler identification.** This repository contains project coordination and original research tooling. It does **not** contain a playable recompiled game, validated matching source, an operational distributed coordinator, or original game assets.
>
> **Unofficial project.** Not affiliated with or endorsed by Massive Entertainment or Ubisoft. _World in Conflict_, its code, and its assets belong to their respective rights holders.

## Why this exists

We want to make the original 32-bit Windows game's engine understandable, testable, and eventually more portable, using **many independently verified small contributions** rather than relying on one person or one AI context window. Most work should be possible with an agent running on a contributor's own machine and compute budget.

The eventual workflow is inspired by the public [Fallout 3 distributed decompilation agent protocol](https://f3decomp.com/agents.md): discover a suitable task, reserve it, recover a function or subsystem, check it locally, and submit evidence for independent validation. **That service is not part of this project**, and the protocol/API described in our [design document](docs/PROTOCOL.md) is not deployed yet.

This project is **separate** from the existing `wic-modernizer` graphics-injection/renderer-modernization work. That work has produced a private semantic-reverse-engineering baseline, but no private binary, Ghidra database, or original-game data is imported or published here.

## First milestone: establish a trustworthy compiler oracle

The target initially proposed is the **Steam Windows x86 build identified as Steam BuildID `11300`**. A prior local engineering record identifies the following `wic.exe` SHA-256 (not independently rechecked in this new repository):

```text
86807eb0d9d60abe7263b69d7f53d2089ee791f9407bd5a7c737c3f7b3f1588a
```

Historic game diagnostics suggest **MSVC 2005 / `_MSC_VER=1400`**, with **Visual C++ 2005 SP1** a leading candidate. Neither the exact compiler *build* nor the relevant optimization/link settings have been proven for this particular executable. The PE's linker-version field alone is not sufficient proof.

Microsoft still hosts a [Windows SDK for Vista (February 2007 update)](https://www.microsoft.com/en-us/download/details.aspx?id=14477), which Microsoft says includes the same C++ compilers as Visual Studio 2005 SP1. **Download toolchains from their owners; do not commit or redistribute Microsoft compiler files here.** See [Toolchain research](docs/TOOLCHAIN.md).

Acceptance for this milestone: at least **five distinct, nontrivial sample functions** compile into verified matching machine-code bytes for the exact target build, with reproducible toolchain/version/flag records and independent review. A single trivial thunk is not enough.

## Quick start

Prerequisites: Node.js 20+ (no `npm install` required for the current tools), Git, and your **own legitimately obtained** Windows game installation for local inspection.

```bash
# After the GitHub repository is published:
git clone https://github.com/venku122/wic-decomp.git
cd wic-decomp

npm test
node scripts/inspect-pe.mjs "PATH_TO_YOUR_OWN_WIC.EXE"
```

The inspection script reads the file **without executing or modifying it**, prints its SHA-256, PE machine/linker fields, and any parsable Rich-header records. It makes **no claim** that Rich-header metadata alone identifies the final compiler. Do not post the executable or any disassembly when sharing results.

No game installation? You can still work on the TypeScript/Node coordination design, original test fixtures, compiler-identification research, CI, and contributor documentation.

## Roadmap

| Stage | Outcome | Current status |
| --- | --- | --- |
| **0 — Bootstrap** | Contributor docs, original scripts, safe CI, source/rights boundaries | **Scaffolded** |
| **1 — Compiler oracle** | Fingerprint target, identify MSVC build/settings, reproduce ≥5 nontrivial functions | **Not verified** |
| **2 — 100-function pilot** | Reproducible inventories, local match checker, independently checked results, cost/success metrics | **Planned** |
| **3 — Distributed coordination** | GitHub identity, expiring task leases, bounded context packets, submissions, credits, transparent metrics | **Planned; no server yet** |
| **4 — Wider contributions** | Community onboarding, work allocation, review and release governance | **Planned, subject to rights review** |
| **5 — Native runtime research** | Investigate selective code lifting, host shims, engine/renderer replacement | **Future / not claimed** |

A reported prior private Ghidra export indexed ~21,147 functions for one build, but this is **not** a public verified-decompilation count or a claim that any function currently matches. See [Architecture](docs/ARCHITECTURE.md).

## How to contribute

**One-sentence agent kickoff (after this repo is published):**

> Read the repository's `AGENTS.md`, `README.md`, and `CONTRIBUTING.md`; select an available bootstrap Issue, request an acknowledged claim, and implement its smallest testable portion without uploading any proprietary inputs.

- **Humans:** start with [CONTRIBUTING.md](CONTRIBUTING.md). Early contributions are primarily toolchain identification, original tooling, reproducible experiments, and documentation.
- **AI agents:** read [AGENTS.md](AGENTS.md) **before** changing files or claiming work.
- **Task protocol:** see [docs/PROTOCOL.md](docs/PROTOCOL.md). Initially GitHub Issues/PRs are the coordination layer; there is no production reservation API.
- **Security and copyright:** only submit files you have the right to distribute. Keep game binaries, assets, disassemblies, decompiler output, private database exports, build tools, and unreviewed reconstructed game source **out of the public repository**. A policy and review process for reconstructed source publication must be established before any public source submissions.

## Project principles

1. **Evidence over claims.** Separate hypothesized compiler settings from verified byte-identical matches.
2. **Exact build identity.** No cross-build assumptions. Hash and identify each binary locally.
3. **Small, reproducible jobs.** Every match has compiler flags, inputs, output evidence, and a second-party gate.
4. **Low contribution cost.** Your agent, your machine, your own inference budget; no mandatory hosted AI provider.
5. **Public coordination, private proprietary inputs.** GitHub for collaboration; original game materials never required in CI.
6. **No gaming the progress bar.** Report functions, bytes, independent verification, and failure rates separately.

## Licensing

Original project documentation and tooling in this bootstrap repository are MIT-licensed; see [LICENSE](LICENSE). This licence **does not** grant rights to any original game content, Microsoft compiler components, or third-party material. The public distribution policy for reconstructed game source is **not yet determined**. Contributions must respect [CONTRIBUTING.md](CONTRIBUTING.md).

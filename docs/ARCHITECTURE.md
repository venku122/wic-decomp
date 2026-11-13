# Architecture and trust boundaries

This document describes the **proposed architecture**, not an already-running service.

```text
Public GitHub repository                       Contributor workstation
─────────────────────────                     ──────────────────────────
README / AGENTS / Issues / PRs                  Legally acquired wic.exe
Original coordinator + test code               Legally acquired MSVC toolchain
Open progress metadata                         Local Ghidra / compiler / checker
          │                                               │
          └──────── future task metadata + claims ────────┘
                                  │
                        Future verifier service
                        (isolated; not deployed)
```

## Existing private baseline (not transferred to this repository)

An August 2026 engineering report from the separate renderer modernization effort describes a local Ghidra 12.1.2 analysis of one Steam x86 build with 21,147 indexed functions, 146,204 call-graph edges, and a known-symbol validation campaign. That is useful *private research context*, **not public recovered source** or evidence of matching decompilation. It must not be uploaded as-is; permissions, provenance, scope and confidentiality must be reviewed first.

## Proposed components

1. **Fingerprint CLI (exists):** read-only PE metadata and SHA-256; no binary execution.
2. **Compiler oracle (not yet built):** controlled MSVC experiments, deterministic compile commands, documented exact-byte match rules.
3. **Function inventory (not yet public):** stable function IDs scoped to a specific build; avoid dumping original bytes in public context packets.
4. **Local match verifier (not yet built):** compare separately produced bytes with locally available original bytes and record a compact, non-sensitive attestation.
5. **Coordinator (not yet built):** TypeScript HTTP/MCP adapters, GitHub account identity, task leasing, retry/backoff, reports, moderation.
6. **Postgres backing store (planned):** function identities, lease generations, expirations, submissions, independent verification and credits. GitHub remains the collaboration entry point, not a high-frequency queue.
7. **Isolated verifier (planned):** do not run untrusted submissions with game binaries or credentials on a persistent self-hosted runner. Prefer ephemeral, restricted jobs and minimize input exposure.

## Safety principles

- Local-only access to original code/data and legacy compilers unless a verified rights decision explicitly permits otherwise.
- CI for public PRs uses synthetic fixtures; no original game in GitHub Actions and no secrets exposed to forked PRs.
- A match report should not conflate semantic equivalence, matching after unbounded masking, or a single locally successful run with independently verified exact bytes.
- Keep `wic-modernizer` renderer translation independent. Native recompilation is a later research objective, not a precondition for graphics improvements.
- Reconstructed source publication needs rights and maintainership decisions before deployment of public submission features.

# Contributing

Welcome. The project is bootstrapping a distributed research workflow; contributors can help with original tooling and evidence without needing an AI subscription or a copy of the game.

## Start here

1. Read `README.md`, `AGENTS.md` (if using an agent), `docs/TOOLCHAIN.md`, and `docs/PROTOCOL.md`.
2. Browse open Issues; look for compiler identification, synthetic fixture, test, documentation, or coordinator design work.
3. Comment on the Issue to request a **maintainer-acknowledged claim** before starting. Claims default to 48 hours, are renewable, and are not enforced automatically yet.
4. Fork/create a topic branch, implement a minimal change, and run `npm test`.
5. Open a pull request referencing the Issue, with commands/results, reproducibility notes, evidence and limitations.

## What is welcome now

- Tests and improvements for the no-execution PE inspection script.
- Documentation of legally accessible MSVC 2005 toolchains, compiler identities, and reproducible flag experiments.
- Original byte-comparison / relocation-aware verifier code using **synthetic** fixtures.
- Agent protocol/schema proposals, GitHub coordination UX, build isolation, reporting and CI hardening.

## What must not be submitted publicly

- `wic.exe`, DLC/asset archives, game-derived shaders/textures, savegames, network credentials, proprietary Microsoft toolchain files, game dumps or private Ghidra project files.
- Raw binary excerpts, disassemblies, decompiler output, or any reconstructed original game source **until a maintainer-approved publication policy is in place**.
- Material downloaded from unofficial binary mirrors or bypassing access controls.

Original tools and docs are MIT-licensed; submitting a PR for those materials means you agree to their distribution under that license. No licence here covers Ubisoft/Massive assets or third-party components. If unsure about a file's rights, open an Issue describing it without attaching the file.

## Pull request checklist

- [ ] Issue linked and scope acknowledged
- [ ] No game/compiler binaries, raw extracts, proprietary code, private traces, credentials, or machine-identifying paths
- [ ] Tests use synthetic or licensed fixtures and `npm test` succeeds
- [ ] Compiler/build claims are marked hypothesis, observed, locally matched, or independently verified accurately
- [ ] No external networks, elevated privileges, or system-wide changes required by tests
- [ ] Docs updated where behavior changed

## Community conduct

Be respectful, give credit for work and negative results, and keep debates evidence-driven. Maintainers may reject risky artifacts or claims that cannot be reproduced.

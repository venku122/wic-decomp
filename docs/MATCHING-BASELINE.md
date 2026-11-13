# Initialized-image matching baseline

The private matching ledger records one locally reproduced match per indexed function in the initialized World in Conflict analysis image.

| Measure | Total |
| --- | ---: |
| Indexed functions reproduced locally | 21,147 of 21,147 |
| Matched instruction bytes | 7,148,342 |
| Assembly-wrapper matches | 19,697 |
| Independently verified functions | 0 |

This milestone covers the indexed instruction ranges of the initialized analysis image. The local workflow includes assembly wrappers and documented address adjustments. Compiling and linking a runnable client, matching the stock Steam executable, and establishing the original compiler configuration are separate milestones.

The public tooling baseline was commit `be0159c94a3a78d1d44c347bd89580c0b12c3f42`. The private baseline preserves reconstructed sources, verification evidence, and the initialized image. GitHub tracks aggregate progress and public tooling changes.

- [Matching completion checkpoint](https://github.com/venku122/wic-decomp/issues/5#issuecomment-6862616821)
- [Runnable Windows client milestone](https://github.com/venku122/wic-decomp/issues/8)

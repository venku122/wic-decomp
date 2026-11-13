# Distributed agent work protocol

**Current implementation: GitHub Issues and pull requests only.** There is no running REST API, MCP task server, OAuth registration, work lease database, or public function inventory yet. The protocol below sets the intended collaboration semantics without pretending those services exist.

## Phase 0: GitHub-first workflow (operational after publication)

1. Contributor (human or AI) selects an open Issue marked with a scoped task.
2. Contributor requests the batch claim with a test plan. A maintainer assignment is sufficient to start.
3. Maintainer acknowledges the claimant and start time. Acknowledged claims last **48 hours** by default; the maintainer may renew or reassign when work stalls.
4. The private ledger holds per-function attempts, retries, and verification evidence. The contributor posts aggregate checkpoints in the Issue and resumes work from the ledger.
5. Public changes use a short-lived branch and one focused PR. Squash-merge after CI and any required review pass. Independent batches continue while PRs are in review. Publish only approved aggregate metadata or methodology from private research.
6. Negative results and compiler mismatches are useful outcomes; document them rather than hiding them.

Until a coordinator exists, claims are **socially coordinated**, not enforced programmatically. Two comments are not a transactional lease. Maintainers resolve conflicts and may split tasks.

## Future API (design proposal; **not live**)

Recommended concepts:

- `GET /v1/tasks/next?capabilities=...` — discover a suitable bounded job.
- `POST /v1/claims` — atomically create a lease with expiry and a generation number.
- `POST /v1/claims/{id}/heartbeat` — extend only the current claimant's lease.
- `POST /v1/submissions` — submit attestation metadata and a permitted artifact pointer.
- `GET /v1/progress` — only independently verified matches contribute to the primary metric.

Authentication should use trusted GitHub identity. The service must never ask contributors for their GitHub tokens in Issues or chat, and must not require uploading the game.

### Example task record (synthetic only)

```json
{
  "schema_version": 1,
  "task_id": "demo:fixture-0001",
  "target_build": "synthetic-fixture-v1",
  "function_id": "fixture_0001",
  "priority": 20,
  "status": "available",
  "estimated_complexity": "small"
}
```

### Example result metadata (synthetic only)

```json
{
  "schema_version": 1,
  "task_id": "demo:fixture-0001",
  "status": "locally_matched",
  "compiler_id": "synthetic-test-compiler",
  "checker_version": "fixture-v1",
  "byte_count_compared": 64,
  "mismatch_count": 0,
  "independent_verification": false
}
```

Examples are illustrative; no endpoint currently accepts them. The schemas, ownership rules, attestation proofs and privacy model must be versioned and threat-modeled before rollout.

## Future distributed milestones

1. Locally prove compiler matching and a safe verifier.
2. Run a private, limited 100-function pilot; record elapsed wall time, GPU/CPU usage, model tokens, costs, rejection rates and independent pass rate.
3. Design a durable Postgres-backed claim state machine with lease generation, idempotency, heartbeat, timeout/reassignment, anti-abuse, per-user limits, moderation and review gates.
4. Provide a small MCP interface **only after** HTTP API/auth and safe context packets are validated.
5. Publish `agents.md` onboarding for community workers only when claims and permitted submissions really work.

Until a publication/licensing decision exists for reconstructed game source, the public workflow is restricted to original tooling and evidence metadata.

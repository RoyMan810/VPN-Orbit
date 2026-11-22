# MVP progress

## Current state

- Main: `c1204e7` (PR #133 merged).
- PRs #126–#133 are merged.
- P0 removal of excluded backup, rescue, activation, self-update, stage0, and recovery installation functionality is complete.
- No production installations or data exist, and no real VPS has been used.
- Active stage: P1 WebUI/reconciliation.

## Completed

- PR #126: VPS cleanup is target-bound and ownership-aware.
- PR #127: Broker recovery persists Authority receipts compatible with reconciliation.
- PR #128: stage0 prototypes and their CI were removed.
- PR #129: self-update, update/migration deployment code, tests, workflow, and documentation were removed.
- PR #130: recovery installation entrypoints were removed.
- PR #131: backup, rescue, and activation CLI entrypoints were removed.
- PR #132: backup/restore/rescue runtime modules, workflows, tests, and documentation were removed.

## P1 sequence

1. Audit current runtime imports, CLI, fresh installer, Authority/Broker/Worker, and application/runtime tests.
2. Fix WebUI operation recovery after reload, lost enqueue responses, correlation IDs and safe API error codes, and resource-level permissions.
3. Test reconciliation after lost responses before/after dispatch, Authority/Broker/Worker restarts, and idempotency-key resubmission.
4. Add focused regression tests, then open a small PR and merge only after required CI passes.

## Current task

The P1 current-runtime audit and historical migration-contract cleanup are complete.
Orphaned recovery/archive runtime modules,
installer backup-target creation, and removed backup/rescue/activation disposable-lab
scenarios were deleted. Auth/RBAC, Audit/Outbox, Vault, Authority/Broker/Worker,
durable jobs, idempotency, UNKNOWN_OUTCOME, reconciliation, TimeHealth, firewall
rollback and SSH checks, Docker restart protection, and unfinished-job recovery remain.
The next task is WebUI/reconciliation; it must not be mixed with deployment work.

## P1.1 verification

- Passed: `pip check`, compile/import checks, Authority tests, runtime CLI tests,
  Worker/Broker tests, database Audit/Outbox tests, and targeted installer checks.
- Full application/runtime suites remain CI work: this sandbox blocks some `/var/tmp`,
  filesystem-permission, network, and socket scenarios.

## Blockers

- The checked-out `origin/main` ref was refreshed to `c1204e7` after PR #133.
- No production VPS is available or permitted. The supplied disposable VM must have its SSH fingerprint, isolation, and fresh rollback snapshot verified before use; no VM or real VPS has been contacted.

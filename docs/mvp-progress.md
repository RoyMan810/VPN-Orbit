# MVP progress

## Current state

- Main: `da33a673a5fa7b0f8d45e3e4f608b24483d45468`.
- PRs #126–#132 are merged.
- P0 removal of excluded backup, rescue, activation, self-update, stage0, and recovery installation functionality is complete.
- No production installations or data exist, and no real VPS has been used.
- Active stage: P1 migration-contract cleanup.

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
2. In a separate PR, remove historical migration contracts (`vpn_orbit.migrations`, `schema_v1.sql`, old schema branches, migration rehearsal, legacy recovery paths, and related tests/docs).
3. Fix WebUI operation recovery after reload, lost enqueue responses, correlation IDs and safe API error codes, and resource-level permissions.
4. Test reconciliation after lost responses before/after dispatch, Authority/Broker/Worker restarts, and idempotency-key resubmission.
5. Add focused regression tests, then open a small PR and merge only after required CI passes.

## Current task

The P1 current-runtime audit is complete. Orphaned recovery/archive runtime modules,
installer backup-target creation, and removed backup/rescue/activation disposable-lab
scenarios were deleted. Auth/RBAC, Audit/Outbox, Vault, Authority/Broker/Worker,
durable jobs, idempotency, UNKNOWN_OUTCOME, reconciliation, TimeHealth, firewall
rollback and SSH checks, Docker restart protection, and unfinished-job recovery remain.
The next task is the separate migration-contract cleanup; it must not be mixed with
WebUI or deployment work.

## P1.1 verification

- Passed: `pip check`, compile/import checks, Authority tests, runtime CLI tests,
  Worker/Broker tests, database Audit/Outbox tests, and targeted installer checks.
- Full application/runtime suites remain CI work: this sandbox blocks some `/var/tmp`,
  filesystem-permission, network, and socket scenarios.

## Blockers

- `origin/main` could not be freshly queried in this environment: the configured SSH client rejects `/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf`; bypassing that file reaches a DNS resolution failure for `github.com`. The checked-out `origin/main` ref points to `da33a673a5fa7b0f8d45e3e4f608b24483d45468`.
- No production VPS is available or permitted. The supplied disposable VM must have its SSH fingerprint, isolation, and fresh rollback snapshot verified before use; no VM or real VPS has been contacted.

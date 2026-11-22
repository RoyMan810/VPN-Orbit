# MVP progress

## Current state

- Main: `b4c43db` (PR #139 merged).
- PRs #126–#139 are merged.
- P0 removal of excluded backup, rescue, activation, self-update, stage0, and recovery installation functionality is complete.
- No production installations or data exist, and no real VPS has been used.
- Active stage: P3 Firewall WebUI and disposable fault acceptance.

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

The P1 current-runtime audit, historical migration-contract cleanup, and WebUI/
resource-permission/reload recovery work are complete.
Orphaned recovery/archive runtime modules,
installer backup-target creation, and removed backup/rescue/activation disposable-lab
scenarios were deleted. Auth/RBAC, Audit/Outbox, Vault, Authority/Broker/Worker,
durable jobs, idempotency, UNKNOWN_OUTCOME, reconciliation, TimeHealth, firewall
rollback and SSH checks, Docker restart protection, and unfinished-job recovery remain.
The existing reconciliation paths now have browser and runtime coverage for lost
responses, UNKNOWN_OUTCOME, restart receipt reconciliation, idempotency replay, and
resource-scoped permissions. P1 regression verification is complete. The next task
is a focused P2 audit of VPS onboarding, resumable repair, target-bound cleanup,
and disposable acceptance coverage are complete. The next stage is P3 Firewall
WebUI and disposable fault acceptance; deployment profiles remain out of scope.

## P2.3 verification

- Disposable VM acceptance passed the separate typed firewall onboarding profile with exact cleanup; no remote managed artifacts remained after cleanup.

## P3.2 implementation

- Extended the typed Firewall WebUI with durable browser state, reload recovery,
  operation timeline polling, and receipt reconciliation for UNKNOWN_OUTCOME.

## P3.1 implementation

- Added Owner-only WebUI flow for typed firewall drafts: rule editing, SSH-port
  preservation through the API contract, baseline preview, re-authentication,
  approval, and durable execution enqueue.
- Preserved the typed runtime, rollback timer, SSH verification, UNKNOWN_OUTCOME,
  and reconciliation gates; full browser/fault acceptance remains pending CI.

## P2.2 verification

- Disposable VM acceptance also passed the typed firewall onboarding profile: separate firewall key/account, helper/postcondition verification, and exact cleanup. Temporary sudo and all remote artifacts were removed.

## P2.1 verification

- Audited `tools/prepare_vps.py`: SSH fingerprint pinning, resumable phases,
  repair after partial effects, exact-target cleanup, and cleanup-on-failure were
  already covered by unit/disposable lab tests.
- Hardened local provisioning state and managed key/policy files against symlinks
  and hardlinks; added regression coverage.
- Console and pinned-SSH preflight verified the disposable VM as Ubuntu 24.04.5
  LTS, x86_64, `192.168.122.244/24`, with the expected Ed25519 fingerprint and
  empty VPN-Orbit/Docker namespaces.
- Disposable acceptance passed fresh onboarding, disconnect-after-account fault,
  resumable repair, exact cleanup, and the separate typed firewall profile. Temporary NOPASSWD sudo and all managed
  artifacts were removed afterward. No production VPS was used.

## P1.1 verification

- Passed: `pip check`, compile/import checks, Authority tests, runtime CLI tests,
  Worker/Broker tests, database Audit/Outbox tests, and targeted installer checks.
- Full application/runtime suites remain CI work: this sandbox blocks some `/var/tmp`,
  filesystem-permission, network, and socket scenarios.

## Blockers

- The checked-out `origin/main` ref was refreshed to `b4c43db` after PR #139.
- No production VPS is available or permitted. The disposable VM remains the only
  acceptance target; its `clear` rollback snapshot is available. P2 acceptance is complete.

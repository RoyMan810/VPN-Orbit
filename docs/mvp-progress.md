# MVP progress

## Current state

- Release-review baseline: `4c4f1bde222248da7c572572572a9a2718391395` (PR #156).
- P0 removal of excluded backup, rescue, activation, self-update, stage0, and recovery installation functionality is complete.
- The dedicated disposable Ubuntu VM is the only server used for staging.
- `v1.0.0` release acceptance is incomplete.
- The MVP scope now includes typed deployment and lifecycle of all four
  products, product dependencies, drift checks, and ownership-verified removal.
  Production readiness still requires a separate decision.

## Expanded MVP implementation

- Replaced the temporary staging shell drill with `tools/staging_vm.py`.
  It keeps the original XML as immutable restore input, pins the domain UUID
  and SSH identity, requires the clean snapshot and loopback SPICE console,
  and restores the original disk even when an acceptance scenario fails.
  Regression tests cover the failed-scenario restore and host-key rejection.
  The actual rollback drill booted a new clean overlay and restored the
  original disk with pinned SSH on November 23, 2026.
- PR #165 passed all nine CI checks and was merged.
- Added fixed product service profiles with upstream image allowlists, Node
  host networking, separate Panel/Bot databases and Redis, and Cabinet API
  proxy configuration. Unknown commands, mounts, capabilities and image
  repositories are rejected. Generated Compose was validated by the staging
  Compose parser; real product startup remains pending. See the
  [application lifecycle](application-lifecycle.md) contract.
- Added the host-local `vpn-orbit-app` CLI and its private operation journal.
  It binds requests to a protected spec digest, records Docker identities
  before startup, checks drift, and removes recorded containers while retaining
  data volumes and networks. A separate receipt records reconciliation.
  Staging confirmed PostgreSQL and Redis health, and the Panel API returned
  HTTP 200 with the headers required by its HTTPS reverse proxy. The first
  staging runs exposed a missing Panel metrics credential and Docker
  normalizing `OomKillDisable` on start. Both are covered by the implementation
  and the product lifecycle CI job.
- PR #167 passed the complete required CI and real product acceptance job.
  The same Panel fixture passed on staging: install/API, idempotent replay,
  a deliberately lost start response, executor restart, read-only reconciliation,
  shared network refusal, and exact-ID removal preserving volumes and networks.
- Added a Node acceptance scenario with a generated disposable CA, client and
  server certificates. It checks the real host-network image, TLS 1.3 and
  rejection of unauthenticated clients; no product security check is bypassed.
- PR #168 passed all CI checks including actual Node and Panel product jobs.
  The Node scenario also passed on staging and restored the original VM disk.
- Added the separate `apps.lifecycle` capability, protected installation/digest
  allowlist, dedicated Vault key purpose and bounded forced SSH gateway.
  Authority/Broker tests check scope refusal, key separation, lost replies
  and receipt-bound reconciliation. Controller enqueue integration is next.
- Full Telegram Bot E2E needs a valid test bot token and administrator Telegram
  ID. No such credentials were supplied; generated fixture tokens cannot
  establish a real Telegram session. Independent product work continues.
- PR #169 passed all required checks. Controller application drafts now require
  Owner re-authentication, exact revision approval and durable enqueue. Worker
  binds the payload to Authority and Broker and preserves UNKNOWN_OUTCOME
  across reconciliation. New installations use schema 6; older development
  databases are refused rather than migrated or overwritten.

## Release review

- Baseline main CI run `45066337967` passed on the reviewed commit.
- Pinned SSH preflight reached the dedicated Ubuntu 24.04.5 x86_64 VM on the
  libvirt NAT network. VPN-Orbit and Docker state directories were absent.
  Non-interactive sudo was unavailable. A fresh offline external snapshot was
  created. The VM failed to boot with duplicate SPICE agent channels; removing
  the duplicate restored boot, console and pinned SSH. A new overlay backed
  by the clean snapshot booted with the same SSH fingerprint, the SPICE
  console endpoint, and no VPN-Orbit or Docker state. The original staging
  disk was then reattached and its HTTPS health check passed.
- Removed the unused Compose removal executor. It trusted a caller-supplied plan
  and resolved resources by name without verifying live ownership. The existing
  CLI now records manual review and leaves ownership explicitly unverified.
- Fixed Firewall WebUI reconciliation to submit the authenticated API request,
  refresh the operation timeline, and allow bounded retries after quarantine.
  Approval now requires the exact draft baseline to have been reviewed.
- The first staging installation exposed a shallow Git checkout failure after
  package installation. Bootstrap now rejects shallow checkouts before changing
  packages; the installer requires a full checkout.
- Staging installed `4e4ae9c` after retrying the pull of the same pinned image.
  The HTTPS proxy restarted after Compose, with a brief interval before it
  accepted connections. With a bounded HTTPS readiness check, the staging
  smoke test verified that the original session survived and the audit chain
  stayed valid. It also verified TLS, WebUI delivery, anonymous access denial,
  Owner and Auditor access checks, CSRF, logout, a networkless Worker, and
  loopback-only API port bindings.
- CI on `4e4ae9c` passed in runs `45072402300` (main), `45072402306` (fresh
  installer), `45073910913` (typed Docker restart), and `45073913947` (WebUI).
  PR #160 added session and audit checks across a Compose restart to the
  one-command installation workflow. Its CI runs `45075743942` and `45075743932`
  both passed.
- Staging also restarted Authority (the Supervisor unit) and Broker separately.
  Each acquired a new PID, its socket stayed active, and HTTPS sessions and
  audit verification still worked after each restart.
- Docker needed more than three minutes to pull the pinned base image during
  the staging install. The installer now allows up to ten minutes and reports
  a dedicated error if that deadline expires before Controller state is created.
  PR #161 passed CI runs `45076503840` and `45076503827`.
- The bundle builder and installer validate release versions such as `1.0.0`
  and keep development bundles behind `--development`. Both channels use
  the same signature or exact local digest verification. The checked-in
  package version is `0.1.0.dev1`. PR #162 passed CI runs `45077176107` and
  `45077176080`. A local rehearsal checkout at `d483203` produced real signed
  and digest-authenticated `1.0.0` bundles. Both passed manifest and wheel
  snapshot verification.
- The first `1.0.0` staging rehearsal stopped when the systemd preflight
  rejected the release image tag. PR #163 fixed tag verification and added a
  signed release fixture to the systemd and Compose CI lab. Runs
  `45078781368` and `45078781371` passed.
- Main at `0f663f4` passed CI (`45077548642`), one-command install
  (`45077548632`), WebUI (`45077552278`), and typed Docker restart (`45077555472`).
- Main at `3eac498` passed CI (`45079114921`, after a rerun of the timesyncd job),
  one-command install (`45079115049`), WebUI (`45079205286`), and typed Docker
  restart (`45079207883`).
- The staging rehearsal at `ffa7993` installed the `1.0.0` Controller on a clean
  overlay. HTTPS login passed. The original session and audit verification
  survived a Compose restart. The teardown script used an incorrect XML path.
  Restoring the saved domain definition manually brought back the original
  staging disk, pinned SSH, and HTTPS health.
- `v1.0.0` blockers include product-backed staging for all four Compose profiles,
  ownership-verified removal with shared-resource preservation, and staging
  end-to-end and fault acceptance. The [acceptance matrix](mvp-acceptance.md)
  identifies the Node network and Bot dependency gaps. Closing these gates
  requires a product-backed deployment path and ownership-verified removal.

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
resource-scoped permissions. P2 disposable acceptance covered onboarding,
resumable repair, and target-bound cleanup. P3 disposable acceptance covered
Firewall WebUI and fault handling. P4 and P5 have fixture coverage for rendering
and diagnostics. Product-backed deployment and ownership-verified removal are
release blockers.

## P4.1 implementation

- Added a non-deploying typed profile catalog/renderer for Remnawave Panel/Node
  and Bedolaga Bot/Cabinet.
- Requires digest-pinned image references; allowlists environment keys, volumes,
  ports, and dependencies; defaults to read-only, cap-drop-all and no-new-privileges.
- Panel/Cabinet expose only loopback-published ports; Node uses network_mode none;
  Bot/Cabinet dependency is explicit.
- Real product images, secrets, deployment, drift repair, and removal remain
  explicitly out of scope until later P4/P5 stages.

## P4.3 verification

- Rendered profile selections carry canonical catalog SHA-256 metadata; P4 profile tests and full CI passed.

## P4.2 implementation

- Added an explicit selection file and renderer CLI for the typed profile catalog.
- Selection remains non-deploying and rejects unknown profiles, mutable tags,
  unallowlisted env/volume keys, unsafe volume paths, missing dependencies, and
  non-isolated Node profiles.
- Related application services use an explicitly shared network group; isolated
  Node profiles remain networkless.
- Rendered selections carry a canonical catalog SHA-256 so later deployment and
  drift workflows can bind installed services to the approved profile catalog.

## P5.1 implementation

- Added non-destructive Compose drift audit against the catalog digest and rendered
  fragment.
- Added removal-plan generation that blocks on drift, requires explicit confirmation,
  lists only owned services/networks/volumes, preserves data, and never runs
  `compose down` or deletes volumes.

## P5.2 implementation

- Added CLI audit/removal-plan interface over the typed catalog validator.
- The CLI only emits JSON audit/plan results; it has no Docker execution or
  filesystem deletion capability.

## P5.3 implementation

- Added a read-only Docker state adapter contract: managed containers must carry
  the approved catalog digest and known profile labels; missing/unknown/drifted
  managed profiles block a match.
- The adapter consumes supplied inspect-like JSON only and performs no Docker
  calls or mutations.

## P5.5 verification

- CI passed the synthetic catalog, fragment and label checks. The previous
  removal test checked generated commands through a test runner. Live ownership
  and data preservation remain release blockers.

## P5.4 implementation

- The release review withdrew the removal executor. Fragment and label checks
  support review, and the tool does not perform Docker mutations.

## P2.3 verification

- Disposable VM acceptance passed the separate typed firewall onboarding profile with exact cleanup; no remote managed artifacts remained after cleanup.

## P3.3 verification

- Browser acceptance covers typed firewall draft payloads and rejects arbitrary command input.
- Full CI, WebUI browser tests, firewall helper rollback/fault tests, and disposable acceptance passed.

## P3.2 implementation

- Extended the typed Firewall WebUI with durable browser state, reload recovery,
  operation timeline polling, and receipt reconciliation for UNKNOWN_OUTCOME.

## P3.1 implementation

- Added Owner-only WebUI flow for typed firewall drafts: rule editing, SSH-port
  preservation through the API contract, baseline preview, re-authentication,
  approval, and durable execution enqueue.
- Preserved the typed runtime, rollback timer, SSH verification, UNKNOWN_OUTCOME,
  and reconciliation gates; full browser/fault acceptance passed CI and disposable runtime checks.

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

## P6 final acceptance

- Added `docs/mvp-acceptance.md` with the evidence matrix for P0–P5.
- Main CI run for `f741656` passed; no open PRs remain.
- Production readiness remains explicitly unclaimed because no production deployment or real VPS was used.

## P1.1 verification

- Passed: `pip check`, compile/import checks, Authority tests, runtime CLI tests,
  Worker/Broker tests, database Audit/Outbox tests, and targeted installer checks.
- Full application/runtime suites remain CI work: this sandbox blocks some `/var/tmp`,
  filesystem-permission, network, and socket scenarios.

## Blockers

- The checked-out `origin/main` ref was refreshed to `b4c43db` after PR #139.
- No production VPS is available or permitted. The disposable VM remains the only
  acceptance target; its `clear` rollback snapshot is available. P2 acceptance is complete.

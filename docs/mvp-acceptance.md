# MVP Acceptance Matrix

Status date: November 23, 2026

## Safety And Runtime

| Area | Evidence | Status |
|---|---|---|
| Auth/RBAC, Audit/Outbox, idempotency | Required CI and application tests | PASS |
| Authority/Broker/Worker and UNKNOWN_OUTCOME | Runtime tests and disposable process-boundary checks | PASS |
| TimeHealth, firewall rollback, SSH verification | Required CI and disposable fault checks | PASS |
| Fresh installation and restart protection | Ubuntu 24.04 disposable CI acceptance | PASS |
| Historical migration and excluded recovery contracts | PRs #133-#134 and required CI | PASS |

## VPS Onboarding

| Area | Evidence | Status |
|---|---|---|
| Pinned SSH fingerprint and VM preflight | Disposable VM console and SSH checks | PASS |
| Fresh helper onboarding | Disposable VM, Ubuntu 24.04.5, x86_64 | PASS |
| Repair after disconnect/partial phase | Disposable VM fault injection and retry | PASS |
| Target-bound cleanup | Disposable VM cleanup and artifact absence checks | PASS |
| Typed firewall onboarding | Separate account/key profile and cleanup | PASS |

## WebUI And Compose

| Area | Evidence | Status |
|---|---|---|
| Probe/restart reload recovery | Browser tests and CI | PASS |
| Lost enqueue response and idempotency replay | Browser tests and runtime tests | PASS |
| Correlation IDs and safe API error codes | Browser/API tests | PASS |
| Resource-level permissions | API projection, browser controls, CI | PASS |
| Typed firewall WebUI and reconciliation | Browser tests, runtime rollback/reconciliation tests | PASS |
| Typed optional Compose profiles | Catalog, selection renderer, digest binding, drift/removal tests | PASS |

## Remaining Boundary

No production deployment, real VPS, Remnawave/Bedolaga image deployment, or destructive
production-like removal was performed. P4 profile work is catalog/validation only;
P5 removal is confirmation-gated and data-preserving. MVP must not be declared ready
for production until a release-specific review accepts those boundaries.

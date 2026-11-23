# MVP Acceptance Matrix

Status date: November 23, 2026

## Safety And Runtime

| Area | Evidence | Status |
|---|---|---|
| Auth/RBAC, Audit/Outbox, idempotency | Required CI and application tests | PASS |
| Authority/Broker/Worker and UNKNOWN_OUTCOME | Runtime tests and disposable process-boundary checks | PASS |
| TimeHealth, firewall rollback, SSH verification | Required CI and disposable fault checks | PASS |
| Fresh installation and restart protection | Ubuntu 24.04 disposable CI acceptance | PASS |
| Release-channel Controller installation | Signed systemd/Compose fixture passed CI. Fresh installation from rehearsal commit `ffa7993`, HTTPS login, session persistence and audit integrity passed on staging | PASS |
| Historical migration and excluded recovery contracts | PRs #133-#134 and required CI | PASS |

## VPS Onboarding

| Area | Evidence | Status |
|---|---|---|
| Pinned SSH fingerprint and VM preflight | Disposable VM console and SSH checks | PASS |
| Staging controller install and restart | Pinned HTTPS, Owner/Auditor access checks, CSRF, session and audit integrity across Compose restart, networkless Worker, loopback-only API (`4e4ae9c`) | PASS |
| Staging Authority and Broker restart | New process IDs, active socket units and intact HTTPS session and audit checks after each restart (`4e4ae9c`) | PASS |
| Staging rollback | Booted clean snapshot via a separate overlay, verified pinned SSH, then restored the installed disk and checked HTTPS health | PASS |
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
| Staging fault acceptance with a managed target | Loss before and after dispatch, reconciliation, idempotency replay, firewall rollback and typed Docker restart have disposable CI coverage. The staging Controller was installed with an empty target policy | PENDING |
| Remnawave Panel | Staging passed API health, idempotent replay, loss of the start reply, executor restart, reconciliation, shared network refusal, and exact-ID removal with volume and network retention | PASS |
| Remnawave Node | CI and staging passed host networking, TLS 1.3, mutual TLS enforcement, health and exact-ID removal | PASS |
| Application Controller-to-host SSH | Real Panel effects, lost SSH reply and reconciliation passed CI runs `45207718030` and `45228644739`. A clean staging run timed out pulling the pinned PostgreSQL image before recording inventory | PENDING |
| Bedolaga Bot and Cabinet | Typed profiles include PostgreSQL, Redis and Cabinet API proxy configuration. Pinned image downloads and Telegram API connections timed out on staging. Product startup and live Telegram acceptance are not verified | PENDING |
| Existing Compose installations | Fragment comparison and labels support manual review. The managed removal executor requires a journal of Docker identities from a VPN-Orbit installation | MANUAL |

## Remaining Boundary

The recorded checks cover the controller and the disposable test scenarios listed
above. The `v1.0.0` gate requires the remaining product-backed staging,
reconciliation and removal scenarios to pass. Production readiness requires
a separate decision.

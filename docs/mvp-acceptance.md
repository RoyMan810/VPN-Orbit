# MVP Acceptance Matrix

Status date: November 24, 2026

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
| Staging fault acceptance with a managed target | Real application SSH effects and journal recovery passed on staging. Separate disposable CI verifies the native process, firewall rollback and typed Docker restart boundaries | PASS |
| Remnawave Panel | Staging passed API health, idempotent replay, loss of the start reply, executor restart, reconciliation, shared network refusal, and exact-ID removal with volume and network retention | PASS |
| Remnawave Node | CI and staging passed host networking, TLS 1.3, mutual TLS enforcement, health and exact-ID removal | PASS |
| Application Controller-to-host SSH | The disposable staging fixture passed real SSH install, a crash after starting a stopped Panel, Authority/Broker/Worker journal recovery, readback without a second start and removal. It uses direct runtime handlers and deterministic TimeHealth. Native process and clock faults have separate CI coverage | PASS |
| Bedolaga Bot and Cabinet | November 24 staging run passed pinned images, migrations, Redis `PONG`, health, verified HTTPS and the native Bot-to-Panel client with a real API key. Replay, stop/start, database readback, drift/shared-resource refusal, and exact-ID removal with volume and network retention passed | PASS |
| Telegram webhook receiver | The pinned Bot image rejected missing and wrong secrets and invalid payloads, then passed a valid synthetic update to the processor on staging | PASS |
| Staging webhook ingress | Temporary Cloudflare Quick Tunnel on an isolated application guest. Verified public HTTPS returns `401` without the correct secret and `404` for other methods and routes, including health and API. Controller stayed online on its original VM | PASS |
| Bedolaga installation reconciliation | Readback matched the original Docker IDs. PostgreSQL and Redis were healthy and Bot was still starting. `APP_QUARANTINED` preserved `UNKNOWN_OUTCOME` without replay. The original test disk is retained offline | BLOCKED |
| Telegram delivery | `getMe` previously confirmed the test token. On the new overlay, `getWebhookInfo` exhausted IPv4 retries before TCP connected. IPv6 had no route. The tunnel passed scope checks, but a successful `setWebhook`, live URL readback and Telegram `/start` remain unverified | BLOCKED |
| Existing Compose installations | Fragment comparison and labels support manual review. The managed removal executor requires a journal of Docker identities from a VPN-Orbit installation | MANUAL |

## Remaining Boundary

The recorded checks cover the controller and the disposable test scenarios listed
above. The `v1.0.0` gate requires the remaining product-backed staging,
reconciliation and removal scenarios to pass. Production readiness requires
a separate decision.

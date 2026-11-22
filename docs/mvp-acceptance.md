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
| Typed optional Compose profiles | Synthetic catalog, selection renderer and fragment diagnostics. Docker Compose v5.8.0 validated the generated `services` and `networks` on staging | FIXTURE PASS |
| Existing Compose installations and protected removal | Runtime ownership, fresh Docker evidence and preservation of shared resources still require acceptance | BLOCKED |
| Remnawave Panel/Node and Bedolaga Bot/Cabinet | Examples use placeholder images. The Node profile has no network, while [upstream Node deployment](https://github.com/remnawave/node/blob/c1f083cab84b05ae2bb01d854248402d6073952d/docker-compose-prod.yml) uses host networking. The Bot profile lacks the PostgreSQL and Redis services declared by the [upstream Bot deployment](https://github.com/BEDOLAGA-DEV/remnawave-bedolaga-telegram-bot/blob/dcefef9704311f97016257890df45ec181d0840c/docker-compose.yml). Product-backed installation and health checks are pending | BLOCKED |

## Remaining Boundary

The recorded checks cover the controller and the disposable test scenarios listed
above. The `v1.0.0` gate also requires product-backed staging and ownership-verified
Compose removal. Compose fragment comparison and matching labels support manual
review. They provide no authorization to delete resources. Production readiness
requires a separate decision.

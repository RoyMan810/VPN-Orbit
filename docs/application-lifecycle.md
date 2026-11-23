# Typed application lifecycle

The product profiles in `vpn_orbit/app_profiles.py` describe Remnawave
Panel/Node and Bedolaga Bot/Cabinet. They generate fixed Compose services
from protected administrator configuration. The older `tools/compose_profiles.py`
remains a diagnostic renderer; its fragments do not authorize deployment.

Panel uses the upstream backend image, PostgreSQL and Redis. Bot has its own
PostgreSQL and Redis, a Telegram token, an administrator ID, an HTTPS Panel
endpoint and a Panel API key. Cabinet proxies `/api/` to Bot. Panel requires
an HTTPS reverse proxy that sets the forwarding headers on its loopback
endpoint. Database credentials and application
secrets must be supplied privately. They are never accepted as arbitrary
Compose YAML, commands or mount paths.

Node uses host networking and a bounded capability list that includes
`NET_ADMIN`. This allows the product to configure the host network. Its
deployment requires explicit administrator configuration; it must run only on
the approved managed host. It receives no Docker socket or general host bind.
Other services publish their application ports only on loopback.

Images must be SHA-256 pinned references from the allowed upstream repositories.
Each installation has its own project, network and data volumes. Generated
labels bind resources to its ID, specification digest and private ownership
token. Labels alone do not authorize deletion. Live ownership and drift checks
are required by the lifecycle executor before any mutation.

The installed `vpn-orbit-app` CLI runs on the Docker host as root. A private
JSON specification contains `v`, `id`, `profiles`, `images` and `settings`.
Use a new ULID for the installation ID. `vpn-orbit-app configure --spec PATH`
registers it. `vpn-orbit-app status --id ID` reports the specification digest.
Use `install`, `start` or `remove` with `--id ID --digest DIGEST --operation ULID`.
Retry an operation with the same operation ID to obtain its stored result.

`vpn-orbit-app reconcile --id ID --operation ULID` compares fresh Docker state
with recorded IDs and configuration. An incomplete create without recorded
IDs stays quarantined for operator investigation. Removal stops and deletes
recorded containers by ID and preserves data volumes and networks. Docker
networks and volumes used by other containers block removal.

The `apps.lifecycle` runtime capability has its own `application_secret_ref`.
The protected target policy maps `applications` installation IDs to specification
digests. Authority signs that exact mapping, action and operation ID. Broker uses
only the dedicated Vault purpose. A lost reply opens the existing incident gate;
only readback through Broker can resolve the matching application receipt.

The managed host needs a root-owned installed VPN-Orbit package, the private
configuration above, and a dedicated `vpn-orbit-apps` SSH account. Its ForceCommand
is the supplied `remote/apps-gateway`, installed as
`/usr/local/libexec/vpn-orbit/apps-gateway`. Configure key-only authentication,
no forwarding, no PTY or user RC, and the exact sudo rule:

```text
vpn-orbit-apps ALL=(root) NOPASSWD: /opt/vpn-orbit/venv/bin/vpn-orbit-app-helper ""
```

The helper accepts bounded JSON on stdin. It accepts no path, command or Compose
fragment. `import-application-key` in the host runtime CLI imports the distinct
SSH credential; key rotation uses purpose `apps.lifecycle`.

Controller uses schema 6 for application jobs and drafts. Existing development
databases are not migrated automatically.

In WebUI, open the VPS and use **Applications** to review and approve a
prepared installation. The browser remembers the approved revision and job
ID across reloads, but does not store the re-authentication password.

The equivalent Owner API flow is:

1. `POST /api/v1/resources/{resource}/application-drafts` with `installation_id`,
   `spec_digest` and action `install`, `start` or `remove`.
2. Re-authenticate against the returned `plan_hash`, then POST the re-authentication
   ID to `/api/v1/change-plans/{draft}/application-approval` with `If-Match`.
3. POST its `approval_id` to the draft's `/application-execution-requests`.
   Repeating that request returns the same durable job.
4. Read `/api/v1/jobs/{job}` and `/api/v1/jobs/{job}/application-timeline`.
5. For an unknown result, POST an empty object to
   `/api/v1/jobs/{job}/application-reconciliations/{attempt}`. Up to three
   sequential readback attempts are allowed. The original job remains
   `UNKNOWN_OUTCOME`; a separate audit event records resolution.

These operations require the normal HTTPS/Origin/CSRF controls. Product secrets
stay on the managed host, outside API payloads and audit events.

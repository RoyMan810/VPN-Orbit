# MVP progress

## Current state

- Main: `889d427` (after merged PRs #126–#129).
- Active stage: P0, removal of excluded recovery/backup functionality.
- No real VPS has been used.

## Completed

- VPS cleanup is target-bound and ownership-aware.
- Broker recovery persists Authority receipts compatible with reconciliation.
- Stage0 prototypes and their CI were removed.
- Self-update and migration deployment code, tests, workflow, and documentation were removed.

## Current task

Remove recovery installation entrypoints from the installer and runtime without changing
normal fresh installation, durable jobs, Audit, Vault, Authority, or UNKNOWN_OUTCOME.

## Next

1. Remove remaining backup/rescue/recovery CLI entrypoints and their workflows.
2. Remove historical application schema compatibility.
3. Fix current WebUI/reconciliation gaps.
4. Complete VPS onboarding, firewall UI, and typed application deployment.

## Blockers

- No dedicated test VPS has been provided; external acceptance remains pending.

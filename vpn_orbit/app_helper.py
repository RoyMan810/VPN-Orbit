"""Bounded stdin-only application lifecycle endpoint for a forced SSH account."""

import json
import os
from pathlib import Path
import signal
import sys

from .app_adoption import EXTERNAL_ACTIONS, ExternalLifecycle
from .app_lifecycle import Lifecycle, ROOT
from .errors import Denied
from .runtime.protocol import application_payload, decode, fields


def dispatch(request):
    fields(request, ("operation", "application"))
    payload = application_payload(request["application"])
    if payload["action"] in EXTERNAL_ACTIONS:
        app = ExternalLifecycle(payload["installation_id"])
        options = {"action": payload["action"], "binding": payload["spec_digest"], "review": payload.get("review")}
        if "registration_id" in payload:
            options["registration_id"] = payload["registration_id"]
        if request["operation"] == "execute":
            result = app.execute(payload["operation_id"], **options)
        elif request["operation"] == "reconcile":
            result = app.reconcile(payload["operation_id"], **options)
        else:
            raise Denied("APP_ACTION_INVALID")
        return {"outcome": result["outcome"], "code": result["code"]}
    if (Path(ROOT) / payload["installation_id"] / "external.json").exists():
        raise Denied("APP_ACTION_INVALID")
    app = Lifecycle(payload["installation_id"])
    with app.locked():
        spec, _, _ = app.configuration()
        from .app_profiles import digest
        if digest(spec) != payload["spec_digest"]:
            raise Denied("APP_POLICY_MISMATCH")
    if request["operation"] == "execute":
        result = app.execute(payload["operation_id"], payload["action"], payload["spec_digest"])
    elif request["operation"] == "reconcile":
        # Check the original action and digest before readback. A different action
        # cannot be used to resolve an unrelated operation.
        with app.journal.connect() as db:
            saved = db.execute("SELECT action,binding FROM operations WHERE id=?", (payload["operation_id"],)).fetchone()
        if saved is None or (saved["action"], saved["binding"]) != (payload["action"], payload["spec_digest"]):
            raise Denied("APP_IDEMPOTENCY_CONFLICT")
        result = app.reconcile(payload["operation_id"])
    else:
        raise Denied("APP_ACTION_INVALID")
    return {"outcome": result["outcome"], "code": result["code"]}


def main():
    try:
        if os.geteuid() != 0 or len(sys.argv) != 1:
            raise Denied("LOCAL_ROOT_REQUIRED")
        signal.alarm(5)
        data = sys.stdin.buffer.read(2049)
        signal.alarm(0)
        if len(data) > 2048:
            raise Denied("APP_REQUEST_INVALID")
        result = dispatch(decode(data.rstrip(b"\n"), canonical_required=False))
    except Denied as error:
        result = {"outcome": "DENIED", "code": error.code}
    except Exception:
        result = {"outcome": "UNKNOWN_OUTCOME", "code": "APP_HELPER_UNAVAILABLE"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] in ("SUCCEEDED", "RECONCILED_SUCCEEDED") else (65 if result["outcome"] == "DENIED" else 70)


if __name__ == "__main__":
    raise SystemExit(main())

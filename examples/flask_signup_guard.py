"""Flask example — route signup risk; a VPN alone means review, not block.

Run:
    pip install flask sentinelsup
    export MASKBREAK_API_KEY=sk_live_...
    python flask_signup_guard.py
"""

import os
from flask import Flask, abort, jsonify, request

from sentinel import Sentinel, SentinelError

app = Flask(__name__)
sentinel = Sentinel()  # reads MASKBREAK_API_KEY (older SENTINEL_KEY still works)


@app.route("/signup", methods=["POST"])
def signup() -> object:
    payload = request.get_json(force=True) or {}
    email = (payload.get("email") or "").strip().lower()
    # What Sentinel.collect() returns ("token"), or the field the script fills in a form ("monocle").
    token = payload.get("token") or payload.get("monocle")

    if not email:
        abort(400, "missing email")

    # No token (a blocked collector) raises SentinelError too: it lands in the fallback below.
    try:
        result = sentinel.evaluate(token=token,
                                   fingerprint_event_id=payload.get("fingerprintEventId"),
                                   email=email)
    except SentinelError as e:
        # Explicit fail-open demo policy; do not reuse for sensitive mutations.
        app.logger.warning("Sentinel unavailable: %s", e)
        result = None

    if result and result.is_blocked:
        return jsonify({"error": "Signup blocked", "reasons": result.reasons}), 403

    if result and result.decision == "review":
        # Soft challenge: email verification, manual review, slower onboarding, etc.
        return jsonify({"ok": True, "needs_verification": True})

    # Normal signup flow
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)), debug=False)

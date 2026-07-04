"""Flask example — block VPN/proxy signups using Sentinel.

Run:
    pip install flask sentinelsup
    export SENTINEL_API_KEY=sk_live_...
    python flask_signup_guard.py
"""

import os
from flask import Flask, abort, jsonify, request

from sentinel import Sentinel, SentinelError

app = Flask(__name__)
sentinel = Sentinel()  # reads SENTINEL_API_KEY


@app.route("/signup", methods=["POST"])
def signup() -> object:
    payload = request.get_json(force=True) or {}
    email = (payload.get("email") or "").strip().lower()
    token = payload.get("sentinelToken")

    if not email or not token:
        abort(400, "missing email or sentinelToken")

    try:
        result = sentinel.evaluate(token=token)
    except SentinelError as e:
        # Fail open if Sentinel is down — log and continue.
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

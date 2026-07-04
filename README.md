# Sentinel Python SDK

Real-time fraud, VPN, proxy, and bot detection — free tier, sub-40ms global response.

Zero dependencies. Just the standard library.

## Install

```bash
pip install sentinelsup
```

## Quick start

```python
import os
from sentinel import Sentinel

s = Sentinel(api_key=os.environ["SENTINEL_API_KEY"])

result = s.evaluate(token=request.json["sentinelToken"])

if result.is_suspicious:
    return abort(403, "Sentinel flagged this session")

print(result.decision)        # 'allow' | 'review' | 'block'
print(result.risk_score)      # 0..100
print(result.network)         # {'vpn': True, 'proxy': False, 'datacenter': True, ...}
print(result.reasons)         # ['ip_in_known_vpn_range', 'datacenter_asn', ...]
```

## Get your API key

Sign up at [sntlhq.com/signup](https://sntlhq.com/signup) — free, no credit card.

## Flask example — block VPN/proxy signups

```python
from flask import Flask, request, abort, jsonify
from sentinel import Sentinel, SentinelError

app = Flask(__name__)
sentinel = Sentinel()  # reads SENTINEL_API_KEY from env

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    try:
        result = sentinel.evaluate(token=data["sentinelToken"])
    except SentinelError as e:
        # Fail open OR fail closed — your call. Logged either way.
        app.logger.warning("Sentinel error: %s", e)
        result = None

    if result and result.is_blocked:
        abort(403, "Signup blocked")

    # ... your normal signup flow
    return jsonify({"ok": True})
```

## Django example — middleware for high-value endpoints

```python
from django.http import JsonResponse
from sentinel import Sentinel

sentinel = Sentinel()  # reads SENTINEL_API_KEY from env

class FraudCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/checkout"):
            token = request.META.get("HTTP_X_SENTINEL_TOKEN")
            if token:
                try:
                    result = sentinel.evaluate(token=token)
                    if result.is_blocked:
                        return JsonResponse({"error": "blocked"}, status=403)
                except Exception:
                    pass  # fail open
        return self.get_response(request)
```

## Configuration

```python
Sentinel(
    api_key="sk_live_...",          # required (or via SENTINEL_API_KEY env var)
    endpoint="https://sntlhq.com",  # override for testing
    timeout=5.0,                    # seconds
)
```

## Response shape

```python
@dataclass
class EvaluateResult:
    decision: str | None        # 'allow' | 'review' | 'block'
    risk_score: int | None      # 0..100
    ip: str | None
    country: str | None         # ISO-2
    asn: str | None             # 'AS16509'
    asn_org: str | None         # 'Amazon.com, Inc.'
    network: dict               # {vpn, proxy, datacenter, anonymous, residential}
    device: dict                # {headless, automation, fingerprint_age_days}
    reasons: list[str]
    raw: dict                   # full upstream response

    is_suspicious: bool         # True if decision != 'allow'
    is_blocked: bool            # True if decision == 'block'
```

## Errors

All failures raise `SentinelError`. The exception carries `.status` (HTTP code) and `.body` (parsed error body) when available.

```python
from sentinel import Sentinel, SentinelError

try:
    result = sentinel.evaluate(token=tok)
except SentinelError as e:
    if e.status == 429:
        # back off
        pass
    elif e.status and 400 <= e.status < 500:
        # bad input, won't recover by retrying
        pass
    else:
        # transient — retry once or fail open
        pass
```

## Try the API without signing up

```bash
curl https://sntlhq.com/v1/evaluate/sample?scenario=vpn
```

Or use the [interactive playground](https://sntlhq.com/api#playground).

## License

MIT. See [LICENSE](LICENSE).

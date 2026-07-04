# sentinelsup — Sentinel Python SDK

Official Python SDK for [Sentinel](https://sntlhq.com) — a real-time fraud detection API that flags VPNs, residential proxies, antidetect browsers (Kameleo, GoLogin, Multilogin), Tor exit nodes, and AI bots in under 40 ms.

[![PyPI](https://img.shields.io/pypi/v/sentinelsup.svg)](https://pypi.org/project/sentinelsup/)
[![Python versions](https://img.shields.io/pypi/pyversions/sentinelsup.svg)](https://pypi.org/project/sentinelsup/)
[![license](https://img.shields.io/pypi/l/sentinelsup.svg)](./LICENSE)

Zero dependencies — just the standard library. Works with Flask, Django, FastAPI, or bare `urllib`.

## Set up with AI (fastest)

Using Claude Code, Cursor, Copilot, or any AI coding assistant? Paste this one
prompt and it wires the whole integration — frontend script, backend check,
env var, and a test:

> Fetch https://sntlhq.com/integrate.md and follow it to add Sentinel fraud
> protection to this app — protect signup, login, and checkout. My API key
> is sk_live_YOUR_KEY; put it in a SENTINEL_API_KEY env var, never in
> client-side code. Then show me how to test it.

[`integrate.md`](https://sntlhq.com/integrate.md) is the canonical
machine-readable integration guide, kept in sync with the live API.

## Install

```bash
pip install sentinelsup
```

Python 3.8+. Get a free API key (no credit card) at [sntlhq.com/signup](https://sntlhq.com/signup).

## Quick start

```python
import os
from sentinel import Sentinel

s = Sentinel(api_key=os.environ["SENTINEL_API_KEY"])  # or omit — reads the env var itself

result = s.evaluate(token=request.json["sentinelToken"])  # token from the frontend SDK

if result.is_blocked:            # decision == 'block'
    abort(403)

print(result.decision)        # 'allow' | 'review' | 'block' — route on this
print(result.risk_score)      # 0..100
print(result.network)         # {'vpn': True, 'proxy': False, 'datacenter': True, ...}
print(result.reasons)         # ['vpn_detected', 'datacenter_asn', ...]
```

## What you get back

`evaluate()` returns an `EvaluateResult` dataclass:

```python
@dataclass
class EvaluateResult:
    decision: str | None        # 'allow' | 'review' | 'block'
    risk_score: int | None      # 0..100
    ip: str | None
    country: str | None         # ISO-2
    network: dict               # {vpn, proxy, datacenter, anonymous, tor, residential, service}
    device: dict                # antidetect / automation / emulator signals
    reasons: list[str]          # machine-readable codes
    raw: dict                   # full upstream response

    is_suspicious: bool         # True if decision != 'allow'
    is_blocked: bool            # True if decision == 'block'
```

Try the live sample (same shape, no key needed):

```bash
curl "https://sntlhq.com/v1/evaluate/sample?scenario=vpn"
```

Or use the [interactive playground](https://sntlhq.com/api#playground).

## Frontend setup

Add the Sentinel Edge SDK to your frontend so Sentinel can collect the token:

```html
<script async src="https://sntlhq.com/assets/edge.js" id="_mcl"></script>

<!-- Add class="monocle-enriched" to any form you want evaluated -->
<form class="monocle-enriched" id="signup-form">
  <!-- The SDK injects: <input type="hidden" name="monocle" value="eyJ..."> -->
</form>
```

Send the injected token to your backend with the form submission and pass it
to `evaluate()`.

## Examples

### Flask — block VPN/proxy signups

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

### Django — middleware for high-value endpoints

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

Runnable versions live in [`examples/`](./examples/).

## API

### `Sentinel(api_key=None, endpoint="https://sntlhq.com", timeout=5.0)`

| Option | Default | Description |
|--------|---------|-------------|
| `api_key` | `$SENTINEL_API_KEY` | Your key starting with `sk_live_` |
| `endpoint` | `https://sntlhq.com` | Override base URL (for testing) |
| `timeout` | `5.0` | Per-request timeout in seconds |

### `sentinel.evaluate(token, fingerprint_event_id=None)`

Returns `EvaluateResult`. Raises `SentinelError` on network/API failure.

## Errors

All failures raise `SentinelError`. The exception carries `.status` (HTTP code) and `.body` (parsed error body) when available.

```python
from sentinel import Sentinel, SentinelError

try:
    result = sentinel.evaluate(token=tok)
except SentinelError as e:
    if e.status == 429:
        pass    # back off
    elif e.status and 400 <= e.status < 500:
        pass    # bad input, won't recover by retrying
    else:
        pass    # transient — retry once or fail open
```

## Rate limits

Free tier: **1,000 requests/hour** per API key. No monthly cap, no credit
card. Upgrade at [sntlhq.com](https://sntlhq.com) when you need more.

## What Sentinel detects

VPNs (commercial + self-hosted) · residential proxies (Bright Data, IPRoyal,
and similar networks) · datacenter IPs · Tor exit nodes · antidetect browsers
(Kameleo, GoLogin, Multilogin, Dolphin{anty}, AdsPower) · headless browsers
and automation (Puppeteer, Playwright, Selenium) · AI agents · emulators and
virtual machines · browser tampering.

## Related

- **Node.js SDK** — [`@sentinelsup/sdk`](https://github.com/sentinelsup/sentinel-node) on npm
- **API docs** — [sntlhq.com/api](https://sntlhq.com/api)
- **Free IP lookup tool** — [sntlhq.com/ip-lookup](https://sntlhq.com/ip-lookup)

## License

MIT © [Sentinel Edge Networks LTD](https://sntlhq.com). See [LICENSE](LICENSE).

# sentinelsup — Maskbreak Python SDK

Official Python SDK for [Maskbreak](https://maskbreak.com) — a real-time fraud detection API that flags VPNs, residential proxies, antidetect browsers (Kameleo, GoLogin, Multilogin), Tor exit nodes, and AI bots in under 150 ms.

[![PyPI](https://img.shields.io/pypi/v/sentinelsup.svg)](https://pypi.org/project/sentinelsup/)
[![Python versions](https://img.shields.io/pypi/pyversions/sentinelsup.svg)](https://pypi.org/project/sentinelsup/)
[![license](https://img.shields.io/pypi/l/sentinelsup.svg)](./LICENSE)

Zero dependencies — just the standard library. Works with Flask, Django, FastAPI, or bare `urllib`.

## Set up with AI (fastest)

Using Claude Code, Cursor, Copilot, or any AI coding assistant? Paste this one
prompt and it wires the whole integration — frontend script, backend check,
env var, and a test:

> Fetch https://maskbreak.com/integrate.md and follow it to add Maskbreak fraud
> protection to this app — protect signup, login, and checkout. My API key
> is sk_live_YOUR_KEY; put it in a SENTINEL_KEY env var, never in
> client-side code. Then show me how to test it.

[`integrate.md`](https://maskbreak.com/integrate.md) is the canonical
machine-readable integration guide, kept in sync with the live API.

## Install

```bash
pip install sentinelsup
```

Python 3.8+. Get a free API key (no credit card) at [maskbreak.com/signup](https://maskbreak.com/signup).

## Quick start

```python
import os
from sentinel import Sentinel

s = Sentinel(api_key=os.environ["SENTINEL_KEY"])  # or omit — reads the env var itself

result = s.evaluate(token=request.json["sentinelToken"])  # token from the frontend SDK

if result.is_blocked:            # decision == 'block'
    abort(403)

print(result.decision)        # 'allow' | 'review' | 'block' — route on this
print(result.risk_score)      # 0..100
print(result.network)         # {'vpn': True, 'proxy': False, 'datacenter': True, ...}
print(result.reasons)         # ['vpn_detected', 'datacenter_asn', ...]
```

Check the signup email against the disposable-domain feed (checked
transiently, never stored), or look up an arbitrary IP with no browser
token at all:

```python
result = s.evaluate(token=tok, email=data["email"])
if result.raw.get("email", {}).get("disposable"):
    ...  # burner domain — decision is escalated allow → review

info = s.lookup("185.220.101.34")   # GET /v1/lookup/{ip} — same key & quota
print(info["verdict"])              # 'allow' | 'review' | 'block'
print(info["signals"])              # {'vpn': ..., 'proxied': ..., 'tor': ..., 'dch': ..., 'anon': ...}
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
    email: dict | None          # {disposable: bool} — present when you passed email=
    decision_source: str | None # 'rules' | 'exception' when your policy matched
    engine_decision: str | None # engine's own verdict when policy changed the decision
    test: bool                  # True for test-token / test-key calls
    raw: dict                   # full upstream response

    is_suspicious: bool         # True if decision != 'allow'
    is_blocked: bool            # True if decision == 'block'
```

Try the live sample (same shape, no key needed):

```bash
curl "https://maskbreak.com/v1/evaluate/sample?scenario=vpn"
```

Or use the [interactive playground](https://maskbreak.com/api#playground).

## Frontend setup

Add the Maskbreak SDK to your frontend. One script loads **both** layers —
network (VPN/proxy/datacenter) and device (antidetect/bot/tampering):

```html
<script async src="https://maskbreak.com/assets/sentinel.js"></script>

<!-- Add class="monocle-enriched" to any form you want evaluated -->
<form class="monocle-enriched" id="signup-form">
  <!-- The SDK injects both:
       <input type="hidden" name="monocle"     value="eyJ...">  (network)
       <input type="hidden" name="sentinel_fp" value="a1b2..."> (device) -->
</form>
```

Forward both fields to your backend with the form submission and pass them to
`evaluate()` as `token` and `fingerprint_event_id` — without the second one,
the device-layer signals (antidetect, automation, emulator) never fire. For
fetch/XHR submissions, collect them explicitly:

```js
const { token, fingerprintEventId } = await window.Sentinel.collect();
```

## Examples

### Flask — block VPN/proxy signups

```python
from flask import Flask, request, abort, jsonify
from sentinel import Sentinel, SentinelError

app = Flask(__name__)
sentinel = Sentinel()  # reads SENTINEL_KEY (or SENTINEL_API_KEY) from env

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

sentinel = Sentinel()  # reads SENTINEL_KEY (or SENTINEL_API_KEY) from env

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

### `Sentinel(api_key=None, endpoint="https://maskbreak.com", timeout=5.0)`

| Option | Default | Description |
|--------|---------|-------------|
| `api_key` | `$SENTINEL_KEY` (falls back to `$SENTINEL_API_KEY`) | Your key starting with `sk_live_` |
| `endpoint` | `https://maskbreak.com` | Override base URL (for testing) |
| `timeout` | `5.0` | Per-request timeout in seconds |

### `sentinel.evaluate(token, fingerprint_event_id=None, account_id=None, email=None)`

Returns `EvaluateResult`. Raises `SentinelError` on network/API failure.

- `fingerprint_event_id` — adds the `device` signal block (antidetect, automation, emulator, …).
- `account_id` — your own user id for this session; enables multi-accounting detection (`device.linked_accounts` / `device.multi_account`).
- `email` — adds `email.disposable` to the raw response; burner domains escalate `allow` to `review`.

### `sentinel.lookup(ip)`

Returns the raw response dict for any public IPv4/IPv6 address (wraps `GET /v1/lookup/{ip}`): `verdict` (`allow`/`review`/`block`), `risk_score` (0–100), `known`, `signals` (`{vpn, proxied, tor, dch, anon}` or `None`), `network` (`{asn, org, country, city}`), `latency_ms`. Shares the per-key hourly quota with `evaluate()`. `known: False` means our feeds hold no data — it is **not** a clean guarantee.

## Testing

Deterministic test tokens exercise your allow / review / block handling end-to-end — no browser needed. Test calls are authenticated and rate-limited like real ones but never billed, stored, or webhooked, and the response carries `test=True`:

```python
result = s.evaluate(token="test_vpn")       # also: test_clean, test_proxy, test_datacenter, test_tor
assert result.decision == "review"
assert result.test
```

No account yet? The public sandbox key accepts the same test tokens:

```python
s = Sentinel(api_key="sk_test_sandbox")     # CI/staging — nothing billed, nothing stored
```

Every account also has a personal `sk_test_...` key (Settings → API Key) that runs the *complete* live pipeline — real tokens, your rules and exception pins included — while events stay flagged as test and never count toward usage or webhooks.

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
card.

## What Maskbreak detects

VPNs (commercial + self-hosted) · residential proxies (Bright Data, IPRoyal,
and similar networks) · datacenter IPs · Tor exit nodes · antidetect browsers
(Kameleo, GoLogin, Multilogin, Dolphin{anty}, AdsPower) · headless browsers
and automation (Puppeteer, Playwright, Selenium) · AI agents · emulators and
virtual machines · browser tampering.

## Related

- **Node.js SDK** — [`@sentinelsup/sdk`](https://github.com/sentinelsup/maskbreak-node) on npm
- **API docs** — [maskbreak.com/api](https://maskbreak.com/api)
- **Free IP lookup tool** — [maskbreak.com/ip-lookup](https://maskbreak.com/ip-lookup)

## License

MIT © [Sentinel Edge Networks LTD](https://maskbreak.com). See [LICENSE](LICENSE).

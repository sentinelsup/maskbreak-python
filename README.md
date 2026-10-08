# sentinelsup — Maskbreak Python SDK

Official Python SDK for [Maskbreak](https://maskbreak.com). Evaluate SDK-backed
visits for network and browser risk signals, or look up a public IP for cloud
range and Tor signals. These are different evidence sources, not interchangeable
checks. VPN/proxy service names are returned when known; a VPN alone routes to
review under the default policy, not automatic blocking.

[![PyPI](https://img.shields.io/pypi/v/sentinelsup.svg)](https://pypi.org/project/sentinelsup/)
[![Python versions](https://img.shields.io/pypi/pyversions/sentinelsup.svg)](https://pypi.org/project/sentinelsup/)
[![license](https://img.shields.io/pypi/l/sentinelsup.svg)](./LICENSE)

Zero dependencies — just the standard library. Works with Flask, Django, FastAPI, or bare `urllib`.

## Set up with an AI assistant

Using Claude Code, Cursor, Copilot, or any AI coding assistant? Paste this one
prompt and it wires the whole integration — frontend script, backend check,
env var, and a test:

> Fetch https://maskbreak.com/integrate.md and follow it to add Maskbreak fraud
> protection to this app — protect signup, login, and checkout. Start in watch
> mode (MASKBREAK_MODE). Read the API key from the server-only MASKBREAK_API_KEY
> environment variable; I will configure the secret separately. Never put it in
> client-side code. Show me how to test it.

[`integrate.md`](https://maskbreak.com/integrate.md) is the canonical
machine-readable integration guide, kept in sync with the live API.

## Install

```bash
pip install sentinelsup
```

Python 3.8+. Get a free API key (no credit card) at [maskbreak.com/signup](https://maskbreak.com/signup).

## Quick start

Three steps give you the first complete check, one that carries both the
network token and the browser check. The Maskbreak dashboard's setup uses the
same names.

**1. Add the script to the page with your form**, and `class="monocle-enriched"`
to the `<form>` element itself (never to an input):

```html
<script async src="https://maskbreak.com/assets/sentinel.js"></script>

<form class="monocle-enriched" method="post" action="/signup">
  <!-- your fields; the script adds monocle, sentinel_fp and sentinel_tz -->
</form>
```

Your site sends a Content-Security-Policy header? A policy that does not list
Maskbreak's hosts blocks the script: helmet's default policy in Express does,
and so does any `default-src 'self'` policy. Add
[the list](https://maskbreak.com/integrate.md#content-security-policy) to it.
The hidden fields fill in a second or two after the page loads.

**2. Send the check from your server.** One field mapping, whichever way the
browser part sends it:

| Form field | `Sentinel.collect()` returns | Send to the API as |
|---|---|---|
| `monocle` (network token) | `token` | `token` |
| `sentinel_fp` (browser check) | `fingerprintEventId` | `fingerprintEventId` (`fingerprint_event_id=` in `evaluate()`) |
| `sentinel_tz` (time zone) | `tz` | `tz` (optional; plain HTTP only, see below) |

Start in watch mode: every submission is checked and logged, a submission with
a missing field included (the dashboard then says which half did not arrive),
and nobody is blocked. `evaluate()` will not send a request without the network
token, so the quick start reports those submissions over plain HTTP:

```python
import json
import os
import urllib.request

from flask import Flask, abort, request
from sentinel import Sentinel

app = Flask(__name__)
sentinel = Sentinel()  # reads MASKBREAK_API_KEY from the environment

# Start in watch mode: log Maskbreak's answer and let everyone through.
# When Events look right, set MASKBREAK_MODE=enforce and redeploy.
MODE = os.environ.get("MASKBREAK_MODE") or "watch"


def report_without_token(fields):
    """evaluate() refuses to send without the network token. In watch mode a
    submission without it is reported anyway, so the dashboard can say so."""
    req = urllib.request.Request(
        "https://maskbreak.com/v1/evaluate",
        data=json.dumps({k: v for k, v in fields.items() if v}).encode(),
        headers={"Authorization": "Bearer " + os.environ["MASKBREAK_API_KEY"],
                 "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def maskbreak_check(data):
    """Return (decision, reasons); decision is None when there is no answer."""
    # Form fields -> API names. Sentinel.collect() already uses the API names.
    token = data.get("token") or data.get("monocle")
    event_id = data.get("fingerprintEventId") or data.get("sentinel_fp")
    tz = data.get("tz") or data.get("sentinel_tz")
    try:
        if token:
            result = sentinel.evaluate(token=token, fingerprint_event_id=event_id)
            return result.decision, result.reasons
        if MODE != "enforce":
            raw = report_without_token({"fingerprintEventId": event_id, "tz": tz})
            return raw.get("decision"), raw.get("reasons")
        return None, "no network token"
    except Exception as e:  # SentinelError, or the plain HTTP call failing
        return None, str(e)


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or request.form
    decision, reasons = maskbreak_check(data)
    print("[maskbreak]", MODE, decision or "no answer", reasons)
    if MODE == "enforce" and decision != "allow":
        abort(403 if decision == "block" else 409)
    ...  # watch mode, or an allow: your existing signup flow runs
```

**3. Submit your form once.** Deploy, open the page and submit the form. The
first check then appears in the dashboard (Integration tab and Events).

This is a handler fragment, not a complete signup implementation. Route `review`
to your verification/review flow; only `allow` is an approval. Keep API keys on
the server. An unavailable device layer or `raw["degraded"]` is not proof of a
clean visit; `degraded` describes the network layer only. The full enforce
policy (review, missing evidence, test and degraded answers) is in
[integrate.md](https://maskbreak.com/integrate.md).

Since v0.2.5, `Sentinel()` without a key reads `MASKBREAK_API_KEY`; the older
`SENTINEL_KEY` and `SENTINEL_API_KEY` names are still read as fallbacks.

Check the signup email against the disposable-domain feed (checked
transiently, never stored), or look up an arbitrary IP with no browser
token at all:

```python
result = sentinel.evaluate(token=tok, email=data["email"])
if result.raw.get("email", {}).get("disposable"):
    ...  # burner domain — decision is escalated allow → review

info = sentinel.lookup("185.220.101.34")  # GET /v1/lookup/{ip} — same key and hourly limit; its own monthly allowance (10x your checks)
print(info["verdict"])                   # 'allow' | 'review' | 'block'
print(info["signals"])                   # {'vpn': ..., 'proxied': ..., 'tor': ..., 'dch': ..., 'anon': ...}
```

An address lookup checks Tor exits and cloud servers only. It is not a visitor
check and does not stand in for the three steps above.

## What you get back

`evaluate()` returns an `EvaluateResult` dataclass. The type sketch below uses
Python 3.10+ annotation syntax for readability; the package minimum stays 3.8:

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

    is_suspicious: bool         # True for a non-null decision other than 'allow'
    is_blocked: bool            # True if decision == 'block'
```

Try the live sample (same shape, no key needed):

```bash
curl "https://maskbreak.com/v1/evaluate/sample?scenario=vpn"
```

Or use the [interactive playground](https://maskbreak.com/api#playground).

## Frontend setup

Add the Maskbreak SDK to the page with your form. One script loads **both**
layers — network (VPN/proxy/datacenter) and device (antidetect/bot/tampering):

```html
<script async src="https://maskbreak.com/assets/sentinel.js"></script>

<!-- class="monocle-enriched" on the form itself, never on an input -->
<form class="monocle-enriched" id="signup-form">
  <!-- The SDK fills in:
       <input type="hidden" name="monocle"     value="eyJ...">  (network)
       <input type="hidden" name="sentinel_fp" value="a1b2..."> (device)
       <input type="hidden" name="sentinel_tz" value="Europe/Tallinn"> -->
</form>
```

An ordinary form post carries the three fields to your server, and the quick
start maps them to the API's names. A form your JavaScript submits (fetch,
React, Next.js, Vue) sends `Sentinel.collect()`'s result with its own data
instead; the quick start's handler reads that JSON too. `collect()` waits at
most 5 seconds for the device check (`collect({ timeout: ms })` to change it);
a value that is not there by then is `null`. Check that the script is there,
and never hold the form because of it:

```js
const evidence = window.Sentinel ? await window.Sentinel.collect() : {};
await fetch('/signup', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  // evidence = { token, fingerprintEventId, tz }, already the API's names
  body: JSON.stringify({ email: form.email.value, ...evidence })
});
```

The integration guide has the same flow as a
[Next.js App Router example](https://maskbreak.com/integrate.md) (client
component and Route Handler).

## Examples

### Django — middleware for high-value endpoints

The quick start's `maskbreak_check()` works in any framework: give it the
submitted fields as a mapping.

```python
import json

from django.http import JsonResponse


class FraudCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "POST" and request.path.startswith("/api/checkout"):
            if request.content_type == "application/json":
                try:
                    data = json.loads(request.body or b"{}")
                except ValueError:
                    data = {}
            else:
                data = request.POST
            decision, reasons = maskbreak_check(data if isinstance(data, dict) else {})
            print("[maskbreak]", MODE, decision or "no answer", reasons)
            if MODE == "enforce" and decision == "block":
                return JsonResponse({"error": "blocked"}, status=403)
            if MODE == "enforce" and decision != "allow":
                return JsonResponse({"error": "additional verification required"}, status=409)
        return self.get_response(request)
```

More examples, enforce-mode guards for checkout, withdrawal and transfer
endpoints, live in [`examples/`](./examples/).

## API

### `Sentinel(api_key=None, endpoint="https://maskbreak.com", timeout=5.0)`

| Option | Default | Description |
|--------|---------|-------------|
| `api_key` | `$MASKBREAK_API_KEY` (falls back to `$SENTINEL_KEY`, then `$SENTINEL_API_KEY`) | Your key starting with `sk_live_` |
| `endpoint` | `https://maskbreak.com` | Override base URL (for testing) |
| `timeout` | `5.0` | Per-request timeout in seconds |

### `sentinel.evaluate(token, fingerprint_event_id=None, account_id=None, email=None)`

Returns `EvaluateResult`. Raises `SentinelError` when `token` is missing or empty, and on network/API failure.

- `fingerprint_event_id` — adds the `device` signal block (antidetect, automation, emulator, …).
- `account_id` — your own user id for this session; enables multi-accounting detection (`device.linked_accounts` / `device.multi_account`).
- `email` — adds `email.disposable` to the raw response; burner domains escalate `allow` to `review`.

This synchronous SDK forwards only these named inputs. It does not expose a
timezone input, automatic retries, a circuit breaker, or every REST endpoint.
Device availability and `degraded` remain accessible through `raw`; missing
device evidence must not be treated as a clean device result. Account linking
(`linked_accounts`) is customer-scoped; device `first_seen`/`times_seen` history
is not customer-scoped.

### `sentinel.lookup(ip)`

Returns the raw response dict for any public IPv4/IPv6 address (wraps `GET /v1/lookup/{ip}`): `verdict` (`allow`/`review`/`block`), `risk_score` (0–100), `known`, `signals` (`{vpn, proxied, tor, dch, anon}` or `None`), `network` (`{asn, org, country, city}`), `latency_ms`. Shares the hourly quota with `evaluate()` (one per account for the live keys; the test key has its own) and has its own monthly allowance. `known: False` means our feeds hold no data — it is **not** a clean guarantee.

Production bare-IP lookup checks cloud ranges and Tor exits, not live-visit
VPN/proxy evidence. Legacy `vpn`/`proxied` keys in the shape do not imply those
checks ran. Use `evaluate()` with browser evidence for VPN/proxy checks. When
obtaining an IP behind a proxy, trust forwarded headers only from configured
trusted proxies; never blindly take the first client-supplied value.

## Testing

Deterministic `test_*` tokens exercise response handling, not detection quality.
SDK fixture calls use authentication and quota but do not increment billable
usage or trigger webhooks; console-originated live-key fixtures can be stored
as test events. Personal rules and exception pins can change fixture decisions.

```python
result = s.evaluate(token="test_vpn")       # also: test_clean, test_proxy, test_datacenter, test_tor
assert result.decision == "review"          # default policy, no overriding rules/pins
assert result.test
```

No account yet? The public sandbox key accepts the same test tokens:

```python
s = Sentinel(api_key="sk_test_sandbox")     # deterministic fixtures only, no live detection
```

The public sandbox is separately rate-limited, accepts only supported fixture
tokens, and does not store events or run live detection. It is not a production
allowance. A personal `sk_test_...` key runs the live pipeline with real browser
evidence and your policy; resulting events are stored with `is_test` set, kept
out of your stats and never fire webhooks, and their checks count toward the
monthly allowance (the fixed `test_*` tokens do not). Test keys still have rate
limits.

Local checks require no API credentials:

```bash
python -m unittest discover -s tests -v
python -m pip install build twine
python -m build
python -m twine check dist/*
```

The CI matrix targets Python 3.8–3.14 without raising the 3.8 minimum. A configured
matrix is not a claim that every interpreter was tested locally; inspect its run.

## Errors

A missing or empty `token`, transport/API failures and unusable success responses raise `SentinelError`.
The exception carries `.status` (HTTP code) and `.body` (parsed error body) when
available. Redirects are rejected to avoid forwarding credentials. Configure the
final API base URL; the client does not retry automatically.

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
        pass    # unknown outcome — use the endpoint's explicit fallback policy
```

A `503` whose body has `"code": "storage_unavailable"` means the key could not
be checked at that moment. It is not an invalid key (that is `401`): retry
after a short delay (the API sends `Retry-After: 30`; `SentinelError` exposes
status and body, not headers, so use raw HTTP if you need to read it) and apply
your outage policy meanwhile.

## Rate limits

Visitor checks (`evaluate()`) are counted per calendar month in UTC, with an hourly cap: **Free — 10,000 a month, up to 1,000 an hour, no credit card**; paid plans from €29 a month ([pricing](https://maskbreak.com/pricing)). IP lookups (`lookup()`) have their own monthly allowance, 10× the plan's checks (100,000 on Free). A used-up month answers `429` with `code: "monthly_quota_exceeded"` and `Retry-After` until the 1st; there are no overage charges.

## What Maskbreak detects

SDK-backed visits can supply VPN/proxy, cloud-hosting and Tor signals, with VPN/proxy service names when known. Available device intelligence adds browser tampering, automation, emulator and virtual-machine signals. Coverage depends on the evidence available; these are not guarantees of detecting every product or visitor. Bare-IP lookup is limited to public cloud-range and Tor evidence.

## Related

- **Node.js SDK** — [`@sentinelsup/sdk`](https://github.com/sentinelsup/maskbreak-node) on npm
- **API docs** — [maskbreak.com/api](https://maskbreak.com/api)
- **Free IP lookup tool** — [maskbreak.com/ip-lookup](https://maskbreak.com/ip-lookup)

## License

MIT © [Sentinel Edge Networks LTD](https://maskbreak.com). See [LICENSE](LICENSE).

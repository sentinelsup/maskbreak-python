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
| `sentinel_tz` (time zone) | `tz` | `tz` (optional; `tz=` in `evaluate()` since 0.4.0) |

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
    """Return (decision, reasons); decision is None when there is no answer,
    and "unchecked" when the month's checks are used up (let it through)."""
    # Form fields -> API names. Sentinel.collect() already uses the API names.
    token = data.get("token") or data.get("monocle")
    event_id = data.get("fingerprintEventId") or data.get("sentinel_fp")
    tz = data.get("tz") or data.get("sentinel_tz")
    try:
        if token:
            result = sentinel.evaluate(token=token, fingerprint_event_id=event_id, tz=tz)
            if result.is_fixture:  # a test or sample answer: anyone can send a test token
                return None, "test answer, not a real visitor"
            return result.decision, result.reasons
        if MODE != "enforce":
            raw = report_without_token({"fingerprintEventId": event_id, "tz": tz})
            return raw.get("decision"), raw.get("reasons")
        return None, "no network token"
    except Exception as e:  # SentinelError, or the plain HTTP call failing
        # The month's checks are used up: let the action through, logged, until the 1st.
        body = getattr(e, "body", None)
        if getattr(e, "status", None) == 429 and isinstance(body, dict) and body.get("code") == "monthly_quota_exceeded":
            return "unchecked", "monthly_quota_exceeded"
        return None, str(e)


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or request.form
    decision, reasons = maskbreak_check(data)
    print("[maskbreak]", MODE, decision or "no answer", reasons)
    if MODE == "enforce" and decision not in ("allow", "unchecked"):
        abort(403 if decision == "block" else 409)
    ...  # watch mode, or an allow: your existing signup flow runs
```

**3. Submit your form once.** Run your app where you can open the page, on
your computer or on your site, and submit the form once. The first check then
appears in the dashboard (Integration tab and Events), and
[`sentinel.setup_status()`](#check-your-setup) says whether it arrived complete
and what to fix.

This is a handler fragment, not a complete signup implementation. Route `review`
to your verification/review flow; only `allow` is an approval. Keep API keys on
the server. An unavailable device layer or `raw["degraded"]` is not proof of a
clean visit; `degraded` describes the network layer only. The full enforce
policy (review, missing evidence, test and degraded answers) is in
[integrate.md](https://maskbreak.com/integrate.md).

Since v0.2.5, `Sentinel()` without a key reads `MASKBREAK_API_KEY`; the older
`SENTINEL_KEY` and `SENTINEL_API_KEY` names are still read as fallbacks.

## What's new

### 0.4.0 (2026-10-27)

- `evaluate()` takes the fields the API has read since 23 October 2026, as
  keyword arguments sent under the API's own names: `tz`, `phone`, and for
  login protection `event`, `login_succeeded`, `succeeded`, `session_id`,
  `user_agent`, `ip`, `reason`, `verification_type` and `verified_event`. See
  [Logins, signups and account events](#logins-signups-and-account-events).
- The account events `password_change`, `verification`, `logout` and
  `account_change` can be sent without the browser's token. A login, a signup
  and a plain check still need it.
- A value the API would ignore or misread (an `event` such as `"signin"`, a
  `login_succeeded` that is not `True` or `False`) raises `SentinelError`
  before anything is sent, instead of a check that quietly runs without it.
- A check sent without `fingerprint_event_id` issues one
  `MissingBrowserPartWarning` per process: such checks have no browser part.
  `Sentinel(warn_missing_browser_part=False)` turns it off.
- New `sentinel.setup_status()` (`GET /v1/setup`) says whether your checks
  arrive complete and what to fix.
- `EvaluateResult` gains `account_takeover`, `account_event`, `phone`,
  `timezone`, `degraded`, `sandbox`, `sample`, `device_evidence`, `evidence`,
  `rule_matched`, `exception_matched` and `evaluated_in_ms`.

Check the signup email against the disposable-domain feed (and, with email
and phone intelligence on, get the provider's score; Maskbreak never stores
the address), or look up an arbitrary IP with no browser token at all:

```python
result = sentinel.evaluate(token=tok, email=data["email"])
if result.raw.get("email", {}).get("disposable"):
    ...  # burner domain — decision is escalated allow → review

info = sentinel.lookup("185.220.101.34")  # GET /v1/lookup/{ip} — same key; its own monthly allowance (10x your checks)
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
    network: dict               # {vpn, proxy, privacy_relay, datacenter, anonymous, tor, residential, service}
    device: dict                # antidetect / automation / emulator signals
    reasons: list[str]          # machine-readable codes
    email: dict | None          # {disposable: bool, ...} — present when you passed email=;
                                # with email and phone intelligence on, also checked/score/risk/signals
    account: dict | None        # the account network (since 0.3.1): present when you
                                # passed account_id= with a live key
    decision_source: str | None # 'rules' | 'exception' when your policy matched
    engine_decision: str | None # engine's own verdict when policy changed the decision
    test: bool                  # True for test-token / test-key calls
    raw: dict                   # full upstream response
    # Since 0.4.0:
    account_takeover: dict | None  # event="login": {checked, score, risk, signals} or {checked: False, why}
    account_event: dict | None     # other events: {event, recorded} or {event, recorded: False, why}
    phone: dict | None             # phone=: {checked, score, risk, signals, ...} or {checked: False, why}
    timezone: dict | None          # tz=: {reported, country, matches_ip, checked}
    degraded: bool                 # True when the network part was unavailable (no or an unreadable token)
    sandbox: bool                  # True when the public sk_test_sandbox key answered
    sample: bool                   # True on GET /v1/evaluate/sample answers
    device_evidence: str | None    # 'ok' | 'unavailable' | 'not_sent'
    evidence: dict | None          # {network_age_s, device_age_s, device_replayed}
    rule_matched: list | None      # signals your rules matched
    exception_matched: list | None # pins that matched
    evaluated_in_ms: int | None

    is_suspicious: bool         # True for a non-null decision other than 'allow'
    is_fixture: bool            # True for a test-token, test-key, sandbox or sample answer
    is_blocked: bool            # True if decision == 'block', or (since 0.3.0) for any
                                # fixture answer unless Sentinel(allow_test_results=True)
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
            if MODE == "enforce" and decision not in ("allow", "unchecked"):
                return JsonResponse({"error": "additional verification required"}, status=409)
        return self.get_response(request)
```

More examples, enforce-mode guards for checkout, withdrawal and transfer
endpoints, live in [`examples/`](./examples/).

## Logins, signups and account events

Since 0.4.0 `evaluate()` takes the fields the API reads for login protection
and for email and phone intelligence, so the call your login, signup and
account views already make carries them. The examples below use two helpers:

```python
from sentinel import SentinelError


def evidence(data):
    """The browser's evidence: form fields or Sentinel.collect()'s names."""
    return {
        "token": data.get("token") or data.get("monocle"),
        "fingerprint_event_id": data.get("fingerprintEventId") or data.get("sentinel_fp"),
        "tz": data.get("tz") or data.get("sentinel_tz"),
    }


def check(**fields):
    """evaluate(), with None instead of an error (no token, API unreachable)."""
    try:
        return sentinel.evaluate(**fields)
    except SentinelError as e:
        print("[maskbreak] check unavailable:", e)
        return None
```

### A login

Make the check after your own password check, so it can say whether the
password was right. `account_id` is the account being signed in to, as your
database knows it (never a form field). Each call is a check: on your login
route this one is the check, not one more.

```python
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    user = find_user_by_email(data.get("email"))                 # your database
    password_ok = bool(user is not None and verify_password(user, data.get("password")))

    result, month_used_up = None, False
    try:
        result = sentinel.evaluate(
            **evidence(data),                                    # the browser's token, event id and tz
            event="login",
            account_id=str(user.id) if user else None,           # your own id for the account
            login_succeeded=password_ok,                         # send failed attempts too
            session_id=your_session_id(),                        # at most 256 characters; only a keyed hash leaves Maskbreak
            user_agent=request.headers.get("User-Agent"),        # as your server received it
            ip=request.remote_addr,                              # as your server saw it
        )
    except SentinelError as e:  # no token from the browser, or the API failed
        print("[maskbreak] check unavailable:", e)
        month_used_up = e.status == 429 and e.body.get("code") == "monthly_quota_exceeded"
    print("[maskbreak]", MODE, result.decision if result else "no answer",
          result.account_takeover if result else None)

    if not password_ok:
        abort(401)
    if MODE == "enforce" and not month_used_up:
        if result is not None and result.decision == "block":
            abort(403)
        # Review, no answer or a test answer: a second factor, not a refusal.
        if result is None or result.decision != "allow" or result.is_fixture:
            return send_second_factor(user)
    return sign_in(user)  # your existing session code
```

- `ip` is used only when the network token gave no address, and never changes
  the network verdict. Behind a proxy, configure werkzeug's `ProxyFix` (or your
  framework's equivalent) for your own proxies so `request.remote_addr` is the
  visitor's address; never take the first `X-Forwarded-For` value on trust.
- `result.account_takeover` is `{"checked": True, "score", "risk", "signals"}`
  with a score from 0 to 100 (higher is riskier; `risk` is `low` below 50,
  `medium` from 50, `high` from 80). A score of 80 or more adds the reason
  `account_takeover_risk` and raises `allow` to `review`, never to `block`:
  answer it with a second factor or an emailed code.
- `"checked": False` comes with `why`: `not_enabled` (switched off in
  Settings), `no_account_id`, `test`, `busy`, `unavailable` or
  `not_available`. Treat it as no opinion; the rest of the answer is
  unaffected.
- Login protection is on for every account until a workspace admin switches
  it off in Settings, and it acts only when you send `event` with
  `account_id`. Its score learns from the logins of every Maskbreak customer
  who uses login protection; say so in your own privacy notice. A login
  counts as a normal check.

### A signup with email and phone

Send `event="signup"` once your database has the new account's id, with the
address and the number the person gave:

```python
result = check(
    **evidence(data),
    event="signup",                # the account was created
    account_id=str(user.id),       # the new account's id, from your database
    email=data.get("email"),
    phone=data.get("phone"),       # international format, such as +44 20 7946 0958
)
if result is not None:
    print("[maskbreak]", result.decision, result.email, result.phone, result.account_event)
    # A review: keep the new account waiting until it confirms its email or phone.
```

- With email and phone intelligence on, `result.email` gains `checked`,
  `score`, `risk`, `signals` and a few facts, and `result.phone` has the same
  shape. A score of 80 or more adds `email_high_risk` or `phone_high_risk` and
  raises `allow` to `review`, never to `block`.
- Email and phone intelligence is on by default for accounts created from 23
  October 2026; an older account switches it on in Settings, and any account
  can switch it off there. Each address or number scored uses one of the
  plan's daily email-and-phone checks: Free 3, Starter 20, Growth 50, Scale
  150 a day.
- `"checked": False` comes with `why`: `not_enabled`, `quota` (the day's
  checks are used up), `invalid`, `test`, `busy`, `unavailable` or
  `not_available`; `invalid`, `busy` and `unavailable` use no daily check.
  Treat it as no opinion. Maskbreak never stores or logs the address or the
  number.
- `result.account_event` says whether login protection took the signup:
  `{"event": "signup", "recorded": True}`.

### Account events

A password change, a second factor, a logout and an account change go to login
protection too: no score comes back, and they teach it what is normal for each
account, so its login scores get sharper. These four may go without the
browser's token (since 0.4.0), for views with no page in front of them:

```python
# After your password-change view has saved the new password:
check(
    event="password_change",
    account_id=str(current_user.id),     # from your server-side session
    succeeded=True,
    reason="user",                       # "forgot" after a reset link, "forced" for a reset you required
    session_id=your_session_id(),
    user_agent=request.headers.get("User-Agent"),
    ip=request.remote_addr,
)

# A second factor, with how it was checked and what it was for:
check(event="verification", account_id=str(user.id), succeeded=code_ok,
      verification_type="sms", verified_event="login")

check(event="logout", account_id=str(current_user.id))
check(event="account_change", account_id=str(current_user.id), email=new_email)  # the new email
```

- `result.account_event` is `{"event": ..., "recorded": True}`, or
  `"recorded": False` with the same `why` values as a login.
- Sent with `**evidence(data)` from a form that carries the script, it is a
  full check. Without the token it is a degraded one (`result.degraded` is
  True): its `decision` says nothing about the visitor's network, so read
  `account_event`. A recorded event counts as a check.
- A login and a signup are visits, so they still need the token:
  `evaluate()` raises `SentinelError` without it, as before.

### The visitor's time zone

`tz` comes with the browser's evidence (`Sentinel.collect()` returns it, a form
carries `sentinel_tz`), so `evidence()` above already sends it:

```python
result = check(**evidence(data))
# result.timezone → {"reported": "Europe/Tallinn", "country": "EE", "matches_ip": True, "checked": True}
```

A zone whose country disagrees with an ordinary-looking address adds
`timezone_mismatch` and raises `allow` to `review`; it never blocks. On a VPN,
proxy, Tor or datacenter exit, where a mismatch is expected, nothing is raised
(`"checked": False`).

### Refused before sending

A value the API would ignore or misread raises `SentinelError`, and nothing is
sent: an `event` other than `login`, `signup`, `password_change`,
`verification`, `logout` and `account_change` (read case-insensitively, so
`"signin"` is refused), a `reason`, `verification_type` or `verified_event`
outside its list, a `login_succeeded` or `succeeded` that is not `True` or
`False`, a `tz`, `phone`, `user_agent` or `ip` that is not a string, and a
`session_id` that is not a string or an int or is longer than 256 characters.
An argument that is `None` or `""` is left out of the request.

### The missing-browser-part warning

A check sent without `fingerprint_event_id` has no browser part, so bots, fake
browsers and emulators go unchecked (the dashboard says the browser part is
missing). The first such call in a process issues one
`MissingBrowserPartWarning` (a `UserWarning`) that says so and how to fix it,
pointing at the line that called `evaluate()`; it never contains your key or
anything about the visitor. The fixed `test_*` tokens and the four account
events never trigger it.

It goes through Python's `warnings` module rather than `logging`: the fix is a
change to your code, which is what Python's warnings are for, and your
warnings filters and `logging.captureWarnings()` (Django turns it on) route it
like any other. Turn it off with `Sentinel(warn_missing_browser_part=False)`
or `warnings.filterwarnings("ignore", category=MissingBrowserPartWarning)`.
Where warnings are turned into errors (`-W error`, pytest's
`filterwarnings = error`), the first such call raises the warning instead.

## Check your setup

After you submit your form once, `setup_status()` (`GET /v1/setup`) tells you
whether the check arrived complete and what to fix:

```python
setup = sentinel.setup_status()
print(setup["status"], "-", setup["message"])
if setup["next_step"]:
    print("Next:", setup["next_step"])
```

| Key | What it says |
|---|---|
| `status` | What the latest check showed: `waiting` (no check in the last 7 days, and none complete before), `complete` (both parts, live key), `missing_network` (no network token), `network_unavailable` (a token that could not be read), `missing_device` (no browser event id), `device_unavailable` (a browser event that could not be verified), `test_mode` (a test token, or the test key without both parts), `test_complete` (the test key with both parts: swap in the live key), `ip_restricted`, `rate_limited` or `request_failed` |
| `complete` | At least one complete live-key check has arrived |
| `message` / `next_step` | What the latest check showed, and what to do next (`None` when nothing is left) |
| `last_check_at`, `complete_checks`, `last_complete_at` | When the latest check arrived, how many complete ones did, and when the latest of those did |
| `website` | `{"confirmed", "origin"}`: the website the first complete check came from |
| `script_seen` | `{"origin", "at"}` where and when the page script last reported in, or `None` |
| `site_id`, `key_type`, `docs` | Your site ID, which key made the call (`live` or `test`), and a link to the guide |

It works with the live key and the test key, and returns the answer as the API
sends it, a dict (typed as `sentinel.SetupStatus` for type checkers).

## API

### `Sentinel(api_key=None, endpoint="https://maskbreak.com", timeout=5.0, allow_test_results=False, warn_missing_browser_part=True)`

| Option | Default | Description |
|--------|---------|-------------|
| `api_key` | `$MASKBREAK_API_KEY` (falls back to `$SENTINEL_KEY`, then `$SENTINEL_API_KEY`) | Your key starting with `sk_live_` |
| `endpoint` | `https://maskbreak.com` | Override base URL (for testing) |
| `timeout` | `5.0` | Per-request timeout in seconds |
| `allow_test_results` | `False` | Only for your own test runs: `is_blocked` treats test, sandbox and sample answers as a normal decision |
| `warn_missing_browser_part` | `True` | `False` turns off the one-time `MissingBrowserPartWarning` (since 0.4.0) |

### `sentinel.evaluate(token=None, fingerprint_event_id=None, account_id=None, email=None, *, ...)`

Returns `EvaluateResult`. Raises `SentinelError` when `token` is missing or empty (except for the four account events below), for a value the API would ignore or misread ([Refused before sending](#refused-before-sending)), and on network/API failure.

The keyword-only arguments (since 0.4.0), each sent under the API's own name and only when given:

| Argument | Sent as | Notes |
|---|---|---|
| `tz` | `tz` | The visitor's IANA time zone |
| `phone` | `phone` | International format |
| `event` | `event` | `login`, `signup`, `password_change`, `verification`, `logout` or `account_change`; needs `account_id`. With `password_change`, `verification`, `logout` or `account_change`, `token` may be left out |
| `login_succeeded` | `loginSucceeded` | With `login`: `True` or `False` |
| `succeeded` | `succeeded` | With `password_change` or `verification`: `True` or `False` (absent means pending) |
| `session_id` | `sessionId` | With an event: your session ID (str or int), at most 256 characters |
| `user_agent`, `ip` | `userAgent`, `ip` | With an event: as your server received them |
| `reason` | `reason` | With `password_change`: `user`, `forgot` or `forced` |
| `verification_type` | `verificationType` | With `verification`: `email`, `sms`, `phone_call`, `app`, `push`, `security_key` or `captcha` |
| `verified_event` | `verifiedEvent` | With `verification`: `login`, `signup`, `password_change` or `account_change` |

- `fingerprint_event_id` — adds the `device` signal block (antidetect, automation, emulator, …).
- `account_id` — your own user id for this session, from your server-side session (never a form field); enables multi-accounting detection (`device.linked_accounts` / `device.multi_account`) and, with a live key, the `account` object (the account network, since 18 October 2026): devices per account, your accounts per device and per address in 24 hours, `new_device`, and the accounts it shares a device or an address with. `device_many_accounts` (3+ of your accounts on one device within 24 hours) raises an allow to review; `account_new_device`, `account_many_devices` and `ip_many_accounts` inform only. Maskbreak keeps the id as a keyed hash and, encrypted, for your console; nothing crosses customers.
- `email` — adds `email.disposable` to the raw response; burner domains escalate `allow` to `review`. With email and phone intelligence on (the default for accounts created from 23 October 2026), `email` also carries the provider's `checked`, `score`, `risk` and `signals`, and each address scored uses one of the plan's daily email-and-phone checks.

This synchronous SDK forwards only these named inputs (the GPU and browser
consistency betas stay raw HTTP). It has no automatic retries, circuit breaker,
or every REST endpoint. Device availability (`device_evidence`) and `degraded`
are fields of the result since 0.4.0 and stay in `raw`; missing device evidence
must not be treated as a clean device result. Account linking
(`linked_accounts`) is customer-scoped; device `first_seen`/`times_seen` history
is not customer-scoped.

### `sentinel.setup_status()`

Wraps `GET /v1/setup` (since 0.4.0) and returns its answer as is: see
[Check your setup](#check-your-setup). Raises `SentinelError` on network/API
failure.

### `sentinel.lookup(ip)`

Returns the raw response dict for any public IPv4/IPv6 address (wraps `GET /v1/lookup/{ip}`): `verdict` (`allow`/`review`/`block`), `risk_score` (0–100), `known`, `signals` (`{vpn, proxied, tor, dch, anon}` or `None`), `network` (`{asn, org, country, city}`), `latency_ms`. Has its own monthly allowance, 10× the plan's checks. `known: False` means our feeds hold no data — it is **not** a clean guarantee.

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

Test keys, test tokens and the sandbox never reach the login-protection or
email-and-phone providers: `account_takeover`, `email` and `phone` answer
`"checked": False, "why": "test"`, and `account_event` answers
`"recorded": False, "why": "test"`, so you can test the shape without using the
day's email-and-phone checks.

No account yet? The public sandbox key accepts the same test tokens:

```python
s = Sentinel(api_key="sk_test_sandbox")     # deterministic fixtures only, no live detection
```

The public sandbox is separately rate-limited, accepts only supported fixture
tokens, and does not store events or run live detection. It is not a production
allowance. A personal `sk_test_...` key runs the live pipeline with real browser
evidence and your policy (login protection, email and phone intelligence and
the account network do not run for it, and it adds nothing to `times_seen` or
`linked_accounts`, which its answers leave out); resulting events are stored with `is_test` set, kept
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

A missing or empty `token` (outside the four account events), an input the API would ignore or misread, transport/API failures and unusable success responses raise `SentinelError`.
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

Visitor checks (`evaluate()`) are counted per calendar month in UTC, with no hourly cap: **Free — 10,000 a month, no credit card**; paid plans from €29 a month ([pricing](https://maskbreak.com/pricing)). IP lookups (`lookup()`) have their own monthly allowance, 10× the plan's checks (100,000 on Free). A used-up month answers `429` with `code: "monthly_quota_exceeded"` and `Retry-After` until the 1st; there are no overage charges. The quick start's `maskbreak_check()` answers `"unchecked"` then, and lets the action through and logs it, in enforce mode too, so running out never takes your form offline.

## What Maskbreak detects

SDK-backed visits can supply VPN/proxy, cloud-hosting and Tor signals, with VPN/proxy service names when known. Available device intelligence adds browser tampering, automation, emulator and virtual-machine signals. Coverage depends on the evidence available; these are not guarantees of detecting every product or visitor. Bare-IP lookup is limited to public cloud-range and Tor evidence.

## Related

- **Node.js SDK** — [`@sentinelsup/sdk`](https://github.com/sentinelsup/maskbreak-node) on npm
- **API docs** — [maskbreak.com/api](https://maskbreak.com/api)
- **Free IP lookup tool** — [maskbreak.com/ip-lookup](https://maskbreak.com/ip-lookup)

## License

MIT © [Sentinel Edge Networks LTD](https://maskbreak.com). See [LICENSE](LICENSE).

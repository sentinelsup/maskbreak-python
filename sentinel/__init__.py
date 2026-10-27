"""
Sentinel Python SDK — thin, dependency-free wrapper around the Sentinel
fraud detection API at https://maskbreak.com/v1/evaluate.

Usage:
    from sentinel import Sentinel, SentinelError
    s = Sentinel()  # reads MASKBREAK_API_KEY from the env
    try:
        result = s.evaluate(token=request.form.get("monocle"),
                            fingerprint_event_id=request.form.get("sentinel_fp"))
    except SentinelError:
        result = None  # no token, or the call failed: apply your fallback
    if result is not None and result.is_blocked:
        abort(403)
"""

import json
import os
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, TypedDict, Union, cast
from urllib import error, parse, request

DEFAULT_ENDPOINT = "https://maskbreak.com"
DEFAULT_TIMEOUT = 5.0
__version__ = "0.4.0"

# The values ``event`` takes (login protection, since 23 October 2026). The API
# reads the name case-insensitively and ignores any other value without a word,
# so a typo such as "signin" would run the check without login protection:
# evaluate() refuses it instead (0.4.0).
_EVENTS = ("login", "signup", "password_change", "verification", "logout", "account_change")
# Account events a server reports on its own, often with no page in front of it:
# the API records them without the visit's network token. A login and a signup
# are visits and still need the token.
_TOKENLESS_EVENTS = ("password_change", "verification", "logout", "account_change")
# Keyword, JSON name, the allowed values, and what the API does with any other
# value (the reason evaluate() refuses it).
_CHOICES = (
    ("event", "event", _EVENTS,
     "the API ignores any other value, and the check would run without login protection"),
    ("reason", "reason", ("user", "forgot", "forced"), "the API reads any other value as user"),
    ("verification_type", "verificationType",
     ("email", "sms", "phone_call", "app", "push", "security_key", "captcha"),
     "the API ignores any other value"),
    ("verified_event", "verifiedEvent", ("login", "signup", "password_change", "account_change"),
     "the API ignores any other value"),
)
# The API drops a longer session ID without a word (the device then stands in
# for the session).
_MAX_SESSION_ID = 256


class MissingBrowserPartWarning(UserWarning):
    """A check was sent without ``fingerprint_event_id``, so it has no browser part.

    Shown once per process (0.4.0). Turn it off with
    ``Sentinel(warn_missing_browser_part=False)``, or with the warnings filter
    ``warnings.filterwarnings("ignore", category=MissingBrowserPartWarning)``.
    """


# Checks that arrive without the browser part (the dashboard's
# missing_device) are a broken integration that is easy to miss. Never carries
# the key or anything about the visitor.
_MISSING_BROWSER_PART = (
    "Sentinel: a check was sent without fingerprint_event_id, so Maskbreak checks it without "
    "the browser part (bots, fake browsers and emulators go unchecked): keep the script on "
    "the page with your form and forward its sentinel_fp field (or the fingerprintEventId "
    "from Sentinel.collect()) as fingerprint_event_id. Shown once per process; "
    "Sentinel(warn_missing_browser_part=False) turns it off."
)
_missing_browser_part_warned = False


def _warn_missing_browser_part() -> None:
    """Issue the missing-browser-part warning, the first time in this process only.

    warnings.warn rather than logging: Python's own advice for a library is to
    warn when the calling application should change its code, which is the case
    here, and the warnings filters (and Django's captureWarnings) already route
    it. stacklevel=3 names the line that called evaluate().
    """
    global _missing_browser_part_warned
    if _missing_browser_part_warned:
        return
    _missing_browser_part_warned = True
    warnings.warn(_MISSING_BROWSER_PART, MissingBrowserPartWarning, stacklevel=3)


def _given(value: Any) -> bool:
    """A field is sent only when given: None and "" stay out of the request."""
    return value is not None and not (isinstance(value, str) and value == "")


class _NoRedirect(request.HTTPRedirectHandler):
    """Do not forward API credentials or replay calls at a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SentinelError(Exception):
    """Raised on any Sentinel API or transport failure, and (since 0.4.0) for an
    evaluate() input the API would ignore or misread."""

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body or {}


@dataclass
class EvaluateResult:
    """Structured response from /v1/evaluate."""

    decision: Optional[str] = None
    risk_score: Optional[int] = None
    ip: Optional[str] = None
    country: Optional[str] = None
    network: Dict[str, Any] = field(default_factory=dict)
    device: Dict[str, Any] = field(default_factory=dict)
    reasons: list = field(default_factory=list)
    email: Optional[Dict[str, Any]] = None
    decision_source: Optional[str] = None
    engine_decision: Optional[str] = None
    test: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)
    # Set by the client: Sentinel(allow_test_results=True) for your own test runs.
    allow_test_results: bool = field(default=False, repr=False)
    # The account network (since 0.3.1): present when account_id was sent with a
    # live key. Last, so positional construction keeps working.
    account: Optional[Dict[str, Any]] = None
    # Since 0.4.0, after the older fields for the same reason. Login protection:
    # account_takeover for event="login" ({checked, score, risk, signals} or
    # {checked: False, why}), account_event for the other events ({event,
    # recorded} or {event, recorded: False, why}).
    account_takeover: Optional[Dict[str, Any]] = None
    account_event: Optional[Dict[str, Any]] = None
    # Email and phone intelligence: present when phone= was sent.
    phone: Optional[Dict[str, Any]] = None
    # Present when a recognised tz= was sent and the address's country is known.
    timezone: Optional[Dict[str, Any]] = None
    # True when the network part was unavailable (no token, or one that could
    # not be read): the decision then says nothing about the visitor's network.
    degraded: bool = False
    # True when the public sk_test_sandbox key answered / on sample answers.
    sandbox: bool = False
    sample: bool = False
    # "ok" | "unavailable" | "not_sent": whether the browser part was usable.
    device_evidence: Optional[str] = None
    # How old the evidence was: {network_age_s, device_age_s, device_replayed}.
    evidence: Optional[Dict[str, Any]] = None
    # Your rules and pins: present when they matched this check.
    rule_matched: Optional[List[str]] = None
    exception_matched: Optional[List[str]] = None
    evaluated_in_ms: Optional[int] = None

    @property
    def is_suspicious(self) -> bool:
        """True if the decision is anything other than 'allow'."""
        return self.decision is not None and self.decision != "allow"

    @property
    def is_fixture(self) -> bool:
        """True for a test-token, test-key, sandbox or sample answer.

        Such an answer describes a pretend visitor, never this one: the fixed
        test tokens are public, so a visitor can type one into your form field.
        Never let it authorize a real action.
        """
        return bool(self.test or self.sample or self.sandbox
                    or self.raw.get("sample") or self.raw.get("sandbox"))

    @property
    def is_blocked(self) -> bool:
        """True for a block, and (since 0.3.0) for any fixture answer unless the
        client was created with allow_test_results=True."""
        if self.is_fixture and not self.allow_test_results:
            return True
        return self.decision == "block"


class SetupWebsite(TypedDict):
    """The website the first complete check came from."""

    confirmed: bool
    origin: Optional[str]


class SetupScriptSeen(TypedDict):
    """Where and when the page script last reported in."""

    origin: str
    at: str


class SetupStatus(TypedDict):
    """The answer of ``GET /v1/setup`` (:meth:`Sentinel.setup_status`, since 0.4.0).

    ``status`` is what the latest check showed: waiting (no check in the last 7 days, and none complete before), complete
    (both parts, live key), missing_network (no network token),
    network_unavailable (a token that could not be read), missing_device (no
    browser event id), device_unavailable (a browser event that could not be
    verified), test_mode (a test token, or the test key without both parts),
    test_complete (the test key with both parts: swap in the live key),
    ip_restricted (refused by your allowed server addresses), rate_limited
    (refused by the hourly or monthly limit) or request_failed (the call
    failed, for example an invalid token).
    """

    status: Literal["waiting", "complete", "missing_network", "network_unavailable",
                    "missing_device", "device_unavailable", "test_mode", "test_complete",
                    "ip_restricted", "rate_limited", "request_failed"]
    complete: bool              # at least one complete live-key check has arrived
    message: str                # what the latest check showed, in words
    next_step: Optional[str]    # what to do next, or None
    last_check_at: Optional[str]     # ISO 8601
    complete_checks: int
    last_complete_at: Optional[str]  # ISO 8601
    website: SetupWebsite
    script_seen: Optional[SetupScriptSeen]
    site_id: Optional[str]
    key_type: Literal["live", "test"]  # which key made the call
    docs: str                   # a link to the setup guide


class Sentinel:
    """Sentinel API client. Pass an API key from https://maskbreak.com/dashboard."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_TIMEOUT,
        allow_test_results: bool = False,
        warn_missing_browser_part: bool = True,
    ) -> None:
        # MASKBREAK_API_KEY is the name every doc surface uses. SENTINEL_KEY
        # and SENTINEL_API_KEY are older names, still read so existing installs
        # keep working; the first non-empty one wins.
        api_key = (
            api_key
            or os.environ.get("MASKBREAK_API_KEY")
            or os.environ.get("SENTINEL_KEY")
            or os.environ.get("SENTINEL_API_KEY")
        )
        if not api_key or not isinstance(api_key, str):
            raise SentinelError(
                "Sentinel: api_key is required. "
                "Pass it explicitly or set MASKBREAK_API_KEY "
                "(the older SENTINEL_KEY still works). "
                "Get one free at https://maskbreak.com/signup"
            )
        # Trimmed (a key read from a file or a secret ends in a line break more
        # often than not), and never echoed: a line break left in made
        # http.client raise an error quoting the whole Authorization header,
        # and the README's handlers log the error text (0.3.0).
        api_key = api_key.strip()
        if not api_key or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in api_key):
            raise SentinelError(
                "Sentinel: the API key is empty or contains a space, a line break "
                "or another control character. Copy it again from the dashboard "
                "(Settings, API keys)."
            )
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.allow_test_results = allow_test_results is True
        # A check sent without fingerprint_event_id gets one MissingBrowserPartWarning
        # per process (0.4.0); False turns it off.
        self.warn_missing_browser_part = warn_missing_browser_part is not False

    def _request(
        self,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Shared transport: auth header, timeout, JSON parsing, error mapping."""
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = request.Request(
            f"{self.endpoint}{path}",
            data=body,
            method="POST" if payload is not None else "GET",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": f"sentinel-python/{__version__}",
            },
        )

        try:
            with request.build_opener(_NoRedirect()).open(req, timeout=self.timeout) as resp:
                try:
                    data = json.loads(resp.read().decode("utf-8"))
                except (ValueError, UnicodeError):
                    raise SentinelError("Sentinel: invalid JSON response", status=resp.status) from None
                if not isinstance(data, dict):
                    raise SentinelError("Sentinel: expected a JSON object", status=resp.status)
                return data
        except SentinelError:
            raise
        except error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
            except Exception:
                err_body = {}
            msg = err_body.get("error") if isinstance(err_body, dict) else None
            raise SentinelError(
                f"Sentinel: API returned {e.code}"
                + (f" — {msg}" if msg else ""),
                status=e.code,
                body=err_body,
            ) from None
        except error.URLError as e:
            raise SentinelError(f"Sentinel: network error — {self._scrub(e.reason)}") from None
        except Exception as e:
            raise SentinelError(f"Sentinel: unexpected error — {self._scrub(e)}") from None

    def _scrub(self, value: Any) -> str:
        """The text of an error with the API key taken out."""
        text = str(value)
        return text.replace(self.api_key, "[api key]") if self.api_key else text

    def evaluate(
        self,
        token: Optional[str] = None,
        fingerprint_event_id: Optional[str] = None,
        account_id: Optional[Union[str, int]] = None,
        email: Optional[str] = None,
        *,
        tz: Optional[str] = None,
        phone: Optional[str] = None,
        event: Optional[str] = None,
        login_succeeded: Optional[bool] = None,
        succeeded: Optional[bool] = None,
        session_id: Optional[Union[str, int]] = None,
        user_agent: Optional[str] = None,
        ip: Optional[str] = None,
        reason: Optional[str] = None,
        verification_type: Optional[str] = None,
        verified_event: Optional[str] = None,
    ) -> EvaluateResult:
        """Evaluate a visitor session for fraud signals.

        Every argument but ``token`` is optional and sent (under the API's
        camelCase name) only when given: None and "" stay out of the request.
        The keyword-only arguments are new in 0.4.0.

        Args:
            token: Sentinel client-side token from the frontend SDK. Required,
                except for the account events password_change, verification,
                logout and account_change (0.4.0).
            fingerprint_event_id: Optional device event id for device signals.
                Without it the check has no browser part, and the SDK warns once
                (see ``warn_missing_browser_part``).
            account_id: Optional account/user id, from your server-side session
                (never a form field) — enables multi-accounting detection
                (device.linked_accounts / device.multi_account) and, with a live
                key, the ``account`` object (account network). Login protection
                needs it with ``event``.
            email: Optional signup email. Adds ``email.disposable`` to the raw
                response (burner domains escalate allow to review); with email
                and phone intelligence on, also checked, score, risk and
                signals. Never stored or logged.
            tz: The visitor's IANA time zone (``tz`` from Sentinel.collect(), or
                the form's sentinel_tz field). Adds ``timezone`` when recognised.
            phone: The visitor's phone number in international format. With email
                and phone intelligence on, adds the ``phone`` object with a score.
                Never stored or logged.
            event: Login protection: "login" adds ``account_takeover`` with a
                score; "signup", "password_change", "verification", "logout" and
                "account_change" add ``account_event``. Read case-insensitively.
            login_succeeded: With event "login": whether the password (or other
                credential) was right. Send failed attempts too.
            succeeded: With event "password_change" or "verification": whether it
                succeeded (absent means pending).
            session_id: With an event: your own session ID (a string or an int, at
                most 256 characters). Only a keyed hash of it leaves Maskbreak.
            user_agent: With an event: the visitor's User-Agent header as your
                server received it.
            ip: With an event: the visitor's address as your server saw it, used
                only when the network token gave none.
            reason: With event "password_change": "user", "forgot" or "forced".
            verification_type: With event "verification": "email", "sms",
                "phone_call", "app", "push", "security_key" or "captcha".
            verified_event: With event "verification": "login", "signup",
                "password_change" or "account_change".

        Returns:
            EvaluateResult with decision, risk_score, network, device, and reasons.

        Raises:
            SentinelError: on a missing or empty token (outside the four account
                events), a value the API would ignore or misread (an unknown
                event, a non-bool login_succeeded, ...; nothing is sent then),
                network failure, timeout, a non-2xx response, or a response
                without a valid decision.
        """
        choices = {"event": event, "reason": reason, "verification_type": verification_type,
                   "verified_event": verified_event}
        picked: Dict[str, str] = {}
        for keyword, name, allowed, otherwise in _CHOICES:
            value = choices[keyword]
            if not _given(value):
                continue
            norm = value.strip().lower() if isinstance(value, str) else None
            if norm is None or norm not in allowed:
                raise SentinelError(
                    f"Sentinel.evaluate: {keyword} must be one of {', '.join(allowed)}; {otherwise}."
                )
            picked[name] = norm

        account_event = picked.get("event") in _TOKENLESS_EVENTS
        if not _given(token) and not account_event:
            raise SentinelError(
                "Sentinel.evaluate: token (client-side Sentinel token) is required "
                "(only the account events password_change, verification, logout and "
                "account_change can be sent without it)"
            )
        if _given(token) and not isinstance(token, str):
            raise SentinelError("Sentinel.evaluate: token (client-side Sentinel token) must be a string")

        payload: Dict[str, Any] = {}
        if _given(token):
            payload["token"] = token
        if fingerprint_event_id:
            payload["fingerprintEventId"] = fingerprint_event_id
        if account_id:
            payload["accountId"] = account_id
        if email:
            payload["email"] = email
        for keyword, name, text in (("tz", "tz", tz), ("phone", "phone", phone),
                                    ("user_agent", "userAgent", user_agent), ("ip", "ip", ip)):
            if not _given(text):
                continue
            if not isinstance(text, str):
                raise SentinelError(f"Sentinel.evaluate: {keyword} must be a string.")
            payload[name] = text
        if "event" in picked:
            payload["event"] = picked["event"]
        for keyword, name, flag in (("login_succeeded", "loginSucceeded", login_succeeded),
                                    ("succeeded", "succeeded", succeeded)):
            if not _given(flag):
                continue
            if not isinstance(flag, bool):
                raise SentinelError(f"Sentinel.evaluate: {keyword} must be True or False.")
            payload[name] = flag
        if _given(session_id):
            if (not isinstance(session_id, (str, int)) or isinstance(session_id, bool)
                    or len(str(session_id).strip()) > _MAX_SESSION_ID):
                raise SentinelError(
                    f"Sentinel.evaluate: session_id must be a string or an int of at most "
                    f"{_MAX_SESSION_ID} characters; for a longer session value, send a shorter "
                    "ID for the session (a hash of it, for example)."
                )
            payload["sessionId"] = session_id
        for name in ("reason", "verificationType", "verifiedEvent"):
            if name in picked:
                payload[name] = picked[name]

        # Account events may come from server code with no page in front of
        # them, and the fixed test_* tokens never carry a browser part; anything
        # else without it is a broken integration, said once.
        if (self.warn_missing_browser_part and not account_event and not fingerprint_event_id
                and not (isinstance(token, str) and token.startswith("test_"))):
            _warn_missing_browser_part()

        data = self._request("/v1/evaluate", payload)
        if data.get("decision") not in ("allow", "review", "block"):
            raise SentinelError("Sentinel: invalid or missing evaluation decision", body=data)

        return EvaluateResult(
            decision=data.get("decision"),
            risk_score=data.get("risk_score"),
            ip=data.get("ip"),
            country=data.get("country"),
            network=data.get("network") or {},
            device=data.get("device") or {},
            reasons=data.get("reasons") or [],
            email=data.get("email"),
            decision_source=data.get("decision_source"),
            engine_decision=data.get("engine_decision"),
            test=bool(data.get("test")),
            raw=data,
            allow_test_results=self.allow_test_results,
            account=data.get("account"),
            account_takeover=data.get("account_takeover"),
            account_event=data.get("account_event"),
            phone=data.get("phone"),
            timezone=data.get("timezone"),
            degraded=bool(data.get("degraded")),
            sandbox=bool(data.get("sandbox")),
            sample=bool(data.get("sample")),
            device_evidence=data.get("device_evidence"),
            evidence=data.get("evidence"),
            rule_matched=data.get("rule_matched"),
            exception_matched=data.get("exception_matched"),
            evaluated_in_ms=data.get("evaluated_in_ms"),
        )

    def lookup(self, ip: str) -> Dict[str, Any]:
        """Look up an arbitrary public IP address — no browser token needed.

        Wraps ``GET /v1/lookup/{ip}``. Useful for batch scoring, log
        enrichment, and server-side screening. Shares the hourly quota
        with :meth:`evaluate` (one per account for the live keys; the test key
        has its own) and has its own monthly allowance.

        Args:
            ip: Public IPv4 or IPv6 address, e.g. ``"185.220.101.34"``.

        Returns:
            The raw response dict: ``verdict`` ('allow' | 'review' | 'block'),
            ``risk_score`` (0-100), ``known``, ``signals``
            ({vpn, proxied, tor, dch, anon} or None), ``network``
            ({asn, org, country, city}), ``latency_ms``. Note ``known: False``
            means our feeds hold no data for the IP — it is NOT a clean
            guarantee.

        Raises:
            SentinelError: on network failure, timeout, or non-2xx response.
        """
        if not isinstance(ip, str) or not ip.strip():
            raise SentinelError(
                "Sentinel.lookup: ip (public IPv4 or IPv6 address) is required"
            )
        return self._request(f"/v1/lookup/{parse.quote(ip.strip(), safe='')}")

    def setup_status(self) -> SetupStatus:
        """Whether your integration's checks arrive complete, and what to fix next.

        Wraps ``GET /v1/setup`` (since 0.4.0). Submit your form once, then call
        it: it says whether that check arrived with both parts and, when not,
        what to change. Works with the live key and the test key.

        Returns:
            The answer as the API sends it (a dict): ``status``, ``complete``,
            ``message``, ``next_step``, ``last_check_at``, ``complete_checks``,
            ``last_complete_at``, ``website``, ``script_seen``, ``site_id``,
            ``key_type`` and ``docs``. See :class:`SetupStatus`.

        Raises:
            SentinelError: on network failure, timeout, or a non-2xx response.
        """
        return cast(SetupStatus, self._request("/v1/setup"))


__all__ = ["Sentinel", "SentinelError", "EvaluateResult", "MissingBrowserPartWarning",
           "SetupStatus", "__version__"]

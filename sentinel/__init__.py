"""
Sentinel Python SDK — thin, dependency-free wrapper around the Sentinel
fraud detection API at https://maskbreak.com/v1/evaluate.

Usage:
    from sentinel import Sentinel, SentinelError
    s = Sentinel()  # reads MASKBREAK_API_KEY from the env
    try:
        result = s.evaluate(token=request.form.get("monocle"))
    except SentinelError:
        result = None  # no token, or the call failed: apply your fallback
    if result is not None and result.is_blocked:
        abort(403)
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib import error, parse, request

DEFAULT_ENDPOINT = "https://maskbreak.com"
DEFAULT_TIMEOUT = 5.0
__version__ = "0.3.0"


class _NoRedirect(request.HTTPRedirectHandler):
    """Do not forward API credentials or replay calls at a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SentinelError(Exception):
    """Raised on any Sentinel API or transport failure."""

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
        return bool(self.test or self.raw.get("sample") or self.raw.get("sandbox"))

    @property
    def is_blocked(self) -> bool:
        """True for a block, and (since 0.3.0) for any fixture answer unless the
        client was created with allow_test_results=True."""
        if self.is_fixture and not self.allow_test_results:
            return True
        return self.decision == "block"


class Sentinel:
    """Sentinel API client. Pass an API key from https://maskbreak.com/dashboard."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_TIMEOUT,
        allow_test_results: bool = False,
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
        token: str,
        fingerprint_event_id: Optional[str] = None,
        account_id: Optional[str] = None,
        email: Optional[str] = None,
    ) -> EvaluateResult:
        """Evaluate a visitor session for fraud signals.

        Args:
            token: Sentinel client-side token from the frontend SDK.
            fingerprint_event_id: Optional device event id for device signals.
            account_id: Optional account/user id — enables multi-accounting
                detection (device.linked_accounts / device.multi_account).
            email: Optional signup email. Adds ``email.disposable`` to the raw
                response (burner domains escalate allow to review). Checked
                transiently — never stored or logged.

        Returns:
            EvaluateResult with decision, risk_score, network, device, and reasons.

        Raises:
            SentinelError: on a missing or empty token, network failure, timeout, a
                non-2xx response, or a response without a valid decision.
        """
        if not token or not isinstance(token, str):
            raise SentinelError(
                "Sentinel.evaluate: token (client-side Sentinel token) is required"
            )

        payload: Dict[str, Any] = {"token": token}
        if fingerprint_event_id:
            payload["fingerprintEventId"] = fingerprint_event_id
        if account_id:
            payload["accountId"] = account_id
        if email:
            payload["email"] = email

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


__all__ = ["Sentinel", "SentinelError", "EvaluateResult", "__version__"]

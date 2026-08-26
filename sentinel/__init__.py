"""
Sentinel Python SDK — thin, dependency-free wrapper around the Sentinel
fraud detection API at https://maskbreak.com/v1/evaluate.

Usage:
    from sentinel import Sentinel
    s = Sentinel()  # reads SENTINEL_KEY or SENTINEL_API_KEY from the env
    result = s.evaluate(token=request.json["sentinelToken"])
    if result.is_blocked:
        abort(403)
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib import error, parse, request

DEFAULT_ENDPOINT = "https://maskbreak.com"
DEFAULT_TIMEOUT = 5.0
__version__ = "0.2.1"


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

    @property
    def is_suspicious(self) -> bool:
        """True if the decision is anything other than 'allow'."""
        return self.decision is not None and self.decision != "allow"

    @property
    def is_blocked(self) -> bool:
        return self.decision == "block"


class Sentinel:
    """Sentinel API client. Pass an API key from https://maskbreak.com/dashboard."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        # SENTINEL_KEY is the name every doc surface uses; SENTINEL_API_KEY
        # is kept for existing installs that already adopted it.
        api_key = api_key or os.environ.get("SENTINEL_KEY") or os.environ.get("SENTINEL_API_KEY")
        if not api_key or not isinstance(api_key, str):
            raise SentinelError(
                "Sentinel: api_key is required. "
                "Pass it explicitly or set SENTINEL_KEY. "
                "Get one free at https://maskbreak.com/signup"
            )
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

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
            with request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
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
            raise SentinelError(f"Sentinel: network error — {e.reason}") from None
        except Exception as e:
            raise SentinelError(f"Sentinel: unexpected error — {e}") from None

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
            fingerprint_event_id: Optional Fingerprint event id for device signals.
            account_id: Optional account/user id — enables multi-accounting
                detection (device.linked_accounts / device.multi_account).
            email: Optional signup email. Adds ``email.disposable`` to the raw
                response (burner domains escalate allow to review). Checked
                transiently — never stored or logged.

        Returns:
            EvaluateResult with decision, risk_score, network, device, and reasons.

        Raises:
            SentinelError: on network failure, timeout, or non-2xx response.
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
        )

    def lookup(self, ip: str) -> Dict[str, Any]:
        """Look up an arbitrary public IP address — no browser token needed.

        Wraps ``GET /v1/lookup/{ip}``. Useful for batch scoring, log
        enrichment, and server-side screening. Shares the per-key hourly
        quota with :meth:`evaluate`.

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
        if not ip or not isinstance(ip, str):
            raise SentinelError(
                "Sentinel.lookup: ip (public IPv4 or IPv6 address) is required"
            )
        return self._request(f"/v1/lookup/{parse.quote(ip.strip(), safe='')}")


__all__ = ["Sentinel", "SentinelError", "EvaluateResult", "__version__"]

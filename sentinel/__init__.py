"""
Sentinel Python SDK — thin, dependency-free wrapper around the Sentinel
fraud detection API at https://sntlhq.com/v1/evaluate.

Usage:
    from sentinel import Sentinel
    s = Sentinel(api_key=os.environ["SENTINEL_KEY"])
    result = s.evaluate(token=request.json["sentinelToken"])
    if result.is_suspicious:
        abort(403)
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib import error, request

DEFAULT_ENDPOINT = "https://sntlhq.com"
DEFAULT_TIMEOUT = 5.0
__version__ = "0.1.0"


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
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    network: Dict[str, Any] = field(default_factory=dict)
    device: Dict[str, Any] = field(default_factory=dict)
    reasons: list = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_suspicious(self) -> bool:
        """True if the decision is anything other than 'allow'."""
        return self.decision is not None and self.decision != "allow"

    @property
    def is_blocked(self) -> bool:
        return self.decision == "block"


class Sentinel:
    """Sentinel API client. Pass an API key from https://sntlhq.com/dashboard."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        api_key = api_key or os.environ.get("SENTINEL_API_KEY")
        if not api_key or not isinstance(api_key, str):
            raise SentinelError(
                "Sentinel: api_key is required. "
                "Pass it explicitly or set SENTINEL_API_KEY. "
                "Get one free at https://sntlhq.com/signup"
            )
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    def evaluate(
        self,
        token: str,
        fingerprint_event_id: Optional[str] = None,
    ) -> EvaluateResult:
        """Evaluate a visitor session for fraud signals.

        Args:
            token: Sentinel client-side token from the frontend SDK.
            fingerprint_event_id: Optional Fingerprint event id for device signals.

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

        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.endpoint}/v1/evaluate",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": f"sentinel-python/{__version__}",
            },
        )

        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw) if raw else {}
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

        return EvaluateResult(
            decision=data.get("decision"),
            risk_score=data.get("risk_score"),
            ip=data.get("ip"),
            country=data.get("country"),
            asn=data.get("asn"),
            asn_org=data.get("asn_org"),
            network=data.get("network") or {},
            device=data.get("device") or {},
            reasons=data.get("reasons") or [],
            raw=data,
        )


__all__ = ["Sentinel", "SentinelError", "EvaluateResult", "__version__"]

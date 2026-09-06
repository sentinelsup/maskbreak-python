"""Django middleware example — score every request to high-value endpoints.

Add to settings.py MIDDLEWARE:
    "yourapp.middleware.SentinelMiddleware",

Then ensure your frontend forwards the Sentinel token via the
X-Sentinel-Token header, and the device event ID via
X-Sentinel-Fingerprint-Event-Id. Only a live, non-degraded allow decision reaches
the guarded view; test/sample/sandbox results and review require a separate
verification flow. This is a middleware example,
not that verification flow's implementation.
"""

import logging

from django.http import JsonResponse

from sentinel import Sentinel, SentinelError

log = logging.getLogger(__name__)
_GUARDED_PATHS = ("/api/checkout", "/api/withdraw", "/api/transfer")


class SentinelMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.sentinel = Sentinel()  # reads SENTINEL_KEY, with legacy fallback

    def __call__(self, request):
        if not request.path.startswith(_GUARDED_PATHS):
            return self.get_response(request)

        token = request.META.get("HTTP_X_SENTINEL_TOKEN")
        if not token:
            return JsonResponse({"error": "missing X-Sentinel-Token"}, status=400)

        try:
            result = self.sentinel.evaluate(token=token,
                fingerprint_event_id=request.META.get("HTTP_X_SENTINEL_FINGERPRINT_EVENT_ID"))
        except SentinelError as e:
            log.warning("Sentinel error: %s", e)
            # Unknown state must not authorize checkout, withdrawal or transfer.
            return JsonResponse({"error": "verification unavailable"}, status=503)

        if result.is_blocked:
            return JsonResponse(
                {"error": "blocked", "risk_score": result.risk_score, "reasons": result.reasons},
                status=403,
            )

        if (result.decision != "allow" or result.test or
                any(result.raw.get(flag) for flag in ("test", "sample", "sandbox", "degraded"))):
            return JsonResponse({"error": "additional verification required"}, status=409)

        # Stash on request so the view can read decision/score
        request.sentinel = result
        return self.get_response(request)

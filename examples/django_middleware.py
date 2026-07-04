"""Django middleware example — score every request to high-value endpoints.

Add to settings.py MIDDLEWARE:
    "yourapp.middleware.SentinelMiddleware",

Then ensure your frontend forwards the Sentinel token via the
X-Sentinel-Token header (set after the SDK injects it on the client).
"""

import logging

from django.http import JsonResponse

from sentinel import Sentinel, SentinelError

log = logging.getLogger(__name__)
_GUARDED_PATHS = ("/api/checkout", "/api/withdraw", "/api/transfer")


class SentinelMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.sentinel = Sentinel()  # reads SENTINEL_API_KEY

    def __call__(self, request):
        if not request.path.startswith(_GUARDED_PATHS):
            return self.get_response(request)

        token = request.META.get("HTTP_X_SENTINEL_TOKEN")
        if not token:
            return JsonResponse({"error": "missing X-Sentinel-Token"}, status=400)

        try:
            result = self.sentinel.evaluate(token=token)
        except SentinelError as e:
            log.warning("Sentinel error: %s", e)
            # Fail open on infra problems; switch to fail-closed for finance flows.
            return self.get_response(request)

        if result.is_blocked:
            return JsonResponse(
                {"error": "blocked", "risk_score": result.risk_score, "reasons": result.reasons},
                status=403,
            )

        # Stash on request so the view can read decision/score
        request.sentinel = result
        return self.get_response(request)

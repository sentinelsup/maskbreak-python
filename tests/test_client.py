"""Standard-library regression tests; all HTTP traffic stays on loopback."""

import json
import os
import runpy
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from sentinel import EvaluateResult, Sentinel, SentinelError


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.calls.append((self.command, self.path, dict(self.headers), body))
        status, response, headers = self.server.reply
        if self.path == "/redirect-target":
            status, response, headers = 200, b'{"decision":"allow"}', {}
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    do_POST = do_GET


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.calls = []
        self.server.reply = (200, b'{"decision":"review","future_field":true}', {})
        self.client = Sentinel("sk_test_fixture", "http://127.0.0.1:%d" % self.server.server_port)

    def test_evaluate_forwards_fields_and_preserves_additive_response(self):
        result = self.client.evaluate("fixture", "device-event", "account", "a@example.test")
        method, path, headers, body = self.server.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/evaluate"))
        self.assertEqual(headers["Authorization"], "Bearer sk_test_fixture")
        self.assertEqual(json.loads(body), {"token": "fixture", "fingerprintEventId": "device-event",
                                            "accountId": "account", "email": "a@example.test"})
        self.assertEqual(result.decision, "review")
        self.assertFalse(result.is_blocked)
        self.assertTrue(result.is_suspicious)
        self.assertTrue(result.raw["future_field"])

    def test_lookup_trims_and_encodes_ipv6_without_body(self):
        self.server.reply = (200, b'{"verdict":"allow","known":false}', {})
        self.assertFalse(self.client.lookup(" 2001:db8::1 ")["known"])
        method, path, _, body = self.server.calls[0]
        self.assertEqual((method, path, body), ("GET", "/v1/lookup/2001%3Adb8%3A%3A1", b""))

    def test_blank_lookup_and_missing_token_do_not_send(self):
        with self.assertRaises(SentinelError):
            self.client.lookup("  ")
        with self.assertRaises(SentinelError):
            self.client.evaluate("")
        self.assertEqual(self.server.calls, [])

    def test_invalid_success_bodies_raise_sdk_error(self):
        for body in (b"", b"<html>gateway</html>", b"null", b"[]", b'"text"', b"42"):
            with self.subTest(body=body):
                self.server.reply = (200, body, {})
                with self.assertRaises(SentinelError) as caught:
                    self.client.evaluate("fixture")
                self.assertEqual(caught.exception.status, 200)

    def test_missing_or_invalid_decisions_are_not_success(self):
        for data in ({}, {"decision": None}, {"decision": "unexpected"}, {"decision": []}):
            with self.subTest(data=data):
                self.server.reply = (200, json.dumps(data).encode(), {})
                with self.assertRaisesRegex(SentinelError, "evaluation decision"):
                    self.client.evaluate("fixture")

    def test_api_errors_preserve_status_and_object_body(self):
        self.server.reply = (429, b'{"error":"Try later"}', {})
        with self.assertRaises(SentinelError) as caught:
            self.client.evaluate("fixture")
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(caught.exception.body, {"error": "Try later"})

    def test_redirect_does_not_forward_key_or_replay_request(self):
        target = "http://localhost:%d/redirect-target" % self.server.server_port
        self.server.reply = (302, b'{}', {"Location": target})
        with self.assertRaises(SentinelError) as caught:
            self.client.lookup("203.0.113.1")
        self.assertEqual(caught.exception.status, 302)
        self.assertEqual(len(self.server.calls), 1, "redirect target must not receive the API key")

    def test_environment_key_precedence(self):
        with patch.dict(os.environ, {"SENTINEL_KEY": "primary", "SENTINEL_API_KEY": "legacy"}):
            self.assertEqual(Sentinel().api_key, "primary")
            self.assertEqual(Sentinel("explicit").api_key, "explicit")
            os.environ.pop("SENTINEL_KEY")
            self.assertEqual(Sentinel().api_key, "legacy")

    def test_result_helpers_keep_review_distinct_from_block(self):
        for decision in ("allow", "review", "block"):
            result = EvaluateResult(decision=decision)
            self.assertEqual(result.is_blocked, decision == "block")
            self.assertEqual(result.is_suspicious, decision != "allow")


class DjangoGuardTests(unittest.TestCase):
    def test_financial_guard_requires_live_complete_allow_before_view(self):
        http = ModuleType("django.http")
        http.JsonResponse = lambda body, status: SimpleNamespace(status_code=status)
        with patch.dict(sys.modules, {"django": ModuleType("django"), "django.http": http}):
            example = runpy.run_path(str(Path(__file__).resolve().parents[1] / "examples" / "django_middleware.py"))
        for decision, flag, status in [("allow", None, 200), ("review", None, 409), ("block", None, 403)] + [
            ("allow", flag, 409) for flag in ("test", "sample", "sandbox", "degraded")
        ]:
            with self.subTest(decision=decision, flag=flag):
                view = Mock(return_value=SimpleNamespace(status_code=200))
                with patch.dict(os.environ, {"SENTINEL_KEY": "sk_test_fixture"}):
                    middleware = example["SentinelMiddleware"](view)
                middleware.sentinel = Mock()
                middleware.sentinel.evaluate.return_value = EvaluateResult(
                    decision=decision, test=flag == "test", raw={flag: True} if flag else {})
                request = SimpleNamespace(path="/api/transfer", META={
                    "HTTP_X_SENTINEL_TOKEN": "fixture", "HTTP_X_SENTINEL_FINGERPRINT_EVENT_ID": "device-event"})
                self.assertEqual(middleware(request).status_code, status)
                self.assertEqual(view.call_count, 1 if status == 200 else 0)
                middleware.sentinel.evaluate.assert_called_once_with(token="fixture", fingerprint_event_id="device-event")


if __name__ == "__main__":
    unittest.main()

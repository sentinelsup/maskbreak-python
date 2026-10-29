"""Standard-library regression tests; all HTTP traffic stays on loopback."""

import json
import os
import re
import runpy
import sys
import threading
import unittest
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

import sentinel as sentinel_module
from sentinel import EvaluateResult, MissingBrowserPartWarning, Sentinel, SentinelError


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
        self.assertIsNone(result.account, "no account object unless the API sends one")

    def test_the_account_network_answer_is_a_field(self):
        self.server.reply = (200, b'{"decision":"review","reasons":["device_many_accounts"],'
                                  b'"account":{"seen_before":true,"device_accounts_24h":3}}', {})
        result = self.client.evaluate("fixture", "device-event", "account")
        self.assertEqual(result.account, {"seen_before": True, "device_accounts_24h": 3})
        self.assertEqual(result.reasons, ["device_many_accounts"])

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
        env = {"MASKBREAK_API_KEY": "current", "SENTINEL_KEY": "primary", "SENTINEL_API_KEY": "legacy"}
        with patch.dict(os.environ, env):
            self.assertEqual(Sentinel().api_key, "current")
            self.assertEqual(Sentinel("explicit").api_key, "explicit")
            os.environ.pop("MASKBREAK_API_KEY")
            self.assertEqual(Sentinel().api_key, "primary")
            os.environ.pop("SENTINEL_KEY")
            self.assertEqual(Sentinel().api_key, "legacy")

    def test_environment_key_new_name_alone(self):
        with patch.dict(os.environ, {"MASKBREAK_API_KEY": "current"}):
            for old in ("SENTINEL_KEY", "SENTINEL_API_KEY"):
                os.environ.pop(old, None)
            self.assertEqual(Sentinel().api_key, "current")

    def test_missing_key_names_the_current_variable(self):
        with patch.dict(os.environ, {}):
            for name in ("MASKBREAK_API_KEY", "SENTINEL_KEY", "SENTINEL_API_KEY"):
                os.environ.pop(name, None)
            with self.assertRaises(SentinelError) as caught:
                Sentinel()
            self.assertIn("MASKBREAK_API_KEY", str(caught.exception))

    def test_result_helpers_keep_review_distinct_from_block(self):
        for decision in ("allow", "review", "block"):
            result = EvaluateResult(decision=decision)
            self.assertEqual(result.is_blocked, decision == "block")
            self.assertEqual(result.is_suspicious, decision != "allow")


class FixtureAndKeyTests(unittest.TestCase):
    """0.3.0: a public test token never reads as an allow, and the key never reaches an error."""

    def test_fixture_answers_are_blocked_unless_the_client_allows_test_results(self):
        for marker in ("test", "sample", "sandbox"):
            raw = {"decision": "allow", marker: True}
            result = EvaluateResult(decision="allow", test=marker == "test", raw=raw)
            self.assertTrue(result.is_fixture, marker)
            self.assertTrue(result.is_blocked, marker)
        own = EvaluateResult(decision="allow", test=True, raw={"test": True}, allow_test_results=True)
        self.assertFalse(own.is_blocked)
        plain = EvaluateResult(decision="allow", raw={})
        self.assertFalse(plain.is_fixture)
        self.assertFalse(plain.is_blocked)

    def test_the_key_is_trimmed_and_a_key_with_a_break_inside_is_refused_without_echo(self):
        self.assertEqual(Sentinel("  sk_live_abc\n").api_key, "sk_live_abc")
        for bad in ("sk_live_a\nb", "sk_live_a b", "sk_live_a\x00b", "   "):
            with self.assertRaises(SentinelError) as caught:
                Sentinel(bad)
            self.assertNotIn("sk_live_a", str(caught.exception))

    def test_no_error_text_carries_the_key(self):
        client = Sentinel("sk_live_secret_value_123", "http://127.0.0.1:9")
        boom = ValueError("Invalid header value b'Bearer sk_live_secret_value_123'")
        with patch("sentinel.request.OpenerDirector.open", side_effect=boom):
            with self.assertRaises(SentinelError) as caught:
                client.lookup("8.8.8.8")
        self.assertNotIn("sk_live_secret_value_123", str(caught.exception))
        self.assertIn("[api key]", str(caught.exception))


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
                with patch.dict(os.environ, {"MASKBREAK_API_KEY": "sk_test_fixture"}):
                    middleware = example["SentinelMiddleware"](view)
                middleware.sentinel = Mock()
                middleware.sentinel.evaluate.return_value = EvaluateResult(
                    decision=decision, test=flag == "test", raw={flag: True} if flag else {})
                request = SimpleNamespace(path="/api/transfer", META={
                    "HTTP_X_SENTINEL_TOKEN": "fixture", "HTTP_X_SENTINEL_FINGERPRINT_EVENT_ID": "device-event"})
                self.assertEqual(middleware(request).status_code, status)
                self.assertEqual(view.call_count, 1 if status == 200 else 0)
                middleware.sentinel.evaluate.assert_called_once_with(token="fixture", fingerprint_event_id="device-event")


class LoginProtectionFieldTests(unittest.TestCase):
    """0.4.0: tz, phone and the login-protection fields, sent under the API's names."""

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
        self.server.reply = (200, b'{"decision":"allow"}', {})
        self.client = Sentinel("sk_live_fields", "http://127.0.0.1:%d" % self.server.server_port,
                               warn_missing_browser_part=False)

    def body(self, index=-1):
        return json.loads(self.server.calls[index][3])

    def test_each_new_field_is_sent_under_its_api_name_only_when_given(self):
        self.client.evaluate("tok", "evt", "u_42", "a@example.com", tz="Europe/Tallinn",
                             phone="+44 20 7946 0958", event="login", login_succeeded=True,
                             succeeded=False, session_id="sess_1", user_agent="Mozilla/5.0 (X11)",
                             ip="81.20.33.4", reason="forgot", verification_type="sms",
                             verified_event="login")
        self.assertEqual(self.body(), {
            "token": "tok", "fingerprintEventId": "evt", "accountId": "u_42", "email": "a@example.com",
            "tz": "Europe/Tallinn", "phone": "+44 20 7946 0958", "event": "login", "loginSucceeded": True,
            "succeeded": False, "sessionId": "sess_1", "userAgent": "Mozilla/5.0 (X11)", "ip": "81.20.33.4",
            "reason": "forgot", "verificationType": "sms", "verifiedEvent": "login"})
        # Nothing given: None and "" stay out.
        self.client.evaluate("tok", "evt", tz=None, phone="", event="", session_id="", user_agent=None,
                             login_succeeded="", succeeded=None)
        self.assertEqual(self.body(), {"token": "tok", "fingerprintEventId": "evt"})
        # False is an answer, so it is sent; an int session ID too.
        self.client.evaluate("tok", "evt", event="login", login_succeeded=False, session_id=7)
        self.assertEqual(self.body(), {"token": "tok", "fingerprintEventId": "evt", "event": "login",
                                       "loginSucceeded": False, "sessionId": 7})

    def test_fixed_list_fields_are_read_like_the_api_reads_them(self):
        self.client.evaluate("tok", "evt", event=" Password_Change ", reason="FORGOT",
                             verification_type="Security_Key", verified_event="SignUp")
        self.assertEqual(self.body(), {"token": "tok", "fingerprintEventId": "evt", "event": "password_change",
                                       "reason": "forgot", "verificationType": "security_key",
                                       "verifiedEvent": "signup"})

    def test_values_the_api_would_ignore_or_misread_are_refused_before_sending(self):
        cases = [
            (dict(event="signin"), r"event must be one of login, signup, password_change, verification, logout, account_change; the API ignores any other value"),
            (dict(event=42), r"event must be one of"),
            (dict(event="login", reason="expired"), r"reason must be one of user, forgot, forced; the API reads any other value as user"),
            (dict(event="verification", verification_type="totp"), r"verification_type must be one of email, sms, phone_call, app, push, security_key, captcha"),
            (dict(event="verification", verified_event="checkout"), r"verified_event must be one of login, signup, password_change, account_change"),
            (dict(event="login", login_succeeded="true"), r"login_succeeded must be True or False"),
            (dict(event="password_change", succeeded=1), r"succeeded must be True or False"),
            (dict(tz=3), r"tz must be a string"),
            (dict(phone=4420794609), r"phone must be a string"),
            (dict(event="login", user_agent=["Mozilla"]), r"user_agent must be a string"),
            (dict(event="login", ip=("81.20.33.4",)), r"ip must be a string"),
            (dict(event="login", session_id="x" * 257), r"session_id must be a string or an int of at most 256 characters"),
            (dict(event="login", session_id=True), r"session_id must be"),
            (dict(event="login", session_id=1.5), r"session_id must be"),
        ]
        for extra, message in cases:
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(SentinelError, message):
                    self.client.evaluate("tok", "evt", **extra)
        self.assertEqual(self.server.calls, [], "nothing reached the API")
        self.client.evaluate("tok", "evt", event="login", session_id="x" * 256)
        self.assertEqual(len(self.server.calls), 1, "256 characters is still fine")

    def test_the_four_account_events_go_without_a_token(self):
        for event in ("password_change", "verification", "logout", "account_change"):
            with self.subTest(event=event):
                self.client.evaluate(event=event, account_id="u_42")
                self.assertEqual(self.body(), {"accountId": "u_42", "event": event})
                self.client.evaluate("tok", event=event, account_id="u_42")
                self.assertEqual(self.body(), {"token": "tok", "accountId": "u_42", "event": event})
                with self.assertRaisesRegex(SentinelError, r"token \(client-side Sentinel token\) must be a string"):
                    self.client.evaluate(12345, event=event, account_id="u_42")

    def test_a_login_a_signup_and_a_plain_check_still_need_the_token(self):
        for kwargs in (dict(event="login", account_id="u"), dict(event="signup", account_id="u"),
                       dict(), dict(account_id="u"), dict(token="", event="login")):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(SentinelError, r"token \(client-side Sentinel token\) is required \(only the account events password_change, verification, logout and account_change can be sent without it\)"):
                    self.client.evaluate(**kwargs)
        self.assertEqual(self.server.calls, [])

    def test_the_new_answer_fields_land_on_the_result(self):
        answer = {"decision": "review", "reasons": ["account_takeover_risk", "phone_high_risk"], "degraded": True,
                  "account_takeover": {"checked": True, "score": 91, "risk": "high", "signals": ["new_location"]},
                  "email": {"disposable": False, "checked": False, "why": "quota"},
                  "phone": {"checked": True, "score": 89, "risk": "high", "signals": ["invalid"]},
                  "timezone": {"reported": "Europe/Tallinn", "country": "EE", "matches_ip": True, "checked": True},
                  "device_evidence": "not_sent", "evidence": {"network_age_s": 3}, "rule_matched": ["vpn"],
                  "evaluated_in_ms": 28}
        self.server.reply = (200, json.dumps(answer).encode(), {})
        result = self.client.evaluate("tok", "evt", event="login", account_id="u")
        self.assertEqual(result.account_takeover, answer["account_takeover"])
        self.assertEqual(result.email, answer["email"])
        self.assertEqual(result.phone, answer["phone"])
        self.assertEqual(result.timezone, answer["timezone"])
        self.assertTrue(result.degraded)
        self.assertEqual((result.device_evidence, result.evidence, result.rule_matched, result.exception_matched,
                          result.evaluated_in_ms), ("not_sent", {"network_age_s": 3}, ["vpn"], None, 28))
        self.assertIsNone(result.account_event)
        self.server.reply = (200, b'{"decision":"allow","degraded":true,"account_event":{"event":"logout","recorded":true}}', {})
        logout = self.client.evaluate(event="logout", account_id="u")
        self.assertEqual(logout.account_event, {"event": "logout", "recorded": True})
        self.assertEqual((logout.account_takeover, logout.phone, logout.timezone, logout.sandbox, logout.sample),
                         (None, None, None, False, False))
        # A sandbox or sample answer is a fixture through the new fields too.
        self.server.reply = (200, b'{"decision":"allow","sandbox":true,"test":true}', {})
        sandbox = self.client.evaluate("test_clean")
        self.assertTrue(sandbox.sandbox)
        self.assertTrue(sandbox.is_fixture)
        self.assertTrue(EvaluateResult(decision="allow", sample=True).is_blocked)

    def test_setup_status_gets_v1_setup_with_the_key_and_returns_the_answer_as_is(self):
        answer = {"status": "missing_device", "complete": False, "message": "A check arrived, but the browser part is missing.",
                  "next_step": "Send sentinel_fp as fingerprintEventId.", "last_check_at": "2026-10-27T10:00:00.000Z",
                  "complete_checks": 0, "last_complete_at": None, "website": {"confirmed": False, "origin": None},
                  "script_seen": {"origin": "https://shop.example", "at": "2026-10-27T09:59:00.000Z"},
                  "site_id": "site_0123456789abcdef", "key_type": "live", "docs": "https://maskbreak.com/integrate.md",
                  "future_field": 1}
        self.server.reply = (200, json.dumps(answer).encode(), {})
        self.assertEqual(self.client.setup_status(), answer)
        method, path, headers, body = self.server.calls[0]
        self.assertEqual((method, path, body), ("GET", "/v1/setup", b""))
        self.assertEqual(headers["Authorization"], "Bearer sk_live_fields")
        self.assertEqual(headers["User-Agent"], "sentinel-python/" + sentinel_module.__version__)
        self.server.reply = (401, b'{"error":"Invalid API Key."}', {})
        with self.assertRaises(SentinelError) as caught:
            self.client.setup_status()
        self.assertEqual((caught.exception.status, caught.exception.body), (401, {"error": "Invalid API Key."}))


class MissingBrowserPartWarningTests(unittest.TestCase):
    """0.4.0: one warning per process for a check sent without the browser part."""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.calls = []
        self.server.reply = (200, b'{"decision":"allow"}', {})
        self.saved = sentinel_module._missing_browser_part_warned
        sentinel_module._missing_browser_part_warned = False   # a process that has not warned yet

    def tearDown(self):
        sentinel_module._missing_browser_part_warned = self.saved

    def caught(self, run):
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            run()
        return [w for w in seen if issubclass(w.category, MissingBrowserPartWarning)]

    def test_once_per_process_without_the_key_or_visitor_data(self):
        key = "sk_live_warning_secret_987"

        def run():
            client = Sentinel(key, self.endpoint)
            client.evaluate("eyJ.live.token", email="visitor@example.com", ip="81.20.33.4")
            client.evaluate("eyJ.live.token")
            Sentinel(key, self.endpoint).evaluate("eyJ.live.token", "")
        seen = self.caught(run)
        self.assertEqual(len(seen), 1, "one warning, however many checks and clients")
        text = str(seen[0].message)
        self.assertIn("sent without fingerprint_event_id", text)
        self.assertIn("keep the script on the page with your form and forward its sentinel_fp field "
                      "(or the fingerprintEventId from Sentinel.collect()) as fingerprint_event_id", text)
        self.assertIn("Sentinel(warn_missing_browser_part=False) turns it off", text)
        for secret in (key, "eyJ.live.token", "visitor@example.com", "81.20.33.4"):
            self.assertNotIn(secret, text)
        self.assertEqual(seen[0].filename, __file__, "the warning points at the line that called evaluate()")
        self.assertEqual(len(self.server.calls), 3, "the checks were sent all the same")

    def test_the_option_turns_it_off_without_using_it_up(self):
        def run():
            Sentinel("k", self.endpoint, warn_missing_browser_part=False).evaluate("eyJ.live.token")
        self.assertEqual(self.caught(run), [])
        self.assertFalse(sentinel_module._missing_browser_part_warned)
        self.assertEqual(len(self.caught(lambda: Sentinel("k", self.endpoint).evaluate(
            "eyJ.live.token", event="login", account_id="u"))), 1)

    def test_quiet_with_the_browser_part_a_test_token_or_an_account_event(self):
        def run():
            client = Sentinel("k", self.endpoint)
            client.evaluate("eyJ.live.token", "evt")
            client.evaluate("test_vpn")
            for event in ("password_change", "verification", "logout", "account_change"):
                client.evaluate(event=event, account_id="u")
            with self.assertRaises(SentinelError):
                client.evaluate(event="login")
        self.assertEqual(self.caught(run), [])

    def test_a_filter_that_ignores_the_category_silences_it(self):
        with warnings.catch_warnings(record=True) as seen:
            warnings.simplefilter("always")
            warnings.filterwarnings("ignore", category=MissingBrowserPartWarning)
            Sentinel("k", self.endpoint).evaluate("eyJ.live.token")
        self.assertEqual([w for w in seen if issubclass(w.category, MissingBrowserPartWarning)], [])


class VersionTests(unittest.TestCase):
    def test_the_package_and_the_module_agree_on_0_4_1(self):
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        self.assertEqual(re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1), "0.4.1")
        self.assertEqual(sentinel_module.__version__, "0.4.1")


if __name__ == "__main__":
    unittest.main()

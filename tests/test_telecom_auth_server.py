import base64
import contextlib
import http.client
import io
import json
import pathlib
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tools.telecom_auth.server import MAX_BODY_BYTES, create_server
from tools.telecom_auth.__main__ import build_parser
from tools.telecom_auth.security import AccessControl
from tools.telecom_auth.sessions import InvalidSession, SessionStore
from tools.telecom_auth.telecom import TelecomAuthError


def runtime_digits(length):
    return "".join(secrets.choice("0123456789") for _ in range(length))


class FakeClock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeProtocol:
    expected_password = None
    fail_verification = False
    fail_sms = False
    instances = []
    active_calls = 0
    maximum_active_calls = 0
    activity_lock = threading.Lock()

    def __init__(self, phone):
        self.phone = phone
        self.device_id = secrets.token_hex(16)
        self.challenge_calls = 0
        self.sms_arguments = []
        self.submitted_codes = []
        self.verified_passwords = []
        type(self).instances.append(self)

    def get_challenge(self):
        self.challenge_calls += 1
        return {
            "background_img": "background-data",
            "slider_img": "slider-data",
            "background_width": 340,
            "background_height": 200,
            "slider_width": 60,
            "slider_height": 200,
        }

    def send_sms(self, distance, track, start_time, end_time):
        with type(self).activity_lock:
            type(self).active_calls += 1
            type(self).maximum_active_calls = max(
                type(self).maximum_active_calls, type(self).active_calls
            )
        try:
            time.sleep(0.05)
            self.sms_arguments.append((distance, track, start_time, end_time))
        finally:
            with type(self).activity_lock:
                type(self).active_calls -= 1

    def submit_sms(self, code):
        self.submitted_codes.append(code)
        if type(self).fail_sms:
            raise TelecomAuthError("SMS_LOGIN_FAILED", "SMS login failed")
        return {"device_id": self.device_id}

    def verify_device_id(self, password):
        self.verified_passwords.append(password)
        return not type(self).fail_verification and password == type(self).expected_password


class ServerTests(unittest.TestCase):
    def setUp(self):
        FakeProtocol.expected_password = secrets.token_urlsafe(24)
        FakeProtocol.fail_verification = False
        FakeProtocol.fail_sms = False
        FakeProtocol.instances = []
        FakeProtocol.active_calls = 0
        FakeProtocol.maximum_active_calls = 0
        self.clock = FakeClock()
        self.phone = runtime_digits(11)
        self.sms_code = runtime_digits(6)
        self.server = create_server(
            "127.0.0.1",
            0,
            protocol_factory=FakeProtocol,
            ttl=600,
            now=self.clock,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address
        self.token = self.page_token()

    def page_token(self, path="/"):
        status, _, page = self.request("GET", path)
        self.assertEqual(status, 200)
        match = re.search(
            r'<meta id="access-token" name="access-token" content="([A-Za-z0-9_-]{43})">',
            page.decode("utf-8"),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read()
            content_type = response.getheader("Content-Type", "")
            if content_type.startswith("application/json") and payload:
                payload = json.loads(payload)
            return response.status, dict(response.getheaders()), payload
        finally:
            connection.close()

    def authorized_headers(self, content_type=True):
        headers = {"Authorization": f"Bearer {self.token}"}
        if content_type:
            headers["Content-Type"] = "application/json"
        return headers

    def post(self, path, data, token=None, content_type=True):
        headers = self.authorized_headers(content_type=content_type)
        if token is None:
            headers.pop("Authorization")
        elif token != self.token:
            headers["Authorization"] = f"Bearer {token}"
        return self.request(
            "POST", path, json.dumps(data).encode("utf-8"), headers=headers
        )

    def start_challenge(self):
        status, _, payload = self.post(
            "/api/challenge", {"phone": self.phone}, token=self.token
        )
        self.assertEqual(status, 200)
        return payload

    def send_sms(self, session_id, distance=0.5, track="0#0#100%0.5#0#200"):
        return self.post(
            "/api/send-sms",
            {
                "session_id": session_id,
                "distance": distance,
                "track": track,
                "start_time": 100,
                "end_time": 200,
            },
            token=self.token,
        )

    def start_sms_session(self):
        session_id = self.start_challenge()["session_id"]
        status, _, _ = self.send_sms(session_id)
        self.assertEqual(status, 200)
        return session_id

    def start_login_session(self):
        session_id = self.start_sms_session()
        status, _, _ = self.post(
            "/api/submit-sms",
            {"session_id": session_id, "code": self.sms_code},
            token=self.token,
        )
        self.assertEqual(status, 200)
        return session_id

    def assert_security_headers(self, headers):
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def test_cli_defaults_match_contract(self):
        arguments = build_parser().parse_args([])

        self.assertEqual(arguments.host, "127.0.0.1")
        self.assertEqual(arguments.port, 8765)

    def test_each_page_load_issues_new_32_byte_access_token(self):
        second = self.page_token()
        third = self.page_token("/index.html")

        self.assertIsInstance(self.server.access_control, AccessControl)
        self.assertEqual(len({self.token, second, third}), 3)
        for token in (self.token, second, third):
            self.assertEqual(len(base64.urlsafe_b64decode(token + "=")), 32)
            self.assertIs(self.server.access_control.is_valid(token), True)

    def test_page_access_tokens_expire_after_idle_ttl(self):
        self.clock.advance(1799)
        self.assertIs(self.server.access_control.is_valid(self.token), True)
        self.clock.advance(1799)
        self.assertIs(self.server.access_control.is_valid(self.token), True)
        self.clock.advance(1800)

        status, _, _ = self.post(
            "/api/challenge", {"phone": self.phone}, token=self.token
        )
        self.assertEqual(status, 401)

    def test_api_requires_exact_bearer_token(self):
        for headers in (
            {},
            {"Authorization": f"Bearer {secrets.token_urlsafe(32)}"},
            {"Authorization": self.token},
            {"Authorization": f"Basic {self.token}"},
            {"Authorization": f"Bearer {self.token} extra"},
        ):
            with self.subTest(headers=bool(headers)):
                status, headers_out, payload = self.request(
                    "POST",
                    "/api/challenge",
                    b"{}",
                    {**headers, "Content-Type": "application/json"},
                )
                self.assertEqual(status, 401)
                self.assertNotIn(self.token, json.dumps(payload))
                self.assert_security_headers(headers_out)
        self.assertEqual(FakeProtocol.instances, [])

    def test_challenge_returns_session_and_slider_but_never_phone(self):
        payload = self.start_challenge()

        self.assertEqual(set(payload), {"session_id", "challenge"})
        self.assertIn("background_img", payload["challenge"])
        self.assertNotIn(self.phone, json.dumps(payload))
        self.assertEqual(len(base64.urlsafe_b64decode(payload["session_id"] + "=")), 32)
        self.assertIsInstance(self.server.sessions, SessionStore)
        self.assertEqual(FakeProtocol.instances[0].challenge_calls, 1)

    def test_complete_operator_workflow_and_revocation(self):
        other_token = self.page_token()
        session_id = self.start_challenge()["session_id"]
        distance = 0.5
        track = "0.000#0.000#1000%0.500#0.000#1500"
        start_time, end_time = 1000, 1500

        status, headers, payload = self.post(
            "/api/send-sms",
            {
                "session_id": session_id,
                "distance": distance,
                "track": track,
                "start_time": start_time,
                "end_time": end_time,
            },
            token=self.token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"sent": True})
        self.assert_security_headers(headers)

        status, _, payload = self.post(
            "/api/submit-sms",
            {"session_id": session_id, "code": self.sms_code},
            token=self.token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"device_id": FakeProtocol.instances[0].device_id})
        self.assertEqual(FakeProtocol.instances[0].submitted_codes, [self.sms_code])

        status, _, payload = self.post(
            "/api/complete",
            {"session_id": session_id, "password": FakeProtocol.expected_password},
            token=self.token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"completed": True})
        self.assertEqual(
            FakeProtocol.instances[0].verified_passwords,
            [FakeProtocol.expected_password],
        )

        status, _, _ = self.post(
            "/api/challenge", {"phone": self.phone}, token=self.token
        )
        self.assertEqual(status, 401)
        with self.assertRaises(Exception):
            self.server.sessions.get(session_id)
        self.assertIs(self.server.access_control.is_valid(other_token), True)

        status, _, _ = self.post(
            "/api/challenge", {"phone": self.phone}, token=self.page_token()
        )
        self.assertEqual(status, 200)

    def test_failed_device_verification_does_not_complete_or_revoke(self):
        session_id = self.start_login_session()
        FakeProtocol.fail_verification = True

        status, _, payload = self.post(
            "/api/complete",
            {"session_id": session_id, "password": FakeProtocol.expected_password},
            token=self.token,
        )

        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "Device verification failed"})
        self.assertIs(self.server.access_control.is_valid(self.token), True)
        self.assertIs(self.server.sessions.get(session_id), FakeProtocol.instances[0])

    def test_submit_sms_before_send_is_rejected_without_protocol_call(self):
        session_id = self.start_challenge()["session_id"]

        status, _, _ = self.post(
            "/api/submit-sms",
            {"session_id": session_id, "code": self.sms_code},
            token=self.token,
        )

        self.assertEqual(status, 409)
        self.assertEqual(FakeProtocol.instances[0].submitted_codes, [])

    def test_complete_before_sms_login_is_rejected_without_protocol_call(self):
        session_id = self.start_sms_session()

        status, _, _ = self.post(
            "/api/complete",
            {"session_id": session_id, "password": FakeProtocol.expected_password},
            token=self.token,
        )

        self.assertEqual(status, 409)
        self.assertEqual(FakeProtocol.instances[0].verified_passwords, [])

    def test_duplicate_sms_send_never_reaches_protocol(self):
        session_id = self.start_sms_session()

        status, _, _ = self.send_sms(session_id)

        self.assertEqual(status, 409)
        self.assertEqual(len(FakeProtocol.instances[0].sms_arguments), 1)

    def test_duplicate_successful_sms_login_never_reaches_protocol(self):
        session_id = self.start_login_session()

        status, _, _ = self.post(
            "/api/submit-sms",
            {"session_id": session_id, "code": self.sms_code},
            token=self.token,
        )

        self.assertEqual(status, 409)
        self.assertEqual(len(FakeProtocol.instances[0].submitted_codes), 1)

    def test_sms_attempts_are_bounded_and_sixth_never_reaches_protocol(self):
        session_id = self.start_sms_session()
        FakeProtocol.fail_sms = True
        statuses = []
        for _ in range(6):
            status, _, _ = self.post(
                "/api/submit-sms",
                {"session_id": session_id, "code": self.sms_code},
                token=self.token,
            )
            statuses.append(status)

        self.assertEqual(statuses, [502, 502, 502, 502, 502, 429])
        self.assertEqual(len(FakeProtocol.instances[0].submitted_codes), 5)

    def test_password_attempts_are_bounded_and_sixth_never_reaches_protocol(self):
        session_id = self.start_login_session()
        FakeProtocol.fail_verification = True
        statuses = []
        for _ in range(6):
            status, _, _ = self.post(
                "/api/complete",
                {"session_id": session_id, "password": "wrong-password"},
                token=self.token,
            )
            statuses.append(status)

        self.assertEqual(statuses, [400, 400, 400, 400, 400, 429])
        self.assertEqual(len(FakeProtocol.instances[0].verified_passwords), 5)

    def test_expired_sessions_return_410_and_are_removed(self):
        session_id = self.start_challenge()["session_id"]
        self.clock.advance(601)

        status, _, payload = self.post(
            "/api/submit-sms",
            {"session_id": session_id, "code": self.sms_code},
            token=self.token,
        )

        self.assertEqual(status, 410)
        self.assertEqual(payload, {"error": "Session expired"})
        with self.assertRaises(InvalidSession):
            self.server.sessions.get(session_id)

    def test_unknown_session_returns_404(self):
        status, _, payload = self.post(
            "/api/submit-sms",
            {"session_id": secrets.token_urlsafe(32), "code": self.sms_code},
            token=self.token,
        )

        self.assertEqual(status, 404)
        self.assertEqual(payload, {"error": "Invalid session"})

    def test_malformed_json_and_wrong_sms_format_return_400(self):
        session_id = self.start_challenge()["session_id"]
        malformed = [b"{", b"null", b"[]", b'"text"', b""]
        for body in malformed:
            with self.subTest(body=body):
                status, _, _ = self.request(
                    "POST",
                    "/api/submit-sms",
                    body,
                    headers=self.authorized_headers(),
                )
                self.assertEqual(status, 400)
        for code in ("12345", "1234567", "abcdef", "１２３４５６", "12345 ", 123456):
            with self.subTest(code=code):
                status, _, _ = self.post(
                    "/api/submit-sms",
                    {"session_id": session_id, "code": code},
                    token=self.token,
                )
                self.assertEqual(status, 400)
        self.assertEqual(FakeProtocol.instances[0].submitted_codes, [])

    def test_duplicate_json_object_keys_are_rejected(self):
        session_id = self.start_challenge()["session_id"]
        body = (
            f'{{"session_id":"{session_id}","code":"{self.sms_code}",'
            f'"code":"{runtime_digits(6)}"}}'
        ).encode("utf-8")

        status, _, payload = self.request(
            "POST", "/api/submit-sms", body, headers=self.authorized_headers()
        )

        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "Malformed JSON"})
        self.assertEqual(FakeProtocol.instances[0].submitted_codes, [])

    def test_invalid_phone_and_slider_fields_return_400(self):
        for phone in ("12345", runtime_digits(10), runtime_digits(12), 12345678901):
            with self.subTest(phone_type=type(phone).__name__, length=len(str(phone))):
                status, _, _ = self.post(
                    "/api/challenge", {"phone": phone}, token=self.token
                )
                self.assertEqual(status, 400)
        session_id = self.start_challenge()["session_id"]
        valid = {
            "session_id": session_id,
            "distance": 0.5,
            "track": "0.000#0.000#100%0.500#0.000#200",
            "start_time": 100,
            "end_time": 200,
        }
        replacements = (
            {"distance": True},
            {"distance": float("nan")},
            {"distance": float("inf")},
            {"distance": -1},
            {"distance": 1.0001},
            {"distance": "0.5"},
            {"track": ""},
            {"track": 4},
            {"track": "0,0;10,100"},
            {"track": "0#0#100%"},
            {"track": "%0#0#100"},
            {"track": "0#0#100%%1#1#200"},
            {"track": "0#0"},
            {"track": "0#0#1.5"},
            {"track": "0#0#-1"},
            {"track": "0#0#+1"},
            {"track": "0#0#01"},
            {"track": ".5#0#100"},
            {"track": "0.5#0#1e3"},
            {"track": "NaN#0#100"},
            {"track": "1.001#0#100"},
            {"track": "-0.1#0#100"},
            {"track": "0.5#NaN#100"},
            {"track": "0.5#0#100#extra"},
            {"start_time": True},
            {"start_time": 100.0},
            {"start_time": -1},
            {"end_time": 99},
        )
        for replacement in replacements:
            with self.subTest(fields=list(replacement)):
                status, _, _ = self.post(
                    "/api/send-sms", {**valid, **replacement}, token=self.token
                )
                self.assertEqual(status, 400)
        self.assertEqual(FakeProtocol.instances[0].sms_arguments, [])

    def test_track_grammar_accepts_frontend_numeric_forms(self):
        tracks = (
            "0#0#0",
            "1.000#12.340#1761432000000",
            "0.001#0.000#100%1#2.5#200",
        )

        for distance, track in zip((0, 1, 0.5), tracks):
            with self.subTest(distance=distance):
                session_id = self.start_challenge()["session_id"]
                status, _, _ = self.post(
                    "/api/send-sms",
                    {
                        "session_id": session_id,
                        "distance": distance,
                        "track": track,
                        "start_time": 0,
                        "end_time": 1761432000000,
                    },
                    token=self.token,
                )
                self.assertEqual(status, 200)
        self.assertEqual(
            sum(len(protocol.sms_arguments) for protocol in FakeProtocol.instances), 3
        )

    def test_json_content_type_and_body_size_are_enforced(self):
        status, _, _ = self.post(
            "/api/challenge", {"phone": self.phone}, token=self.token, content_type=False
        )
        self.assertEqual(status, 415)

        status, _, _ = self.request(
            "POST",
            "/api/challenge",
            b" " * (MAX_BODY_BYTES + 1),
            headers=self.authorized_headers(),
        )
        self.assertEqual(status, 413)

        raw = socket.create_connection((self.host, self.port), timeout=3)
        try:
            raw.sendall(
                b"POST /api/challenge HTTP/1.1\r\nHost: localhost\r\n"
                + f"Authorization: Bearer {self.token}\r\n".encode("ascii")
                + b"Content-Type: application/json\r\nConnection: close\r\n\r\n{}"
            )
            response = raw.recv(4096)
        finally:
            raw.close()
        self.assertIn(b" 411 ", response.split(b"\r\n", 1)[0])

    def test_operations_on_one_auth_instance_are_serialized(self):
        session_id = self.start_challenge()["session_id"]
        body = json.dumps({
            "session_id": session_id,
            "distance": 0.5,
            "track": "0.000#0.000#100%0.500#0.000#200",
            "start_time": 100,
            "end_time": 200,
        }).encode("utf-8")
        barrier = threading.Barrier(3)
        statuses = []
        status_lock = threading.Lock()

        def send():
            barrier.wait()
            status, _, _ = self.request(
                "POST", "/api/send-sms", body, headers=self.authorized_headers()
            )
            with status_lock:
                statuses.append(status)

        threads = [threading.Thread(target=send) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=3)

        self.assertEqual(sorted(statuses), [200, 409])
        self.assertEqual(len(FakeProtocol.instances[0].sms_arguments), 1)
        self.assertEqual(FakeProtocol.maximum_active_calls, 1)

    def test_framework_method_errors_also_have_security_headers(self):
        status, headers, payload = self.request("PUT", "/")

        self.assertEqual(status, 501)
        self.assertEqual(payload, {"error": "Unsupported method"})
        self.assert_security_headers(headers)

    def test_frontend_slider_and_challenge_race_behavior(self):
        completed = subprocess.run(
            ["node", "--test", str(HERE / "telecom_auth_frontend_harness.js")],
            cwd=HERE.parent,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        self.assertEqual(
            completed.returncode,
            0,
            msg=f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}",
        )
        self.assertIn("pass 4", completed.stdout)

    def test_static_page_is_self_contained_and_embeds_fresh_token(self):
        status, headers, page = self.request("GET", f"/?token={self.token}")
        self.assertEqual(status, 200)
        page = page.decode("utf-8")
        self.assert_security_headers(headers)
        self.assertIn('id="phone"', page)
        self.assertIn('id="slider"', page)
        self.assertIn('id="sms-code"', page)
        self.assertIn('id="result"', page)
        self.assertNotIn(self.token, page)
        self.assertIn('<meta id="access-token" name="access-token" content="', page)
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)
        self.assertIn('src="/app.js"', page)
        self.assertIn('href="/style.css"', page)

        status, headers, script = self.request("GET", "/app.js")
        self.assertEqual(status, 200)
        script = script.decode("utf-8")
        self.assert_security_headers(headers)
        self.assertIn('document.getElementById("access-token").content', script)
        self.assertNotIn("window.location", script)
        self.assertIn("Authorization", script)
        self.assertIn("`Bearer ${accessToken}`", script)
        self.assertNotIn("localStorage", script)
        self.assertNotIn("sessionStorage", script)
        self.assertNotIn("http://", script)
        self.assertNotIn("https://", script)

        status, headers, stylesheet = self.request("GET", "/style.css")
        self.assertEqual(status, 200)
        self.assert_security_headers(headers)
        self.assertNotIn(b"@import", stylesheet)
        self.assertNotIn(b"url(", stylesheet)

    def test_api_does_not_accept_url_tokens_or_unknown_paths(self):
        status, _, _ = self.request(
            "POST",
            f"/api/challenge?token={self.token}",
            json.dumps({"phone": self.phone}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 401)
        status, _, _ = self.request("GET", "/not-found")
        self.assertEqual(status, 404)

    def test_server_logs_never_contain_request_secrets(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.request("GET", f"/?token={self.token}")
            self.post("/api/challenge", {"phone": self.phone}, token=self.token)

        logged = stderr.getvalue()
        for secret in (
            self.token,
            self.phone,
            self.sms_code,
            FakeProtocol.expected_password,
            FakeProtocol.instances[0].device_id,
        ):
            self.assertNotIn(secret, logged)
        self.assertEqual(logged, "")

    def test_protocol_errors_return_generic_502_without_sensitive_details(self):
        class FailingProtocol(FakeProtocol):
            def get_challenge(self):
                raise TelecomAuthError("CARRIER_ERROR", self.phone)

        self.server.protocol_factory = FailingProtocol
        status, _, payload = self.post(
            "/api/challenge", {"phone": self.phone}, token=self.token
        )

        self.assertEqual(status, 502)
        self.assertEqual(payload, {"error": "Carrier request failed", "code": "CARRIER_ERROR"})
        self.assertNotIn(self.phone, json.dumps(payload))
        self.assertNotIn(self.phone, json.dumps(payload))


if __name__ == "__main__":
    unittest.main()

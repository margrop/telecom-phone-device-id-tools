import base64
import pathlib
import secrets
import sys
import threading
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tools.telecom_auth.security import AccessControl
from tools.telecom_auth.sessions import InvalidSession, SessionExpired, SessionStore


def runtime_digits(length):
    return "".join(secrets.choice("0123456789") for _ in range(length))


class FakeClock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.phone = runtime_digits(11)
        self.clock = FakeClock()
        self.store = SessionStore(ttl=600, now=self.clock)

    def test_create_returns_32_byte_urlsafe_token_and_live_auth(self):
        token = secrets.token_urlsafe(32)
        with mock.patch(
            "tools.telecom_auth.sessions.secrets.token_urlsafe", return_value=token
        ) as generate:
            session_id = self.store.create(self.phone)

        generate.assert_called_once_with(32)
        self.assertIs(session_id == token, True)
        self.assertEqual(len(base64.urlsafe_b64decode(session_id + "=")), 32)
        self.assertIs(self.store.get(session_id).phone == self.phone, True)

    def test_session_ids_are_unique(self):
        first = self.store.create(runtime_digits(11))
        second = self.store.create(runtime_digits(11))

        self.assertIs(first == second, False)

    def test_get_rejects_unknown_session_without_leaking_identifier(self):
        session_id = secrets.token_urlsafe(32)

        with self.assertRaises(InvalidSession) as raised:
            self.store.get(session_id)

        self.assertNotIn(session_id, str(raised.exception))

    def test_get_expires_session_at_ttl(self):
        session_id = self.store.create(self.phone)
        self.clock.advance(600)

        with self.assertRaises(InvalidSession):
            self.store.get(session_id)

    def test_expiration_removes_session_and_candidate_identifier(self):
        session_id = self.store.create(self.phone)
        self.clock.advance(601)

        with self.assertRaises(InvalidSession) as raised:
            self.store.get(session_id)

        self.assertNotIn(self.phone, str(raised.exception))
        self.assertEqual(self.store._sessions, {})
        self.assertEqual(self.store._phone_sessions, {})

    def test_complete_deletes_session_and_candidate_identifier(self):
        session_id = self.store.create(self.phone)

        self.assertIsNone(self.store.complete(session_id))

        self.assertEqual(self.store._sessions, {})
        self.assertEqual(self.store._phone_sessions, {})
        with self.assertRaises(InvalidSession):
            self.store.get(session_id)

    def test_complete_rejects_unknown_session(self):
        with self.assertRaises(InvalidSession):
            self.store.complete(secrets.token_urlsafe(32))

    def test_complete_reports_expired_session_and_cleans_it_up(self):
        session_id = self.store.create(self.phone)
        self.clock.advance(601)

        with self.assertRaises(InvalidSession) as raised:
            self.store.complete(session_id)

        self.assertNotIn(self.phone, str(raised.exception))
        self.assertEqual(self.store._sessions, {})
        self.assertEqual(self.store._phone_sessions, {})

    def test_creating_same_phone_replaces_old_session(self):
        old_session_id = self.store.create(self.phone)
        new_session_id = self.store.create(self.phone)

        with self.assertRaises(InvalidSession):
            self.store.get(old_session_id)
        self.assertIs(self.store.get(new_session_id).phone == self.phone, True)
        self.assertEqual(len(self.store._sessions), 1)
        self.assertEqual(len(self.store._phone_sessions), 1)

    def test_concurrent_creation_leaves_one_live_session_per_phone(self):
        session_ids = []
        session_ids_lock = threading.Lock()
        barrier = threading.Barrier(8)

        def create_session():
            barrier.wait()
            session_id = self.store.create(self.phone)
            with session_ids_lock:
                session_ids.append(session_id)

        threads = [threading.Thread(target=create_session) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(session_ids), 8)
        live_session_ids = []
        for session_id in session_ids:
            try:
                self.store.get(session_id)
            except InvalidSession:
                continue
            live_session_ids.append(session_id)
        self.assertEqual(len(live_session_ids), 1)
        self.assertEqual(len(self.store._sessions), 1)
        self.assertEqual(len(self.store._phone_sessions), 1)

    @mock.patch("tools.telecom_auth.sessions.time.monotonic", return_value=123.0)
    def test_default_clock_is_monotonic(self, monotonic):
        store = SessionStore(ttl=600)
        session_id = store.create(runtime_digits(11))

        store.get(session_id)

        self.assertGreaterEqual(monotonic.call_count, 2)


class AccessControlTests(unittest.TestCase):
    def setUp(self):
        self.token = secrets.token_urlsafe(32)
        self.control = AccessControl(self.token)

    @mock.patch("tools.telecom_auth.security.hmac.compare_digest")
    def test_is_valid_uses_constant_time_comparison(self, compare_digest):
        compare_digest.return_value = True

        self.assertIs(self.control.is_valid(self.token), True)

        compare_digest.assert_called_once_with(
            self.token.encode("utf-8"), self.token.encode("utf-8")
        )

    def test_is_valid_accepts_only_matching_token(self):
        wrong_token = secrets.token_urlsafe(32)

        self.assertIs(self.control.is_valid(self.token), True)
        self.assertIs(self.control.is_valid(wrong_token), False)
        self.assertIs(self.control.is_valid("不是 ASCII"), False)

    def test_revoke_invalidates_token(self):
        self.control.revoke()

        self.assertIs(self.control.is_valid(self.token), False)
        self.assertIsNone(self.control._token)

    def test_revoke_is_idempotent(self):
        self.control.revoke()

        self.assertIsNone(self.control.revoke())
        self.assertIs(self.control.is_valid(self.token), False)


if __name__ == "__main__":
    unittest.main()

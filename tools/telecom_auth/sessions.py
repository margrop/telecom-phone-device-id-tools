import secrets
import threading
import time

from .telecom import TelecomAuth


class InvalidSession(RuntimeError):
    pass


class SessionExpired(InvalidSession):
    pass


class SessionStore:
    def __init__(self, ttl=600, now=None):
        self._ttl = ttl
        self._now = now or time.monotonic
        self._sessions = {}
        self._phone_sessions = {}
        self._lock = threading.RLock()

    def create(self, phone: str) -> str:
        with self._lock:
            self._purge_expired()
            old_session_id = self._phone_sessions.get(phone)
            if old_session_id is not None:
                self._remove(old_session_id)
            session_id = secrets.token_urlsafe(32)
            self._sessions[session_id] = (
                phone,
                TelecomAuth(phone),
                self._now() + self._ttl,
            )
            self._phone_sessions[phone] = session_id
            return session_id

    def get(self, session_id: str) -> TelecomAuth:
        with self._lock:
            self._purge_expired()
            session = self._get_live_session(session_id)
            return session[1]

    def complete(self, session_id: str) -> None:
        with self._lock:
            self._purge_expired()
            self._get_live_session(session_id)
            self._remove(session_id)

    def _purge_expired(self):
        now = self._now()
        expired = [sid for sid, session in self._sessions.items() if now >= session[2]]
        for session_id in expired:
            self._remove(session_id)

    def _get_live_session(self, session_id):
        session = self._sessions.get(session_id)
        if session is None:
            raise InvalidSession("Invalid session")
        if self._now() >= session[2]:
            self._remove(session_id)
            raise SessionExpired("Session expired")
        return session

    def _remove(self, session_id):
        session = self._sessions.pop(session_id)
        phone = session[0]
        if self._phone_sessions.get(phone) == session_id:
            del self._phone_sessions[phone]

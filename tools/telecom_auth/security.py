import hmac
import secrets
import threading
import time


class AccessControl:
    def __init__(self, ttl=1800, now=None, limit=64):
        self._ttl = ttl
        self._now = now or time.monotonic
        self._limit = limit
        self._tokens = {}
        self._lock = threading.Lock()

    def issue(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge_expired()
            while len(self._tokens) >= self._limit:
                del self._tokens[next(iter(self._tokens))]
            self._tokens[token] = self._now() + self._ttl
        return token

    def is_valid(self, candidate: str) -> bool:
        with self._lock:
            self._purge_expired()
            encoded = candidate.encode("utf-8")
            matched = None
            for token in self._tokens:
                if hmac.compare_digest(encoded, token.encode("utf-8")):
                    matched = token
            if matched is None:
                return False
            self._tokens[matched] = self._now() + self._ttl
            return True

    def revoke(self, candidate: str) -> None:
        with self._lock:
            self._tokens.pop(candidate, None)

    def _purge_expired(self):
        now = self._now()
        for token in [token for token, expiry in self._tokens.items() if now >= expiry]:
            del self._tokens[token]

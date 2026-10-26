import hmac
import threading


class AccessControl:
    def __init__(self, token: str):
        self._token = token
        self._lock = threading.Lock()

    def is_valid(self, candidate: str) -> bool:
        with self._lock:
            if self._token is None:
                return False
            return hmac.compare_digest(
                candidate.encode("utf-8"), self._token.encode("utf-8")
            )

    def revoke(self) -> None:
        with self._lock:
            self._token = None

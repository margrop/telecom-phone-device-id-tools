import json
import math
import re
import secrets
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .security import AccessControl
from .sessions import InvalidSession, SessionExpired, SessionStore
from .telecom import TelecomAuth, TelecomAuthError


MAX_BODY_BYTES = 16 * 1024
_STATIC_ROOT = Path(__file__).resolve().parent / "static"
_INDEX_PATHS = {"/", "/index.html"}
_TOKEN_PLACEHOLDER = '<meta id="access-token" name="access-token" content="">'
_STATIC_FILES = {
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
_CHALLENGE_FIELDS = (
    "background_img",
    "slider_img",
    "background_width",
    "background_height",
    "slider_width",
    "slider_height",
)
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
}
_TRACK_NUMBER = r"(?:0|[1-9][0-9]{0,30})(?:\.[0-9]{1,6})?"
_TRACK_MILLISECONDS = r"(?:0|[1-9][0-9]{0,19})"
_TRACK_ITEM = re.compile(
    rf"({_TRACK_NUMBER})#({_TRACK_NUMBER})#({_TRACK_MILLISECONDS})"
)


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _valid_track(track):
    if not isinstance(track, str) or not 1 <= len(track) <= 8192:
        return False
    for item in track.split("%"):
        match = _TRACK_ITEM.fullmatch(item)
        if match is None:
            return False
        horizontal, vertical = float(match.group(1)), float(match.group(2))
        if not 0 <= horizontal <= 1 or not math.isfinite(vertical):
            return False
    return True


class _RequestError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class _CarrierError(RuntimeError):
    def __init__(self, code="CARRIER_ERROR", message="Carrier request failed"):
        super().__init__(message)
        self.code = code


class _ProtocolSessionStore(SessionStore):
    def __init__(self, protocol_factory, ttl, now):
        super().__init__(ttl=ttl, now=now)
        self._protocol_factory = protocol_factory
        self._workflows = {}

    def create(self, phone):
        with self._lock:
            old_session_id = self._phone_sessions.get(phone)
            if old_session_id is not None:
                self._remove(old_session_id)
            session_id = secrets.token_urlsafe(32)
            self._sessions[session_id] = (
                phone,
                self._protocol_factory(phone),
                self._now() + self._ttl,
            )
            self._phone_sessions[phone] = session_id
            self._workflows[session_id] = {
                "sms_send_attempted": False,
                "sms_sent": False,
                "sms_failed": False,
                "sms_login_succeeded": False,
                "sms_attempts": 0,
                "password_attempts": 0,
            }
            return session_id

    def begin_sms_send(self, session_id):
        with self._lock:
            session = self._get_live_session(session_id)
            workflow = self._workflows[session_id]
            if workflow["sms_send_attempted"]:
                raise _RequestError(409, "SMS was already requested")
            if workflow["sms_sent"] is False and workflow["sms_failed"]:
                raise _RequestError(429, "SMS request failed; refresh challenge or start over")
            workflow["sms_send_attempted"] = True
            return session[1]

    def finish_sms_send(self, session_id):
        with self._lock:
            self._workflows[session_id]["sms_sent"] = True

    def fail_sms_send(self, session_id):
        with self._lock:
            self._workflows[session_id]["sms_send_attempted"] = False
            self._workflows[session_id]["sms_failed"] = True

    def begin_sms_submit(self, session_id):
        with self._lock:
            session = self._get_live_session(session_id)
            workflow = self._workflows[session_id]
            if not workflow["sms_sent"] or workflow["sms_login_succeeded"]:
                raise _RequestError(409, "SMS login is not available")
            if workflow["sms_attempts"] >= 5:
                raise _RequestError(429, "Too many SMS attempts")
            workflow["sms_attempts"] += 1
            return session[1]

    def finish_sms_submit(self, session_id):
        with self._lock:
            self._workflows[session_id]["sms_login_succeeded"] = True

    def fail_sms_submit(self, session_id):
        pass

    def begin_password_verification(self, session_id):
        with self._lock:
            session = self._get_live_session(session_id)
            workflow = self._workflows[session_id]
            if not workflow["sms_login_succeeded"]:
                raise _RequestError(409, "Complete SMS login first")
            if workflow["password_attempts"] >= 5:
                raise _RequestError(429, "Too many password attempts")
            workflow["password_attempts"] += 1
            return session[1]

    def _remove(self, session_id):
        self._workflows.pop(session_id, None)
        super()._remove(session_id)


class _OperationLocks:
    def __init__(self):
        self._guard = threading.Lock()
        self._entries = {}

    @contextmanager
    def hold(self, session_id):
        with self._guard:
            entry = self._entries.get(session_id)
            if entry is None:
                entry = [threading.RLock(), 0]
                self._entries[session_id] = entry
            entry[1] += 1
        entry[0].acquire()
        try:
            yield
        finally:
            entry[0].release()
            with self._guard:
                entry[1] -= 1
                if entry[1] == 0 and self._entries.get(session_id) is entry:
                    del self._entries[session_id]


class TelecomAuthHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, protocol_factory, ttl, now):
        self.access_control = AccessControl(now=now)
        self.protocol_factory = protocol_factory
        self.sessions = _ProtocolSessionStore(
            lambda phone: self.protocol_factory(phone), ttl, now
        )
        self.operation_locks = _OperationLocks()
        super().__init__(address, TelecomAuthRequestHandler)


class TelecomAuthRequestHandler(BaseHTTPRequestHandler):
    server_version = "TelecomAuth"
    sys_version = ""

    def log_message(self, format, *args):
        return

    def send_error(self, code, message=None, explain=None):
        error = "Unsupported method" if code == 501 else "Request error"
        self._send_json(code, {"error": error})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in _INDEX_PATHS:
            self._serve_index()
            return
        static_file = _STATIC_FILES.get(path)
        if static_file is None:
            self._send_json(404, {"error": "Not found"})
            return
        filename, content_type = static_file
        content = (_STATIC_ROOT / filename).read_bytes()
        self._send_bytes(200, content, content_type)

    def _serve_index(self):
        token = self.server.access_control.issue()
        content = (_STATIC_ROOT / "index.html").read_text(encoding="utf-8")
        content = content.replace(
            _TOKEN_PLACEHOLDER,
            f'<meta id="access-token" name="access-token" content="{token}">',
        )
        self._send_bytes(200, content.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in {
            "/api/challenge",
            "/api/refresh-challenge",
            "/api/send-sms",
            "/api/submit-sms",
            "/api/complete",
        }:
            self._send_json(404, {"error": "Not found"})
            return
        if not self._is_authorized():
            self._send_json(
                401,
                {"error": "Unauthorized"},
                {"WWW-Authenticate": "Bearer"},
            )
            return
        if urlsplit(self.path).query:
            self._send_json(400, {"error": "Query parameters are not accepted"})
            return
        try:
            body = self._read_json()
            if path == "/api/challenge":
                self._challenge(body)
            elif path == "/api/refresh-challenge":
                self._refresh_challenge(body)
            elif path == "/api/send-sms":
                self._send_sms(body)
            elif path == "/api/submit-sms":
                self._submit_sms(body)
            elif path == "/api/complete":
                self._complete(body)
        except _RequestError as error:
            self._send_json(error.status, {"error": error.message})
        except SessionExpired:
            self._send_json(410, {"error": "Session expired"})
        except InvalidSession:
            self._send_json(404, {"error": "Invalid session"})
        except _CarrierError as error:
            self._send_json(502, {"error": "Carrier request failed", "code": error.code})
        except Exception:
            self._send_json(500, {"error": "Internal server error"})

    def _is_authorized(self):
        values = self.headers.get_all("Authorization") or []
        if len(values) != 1:
            return False
        value = values[0]
        if not value.startswith("Bearer "):
            return False
        candidate = value[7:]
        if not candidate or candidate.strip() != candidate or " " in candidate:
            return False
        if not self.server.access_control.is_valid(candidate):
            return False
        self._access_token = candidate
        return True

    def _read_json(self):
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            raise _RequestError(400, "Transfer encoding is not accepted")
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) != 1:
            self.close_connection = True
            raise _RequestError(411, "A single Content-Length is required")
        try:
            length = int(lengths[0], 10)
        except ValueError as error:
            self.close_connection = True
            raise _RequestError(400, "Invalid Content-Length") from error
        if length < 0:
            self.close_connection = True
            raise _RequestError(400, "Invalid Content-Length")
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            raise _RequestError(413, "Request body too large")
        content_types = self.headers.get_all("Content-Type") or []
        if len(content_types) != 1:
            raise _RequestError(415, "Content-Type must be application/json")
        content_type = content_types[0].split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise _RequestError(415, "Content-Type must be application/json")
        content = self.rfile.read(length)
        if len(content) != length:
            self.close_connection = True
            raise _RequestError(400, "Incomplete request body")
        try:
            text = content.decode("utf-8")
            return json.loads(
                text,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError("Invalid JSON number")
                ),
                object_pairs_hook=_unique_json_object,
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise _RequestError(400, "Malformed JSON") from error

    @staticmethod
    def _fields(body, names):
        if not isinstance(body, dict) or set(body) != set(names):
            raise _RequestError(400, "Invalid request fields")
        return [body[name] for name in names]

    @staticmethod
    def _session_id(value):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
            raise _RequestError(400, "Invalid session")
        return value

    def _refresh_challenge(self, body):
        (session_id,) = self._fields(body, ("session_id",))
        session_id = self._session_id(session_id)
        with self.server.operation_locks.hold(session_id):
            auth = self.server.sessions.get(session_id)
            challenge = self._carrier_call(auth.get_challenge)
        self._send_json(200, {"challenge": {name: challenge[name] for name in _CHALLENGE_FIELDS}})

    def _challenge(self, body):
        (phone,) = self._fields(body, ("phone",))
        if not isinstance(phone, str) or not re.fullmatch(r"[0-9]{11}", phone):
            raise _RequestError(400, "Invalid phone format")
        session_id = self.server.sessions.create(phone)
        try:
            with self.server.operation_locks.hold(session_id):
                auth = self.server.sessions.get(session_id)
                challenge = self._carrier_call(auth.get_challenge)
        except Exception:
            try:
                self.server.sessions.complete(session_id)
            except InvalidSession:
                pass
            raise
        self._send_json(
            200,
            {
                "session_id": session_id,
                "challenge": {name: challenge[name] for name in _CHALLENGE_FIELDS},
            },
        )

    def _send_sms(self, body):
        session_id, distance, track, start_time, end_time = self._fields(
            body, ("session_id", "distance", "track", "start_time", "end_time")
        )
        session_id = self._session_id(session_id)
        if (
            isinstance(distance, bool)
            or not isinstance(distance, (int, float))
            or not math.isfinite(distance)
            or not 0 <= distance <= 1
            or not _valid_track(track)
            or isinstance(start_time, bool)
            or isinstance(end_time, bool)
            or not isinstance(start_time, int)
            or not isinstance(end_time, int)
            or start_time < 0
            or end_time < start_time
        ):
            raise _RequestError(400, "Invalid slider fields")
        auth = self.server.sessions.begin_sms_send(session_id)
        try:
            with self.server.operation_locks.hold(session_id):
                self._carrier_call(auth.send_sms, distance, track, start_time, end_time)
                self.server.sessions.finish_sms_send(session_id)
        except Exception:
            self.server.sessions.fail_sms_send(session_id)
            raise
        self._send_json(200, {"sent": True})

    def _submit_sms(self, body):
        session_id, code = self._fields(body, ("session_id", "code"))
        session_id = self._session_id(session_id)
        if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
            raise _RequestError(400, "SMS code must contain six ASCII digits")
        auth = self.server.sessions.begin_sms_submit(session_id)
        try:
            with self.server.operation_locks.hold(session_id):
                result = self._carrier_call(auth.submit_sms, code)
                self.server.sessions.finish_sms_submit(session_id)
        except Exception:
            self.server.sessions.fail_sms_submit(session_id)
            raise
        self._send_json(200, {"device_id": result["device_id"]})

    def _complete(self, body):
        session_id, password = self._fields(body, ("session_id", "password"))
        session_id = self._session_id(session_id)
        if not isinstance(password, str) or not 1 <= len(password) <= 128:
            raise _RequestError(400, "Invalid password format")
        auth = self.server.sessions.begin_password_verification(session_id)
        with self.server.operation_locks.hold(session_id):
            verified = self._carrier_call(auth.verify_device_id, password)
            if not verified:
                raise _RequestError(400, "Device verification failed")
            self.server.sessions.complete(session_id)
            self.server.access_control.revoke(self._access_token)
        self._send_json(200, {"completed": True})

    @staticmethod
    def _carrier_call(callback, *args):
        try:
            return callback(*args)
        except TelecomAuthError as error:
            raise _CarrierError(code=error.code, message=str(error)) from error
        except Exception as error:
            raise _CarrierError(code="CARRIER_ERROR", message="Carrier request failed") from error

    def _send_json(self, status, payload, extra_headers=None):
        content = json.dumps(
            payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        self._send_bytes(
            status, content, "application/json; charset=utf-8", extra_headers
        )

    def _send_bytes(self, status, content, content_type, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)


def create_server(
    host="127.0.0.1",
    port=0,
    *,
    protocol_factory=TelecomAuth,
    ttl=600,
    now=None,
):
    return TelecomAuthHTTPServer(
        (host, port), protocol_factory, ttl, now
    )

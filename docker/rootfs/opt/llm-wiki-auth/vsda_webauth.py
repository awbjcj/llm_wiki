#!/usr/bin/env python3
"""Web authentication service for the LLM Wiki container, backed by VSDA Deep Agent.

Drop-in replacement for the jlesage/baseimage-gui ``webauth`` binary. The
container nginx (``/opt/base/etc/nginx/include/auth.conf``) talks to it over
the ``/tmp/webauth.sock`` unix socket:

* ``GET  /auth``   - ``auth_request`` subrequest; 200 allows the request, 401
                     sends the browser to the login page.
* ``POST /login``  - credentials from the login page, checked against VSDA
                     Deep Agent's ``POST /api/auth/login``.
* ``GET  /logout`` - clears the session.

Accounts live only in VSDA Deep Agent: the session cookie holds the VSDA access
token, and ``/auth`` periodically re-checks it with ``GET /api/user/profile``
so deleted accounts and expired tokens lose access. Registration, password
changes, and profile edits happen in the VSDA Deep Agent app.

Standard library only (the container ships plain ``python3``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Callable

LOG = logging.getLogger("vsda-webauth")

SESSION_COOKIE = "llm_wiki_session"
LOGIN_RESULT_COOKIE = "login_result"
MAX_BODY_BYTES = 8 * 1024
MAX_REDIRECT_LENGTH = 2048
# Field limits mirror VSDA Deep Agent's LoginRequest schema.
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 128


# --- Configuration -----------------------------------------------------------


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        LOG.warning("ignoring non-integer %s=%r", name, raw)
        return default


@dataclass(frozen=True)
class Config:
    vsda_api_url: str = "http://127.0.0.1:8000"
    socket_path: str = "/tmp/webauth.sock"
    # "auto" marks cookies Secure when the request arrived over HTTPS.
    cookie_secure: str = "auto"
    revalidate_seconds: int = 60
    offline_grace_seconds: int = 900
    session_max_seconds: int = 24 * 3600
    login_attempts_per_minute: int = 10
    request_timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            vsda_api_url=(
                os.environ.get("LLM_WIKI_VSDA_API_URL", "").strip()
                or cls.vsda_api_url
            ).rstrip("/"),
            socket_path=os.environ.get("LLM_WIKI_AUTH_SOCKET", "").strip()
            or cls.socket_path,
            cookie_secure=(
                os.environ.get("LLM_WIKI_AUTH_COOKIE_SECURE", "").strip().lower()
                or cls.cookie_secure
            ),
            revalidate_seconds=_env_int(
                "LLM_WIKI_AUTH_REVALIDATE_SECONDS", cls.revalidate_seconds
            ),
            offline_grace_seconds=_env_int(
                "LLM_WIKI_AUTH_OFFLINE_GRACE_SECONDS", cls.offline_grace_seconds
            ),
            session_max_seconds=_env_int(
                "LLM_WIKI_AUTH_SESSION_MAX_SECONDS", cls.session_max_seconds, 60
            ),
            login_attempts_per_minute=_env_int(
                "LLM_WIKI_AUTH_LOGIN_ATTEMPTS_PER_MINUTE",
                cls.login_attempts_per_minute,
                1,
            ),
        )


# --- VSDA Deep Agent client --------------------------------------------------


class VsdaUnavailable(Exception):
    """VSDA Deep Agent could not be reached or answered with a server error."""


@dataclass
class VsdaResponse:
    status: int
    body: dict


class VsdaClient:
    def __init__(self, base_url: str, timeout: float) -> None:
        self._base_url = base_url
        self._timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> VsdaResponse:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self._base_url + path, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise VsdaUnavailable(str(exc)) from exc
        if status >= 500:
            raise VsdaUnavailable(f"HTTP {status}")
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}
        return VsdaResponse(status, body if isinstance(body, dict) else {})

    def login(self, username: str, password: str, client_ip: str) -> VsdaResponse:
        return self._request(
            "POST",
            "/api/auth/login",
            payload={"username": username, "password": password},
            headers={"X-Forwarded-For": client_ip, "X-Real-IP": client_ip},
        )

    def profile(self, token: str) -> VsdaResponse:
        return self._request(
            "GET", "/api/user/profile", headers={"Authorization": f"Bearer {token}"}
        )


# --- Session validation cache ------------------------------------------------


@dataclass
class _Entry:
    username: str
    checked_at: float
    last_ok_at: float
    expires_at: float | None


@dataclass
class SessionCache:
    """Remembers recent VSDA token checks so /auth stays cheap.

    nginx runs ``/auth`` for every request (assets, the VNC WebSocket), so a
    successful check is reused for ``revalidate_seconds``. When VSDA Deep Agent
    is unreachable, a session verified within ``offline_grace_seconds`` stays
    valid so a short backend restart does not sign everyone out.
    """

    revalidate_seconds: int
    offline_grace_seconds: int
    max_entries: int = 10_000
    clock: Callable[[], float] = time.time
    _entries: dict[str, _Entry] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _key_locks: dict[str, threading.Lock] = field(default_factory=dict)

    @staticmethod
    def key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def key_lock(self, key: str) -> threading.Lock:
        with self._lock:
            lock = self._key_locks.get(key)
            if lock is None:
                if len(self._key_locks) > self.max_entries:
                    self._key_locks.clear()
                lock = self._key_locks[key] = threading.Lock()
            return lock

    def fresh(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return False
            if entry.expires_at is not None and now >= entry.expires_at:
                del self._entries[key]
                return False
            return now - entry.checked_at < self.revalidate_seconds

    def within_grace(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return False
            if entry.expires_at is not None and now >= entry.expires_at:
                return False
            return now - entry.last_ok_at < self.offline_grace_seconds

    def store(self, key: str, username: str, expires_at: float | None) -> None:
        now = self.clock()
        with self._lock:
            if len(self._entries) >= self.max_entries:
                self._prune(now)
            self._entries[key] = _Entry(username, now, now, expires_at)

    def drop(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def _prune(self, now: float) -> None:
        horizon = max(self.revalidate_seconds, self.offline_grace_seconds)
        for key in [
            k
            for k, e in self._entries.items()
            if now - e.last_ok_at >= horizon
            or (e.expires_at is not None and now >= e.expires_at)
        ]:
            del self._entries[key]
        while len(self._entries) >= self.max_entries:
            self._entries.pop(next(iter(self._entries)))


# --- Login rate limiting -----------------------------------------------------


@dataclass
class LoginRateLimiter:
    """Fixed one-minute window of sign-in attempts per client IP."""

    max_attempts: int
    window_seconds: int = 60
    clock: Callable[[], float] = time.monotonic
    _attempts: dict[str, list[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def allow(self, ip: str) -> bool:
        now = self.clock()
        cutoff = now - self.window_seconds
        with self._lock:
            if len(self._attempts) > 10_000:
                self._attempts = {
                    k: v for k, v in self._attempts.items() if v and v[-1] > cutoff
                }
            recent = [t for t in self._attempts.get(ip, []) if t > cutoff]
            if len(recent) >= self.max_attempts:
                self._attempts[ip] = recent
                return False
            recent.append(now)
            self._attempts[ip] = recent
            return True


# --- Helpers -----------------------------------------------------------------


def parse_cookies(header: str | None) -> dict[str, str]:
    """Lenient Cookie header parser; the last occurrence of a name wins.

    nginx appends ``logout_redirect_url=/`` to the client's cookies on
    ``/logout``, so the trusted value is the last one.
    """
    cookies: dict[str, str] = {}
    for part in (header or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name:
            cookies[name] = urllib.parse.unquote(value.strip().strip('"'))
    return cookies


def safe_redirect(target: str | None, default: str = "/") -> str:
    """Only allow same-origin absolute paths, and never loop back to auth pages."""
    if not target or len(target) > MAX_REDIRECT_LENGTH:
        return default
    if not target.startswith("/") or target.startswith(("//", "/\\")):
        return default
    if any(ord(ch) < 0x20 or ch in "\\\x7f" for ch in target):
        return default
    path = urllib.parse.urlsplit(target).path
    if path in ("/login", "/logout", "/auth") or path.startswith("/login/"):
        return default
    return target


def client_ip(forwarded_for: str | None, real_ip: str | None) -> str:
    """Pick the address the nearest non-loopback proxy reported.

    The chain is ``client -> host nginx -> container nginx -> this service``.
    Each proxy appends what it saw, so the rightmost non-loopback entry is the
    one the host nginx recorded; earlier entries are client-controlled.
    """
    for candidate in reversed((forwarded_for or "").split(",")):
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            if ipaddress.ip_address(candidate).is_loopback:
                continue
        except ValueError:
            continue
        return candidate
    return (real_ip or "").strip() or "unknown"


def token_expiry(token: str) -> float | None:
    """Read ``exp`` from a JWT payload (unverified; VSDA does the real check)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        exp = claims.get("exp") if isinstance(claims, dict) else None
        return float(exp) if isinstance(exp, (int, float)) else None
    except (IndexError, ValueError, binascii.Error):
        return None


# --- HTTP service ------------------------------------------------------------


@dataclass
class AuthService:
    config: Config
    vsda: VsdaClient
    cache: SessionCache
    limiter: LoginRateLimiter
    clock: Callable[[], float] = time.time

    @classmethod
    def from_config(cls, config: Config) -> "AuthService":
        return cls(
            config=config,
            vsda=VsdaClient(config.vsda_api_url, config.request_timeout_seconds),
            cache=SessionCache(
                revalidate_seconds=config.revalidate_seconds,
                offline_grace_seconds=config.offline_grace_seconds,
            ),
            limiter=LoginRateLimiter(config.login_attempts_per_minute),
        )

    def is_authorized(self, token: str | None) -> bool:
        if not token or len(token) > 8192:
            return False
        expires_at = token_expiry(token)
        if expires_at is not None and self.clock() >= expires_at:
            return False
        key = self.cache.key(token)
        if self.cache.fresh(key):
            return True
        # One VSDA call per token at a time; concurrent asset requests wait
        # for it and then hit the fresh cache entry.
        with self.cache.key_lock(key):
            if self.cache.fresh(key):
                return True
            try:
                response = self.vsda.profile(token)
            except VsdaUnavailable as exc:
                allowed = self.cache.within_grace(key)
                LOG.warning(
                    "VSDA Deep Agent unreachable during session check (%s); %s",
                    exc,
                    "within offline grace" if allowed else "denying",
                )
                return allowed
            if response.status == 200:
                self.cache.store(key, str(response.body.get("username", "")), expires_at)
                return True
            self.cache.drop(key)
            return False

    def sign_out(self, token: str | None) -> None:
        if token:
            self.cache.drop(self.cache.key(token))


class Handler(BaseHTTPRequestHandler):
    server_version = "llm-wiki-vsda-webauth"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    service: AuthService  # bound by make_server()

    # Unix sockets have no peer address, which BaseHTTPRequestHandler expects.
    def address_string(self) -> str:
        headers = getattr(self, "headers", None)
        return headers.get("X-Real-IP", "-") if headers else "-"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        LOG.debug("%s %s", self.address_string(), format % args)

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/auth":
            self._auth()
        elif path == "/logout":
            self._logout()
        else:
            self._send(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/login":
            self._login()
        elif path == "/logout":
            self._logout()
        else:
            self._send(HTTPStatus.NOT_FOUND)

    def _auth(self) -> None:
        token = self._cookies().get(SESSION_COOKIE)
        if self.service.is_authorized(token):
            self._send(HTTPStatus.OK)
        else:
            self._send(HTTPStatus.UNAUTHORIZED)

    def _login(self) -> None:
        cookies = self._cookies()
        wants_json = "application/json" in self.headers.get("Accept", "")
        ip = client_ip(self.headers.get("X-Forwarded-For"), self.headers.get("X-Real-IP"))
        success_url = safe_redirect(cookies.get("login_success_url"))

        def fail(status: HTTPStatus, code: str, message: str) -> None:
            if wants_json:
                self._send_json(status, {"ok": False, "error": code, "message": message})
            else:
                self._redirect(
                    "/login/",
                    [self._cookie(LOGIN_RESULT_COOKIE, code, path="/login", max_age=60)],
                )

        if not self.service.limiter.allow(ip):
            LOG.warning("login throttled ip=%s", ip)
            fail(
                HTTPStatus.TOO_MANY_REQUESTS,
                "TOO_MANY_ATTEMPTS",
                "Too many sign-in attempts. Wait a minute and try again.",
            )
            return

        form = self._read_form()
        username = (form.get("username") or "").strip()
        password = form.get("password") or ""
        if (
            not username
            or not password
            or len(username) > MAX_USERNAME_LENGTH
            or len(password) > MAX_PASSWORD_LENGTH
        ):
            fail(
                HTTPStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Incorrect username or password.",
            )
            return

        try:
            response = self.service.vsda.login(username, password, ip)
        except VsdaUnavailable as exc:
            LOG.error("login unavailable user=%s ip=%s: %s", username, ip, exc)
            fail(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                "VSDA Deep Agent sign-in is unavailable right now. Try again shortly.",
            )
            return

        if response.status == 429:
            fail(
                HTTPStatus.TOO_MANY_REQUESTS,
                "TOO_MANY_ATTEMPTS",
                "Too many sign-in attempts. Wait a minute and try again.",
            )
            return
        token = response.body.get("access_token") if response.status == 200 else None
        if not isinstance(token, str) or not token:
            LOG.warning("login failed user=%s ip=%s status=%s", username, ip, response.status)
            fail(
                HTTPStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Incorrect username or password.",
            )
            return

        account = str(response.body.get("username") or username)
        expires_at = token_expiry(token)
        max_age = self.service.config.session_max_seconds
        if expires_at is not None:
            max_age = max(0, min(max_age, int(expires_at - self.service.clock())))
        self.service.cache.store(self.service.cache.key(token), account, expires_at)
        LOG.info("login ok user=%s ip=%s", account, ip)

        set_cookies = [
            self._cookie(SESSION_COOKIE, token, max_age=max_age, http_only=True),
            self._cookie("login_success_url", "", max_age=0),
            self._cookie("login_failure_url", "", max_age=0),
            self._cookie(LOGIN_RESULT_COOKIE, "", path="/login", max_age=0),
        ]
        if wants_json:
            self._send_json(HTTPStatus.OK, {"ok": True, "redirect": success_url}, set_cookies)
        else:
            self._redirect(success_url, set_cookies)

    def _logout(self) -> None:
        cookies = self._cookies()
        self.service.sign_out(cookies.get(SESSION_COOKIE))
        self._redirect(
            safe_redirect(cookies.get("logout_redirect_url")),
            [
                self._cookie(SESSION_COOKIE, "", max_age=0, http_only=True),
                self._cookie(LOGIN_RESULT_COOKIE, "SIGNED_OUT", path="/login", max_age=60),
            ],
        )

    def _cookies(self) -> dict[str, str]:
        return parse_cookies(self.headers.get("Cookie"))

    def _read_form(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        if "application/json" in self.headers.get("Content-Type", ""):
            try:
                data = json.loads(raw)
            except ValueError:
                return {}
            if not isinstance(data, dict):
                return {}
            return {k: v for k, v in data.items() if isinstance(v, str)}
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def _secure(self) -> bool:
        mode = self.service.config.cookie_secure
        if mode in ("1", "true", "yes", "on"):
            return True
        if mode in ("0", "false", "no", "off"):
            return False
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _cookie(
        self,
        name: str,
        value: str,
        *,
        path: str = "/",
        max_age: int | None = None,
        http_only: bool = False,
    ) -> str:
        parts = [f"{name}={urllib.parse.quote(value, safe='')}", f"Path={path}", "SameSite=Lax"]
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        if http_only:
            parts.append("HttpOnly")
        if self._secure():
            parts.append("Secure")
        return "; ".join(parts)

    def _send(
        self,
        status: HTTPStatus,
        headers: list[tuple[str, str]] | None = None,
        body: bytes = b"",
    ) -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        for key, value in headers or []:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(
        self, status: HTTPStatus, payload: dict, cookies: list[str] | None = None
    ) -> None:
        headers = [("Content-Type", "application/json")]
        headers += [("Set-Cookie", c) for c in cookies or []]
        self._send(status, headers, json.dumps(payload).encode())

    def _redirect(self, location: str, cookies: list[str]) -> None:
        self._send(
            HTTPStatus.FOUND,
            [("Location", location)] + [("Set-Cookie", c) for c in cookies],
        )


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    # socketserver's default backlog is 5. nginx sends an /auth subrequest for
    # every one of noVNC's ~60 parallel module loads and connects without
    # blocking, so a full backlog fails with EAGAIN and the page breaks with
    # 500s. The kernel caps this at net.core.somaxconn.
    request_queue_size = 1024


def make_server(service: AuthService, socket_path: str) -> _UnixServer:
    handler = type("BoundHandler", (Handler,), {"service": service})
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    old_umask = os.umask(0o177)  # socket is 0600, like the stock webauth
    try:
        return _UnixServer(socket_path, handler)
    finally:
        os.umask(old_umask)


def main() -> int:
    debug = os.environ.get("CONTAINER_DEBUG", "0").lower() in ("1", "true", "yes", "on")
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="[vsda-webauth] %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    config = Config.from_env()
    server = make_server(AuthService.from_config(config), config.socket_path)
    LOG.info(
        "listening on %s; accounts from VSDA Deep Agent at %s",
        config.socket_path,
        config.vsda_api_url,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

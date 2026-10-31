"""Tests for the VSDA-backed web sign-in service (docker/rootfs/opt/llm-wiki-auth).

Run: python3 -m unittest discover -s docker/tests
"""

from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import logging
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "rootfs"
    / "opt"
    / "llm-wiki-auth"
    / "vsda_webauth.py"
)
_spec = importlib.util.spec_from_file_location("vsda_webauth", MODULE_PATH)
webauth = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = webauth  # dataclasses resolve annotations via sys.modules
_spec.loader.exec_module(webauth)
webauth.LOG.setLevel(logging.CRITICAL)


def make_jwt(exp: float | None, username: str = "alice") -> str:
    def b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    claims = {"sub": "1", "username": username}
    if exp is not None:
        claims["exp"] = int(exp)
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(claims)}.signature"


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


# --- Pure helpers ------------------------------------------------------------


class SafeRedirectTest(unittest.TestCase):
    def test_allows_same_origin_paths(self):
        for target in ("/", "/index.html", "/websockify?x=1", "/a/b#frag"):
            self.assertEqual(webauth.safe_redirect(target), target)

    def test_rejects_offsite_and_malformed(self):
        for target in (
            None,
            "",
            "https://evil.example/",
            "//evil.example/",
            "/\\evil.example",
            "/a\\b",
            "javascript:alert(1)",
            "relative/path",
            "/a\r\nSet-Cookie: x=1",
            "/" + "a" * 3000,
        ):
            self.assertEqual(webauth.safe_redirect(target), "/", target)

    def test_never_loops_back_to_auth_pages(self):
        for target in ("/login", "/login/", "/login/login", "/logout", "/auth", "/login/?x"):
            self.assertEqual(webauth.safe_redirect(target), "/", target)


class ClientIpTest(unittest.TestCase):
    def test_rightmost_non_loopback_entry(self):
        self.assertEqual(
            webauth.client_ip("6.6.6.6, 203.0.113.9, 127.0.0.1", "127.0.0.1"),
            "203.0.113.9",
        )

    def test_ignores_garbage_and_falls_back_to_real_ip(self):
        self.assertEqual(webauth.client_ip("not-an-ip, ::1", "10.0.0.2"), "10.0.0.2")
        self.assertEqual(webauth.client_ip(None, None), "unknown")


class ParseCookiesTest(unittest.TestCase):
    def test_last_occurrence_wins(self):
        cookies = webauth.parse_cookies(
            "logout_redirect_url=https://evil; a=1; logout_redirect_url=/"
        )
        self.assertEqual(cookies["logout_redirect_url"], "/")
        self.assertEqual(cookies["a"], "1")

    def test_decodes_and_tolerates_junk(self):
        cookies = webauth.parse_cookies('x="%2Fpath%3Fq"; ;novalue; y=')
        self.assertEqual(cookies, {"x": "/path?q", "y": ""})


class TokenExpiryTest(unittest.TestCase):
    def test_reads_exp(self):
        self.assertEqual(webauth.token_expiry(make_jwt(1234567890)), 1234567890.0)

    def test_missing_or_malformed(self):
        self.assertIsNone(webauth.token_expiry(make_jwt(None)))
        self.assertIsNone(webauth.token_expiry("garbage"))
        self.assertIsNone(webauth.token_expiry("a.!!!.c"))


class SessionCacheTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.cache = webauth.SessionCache(
            revalidate_seconds=60, offline_grace_seconds=900, clock=self.clock
        )

    def test_fresh_then_stale_then_grace(self):
        self.cache.store("k", "alice", None)
        self.assertTrue(self.cache.fresh("k"))
        self.clock.now += 61
        self.assertFalse(self.cache.fresh("k"))
        self.assertTrue(self.cache.within_grace("k"))
        self.clock.now += 900
        self.assertFalse(self.cache.within_grace("k"))

    def test_expired_token_is_never_fresh(self):
        self.cache.store("k", "alice", self.clock.now + 10)
        self.clock.now += 11
        self.assertFalse(self.cache.fresh("k"))
        self.assertFalse(self.cache.within_grace("k"))

    def test_drop(self):
        self.cache.store("k", "alice", None)
        self.cache.drop("k")
        self.assertFalse(self.cache.fresh("k"))


class RateLimiterTest(unittest.TestCase):
    def test_window(self):
        clock = FakeClock()
        limiter = webauth.LoginRateLimiter(max_attempts=3, clock=clock)
        self.assertTrue(all(limiter.allow("1.2.3.4") for _ in range(3)))
        self.assertFalse(limiter.allow("1.2.3.4"))
        self.assertTrue(limiter.allow("5.6.7.8"))
        clock.now += 61
        self.assertTrue(limiter.allow("1.2.3.4"))


# --- End to end over the unix socket, against a fake VSDA Deep Agent ------------


class FakeVsda:
    """Mimics VSDA Deep Agent's /api/auth/login and /api/user/profile."""

    def __init__(self) -> None:
        self.users = {"alice": "correct horse"}
        self.valid_tokens: set[str] = set()
        self.down = False
        self.login_status_override: int | None = None
        self.profile_calls = 0
        self.login_headers: list[dict[str, str]] = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _json(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if fake.down:
                    return self._json(503, {"detail": "down"})
                length = int(self.headers.get("Content-Length") or 0)
                data = json.loads(self.rfile.read(length) or b"{}")
                fake.login_headers.append(dict(self.headers))
                if fake.login_status_override:
                    return self._json(fake.login_status_override, {"detail": "x"})
                if self.path != "/api/auth/login":
                    return self._json(404, {})
                if fake.users.get(data.get("username")) != data.get("password"):
                    return self._json(401, {"detail": "Invalid username or password"})
                token = make_jwt(time.time() + 3600, data["username"])
                fake.valid_tokens.add(token)
                return self._json(
                    200,
                    {
                        "access_token": token,
                        "user_id": 1,
                        "username": data["username"],
                        "role": "user",
                        "email": None,
                    },
                )

            def do_GET(self):
                if fake.down:
                    return self._json(503, {"detail": "down"})
                if self.path != "/api/user/profile":
                    return self._json(404, {})
                fake.profile_calls += 1
                auth = self.headers.get("Authorization", "")
                token = auth.split(" ", 1)[1] if " " in auth else ""
                if token in fake.valid_tokens:
                    return self._json(200, {"username": "alice"})
                return self._json(401, {"detail": "Could not validate credentials"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=10)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self._path)


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.vsda = FakeVsda()
        self.tmp = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.tmp.name, "webauth.sock")
        self.clock = FakeClock(time.time())
        config = webauth.Config(
            vsda_api_url=self.vsda.url,
            socket_path=self.sock_path,
            revalidate_seconds=60,
            offline_grace_seconds=900,
            login_attempts_per_minute=5,
            request_timeout_seconds=5,
        )
        service = webauth.AuthService.from_config(config)
        service.clock = self.clock
        service.cache.clock = self.clock
        self.service = service
        self.server = webauth.make_server(service, self.sock_path)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.vsda.close()
        self.tmp.cleanup()

    def request(self, method, path, *, body=None, headers=None):
        conn = UnixHTTPConnection(self.sock_path)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            data = response.read()
            return response, data
        finally:
            conn.close()

    def login(self, username="alice", password="correct horse", *, json_api=True, extra=None):
        body = f"username={username}&password={password}".replace(" ", "+")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Forwarded-For": "203.0.113.7, 127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "Cookie": "login_success_url=/index.html?a=1; login_failure_url=/login/",
        }
        if json_api:
            headers["Accept"] = "application/json"
        headers.update(extra or {})
        return self.request("POST", "/login", body=body, headers=headers)

    @staticmethod
    def session_cookie(response) -> str:
        for header in response.headers.get_all("Set-Cookie"):
            if header.startswith("llm_wiki_session="):
                return header
        raise AssertionError("no session cookie")

    def auth(self, token):
        cookie = {"Cookie": f"llm_wiki_session={token}"} if token is not None else {}
        response, _ = self.request("GET", "/auth", headers=cookie)
        return response.status

    def test_socket_is_private(self):
        self.assertEqual(os.stat(self.sock_path).st_mode & 0o777, 0o600)

    def test_json_login_success_sets_session_and_redirect(self):
        response, data = self.login()
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(data), {"ok": True, "redirect": "/index.html?a=1"})
        cookie = self.session_cookie(response)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)
        max_age = int(cookie.split("Max-Age=")[1].split(";")[0])
        self.assertTrue(3500 <= max_age <= 3600, max_age)
        cleared = "; ".join(response.headers.get_all("Set-Cookie"))
        self.assertIn("login_success_url=; Path=/", cleared)
        self.assertIn("login_failure_url=; Path=/", cleared)
        # Client IP forwarded to VSDA is the one the host proxy saw.
        self.assertEqual(self.vsda.login_headers[-1]["X-Forwarded-For"], "203.0.113.7")

    def test_secure_cookie_behind_https_proxy(self):
        response, _ = self.login(extra={"X-Forwarded-Proto": "https"})
        self.assertIn("Secure", self.session_cookie(response))

    def test_form_login_redirects(self):
        response, _ = self.login(json_api=False)
        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers["Location"], "/index.html?a=1")

    def test_bad_password_json_and_form(self):
        response, data = self.login(password="nope")
        self.assertEqual(response.status, 401)
        self.assertEqual(json.loads(data)["error"], "INVALID_CREDENTIALS")
        self.assertFalse(
            any(h.startswith("llm_wiki_session=") for h in response.headers.get_all("Set-Cookie") or [])
        )
        response, _ = self.login(password="nope", json_api=False)
        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers["Location"], "/login/")
        self.assertIn(
            "login_result=INVALID_CREDENTIALS; Path=/login",
            response.headers["Set-Cookie"],
        )

    def test_empty_and_oversized_fields_never_reach_vsda(self):
        for username, password in (("", "x"), ("alice", ""), ("a" * 65, "x"), ("alice", "p" * 129)):
            response, data = self.login(username=username, password=password)
            self.assertEqual(response.status, 401)
        self.assertEqual(self.vsda.login_headers, [])

    def test_json_body_login(self):
        response, data = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "alice", "password": "correct horse"}),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(data)["redirect"], "/")

    def test_rate_limit(self):
        for _ in range(5):
            self.login(password="nope")
        response, data = self.login()
        self.assertEqual(response.status, 429)
        self.assertEqual(json.loads(data)["error"], "TOO_MANY_ATTEMPTS")

    def test_vsda_rate_limit_is_reported(self):
        self.vsda.login_status_override = 429
        response, data = self.login()
        self.assertEqual(response.status, 429)

    def test_vsda_down_during_login(self):
        self.vsda.down = True
        response, data = self.login()
        self.assertEqual(response.status, 503)
        self.assertEqual(json.loads(data)["error"], "SERVICE_UNAVAILABLE")

    def test_auth_flow_caching_and_revocation(self):
        response, _ = self.login()
        token = self.session_cookie(response).split(";")[0].split("=", 1)[1]
        self.assertEqual(self.auth(None), 401)
        self.assertEqual(self.auth("not-a-token"), 401)  # VSDA rejects it
        self.vsda.profile_calls = 0
        # Fresh from login: no VSDA call needed.
        self.assertEqual(self.auth(token), 200)
        self.assertEqual(self.vsda.profile_calls, 0)
        # After the revalidation window, VSDA is asked again.
        self.clock.now += 61
        self.assertEqual(self.auth(token), 200)
        self.assertEqual(self.vsda.profile_calls, 1)
        # Account deleted / token revoked in VSDA: access ends on next check.
        self.vsda.valid_tokens.clear()
        self.clock.now += 61
        self.assertEqual(self.auth(token), 401)
        # And stays denied, even if VSDA then goes down.
        self.vsda.down = True
        self.assertEqual(self.auth(token), 401)

    def test_offline_grace(self):
        response, _ = self.login()
        token = self.session_cookie(response).split(";")[0].split("=", 1)[1]
        self.vsda.down = True
        self.clock.now += 300
        self.assertEqual(self.auth(token), 200)
        self.clock.now += 700
        self.assertEqual(self.auth(token), 401)

    def test_expired_token_rejected_without_vsda_call(self):
        token = make_jwt(self.clock.now - 1)
        self.vsda.valid_tokens.add(token)
        self.assertEqual(self.auth(token), 401)
        self.assertEqual(self.vsda.profile_calls, 0)

    def test_unknown_token_checked_with_vsda(self):
        token = make_jwt(self.clock.now + 600)
        self.vsda.valid_tokens.add(token)
        self.assertEqual(self.auth(token), 200)
        self.assertEqual(self.vsda.profile_calls, 1)

    def test_logout(self):
        response, _ = self.login()
        token = self.session_cookie(response).split(";")[0].split("=", 1)[1]
        response, _ = self.request(
            "GET",
            "/logout",
            headers={"Cookie": f"llm_wiki_session={token};logout_redirect_url=//evil;logout_redirect_url=/"},
        )
        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers["Location"], "/")
        cookies = response.headers.get_all("Set-Cookie")
        self.assertIn("llm_wiki_session=; Path=/; SameSite=Lax; Max-Age=0; HttpOnly", cookies)
        self.assertTrue(any(c.startswith("login_result=SIGNED_OUT; Path=/login") for c in cookies))
        # The cache entry is gone, so the next /auth asks VSDA again.
        self.assertEqual(self.auth(token), 200)
        self.assertEqual(self.vsda.profile_calls, 1)

    def test_unknown_paths(self):
        response, _ = self.request("GET", "/login")
        self.assertEqual(response.status, 404)
        response, _ = self.request("POST", "/auth")
        self.assertEqual(response.status, 404)


class ListenBacklogTest(unittest.TestCase):
    """noVNC loads ~60 ES modules at once and nginx sends an /auth subrequest
    for each. nginx connects without blocking, so a full listen backlog fails
    with EAGAIN, the subrequest becomes a 500, and the page never loads."""

    def test_burst_of_auth_connections_is_queued(self):
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = os.path.join(tmp, "webauth.sock")
            config = webauth.Config(socket_path=sock_path)
            server = webauth.make_server(webauth.AuthService.from_config(config), sock_path)
            clients = []
            try:
                # The accept loop is not running, so only the backlog holds these.
                for _ in range(128):
                    client = socket.socket(socket.AF_UNIX)
                    client.setblocking(False)
                    clients.append(client)
                    client.connect(sock_path)
            finally:
                for client in clients:
                    client.close()
                server.server_close()


if __name__ == "__main__":
    unittest.main()

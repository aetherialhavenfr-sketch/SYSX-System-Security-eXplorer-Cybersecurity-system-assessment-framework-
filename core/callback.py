"""A tiny operator-controlled HTTP listener used to confirm SSRF out of band.

SSRF is confirmed in exactly one way: the target is given a URL that points at *this* listener,
carrying a one-time random token, and the listener sees that token arrive. SYSX never aims the
target at cloud-metadata addresses, internal hosts or any third party. The listener records only
the token, the caller's address and the User-Agent; it never serves or stores anything else.

It is started lazily, only when a scan actually needs it, and is configured by the operator:
``SYSX_CALLBACK_URL`` is the base URL the *target* can use to reach this machine and
``SYSX_CALLBACK_BIND`` is the local address to listen on (default 127.0.0.1).
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_TOKEN = re.compile(r"^/([0-9a-f]{24})(?:[/?].*)?$")
MAX_HITS = 2000


class CallbackError(RuntimeError):
    pass


class CallbackServer:
    def __init__(self, public_url: str | None = None, bind_host: str = "127.0.0.1", bind_port: int | None = None):
        """``public_url`` may omit the port when ``bind_port`` is 0: the real port is filled in once bound."""
        self.bind_host = bind_host
        self._public = public_url.rstrip("/") if public_url else None
        self._requested_port = bind_port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._hits: dict[str, list[dict]] = {}
        self._issued: set[str] = set()
        self._lock = threading.Lock()
        self.port: int | None = None

    # -- lifecycle -----------------------------------------------------------
    @property
    def configured(self) -> bool:
        return self._public is not None

    def start(self) -> "CallbackServer":
        if self._server is not None:
            return self
        if not self.configured:
            raise CallbackError("No callback URL configured (set SYSX_CALLBACK_URL).")
        port = self._requested_port
        if port is None:
            port = urlsplit(self._public).port or 80
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib naming
                match = _TOKEN.match(self.path)
                if match:
                    owner._record(match.group(1), self.client_address[0], self.headers.get("User-Agent", "")[:200])
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_HEAD = do_GET  # noqa: N815

            def log_message(self, *args):  # silence stderr logging
                pass

        try:
            self._server = ThreadingHTTPServer((self.bind_host, port), Handler)
        except OSError as exc:
            raise CallbackError(f"Cannot listen on {self.bind_host}:{port}: {exc}") from exc
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name="sysx-callback", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- tokens ----------------------------------------------------------------
    def new_token(self) -> str:
        token = secrets.token_hex(12)
        with self._lock:
            self._issued.add(token)
        return token

    def url_for(self, token: str) -> str:
        if self._server is None:
            raise CallbackError("Callback listener is not running.")
        base = self._public
        parts = urlsplit(base)
        if parts.port is None and self._requested_port == 0:
            base = f"{parts.scheme}://{parts.hostname}:{self.port}"
        return f"{base}/{token}"

    def _record(self, token: str, addr: str, user_agent: str) -> None:
        with self._lock:
            if token not in self._issued:
                return  # only tokens SYSX itself issued count
            if sum(len(v) for v in self._hits.values()) >= MAX_HITS:
                return
            self._hits.setdefault(token, []).append({"addr": addr, "user_agent": user_agent, "at": time.time()})

    def hits(self, token: str) -> list[dict]:
        with self._lock:
            return list(self._hits.get(token, []))

    def wait_for(self, token: str, timeout: float = 4.0, poll: float = 0.05, cancelled=lambda: False) -> list[dict]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = self.hits(token)
            if found or cancelled():
                return found
            time.sleep(poll)
        return self.hits(token)

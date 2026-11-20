"""A local HTTP stand-in for the PDP on 127.0.0.1 (no network), answering what each test sets in `reply`."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _answer(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers),
                                     "body": json.loads(body) if body else None})
        status, payload, headers = self.server.reply(self.path, self.server.requests[-1]["body"])
        if self.server.delay:
            time.sleep(self.server.delay)
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        for name, value in {"content-type": "application/json", **headers}.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _answer


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):  # a client that gave up (timeout tests) is expected
        pass


class FakePdp:
    def __init__(self):
        self.server = _Server(("127.0.0.1", 0), _Handler)
        self.server.requests = []
        self.server.delay = 0
        self.server.reply = lambda path, body: (200, {}, {})
        threading.Thread(target=self.server.serve_forever, args=(0.05,), daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    @property
    def requests(self):
        return self.server.requests

    def answer(self, payload, status=200, headers=None):
        self.server.reply = lambda path, body: (status, payload, headers or {})

    def set_reply(self, reply):
        self.server.reply = reply

    def set_delay(self, seconds):
        self.server.delay = seconds

    def close(self):
        self.server.shutdown()
        self.server.server_close()

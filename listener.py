"""
listener.py
A tiny HTTP listener you run on your own machine. Every request that hits
it is logged with time + source. Used for out-of-band (OOB) XXE proof:
if the lab app's XML parser follows our external entity, IT will make a
request to this listener - and we'll see it land here.
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class Hit:
    def __init__(self, method, path, source, when):
        self.method = method
        self.path = path
        self.source = source
        self.when = when

    def as_dict(self):
        return {
            "method": self.method,
            "path": self.path,
            "source": self.source,
            "time": self.when,
        }


class XXEListener:
    def __init__(self, host="127.0.0.1", port=8000):
        self.host = host
        self.port = port
        self.hits = []
        self._server = None
        self._thread = None
        hits_ref = self.hits

        class Handler(BaseHTTPRequestHandler):
            def _record(self):
                hits_ref.append(
                    Hit(
                        method=self.command,
                        path=self.path,
                        source=self.client_address[0],
                        when=time.strftime("%Y-%m-%d %H:%M:%S"),
                    )
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def do_GET(self):
                self._record()

            def do_POST(self):
                self._record()

            def log_message(self, fmt, *args):
                pass  # keep console quiet; we log into self.hits instead

        self._handler_cls = Handler

    @property
    def url(self):
        return f"http://{self.host}:{self.port}/xxeprobe-callback"

    def start(self):
        self._server = HTTPServer((self.host, self.port), self._handler_cls)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def had_hit(self):
        return len(self.hits) > 0


if __name__ == "__main__":
    # Manual test: run this file, then browse to the printed URL yourself.
    l = XXEListener()
    l.start()
    print(f"Listener running at {l.url}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
            if l.hits:
                print("HIT:", l.hits[-1].as_dict())
                l.hits.clear()
    except KeyboardInterrupt:
        l.stop()

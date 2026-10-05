"""Dashboard HTTP layer: bad input must produce a clean JSON error, never a crashed handler or an unbounded read."""
import base64
import collections
import http.client
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path


class StubDetector:
    def __init__(self):
        self.enabled, self.conf, self._want, self.imgsz, self.enhance = True, 0.3, "general", 640, False
        self.custom_vocab = ["pencil"]
        self.latest = {"seq": 1, "dets": [], "frame_ts": time.time()}
        self.taught = []

    def configure(self, profile=None, vocab=None, conf=None, imgsz=None, enhance=None):
        if profile not in (None, "general", "fast"):
            raise ValueError("profile must be one of ['fast', 'general']")
        if vocab == "":
            raise ValueError("vocabulary is empty")

    def teach(self, name, jpeg, box):
        if not name:
            raise ValueError("name must be letters, digits, spaces, '-' or '_'")
        self.taught.append(name)
        return {"name": name, "examples": 1}

    def forget(self, name=None):
        self.taught.clear()
        return {"removed": 1}


class StubStore:
    path = Path("/nonexistent")

    def event(self, *a): pass

    def query(self, sql, args=()):
        if "ORDER BY ts DESC LIMIT" in sql:
            return [{"ts": 1.0}] * min(args[0], 3)
        return []


class TestHttpApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from kyber6g.ground.main import GroundApp, make_handler
        app = GroundApp.__new__(GroundApp)                       # no keys, UDP socket or camera needed for the HTTP layer
        app.detector, app.finder, app.store = StubDetector(), None, StubStore()
        app.log = collections.deque(maxlen=50)
        app.data = Path(tempfile.mkdtemp())
        app.home = app.last_fix = app.home_source = None
        app.command = lambda cmd, args, timeout=20: {"ok": True, "result": {"echo": cmd}}
        app.detections_latest = lambda: {**app.detector.latest, "now": time.time()}
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
        cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def req(self, method, path, body=None, raw=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        c.request(method, path, body=data, headers=headers or ({"Content-Type": "application/json"} if data else {}))
        r = c.getresponse()
        txt = r.read()
        c.close()
        try:
            return r.status, json.loads(txt)
        except ValueError:
            return r.status, txt

    def test_unknown_paths_and_traversal(self):
        self.assertEqual(self.req("GET", "/nope")[0], 404)
        self.assertEqual(self.req("GET", "/static/../../etc/passwd")[0], 404)
        self.assertEqual(self.req("GET", "/static/..%2f..%2fetc%2fpasswd")[0], 404)
        self.assertEqual(self.req("GET", "/images/..%2f..%2f.kyber6g%2fgcs_ML-DSA-87.sk")[0], 404)
        s, body = self.req("GET", "/static/index.html")
        self.assertEqual(s, 200)
        self.assertIn(b"KYBER-6G GROUND STATION", body)

    def test_static_files_the_page_needs(self):
        for f in ("app.js", "boxtracker.js", "voxel.js"):
            s, body = self.req("GET", f"/static/{f}")
            self.assertEqual(s, 200, f)
            self.assertGreater(len(body), 500)

    def test_bad_post_bodies(self):
        self.assertEqual(self.req("POST", "/api/cmd", raw=b"{not json")[0], 400)
        for not_a_command in (b"[1, 2]", b'"start_live"', b"5", b"null", b'{"cmd": 5}', b'{"cmd": ["start_live"]}'):
            s, r = self.req("POST", "/api/cmd", raw=not_a_command)                              # valid JSON, wrong shape
            self.assertEqual((s, r.get("ok")), (400, False), not_a_command)
        self.assertEqual(self.req("POST", "/api/cmd", body={"cmd": "format_disk"})[0], 400)
        self.assertEqual(self.req("POST", "/api/cmd", body={"cmd": "status", "args": [1, 2]})[0], 400)
        try:                                                                                    # refused before reading the body:
            self.assertEqual(self.req("POST", "/api/cmd", raw=b"x" * 5_000_000)[0], 413)       # either the 413 arrives ...
        except (BrokenPipeError, ConnectionResetError):                                         # ... or the socket is closed on us
            pass
        self.assertEqual(self.req("GET", "/api/detections/latest")[0], 200)                    # and the server is still serving
        self.assertEqual(self.req("POST", "/api/cmd", body={"cmd": "start_rec", "args": {"pad": "x" * 70_000}})[0], 400)  # only 'detector' may be big
        self.assertEqual(self.req("POST", "/nope", body={})[0], 404)

    def test_detector_command_validation(self):
        s, r = self.req("POST", "/api/cmd", body={"cmd": "detector", "args": {"profile": "nonsense"}})
        self.assertEqual((s, r["ok"]), (200, False))
        s, r = self.req("POST", "/api/cmd", body={"cmd": "detector", "args": {"profile": "fast", "conf": 0.4}})
        self.assertEqual((s, r["ok"]), (200, True))
        for bad in ({"name": "pencil", "box": [0.1, 0.1, 0.3, 0.6], "image": "!!!not-base64!!!"},
                    {"name": "pencil", "box": [0.1, 0.1, 0.3, 0.6], "image": base64.b64encode(b"not a jpeg").decode()},
                    {"name": "pencil", "box": [0.1, 0.1, 0.3, 0.6]}):
            s, r = self.req("POST", "/api/cmd", body={"cmd": "detector", "args": {"teach": bad}})
            self.assertEqual((s, r["ok"]), (200, False), bad)
        jpeg = base64.b64encode(b"\xff\xd8" + b"\x00" * 100).decode()
        s, r = self.req("POST", "/api/cmd", body={"cmd": "detector", "args": {"teach": {"name": "pencil", "box": [0.1, 0.1, 0.3, 0.6], "image": jpeg}}})
        self.assertEqual((s, r["ok"], r["result"]["name"]), (200, True, "pencil"))
        s, r = self.req("POST", "/api/cmd", body={"cmd": "detector", "args": {"teach": {"name": "", "box": [0, 0, 1, 1], "image": jpeg}}})
        self.assertFalse(r["ok"])                                                              # ValueError from the detector -> ok:false
        s, r = self.req("POST", "/api/cmd", body={"cmd": "finder", "args": {"enabled": True}})
        self.assertEqual((s, r["ok"]), (200, False))                                           # finder disabled in this stub

    def test_server_survives_a_failing_query(self):
        s, r = self.req("GET", "/api/telemetry?latest=abc")                                    # int('abc') -> handled, JSON 400
        self.assertEqual(s, 400)
        self.assertIn("error", r)
        s, r = self.req("GET", "/api/series?minutes=abc")
        self.assertEqual(s, 400)
        s, r = self.req("GET", "/api/telemetry?latest=2")                                      # and the next request still works
        self.assertEqual((s, len(r)), (200, 2))
        s, r = self.req("GET", "/api/detections/latest")
        self.assertEqual(s, 200)
        self.assertIn("now", r)


if __name__ == "__main__":
    unittest.main()

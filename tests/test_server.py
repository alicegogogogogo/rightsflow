import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from rightsflow.clock import FixedClock
from rightsflow.server import Handler
from rightsflow.service import RightsFlow


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        Handler.service = RightsFlow(str(Path(self.directory.name) / "http.db"), clock=FixedClock("2026-01-01T00:00:00Z"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.directory.cleanup()

    def call(self, method, path, body=None, key=None, content_type="application/json"):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if body is not None:
            headers["Content-Type"] = content_type
        if key:
            headers["Idempotency-Key"] = key
        connection.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
        response = connection.getresponse()
        document = json.loads(response.read())
        connection.close()
        return response.status, document

    def test_health_and_full_lifecycle_over_http(self):
        self.assertEqual((200, {"status": "ok"}), self.call("GET", "/health"))
        status, policy = self.call("POST", "/policies", {"id": "eu", "retention_days": 30, "action": "delete"}, key="p1")
        self.assertEqual((201, "eu"), (status, policy["id"]))
        status, request = self.call("POST", "/requests", {"id": "req-http", "subject_id": "user-1",
                                                          "request_type": "portability", "policy_id": "eu",
                                                          "sla_days": 30, "actor": "agent"}, key="r1")
        self.assertEqual((201, "received"), (status, request["state"]))
        status, moved = self.call("POST", "/requests/req-http/transitions", {"action": "verify_identity", "actor": "dpo"}, key="t1")
        self.assertEqual((200, "identity_verified"), (status, moved["state"]))
        self.assertEqual(2, self.call("GET", "/requests/req-http/evidence")[1]["count"])
        self.assertEqual("req-http", self.call("GET", "/requests/req-http")[1]["id"])
        self.assertEqual([], self.call("GET", "/policy/eu/due")[1]["due"])
        self.assertEqual(0, self.call("GET", "/subjects/user-1/records")[1]["count"])

    def test_error_bodies_and_strictness_over_http(self):
        self.assertEqual((404, {"error": {"code": "not_found", "message": "route was not found"}}), self.call("GET", "/nope"))
        status, body = self.call("POST", "/policies", {"id": "eu", "retention_days": 1, "action": "delete"})
        self.assertEqual((400, "validation_error"), (status, body["error"]["code"]))
        self.call("POST", "/policies", {"id": "eu", "retention_days": 1, "action": "delete"}, key="p1")
        status, body = self.call("POST", "/policies", {"id": "eu", "retention_days": 1, "action": "delete"}, key="p2")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))
        status, body = self.call("POST", "/evidence/verify", {"entries": []})
        self.assertEqual((200, {"chain_valid": True, "count": 0, "head": None,
                                "first_invalid_sequence": None, "reason": None}), (status, body))

    def test_content_type_and_query_parameters_are_enforced(self):
        status, body = self.call("POST", "/policies", "{}", key="p1", content_type="text/plain")
        self.assertEqual((400, "Content-Type must be application/json"), (status, body["error"]["message"]))
        self.call("POST", "/policies", {"id": "eu", "retention_days": 1, "action": "delete"}, key="p2")
        status, body = self.call("GET", "/policy/eu/due?when=2026-02-01T00:00:00Z")
        self.assertEqual((400, "unknown query parameter(s): when"), (status, body["error"]["message"]))
        self.assertEqual("2026-02-01T00:00:00Z", self.call("GET", "/policy/eu/due?at=2026-02-01T00:00:00Z")[1]["at"])


if __name__ == "__main__":
    unittest.main()

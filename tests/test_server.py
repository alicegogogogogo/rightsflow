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

    def test_retrieval_tasks_over_http(self):
        self.call("POST", "/policies", {"id": "eu", "retention_days": 30, "action": "delete"}, key="p1")
        self.call("POST", "/requests", {"id": "req-1", "subject_id": "user-1", "request_type": "access",
                                        "policy_id": "eu", "sla_days": 30, "actor": "agent"}, key="r1")
        status, task = self.call("POST", "/requests/req-1/retrieval-tasks",
                                 {"id": "t-1", "system": "crm", "query": "email = x", "actor": "agent"}, key="rt1")
        self.assertEqual((201, "queued", None), (status, task["status"], task["started_at"]))
        status, body = self.call("POST", "/requests/req-1/retrieval-tasks",
                                 {"id": "t-1", "system": "crm", "query": "email = x", "actor": "agent"}, key="rt2")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))
        status, started = self.call("POST", "/requests/req-1/retrieval-tasks/t-1/start", {"actor": "w"}, key="rt3")
        self.assertEqual((200, "running", "2026-01-01T00:00:00Z"),
                         (status, started["status"], started["started_at"]))
        status, body = self.call("POST", "/requests/req-1/retrieval-tasks/t-1/start", {"actor": "w"}, key="rt4")
        self.assertEqual((409, "illegal_transition"), (status, body["error"]["code"]))
        status, done = self.call("POST", "/requests/req-1/retrieval-tasks/t-1/complete",
                                 {"actor": "w", "records": [{"id": "r-1", "payload": {"a": 1}}]}, key="rt5")
        self.assertEqual((200, "succeeded"), (status, done["status"]))
        status, listing = self.call("GET", "/requests/req-1/retrieval-tasks")
        self.assertEqual((200, 1, 100), (status, listing["totals"]["total"], listing["totals"]["progress_percent"]))
        status, body = self.call("GET", "/requests/ghost/retrieval-tasks")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))
        status, body = self.call("POST", "/requests/req-1/retrieval-tasks/ghost/fail",
                                 {"actor": "w", "reason": "x"}, key="rt6")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))
        self.assertEqual("received", self.call("GET", "/requests/req-1")[1]["state"])

    def test_sla_alerts_over_http(self):
        self.call("POST", "/policies", {"id": "eu", "retention_days": 30, "action": "delete"}, key="p1")
        self.call("POST", "/requests", {"id": "req-1", "subject_id": "user-1", "request_type": "access",
                                        "policy_id": "eu", "sla_days": 30, "actor": "agent"}, key="r1")
        status, body = self.call("POST", "/requests/req-1/sla-alerts", {"actor": "m", "reason": "late"}, key="a1")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))
        status, body = self.call("POST", "/requests/ghost/sla-alerts", {"actor": "m", "reason": "late"}, key="a2")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))
        status, body = self.call("POST", "/requests/req-1/sla-alerts", {"actor": "m"}, key="a3")
        self.assertEqual((400, "validation_error"), (status, body["error"]["code"]))
        Handler.service.clock.advance(days=31)
        status, alert = self.call("POST", "/requests/req-1/sla-alerts", {"actor": "m", "reason": "late"}, key="a4")
        self.assertEqual((201, "open", "2026-02-01T00:00:00Z", 86400),
                         (status, alert["status"], alert["detected_at"], alert["overdue_seconds"]))
        status, body = self.call("POST", "/requests/req-1/sla-alerts", {"actor": "m", "reason": "late"}, key="a5")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))
        status, listing = self.call("GET", "/requests/req-1/sla-alerts")
        self.assertEqual((200, 1, 1, 0), (status, listing["totals"]["total"],
                                          listing["totals"]["open"], listing["totals"]["acknowledged"]))
        self.assertEqual(alert["alert_id"], listing["alerts"][0]["alert_id"])
        status, body = self.call("GET", "/requests/ghost/sla-alerts")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))
        status, acknowledged = self.call("POST", f"/sla-alerts/{alert['alert_id']}/acknowledge",
                                         {"actor": "dpo", "note": "on it"}, key="a6")
        self.assertEqual((200, "acknowledged", "dpo", "on it"),
                         (status, acknowledged["status"], acknowledged["acknowledged_by"],
                          acknowledged["acknowledged_note"]))
        self.assertEqual((alert["due_at"], alert["detected_at"], alert["overdue_seconds"]),
                         (acknowledged["due_at"], acknowledged["detected_at"], acknowledged["overdue_seconds"]))
        status, body = self.call("POST", f"/sla-alerts/{alert['alert_id']}/acknowledge",
                                 {"actor": "dpo", "note": "again"}, key="a7")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))
        status, body = self.call("POST", "/sla-alerts/ghost/acknowledge", {"actor": "dpo", "note": "x"}, key="a8")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))
        self.assertEqual("received", self.call("GET", "/requests/req-1")[1]["state"])
        self.assertEqual(1, self.call("GET", "/requests/req-1/evidence")[1]["count"])

    def test_audit_export_over_http(self):
        from rightsflow.evidence import canonical_json, sha256_hex
        status, export = self.call("GET", "/audit/export")
        self.assertEqual((200, None, [], [], [], {"requests": 0, "evidence": 0, "records": 0}),
                         (status, export["filter"], export["requests"], export["evidence"],
                          export["records"], export["totals"]))
        self.call("POST", "/policies", {"id": "eu", "retention_days": 30, "action": "delete"}, key="p1")
        self.call("POST", "/requests", {"id": "req-1", "subject_id": "user-1", "request_type": "access",
                                        "policy_id": "eu", "sla_days": 30, "actor": "agent"}, key="r1")
        self.call("POST", "/requests", {"id": "req-2", "subject_id": "user-2", "request_type": "erasure",
                                        "policy_id": "eu", "sla_days": 30, "actor": "agent"}, key="r2")
        self.call("POST", "/requests/req-1/transitions", {"action": "verify_identity", "actor": "dpo"}, key="t1")
        self.call("POST", "/requests/req-1/transitions", {"action": "scope", "actor": "dpo"}, key="t2")
        self.call("POST", "/requests/req-1/transitions",
                  {"action": "collect", "actor": "agent",
                   "details": {"records": [{"id": "rec-1", "payload": {"email": "a@b.c"}}]}}, key="t3")
        status, export = self.call("GET", "/audit/export")
        self.assertEqual(200, status)
        self.assertEqual(("2026-01-01T00:00:00Z", None), (export["generated_at"], export["filter"]))
        self.assertEqual(["req-1", "req-2"], [request["id"] for request in export["requests"]])
        first = export["requests"][0]
        self.assertEqual(("req-1", "user-1", "collected", None),
                         (first["id"], first["subject_id"], first["state"], first["first_invalid_sequence"]))
        self.assertEqual(first["evidence_head"], export["evidence"][-2]["hash"])
        self.assertEqual({("req-1", 1), ("req-1", 2), ("req-1", 3), ("req-1", 4), ("req-2", 1)},
                         {(entry["content"]["request_id"], entry["content"]["sequence"])
                          for entry in export["evidence"]})
        self.assertEqual([{"request_id": "req-1", "record_id": "rec-1",
                           "subject_id": "user-1", "anonymized": False}], export["records"])
        self.assertEqual({"requests": 2, "evidence": 5, "records": 1}, export["totals"])
        digest = sha256_hex(canonical_json({"filter": export["filter"], "requests": export["requests"],
                                            "evidence": export["evidence"], "records": export["records"]}))
        self.assertEqual(digest, export["export_digest"])
        status, filtered = self.call("GET", "/audit/export?request_id=req-1&include_records=true")
        self.assertEqual((200, "req-1"), (status, filtered["filter"]))
        self.assertEqual(["req-1"], [request["id"] for request in filtered["requests"]])
        self.assertEqual({"email": "a@b.c"}, filtered["records"][0]["payload"])
        self.assertNotEqual(export["export_digest"], filtered["export_digest"])

    def test_audit_export_rejects_bad_queries_over_http(self):
        self.call("POST", "/policies", {"id": "eu", "retention_days": 30, "action": "delete"}, key="p1")
        self.call("POST", "/requests", {"id": "req-1", "subject_id": "user-1", "request_type": "access",
                                        "policy_id": "eu", "sla_days": 30, "actor": "agent"}, key="r1")
        for path, error_code in (("/audit/export?when=now", "unknown_query"),
                                 ("/audit/export?request_id=req-1&request_id=req-1", "duplicate_query"),
                                 ("/audit/export?include_records=true&include_records=false", "duplicate_query"),
                                 ("/audit/export?include_records=yes", "invalid_include_records"),
                                 ("/audit/export?include_records=", "invalid_include_records")):
            status, body = self.call("GET", path)
            self.assertEqual((400, "validation_error", error_code),
                             (status, body["error"]["code"], body["error"]["error_code"]))
        status, body = self.call("GET", "/audit/export?request_id=ghost")
        self.assertEqual((404, "not_found", "request ghost was not found"),
                         (status, body["error"]["code"], body["error"]["message"]))
        status, export = self.call("GET", "/audit/export?include_records=false")
        self.assertEqual((200, False), (status, "payload" in export["records"][0] if export["records"] else False))

    def test_content_type_and_query_parameters_are_enforced(self):
        status, body = self.call("POST", "/policies", "{}", key="p1", content_type="text/plain")
        self.assertEqual((400, "Content-Type must be application/json"), (status, body["error"]["message"]))
        self.call("POST", "/policies", {"id": "eu", "retention_days": 1, "action": "delete"}, key="p2")
        status, body = self.call("GET", "/policy/eu/due?when=2026-02-01T00:00:00Z")
        self.assertEqual((400, "unknown query parameter(s): when"), (status, body["error"]["message"]))
        self.assertEqual("2026-02-01T00:00:00Z", self.call("GET", "/policy/eu/due?at=2026-02-01T00:00:00Z")[1]["at"])


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from rightsflow.clock import FixedClock
from rightsflow.errors import ConflictError, IllegalTransitionError, NotFoundError, ValidationError
from rightsflow.server import Handler
from rightsflow.service import RightsFlow


class ReviewServiceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.clock = FixedClock("2026-01-01T00:00:00Z")
        self.service = RightsFlow(str(Path(self.directory.name) / "test.db"), clock=self.clock)
        self.service.create_policy(
            {"id": "eu-access", "retention_days": 30, "action": "delete"}, "policy-1")
        self.service.create_request(
            {"id": "req-1", "subject_id": "user-42", "request_type": "access",
             "policy_id": "eu-access", "sla_days": 30, "actor": "agent-7"}, "create-req-1")

    def tearDown(self):
        self.directory.cleanup()

    def receive(self, request_id="req-1", **overrides):
        body = {"id": request_id, "subject_id": "user-42", "request_type": "access",
                "policy_id": "eu-access", "sla_days": 30, "actor": "agent-7"}
        body.update(overrides)
        return self.service.create_request(body, f"create-{request_id}")

    def move(self, action, request_id="req-1", **body):
        return self.service.transition(
            request_id, {"action": action, "actor": "dpo", **body}, f"{request_id}-{action}")

    def reach_packaged(self, request_id="req-1"):
        self.move("verify_identity", request_id)
        self.move("scope", request_id)
        self.move("collect", request_id, details={"records": [{"id": "r-1", "payload": {"a": 1}}]})
        return self.move("package", request_id, details={"artifact": "bundle-1"})

    def review(self, action="reject", review_id="rev-1", request_id="req-1", **overrides):
        body = {"review_id": review_id, "action": action, "actor": "proposer",
                "reason": "manifestly unfounded" if action == "reject" else None, "note": None}
        body.update(overrides)
        return self.service.create_review(request_id, body, f"create-{request_id}-{review_id}")

    def decide(self, actor, decision, review_id="rev-1", request_id="req-1", key=None, **overrides):
        body = {"actor": actor, "decision": decision, "note": None}
        body.update(overrides)
        return self.service.review_decision(
            request_id, review_id, body, key or f"{request_id}-{review_id}-{actor}-{decision}")

    # --------------------------------------------------------------- creation

    def test_create_snapshots_state_and_evidence_head(self):
        self.reach_packaged()
        head = self.service.get_request("req-1")["evidence_head"]
        created = self.review("fulfill")
        self.assertEqual(
            {"request_id": "req-1", "review_id": "rev-1", "action": "fulfill", "actor": "proposer",
             "reason": None, "note": None, "status": "pending",
             "state_snapshot": "packaged", "evidence_head_snapshot": head,
             "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
             "applied_at": None, "decisions": [], "transition_result": None},
            created)
        # Opening a review touches neither the request nor the evidence chain.
        self.assertEqual("packaged", self.service.get_request("req-1")["state"])
        self.assertEqual(5, self.service.evidence("req-1")["count"])

    def test_create_reason_rules_match_direct_transitions(self):
        with self.assertRaisesRegex(ValidationError, "reject requires a non-empty reason"):
            self.review("reject", reason=None)
        with self.assertRaisesRegex(ValidationError, "reject requires a non-empty reason"):
            self.review("reject", reason="")
        with self.assertRaisesRegex(ValidationError, "reason is only allowed for reject"):
            self.review("fulfill", reason="not allowed")
        with self.assertRaisesRegex(ValidationError, "action must be one of reject, fulfill"):
            self.review("scope")
        with self.assertRaisesRegex(ValidationError,
                                    "exactly review_id, action, actor, reason, and note"):
            self.service.create_review(
                "req-1", {"review_id": "x", "action": "reject", "actor": "p", "reason": "r"}, "bad")
        with self.assertRaisesRegex(ValidationError, "reason must be a non-empty string of at most 1000"):
            self.review("reject", reason="x" * 1001)
        with self.assertRaisesRegex(ValidationError, "note must be a non-empty string of at most 2000"):
            self.review("reject", note="x" * 2001)

    def test_create_rejects_illegal_successor_and_duplicate_pending_action(self):
        # fulfill is not legal from received.
        with self.assertRaisesRegex(
                IllegalTransitionError,
                "illegal transition from received to fulfilled; legal successors: "
                "cancelled, identity_verified, rejected") as caught:
            self.review("fulfill")
        self.assertEqual((409, "illegal_transition"),
                         (caught.exception.status, caught.exception.code))
        self.review("reject")
        with self.assertRaisesRegex(ConflictError, "a pending review rev-1 for action reject"):
            self.service.create_review(
                "req-1", {"review_id": "rev-2", "action": "reject", "actor": "p",
                          "reason": "again", "note": None}, "create-req-1-rev-2")
        # With rev-1 denied, the action is open again: rev-2 can now be created.
        self.decide("reviewer-x", "deny", key="deny-rev-1")
        self.service.create_review(
            "req-1", {"review_id": "rev-2", "action": "reject", "actor": "p",
                      "reason": "again", "note": None}, "create-req-1-rev-2")
        # Once that one is also finished, reusing rev-1's id hits the primary key.
        self.service.review_decision(
            "req-1", "rev-2", {"actor": "reviewer-y", "decision": "deny", "note": None}, "deny-rev-2")
        with self.assertRaisesRegex(ConflictError, "review rev-1 already exists"):
            self.service.create_review(
                "req-1", {"review_id": "rev-1", "action": "reject", "actor": "p",
                          "reason": "third", "note": None}, "dup-rev-1")

    def test_create_requires_existing_request(self):
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.review(request_id="ghost")

    # ------------------------------------------------------------- first approval

    def test_first_independent_approval_only_records_the_decision(self):
        self.review("reject", note="please close")
        first = self.decide("reviewer-a", "approve", note="looks good")
        self.assertEqual("pending", first["status"])
        self.assertEqual(
            [{"actor": "reviewer-a", "decision": "approve", "note": "looks good",
              "decided_at": "2026-01-01T00:00:00Z"}],
            first["decisions"])
        self.assertIsNone(first["transition_result"])
        request = self.service.get_request("req-1")
        self.assertEqual("received", request["state"])
        self.assertEqual(1, self.service.evidence("req-1")["count"])

    def test_proposer_and_duplicate_actor_are_conflicts(self):
        self.review("reject")
        with self.assertRaisesRegex(ConflictError, "proposing actor may not review"):
            self.decide("proposer", "approve", key="self-1")
        self.decide("reviewer-a", "approve")
        with self.assertRaisesRegex(ConflictError, "reviewer-a has already decided"):
            self.decide("reviewer-a", "deny", key="a-again")
        # Nothing was recorded by either rejected attempt.
        review = self.service.get_review("req-1", "rev-1")
        self.assertEqual(["reviewer-a"], [decision["actor"] for decision in review["decisions"]])

    # ------------------------------------------------------------- second approval

    def test_second_approval_applies_fulfill_like_a_direct_transition(self):
        self.reach_packaged()
        self.review("fulfill", note="send bundle")
        self.decide("reviewer-a", "approve")
        self.clock.advance(hours=2)
        applied = self.decide("reviewer-b", "approve")
        self.assertEqual("applied", applied["status"])
        self.assertEqual("2026-01-01T02:00:00Z", applied["applied_at"])
        request = self.service.get_request("req-1")
        self.assertEqual("fulfilled", request["state"])
        self.assertEqual("2026-01-01T02:00:00Z", request["closed_at"])
        self.assertEqual(6, self.service.evidence("req-1")["count"])
        # Exactly one history entry and one evidence entry were produced.
        self.assertEqual([None, "verify_identity", "scope", "collect", "package", "fulfill"],
                         [entry["action"] for entry in request["history"]])
        last = request["history"][-1]
        self.assertEqual(("packaged", "fulfilled", "proposer", "send bundle", None),
                         (last["from"], last["to"], last["actor"], last["note"], last["reason"]))
        evidence = self.service.evidence("req-1")["entries"][-1]["content"]["payload"]
        self.assertEqual(
            {"action": "fulfill", "from": "packaged", "to": "fulfilled", "actor": "proposer",
             "note": "send bundle", "reason": None, "details": None}, evidence)
        # transition_result is the same materialized request a direct transition returns.
        result = applied["transition_result"]
        self.assertEqual(request, result)
        # The retention window starts at the injected-clock closure time (+2h).
        self.assertEqual("2026-01-31T02:00:00Z", result["retention"]["expires_at"])
        self.assertEqual("delete", result["retention"]["action"])

    def test_second_approval_applies_reject_with_closed_reason_and_retention(self):
        self.review("reject", reason="manifestly unfounded")
        self.decide("reviewer-a", "approve")
        applied = self.decide("reviewer-b", "approve")
        self.assertEqual("applied", applied["status"])
        request = self.service.get_request("req-1")
        self.assertEqual(("rejected", "manifestly unfounded"),
                         (request["state"], request["closed_reason"]))
        self.assertEqual(2, self.service.evidence("req-1")["count"])
        self.assertEqual({"policy_id": "eu-access", "retention_days": 30, "action": "delete",
                          "expires_at": "2026-01-31T00:00:00Z",
                          "applied_at": None, "affected_records": 0}, request["retention"])
        self.assertEqual(request, applied["transition_result"])

    def test_reviewed_change_is_identical_to_a_direct_one(self):
        # Reviewed reject in one database ...
        self.review("reject", reason="same reason", note="same note")
        self.decide("a", "approve")
        reviewed = self.decide("b", "approve")["transition_result"]
        reviewed_entry = self.service.evidence("req-1")["entries"][-1]

        # ... direct reject in another, using the same actor/note/reason and clock.
        other_directory = tempfile.TemporaryDirectory()
        self.addCleanup(other_directory.cleanup)
        other = RightsFlow(str(Path(other_directory.name) / "other.db"),
                           clock=FixedClock("2026-01-01T00:00:00Z"))
        other.create_policy({"id": "eu-access", "retention_days": 30, "action": "delete"}, "p")
        other.create_request({"id": "req-1", "subject_id": "user-42", "request_type": "access",
                              "policy_id": "eu-access", "sla_days": 30, "actor": "agent-7"}, "r")
        direct = other.transition(
            "req-1", {"action": "reject", "actor": "proposer",
                      "reason": "same reason", "note": "same note"}, "t")
        direct_entry = other.evidence("req-1")["entries"][-1]
        self.assertEqual(direct["state"], reviewed["state"])
        self.assertEqual(direct["closed_reason"], reviewed["closed_reason"])
        self.assertEqual(direct["retention"], reviewed["retention"])
        self.assertEqual(direct["history"][-1], reviewed["history"][-1])
        self.assertEqual(direct["evidence_head"], reviewed["evidence_head"])
        self.assertEqual(direct_entry, reviewed_entry)

    # -------------------------------------------------------------------- deny

    def test_any_deny_terminates_denied_and_changes_nothing(self):
        self.review("reject")
        self.decide("reviewer-a", "approve")
        denied = self.decide("reviewer-b", "deny", note="not justified")
        self.assertEqual("denied", denied["status"])
        self.assertEqual(["approve", "deny"],
                         [decision["decision"] for decision in denied["decisions"]])
        self.assertIsNone(denied["applied_at"])
        self.assertIsNone(denied["transition_result"])
        request = self.service.get_request("req-1")
        self.assertEqual(("received", None, None),
                         (request["state"], request["closed_at"], request["retention"]))
        self.assertEqual(1, self.service.evidence("req-1")["count"])
        with self.assertRaisesRegex(ConflictError, "review rev-1 is denied"):
            self.decide("reviewer-c", "approve", key="late-c")

    def test_deny_as_first_decision_terminates_immediately(self):
        self.review("reject")
        denied = self.decide("reviewer-a", "deny")
        self.assertEqual("denied", denied["status"])
        self.assertEqual(1, len(denied["decisions"]))
        self.assertEqual("received", self.service.get_request("req-1")["state"])

    # ------------------------------------------------------------------- stale

    def test_decision_after_state_moved_terminates_stale_without_recording(self):
        self.review("reject")
        self.decide("reviewer-a", "approve")
        # The request moves away from the snapshot through the ordinary transition API.
        self.move("verify_identity")
        stale = self.decide("reviewer-b", "approve")
        self.assertEqual("stale", stale["status"])
        self.assertEqual([], [d for d in stale["decisions"] if d["actor"] == "reviewer-b"])
        self.assertEqual(["reviewer-a"], [d["actor"] for d in stale["decisions"]])
        self.assertEqual("identity_verified", self.service.get_request("req-1")["state"])
        self.assertIsNone(stale["transition_result"])
        with self.assertRaisesRegex(ConflictError, "review rev-1 is stale"):
            self.decide("reviewer-c", "deny", key="late-c")

    def test_stale_rule_fires_even_for_the_proposer_and_is_unconditional(self):
        self.review("reject")
        self.move("verify_identity")
        stale = self.decide("proposer", "approve", key="stale-proposer")
        self.assertEqual("stale", stale["status"])
        self.assertEqual([], stale["decisions"])

    # --------------------------------------------------------------- not found

    def test_decisions_and_lookups_404_on_missing_request_or_review(self):
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.decide("a", "approve", request_id="ghost")
        with self.assertRaisesRegex(NotFoundError, "review ghost was not found"):
            self.decide("a", "approve", review_id="ghost")
        with self.assertRaisesRegex(NotFoundError, "review ghost was not found"):
            self.service.get_review("req-1", "ghost")
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.service.list_reviews("ghost")

    # -------------------------------------------------------------- validation

    def test_decision_validation(self):
        self.review("reject")
        for bad in (
            {"actor": "a", "decision": "maybe", "note": None},
            {"actor": "a", "decision": "APPROVE", "note": None},
            {"actor": "", "decision": "approve", "note": None},
            {"actor": "a", "decision": "approve", "note": "x" * 2001},
            {"actor": "a", "decision": "approve"},
            {"actor": "a", "decision": "approve", "note": None, "extra": 1},
        ):
            with self.assertRaisesRegex(ValidationError, ""):
                self.service.review_decision("req-1", "rev-1", bad, f"bad-{json.dumps(bad)}")

    # ------------------------------------------------------------- idempotency

    def test_decisions_require_key_and_replay_without_reapplying(self):
        self.review("reject")
        with self.assertRaisesRegex(ValidationError, "Idempotency-Key"):
            self.service.review_decision(
                "req-1", "rev-1", {"actor": "a", "decision": "approve", "note": None}, None)
        first = self.decide("a", "approve", note="first note")
        replayed = self.service.review_decision(
            "req-1", "rev-1", {"actor": "someone-else", "decision": "deny", "note": "changed"},
            "req-1-rev-1-a-approve")
        self.assertEqual(first, replayed)
        self.assertEqual(1, len(replayed["decisions"]))
        self.assertEqual("a", replayed["decisions"][0]["actor"])
        # Reusing the key for a different operation is a conflict.
        with self.assertRaises(ConflictError):
            self.service.transition(
                "req-1", {"action": "verify_identity", "actor": "dpo"}, "req-1-rev-1-a-approve")

    def test_applied_decision_replays_the_applied_response(self):
        self.review("reject")
        self.decide("a", "approve")
        second_key = "req-1-rev-1-b-approve"
        applied = self.decide("b", "approve", key=second_key)
        again = self.decide("b", "approve", key=second_key, note="different")
        self.assertEqual(applied, again)
        self.assertEqual(2, self.service.evidence("req-1")["count"])
        self.assertEqual(2, len(self.service.get_review("req-1", "rev-1")["decisions"]))

    # ------------------------------------------------------- ordering / listing

    def test_decisions_keep_commit_order_and_listing_sorts_by_created_at(self):
        self.reach_packaged()
        # rev-b is created, decided, and denied first; rev-a is opened later after
        # the clock advances. Listing must order by created_at regardless of name.
        self.review("fulfill", review_id="rev-b")
        self.decide("a", "approve", review_id="rev-b")
        self.decide("b", "deny", review_id="rev-b")
        self.clock.advance(seconds=10)
        self.review("fulfill", review_id="rev-a")
        listing = self.service.list_reviews("req-1")
        self.assertEqual(["rev-b", "rev-a"], [review["review_id"] for review in listing["reviews"]])
        self.assertEqual("req-1", listing["request_id"])
        self.assertEqual(["a", "b"],
                         [d["actor"] for d in listing["reviews"][0]["decisions"]])
        self.assertEqual("denied", listing["reviews"][0]["status"])

    def test_listing_tie_breaks_on_review_id(self):
        # rev-c (reject) is opened at received; the clock stays frozen while the
        # request advances and a fulfill review is opened, denied, and replaced by
        # a second one. All three share created_at, so review_id orders them.
        self.review("reject", review_id="rev-c")
        self.reach_packaged()
        self.service.create_review(
            "req-1", {"review_id": "rev-b", "action": "fulfill", "actor": "p",
                      "reason": None, "note": None}, "create-req-1-rev-b")
        self.service.review_decision(
            "req-1", "rev-b", {"actor": "a", "decision": "deny", "note": None}, "deny-rev-b")
        self.service.create_review(
            "req-1", {"review_id": "rev-a", "action": "fulfill", "actor": "p",
                      "reason": None, "note": None}, "create-req-1-rev-a")
        ids = [r["review_id"] for r in self.service.list_reviews("req-1")["reviews"]]
        self.assertEqual(["rev-a", "rev-b", "rev-c"], ids)

    # ------------------------------------------------------------ concurrency

    def test_concurrent_second_approvals_apply_exactly_once(self):
        self.review("reject")
        self.decide("a", "approve")
        barrier = threading.Barrier(2)
        outcomes: dict[str, object] = {}

        def decide(actor: str) -> None:
            barrier.wait()
            try:
                outcomes[actor] = self.service.review_decision(
                    "req-1", "rev-1", {"actor": actor, "decision": "approve", "note": None},
                    f"concurrent-{actor}")
            except ConflictError as error:
                outcomes[actor] = error

        threads = [threading.Thread(target=decide, args=(name,)) for name in ("b", "c")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        applied = [value for value in outcomes.values() if isinstance(value, dict)]
        conflicts = [value for value in outcomes.values() if isinstance(value, ConflictError)]
        self.assertEqual((1, 1), (len(applied), len(conflicts)))
        request = self.service.get_request("req-1")
        self.assertEqual(("rejected", 2, 2),
                         (request["state"], self.service.evidence("req-1")["count"],
                          len(request["history"])))
        # The losing decision was not recorded: exactly the first approver + winner.
        self.assertEqual(2, len(self.service.get_review("req-1", "rev-1")["decisions"]))


class ReviewHttpTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        Handler.service = RightsFlow(
            str(Path(self.directory.name) / "http.db"), clock=FixedClock("2026-01-01T00:00:00Z"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.call("POST", "/policies", {"id": "eu", "retention_days": 30, "action": "delete"}, key="p1")
        self.call("POST", "/requests", {"id": "req-1", "subject_id": "user-1", "request_type": "access",
                                        "policy_id": "eu", "sla_days": 30, "actor": "agent"}, key="r1")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.directory.cleanup()

    def call(self, method, path, body=None, key=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if key:
            headers["Idempotency-Key"] = key
        connection.request(method, path,
                           body=json.dumps(body).encode() if body is not None else None, headers=headers)
        response = connection.getresponse()
        document = json.loads(response.read())
        connection.close()
        return response.status, document

    def advance(self, **delta):
        Handler.service.clock.advance(**delta)

    def test_full_review_flow_over_http(self):
        status, review = self.call(
            "POST", "/requests/req-1/reviews",
            {"review_id": "rev-1", "action": "reject", "actor": "proposer",
             "reason": "unfounded", "note": None}, key="rv1")
        self.assertEqual((201, "pending", "received"),
                         (status, review["status"], review["state_snapshot"]))

        status, body = self.call(
            "POST", "/requests/req-1/reviews",
            {"review_id": "rev-2", "action": "reject", "actor": "proposer",
             "reason": "again", "note": None}, key="rv2")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))

        status, body = self.call(
            "POST", "/requests/req-1/reviews",
            {"review_id": "rev-3", "action": "fulfill", "actor": "proposer",
             "reason": None, "note": None}, key="rv3")
        self.assertEqual((409, "illegal_transition"), (status, body["error"]["code"]))

        status, body = self.call(
            "POST", "/requests/req-1/reviews",
            {"review_id": "rev-4", "action": "reject", "actor": "proposer",
             "reason": None, "note": None}, key="rv4")
        self.assertEqual((400, "validation_error"), (status, body["error"]["code"]))

        status, body = self.call(
            "POST", "/requests/req-1/rev-1/decisions",
            {"actor": "proposer", "decision": "approve", "note": None}, key="d-bad")
        # Wrong path shape (review id under requests, not reviews) is a route 404.
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))

        status, first = self.call(
            "POST", "/requests/req-1/reviews/rev-1/decisions",
            {"actor": "reviewer-a", "decision": "approve", "note": "ok"}, key="d1")
        self.assertEqual((200, "pending"), (status, first["status"]))

        status, body = self.call(
            "POST", "/requests/req-1/reviews/rev-1/decisions",
            {"actor": "reviewer-a", "decision": "deny", "note": None}, key="d1-dup")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))

        self.advance(hours=1)
        status, applied = self.call(
            "POST", "/requests/req-1/reviews/rev-1/decisions",
            {"actor": "reviewer-b", "decision": "approve", "note": None}, key="d2")
        self.assertEqual((200, "applied"), (status, applied["status"]))
        self.assertEqual("2026-01-01T01:00:00Z", applied["applied_at"])
        self.assertEqual("rejected", applied["transition_result"]["state"])
        self.assertEqual("unfounded", applied["transition_result"]["closed_reason"])

        status, body = self.call(
            "POST", "/requests/req-1/reviews/rev-1/decisions",
            {"actor": "reviewer-c", "decision": "approve", "note": None}, key="d3")
        self.assertEqual((409, "conflict"), (status, body["error"]["code"]))

        status, one = self.call("GET", "/requests/req-1/reviews/rev-1")
        self.assertEqual((200, applied), (status, one))
        status, listing = self.call("GET", "/requests/req-1/reviews")
        self.assertEqual(200, status)
        self.assertEqual(["rev-1"], [r["review_id"] for r in listing["reviews"]])

    def test_review_errors_over_http(self):
        status, body = self.call(
            "POST", "/requests/ghost/reviews",
            {"review_id": "rev-1", "action": "reject", "actor": "p",
             "reason": "r", "note": None}, key="rv-ghost")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))
        status, body = self.call(
            "POST", "/requests/req-1/reviews/rev-missing/decisions",
            {"actor": "a", "decision": "approve", "note": None}, key="d-ghost")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))
        status, body = self.call(
            "POST", "/requests/req-1/reviews",
            {"review_id": "rev-1", "action": "reject", "actor": "p", "reason": "r", "note": None})
        self.assertEqual((400, "validation_error"), (status, body["error"]["code"]))
        status, body = self.call(
            "POST", "/requests/req-1/reviews/rev-missing/decisions",
            {"actor": "a", "decision": "approve", "note": None})
        self.assertEqual((400, "validation_error"), (status, body["error"]["code"]))
        status, body = self.call("GET", "/requests/ghost/reviews")
        self.assertEqual((404, "not_found"), (status, body["error"]["code"]))

    def test_deny_and_stale_over_http(self):
        self.call("POST", "/requests/req-1/reviews",
                  {"review_id": "rev-1", "action": "reject", "actor": "proposer",
                   "reason": "r", "note": None}, key="rv1")
        status, denied = self.call("POST", "/requests/req-1/reviews/rev-1/decisions",
                                  {"actor": "reviewer-a", "decision": "deny", "note": "no"}, key="d1")
        self.assertEqual((200, "denied"), (status, denied["status"]))
        self.assertEqual("received", self.call("GET", "/requests/req-1")[1]["state"])

        self.call("POST", "/requests/req-1/reviews",
                  {"review_id": "rev-2", "action": "reject", "actor": "proposer",
                   "reason": "r", "note": None}, key="rv2")
        self.call("POST", "/requests/req-1/transitions",
                  {"action": "verify_identity", "actor": "dpo"}, key="t1")
        status, stale = self.call("POST", "/requests/req-1/reviews/rev-2/decisions",
                                  {"actor": "reviewer-a", "decision": "approve", "note": None}, key="d2")
        self.assertEqual((200, "stale", []),
                         (status, stale["status"], stale["decisions"]))


if __name__ == "__main__":
    unittest.main()

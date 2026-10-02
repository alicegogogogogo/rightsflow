import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from rightsflow.clock import FixedClock
from rightsflow.errors import ConflictError, IllegalTransitionError, NotFoundError, ValidationError
from rightsflow.service import RightsFlow


def canonical(value):
    """Independent reimplementation of the documented canonical encoding."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def link(content, previous):
    """Independent reimplementation of sha256(previous + canonical_json(content))."""
    return hashlib.sha256(((previous or "") + canonical(content)).encode("utf-8")).hexdigest()


RECORDS = [{"id": "r-1", "payload": {"email": "subject@example.test"}}, {"id": "r-2", "payload": {"phone": "555"}}]


class RightsFlowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.clock = FixedClock("2026-01-01T00:00:00Z")
        self.service = RightsFlow(str(Path(self.directory.name) / "test.db"), clock=self.clock)
        self.service.create_policy({"id": "eu-access", "retention_days": 30, "action": "delete"}, "policy-1")

    def tearDown(self):
        self.directory.cleanup()

    def receive(self, request_id="req-1", key=None, **overrides):
        body = {"id": request_id, "subject_id": "user-42", "request_type": "access",
                "policy_id": "eu-access", "sla_days": 30, "actor": "agent-7"}
        body.update(overrides)
        return self.service.create_request(body, key or f"create-{request_id}")

    def warp(self, moment):
        """Move the injected clock without touching any wall clock."""
        self.clock = FixedClock(moment)
        self.service.clock = self.clock

    def move(self, action, request_id="req-1", key=None, **body):
        return self.service.transition(request_id, {"action": action, "actor": "dpo", **body},
                                       key or f"{request_id}-{action}")

    def reach_collected(self, request_id="req-1"):
        self.move("verify_identity", request_id)
        self.move("scope", request_id, note="scope agreed")
        return self.move("collect", request_id, details={"records": copy.deepcopy(RECORDS)})

    def reach_fulfilled(self, request_id="req-1"):
        self.reach_collected(request_id)
        self.move("package", request_id, details={"artifact": "bundle-1"})
        return self.move("fulfill", request_id)

    # -------------------------------------------------------------- state machine

    def test_intake_creates_received_request_with_first_link(self):
        request = self.receive()
        self.assertEqual("received", request["state"])
        self.assertEqual(["cancelled", "identity_verified", "rejected"], request["legal_transitions"])
        self.assertEqual((None, None, None), (request["closed_at"], request["collection"], request["retention"]))
        self.assertEqual(request["received_at"], request["updated_at"])
        self.assertEqual([], request["records"])
        chain = self.service.evidence("req-1")
        self.assertEqual(1, chain["count"])
        self.assertTrue(chain["chain_valid"])
        entry = chain["entries"][0]
        self.assertIsNone(entry["previous_hash"])
        self.assertEqual(
            {"sequence": 1, "request_id": "req-1", "type": "request_received",
             "occurred_at": "2026-01-01T00:00:00Z",
             "payload": {"subject_id": "user-42", "request_type": "access", "policy_id": "eu-access",
                         "sla_days": 30, "sla_due_at": "2026-01-31T00:00:00Z", "actor": "agent-7"}},
            entry["content"])
        self.assertEqual(link(entry["content"], None), entry["hash"])
        self.assertEqual(entry["hash"], request["evidence_head"])

    def test_full_lifecycle_reaches_fulfilled(self):
        self.receive()
        state = self.reach_fulfilled()
        self.assertEqual("fulfilled", state["state"])
        self.assertEqual([], state["legal_transitions"])
        self.assertEqual("2026-01-01T00:00:00Z", state["closed_at"])
        self.assertEqual([None, "verify_identity", "scope", "collect", "package", "fulfill"],
                         [entry["action"] for entry in state["history"]])
        self.assertEqual([1, 2, 3, 4, 5, 6], [entry["sequence"] for entry in state["history"]])
        self.assertEqual(6, self.service.evidence("req-1")["count"])
        self.assertFalse(state["sla"]["breached"])
        self.assertEqual({"policy_id": "eu-access", "retention_days": 30, "action": "delete",
                          "expires_at": "2026-01-31T00:00:00Z", "applied_at": None, "affected_records": 0},
                         state["retention"])

    def test_illegal_and_terminal_transitions_list_legal_successors(self):
        self.receive()
        with self.assertRaisesRegex(
                IllegalTransitionError,
                "illegal transition from received to collected; legal successors: cancelled, identity_verified, rejected"
        ) as caught:
            self.move("collect", details={"records": []})
        self.assertEqual((409, "illegal_transition"), (caught.exception.status, caught.exception.code))
        self.assertEqual(1, self.service.evidence("req-1")["count"])

        self.move("cancel", reason="withdrawn")
        for action in ("verify_identity", "cancel"):
            body = {"reason": "again"} if action == "cancel" else {}
            with self.assertRaisesRegex(IllegalTransitionError, "legal successors: none"):
                self.move(action, key=f"again-{action}", **body)
        self.assertEqual(2, self.service.evidence("req-1")["count"])

    def test_reject_branch_and_reason_rules(self):
        self.receive()
        with self.assertRaisesRegex(ValidationError, "reject requires a non-empty reason"):
            self.move("reject")
        self.move("verify_identity")
        self.move("scope")
        state = self.move("reject", reason="manifestly unfounded")
        self.assertEqual("rejected", state["state"])
        self.assertEqual("manifestly unfounded", state["closed_reason"])
        self.assertEqual(4, self.service.evidence("req-1")["count"])
        with self.assertRaisesRegex(ValidationError, "reason is only allowed"):
            self.service.transition("req-1", {"action": "scope", "actor": "a", "reason": "no"}, "late")

    def test_unknown_action_and_unknown_fields_are_rejected(self):
        self.receive()
        with self.assertRaisesRegex(ValidationError, "action must be one of"):
            self.move("escalate")
        with self.assertRaisesRegex(ValidationError, "unknown field"):
            self.service.transition("req-1", {"action": "scope", "actor": "a", "urgent": True}, "u1")

    def test_collect_records_digest_and_details_validation(self):
        self.receive()
        self.move("verify_identity")
        with self.assertRaisesRegex(ValidationError, "collect requires details"):
            self.move("collect")
        with self.assertRaisesRegex(ValidationError, "duplicate record id"):
            self.move("collect", details={"records": [{"id": "r-1", "payload": {}}] * 2})
        with self.assertRaisesRegex(ValidationError, "exactly id and payload"):
            self.move("collect", details={"records": [{"id": "r-1"}]})
        self.move("scope")
        state = self.move("collect", details={"records": copy.deepcopy(RECORDS)})
        digest = hashlib.sha256(canonical(RECORDS).encode("utf-8")).hexdigest()
        self.assertEqual({"record_count": 2, "records_digest": digest}, state["collection"])
        self.assertEqual(["r-1", "r-2"], [record["id"] for record in state["records"]])
        entry = self.service.evidence("req-1")["entries"][-1]
        self.assertEqual({"record_count": 2, "records_digest": digest}, entry["content"]["payload"]["details"])
        self.assertNotIn("subject@example.test", json.dumps(entry["content"]))

    def test_package_requires_artifact_and_rejects_foreign_details(self):
        self.receive()
        with self.assertRaisesRegex(ValidationError, "details is only allowed"):
            self.move("verify_identity", details={"scope": "everything"})
        self.move("verify_identity")
        self.move("scope")
        self.move("collect", details={"records": copy.deepcopy(RECORDS)})
        with self.assertRaisesRegex(ValidationError, "package requires details"):
            self.move("package")
        self.assertEqual("bundle-1",
                         self.move("package", details={"artifact": "bundle-1"})["history"][-1]["details"]["artifact"])

    # ------------------------------------------------------------------ evidence

    def test_every_link_matches_the_documented_formula(self):
        self.receive()
        self.reach_collected()
        chain = self.service.evidence("req-1")
        previous = None
        for entry in chain["entries"]:
            self.assertEqual(previous, entry["previous_hash"])
            self.assertEqual(link(entry["content"], previous), entry["hash"])
            previous = entry["hash"]
        self.assertEqual(previous, chain["head"])
        self.assertEqual({"chain_valid": True, "count": 4, "head": previous,
                          "first_invalid_sequence": None, "reason": None},
                         self.service.verify_evidence({"entries": chain["entries"]}))
        self.assertEqual(previous, self.service.get_request("req-1")["evidence_head"])

    def test_tampering_with_any_link_is_detected(self):
        self.receive()
        self.reach_collected()
        entries = copy.deepcopy(self.service.evidence("req-1")["entries"])
        entries[2]["content"]["payload"]["actor"] = "attacker"
        self.assertEqual({"chain_valid": False, "count": 4, "head": None,
                          "first_invalid_sequence": 3, "reason": "hash mismatch"},
                         self.service.verify_evidence({"entries": entries}))
        entries = copy.deepcopy(self.service.evidence("req-1")["entries"])
        entries[3]["previous_hash"] = "0" * 64
        report = self.service.verify_evidence({"entries": entries})
        self.assertEqual((4, "previous_hash does not match the preceding hash"),
                         (report["first_invalid_sequence"], report["reason"]))
        entries = copy.deepcopy(self.service.evidence("req-1")["entries"])
        entries[1]["content"]["sequence"] = 7
        report = self.service.verify_evidence({"entries": entries})
        self.assertEqual((2, "sequence must be contiguous starting at 1"),
                         (report["first_invalid_sequence"], report["reason"]))

    def test_verify_accepts_empty_chain_and_rejects_malformed_entries(self):
        self.assertEqual({"chain_valid": True, "count": 0, "head": None,
                          "first_invalid_sequence": None, "reason": None},
                         self.service.verify_evidence({"entries": []}))
        with self.assertRaisesRegex(ValidationError, "exactly an entries array"):
            self.service.verify_evidence({"chain": []})
        with self.assertRaisesRegex(ValidationError, "entry 1 must contain exactly"):
            self.service.verify_evidence({"entries": [{"content": {}, "hash": "x", "extra": 1}]})
        with self.assertRaisesRegex(ValidationError, "entry 1 content must be an object"):
            self.service.verify_evidence({"entries": [{"content": 5, "previous_hash": None, "hash": "x"}]})
        report = self.service.verify_evidence({"entries": [{"content": {"sequence": 1}, "previous_hash": None, "hash": "x"}]})
        self.assertEqual((1, "content fields do not match the documented entry shape"),
                         (report["first_invalid_sequence"], report["reason"]))

    # ------------------------------------------------------- SLA and idempotency

    def test_sla_reads_only_the_injected_clock(self):
        self.receive()
        self.assertEqual(0, self.service.get_request("req-1")["sla"]["elapsed_seconds"])
        self.clock.advance(days=10)
        sla = self.service.get_request("req-1")["sla"]
        self.assertEqual("2026-01-11T00:00:00Z", sla["measured_at"])
        self.assertEqual((864000, 20 * 86400, 0, False),
                         (sla["elapsed_seconds"], sla["remaining_seconds"], sla["overdue_seconds"], sla["breached"]))
        self.clock.advance(days=25)
        sla = self.service.get_request("req-1")["sla"]
        self.assertEqual((True, 5 * 86400, 0), (sla["breached"], sla["overdue_seconds"], sla["remaining_seconds"]))

    def test_sla_stops_at_closure_and_records_a_late_close(self):
        self.receive()
        self.reach_fulfilled()
        self.clock.advance(days=365)
        sla = self.service.get_request("req-1")["sla"]
        self.assertEqual(("2026-01-01T00:00:00Z", 0, False), (sla["measured_at"], sla["elapsed_seconds"], sla["breached"]))
        self.warp("2026-01-20T00:00:00Z")
        self.service.create_policy({"id": "short", "retention_days": 1, "action": "delete"}, "p-short")
        self.receive("req-late", policy_id="short", sla_days=1)
        self.warp("2026-01-25T00:00:00Z")
        self.move("cancel", "req-late", reason="subject withdrew")
        sla = self.service.get_request("req-late")["sla"]
        self.assertEqual((True, 4 * 86400), (sla["breached"], sla["overdue_seconds"]))

    def test_idempotency_replays_the_first_result(self):
        self.receive()
        first = self.service.transition("req-1", {"action": "verify_identity", "actor": "dpo"}, "same")
        repeated = self.service.transition("req-1", {"action": "verify_identity", "actor": "someone-else"}, "same")
        self.assertEqual(first, repeated)
        self.assertEqual("dpo", repeated["history"][-1]["actor"])
        self.assertEqual(2, self.service.evidence("req-1")["count"])
        with self.assertRaisesRegex(ValidationError, "Idempotency-Key"):
            self.service.transition("req-1", {"action": "scope", "actor": "dpo"}, None)
        with self.assertRaises(ConflictError):
            self.service.transition("req-1", {"action": "scope", "actor": "dpo"}, "same")

    # ---------------------------------------------------------------- validation

    def test_request_policy_and_lookup_validation(self):
        with self.assertRaisesRegex(ValidationError, "exactly id, subject_id"):
            self.receive(extra="nope")
        with self.assertRaisesRegex(ValidationError, "sla_days must be an integer"):
            self.receive(sla_days=True)
        with self.assertRaisesRegex(ValidationError, "sla_days must be between 1 and 365"):
            self.receive(sla_days=0)
        with self.assertRaisesRegex(ValidationError, "request_type must be one of"):
            self.receive(request_type="deletion")
        with self.assertRaisesRegex(NotFoundError, "policy nope was not found"):
            self.receive(policy_id="nope")
        with self.assertRaisesRegex(ValidationError, "action must be one of"):
            self.service.create_policy({"id": "p2", "retention_days": 1, "action": "purge"}, "p2")
        with self.assertRaisesRegex(ValidationError, "retention_days must be between 0 and 3650"):
            self.service.create_policy({"id": "p3", "retention_days": -1, "action": "delete"}, "p3")
        for lookup in (self.service.get_request, self.service.evidence):
            with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
                lookup("ghost")
        self.receive()
        with self.assertRaisesRegex(ConflictError, "request req-1 already exists"):
            self.receive(key="create-req-1-again")
        with self.assertRaisesRegex(ConflictError, "policy eu-access already exists"):
            self.service.create_policy({"id": "eu-access", "retention_days": 30, "action": "delete"}, "again")

    # ------------------------------------------------------------------ retention

    def test_due_window_is_inclusive_and_sorted(self):
        self.receive("req-b")
        self.reach_fulfilled("req-b")
        self.receive("req-a")
        self.reach_fulfilled("req-a")
        self.assertEqual([], self.service.policy_due("eu-access")["due"])
        self.assertEqual([], self.service.policy_due("eu-access", "2026-01-30T23:59:59Z")["due"])
        due = self.service.policy_due("eu-access", "2026-01-31T00:00:00Z")
        self.assertEqual(["req-a", "req-b"], [item["request_id"] for item in due["due"]])
        self.assertEqual((30, "delete", 2, "2026-01-31T00:00:00Z"),
                         (due["retention_days"], due["action"], due["due"][0]["record_count"], due["due"][0]["expires_at"]))
        with self.assertRaisesRegex(ValidationError, "at must include a UTC offset"):
            self.service.policy_due("eu-access", "2026-01-31")

    def test_delete_retention_erases_records_but_keeps_the_evidence_chain(self):
        self.receive()
        self.reach_fulfilled()
        self.assertEqual(2, self.service.subject_records("user-42")["count"])
        digest = self.service.get_request("req-1")["collection"]["records_digest"]
        result = self.service.enforce_policy("eu-access", {"at": "2026-01-31T00:00:00Z"}, "enforce-1")
        self.assertEqual((0, [{"request_id": "req-1", "subject_id": "user-42", "action": "delete",
                               "affected_records": 2}]),
                         (result["due_remaining"], result["results"]))
        self.assertEqual(0, self.service.subject_records("user-42")["count"])
        state = self.service.get_request("req-1")
        self.assertEqual(([], "2026-01-31T00:00:00Z", digest, "fulfilled"),
                         (state["records"], state["retention"]["applied_at"],
                          state["collection"]["records_digest"], state["state"]))
        chain = self.service.evidence("req-1")
        self.assertEqual((6, True), (chain["count"], chain["chain_valid"]))

    def test_anonymize_retention_moves_records_to_a_pseudonym(self):
        self.service.create_policy({"id": "anon", "retention_days": 0, "action": "anonymize"}, "p-anon")
        self.receive("req-anon", policy_id="anon")
        self.reach_fulfilled("req-anon")
        result = self.service.enforce_policy("anon", {"at": "2026-01-01T00:00:00Z"}, "enforce-anon")
        self.assertEqual(2, result["results"][0]["affected_records"])
        pseudonym = "anon:" + hashlib.sha256(b"user-42:req-anon").hexdigest()[:16]
        self.assertEqual(0, self.service.subject_records("user-42")["count"])
        moved = self.service.subject_records(pseudonym)
        self.assertEqual(2, moved["count"])
        self.assertTrue(all(record["anonymized"] for record in moved["records"]))
        self.assertEqual(2, len(self.service.get_request("req-anon")["records"]))

    def test_enforcement_is_idempotent_and_never_double_applies(self):
        self.receive()
        self.reach_fulfilled()
        first = self.service.enforce_policy("eu-access", {"at": "2026-01-31T00:00:00Z"}, "same")
        self.assertEqual(first, self.service.enforce_policy("eu-access", {"at": "2026-01-31T00:00:00Z"}, "same"))
        self.assertEqual([], self.service.enforce_policy("eu-access", {"at": "2026-02-15T00:00:00Z"}, "other")["results"])
        self.assertEqual([], self.service.policy_due("eu-access", "2026-02-15T00:00:00Z")["due"])
        with self.assertRaisesRegex(ValidationError, "body must contain exactly at"):
            self.service.enforce_policy("eu-access", {}, "bad")
        with self.assertRaisesRegex(ValidationError, "at must include a UTC offset"):
            self.service.enforce_policy("eu-access", {"at": "2026-01-31"}, "bad2")
        with self.assertRaisesRegex(NotFoundError, "policy ghost was not found"):
            self.service.enforce_policy("ghost", {"at": "2026-01-31T00:00:00Z"}, "bad3")


class RetrievalTaskTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.clock = FixedClock("2026-01-01T00:00:00Z")
        self.service = RightsFlow(str(Path(self.directory.name) / "test.db"), clock=self.clock)
        self.service.create_policy({"id": "eu-access", "retention_days": 30, "action": "delete"}, "policy-1")
        self.service.create_request({"id": "req-1", "subject_id": "user-42", "request_type": "access",
                                     "policy_id": "eu-access", "sla_days": 30, "actor": "agent-7"}, "create-req-1")

    def tearDown(self):
        self.directory.cleanup()

    def create(self, task_id="task-1", key=None, **overrides):
        body = {"id": task_id, "system": "crm", "query": "email = subject@example.test", "actor": "agent-7"}
        body.update(overrides)
        return self.service.create_retrieval_task("req-1", body, key or f"create-{task_id}")

    def act(self, action, task_id="task-1", key=None, **body):
        return self.service.retrieval_task_action(
            "req-1", task_id, action, {"actor": "worker-1", **body}, key or f"{task_id}-{action}")

    def test_create_returns_queued_task_with_clock_timestamps(self):
        task = self.create()
        self.assertEqual({"request_id": "req-1", "task_id": "task-1", "system": "crm", "status": "queued",
                          "records": None, "reason": None,
                          "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
                          "started_at": None, "finished_at": None}, task)

    def test_create_validation_and_conflicts(self):
        with self.assertRaisesRegex(ValidationError, "exactly id, system, query, and actor"):
            self.create(extra="nope")
        with self.assertRaisesRegex(ValidationError, "system must be a non-empty string"):
            self.create(system="")
        with self.assertRaisesRegex(ValidationError, "query must be a non-empty string of at most 2000"):
            self.create(query="x" * 2001)
        with self.assertRaisesRegex(ValidationError, "actor must be a non-empty string of at most 200"):
            self.create(actor="x" * 201)
        with self.assertRaisesRegex(ValidationError, "task id must be a non-empty string of at most 100"):
            self.create(task_id="x" * 101)
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.service.create_retrieval_task(
                "ghost", {"id": "t", "system": "crm", "query": "q", "actor": "a"}, "ghost-task")
        self.create()
        with self.assertRaisesRegex(ConflictError, "retrieval task task-1 already exists"):
            self.create(key="another-key")

    def test_start_complete_flow_and_timestamps(self):
        self.create()
        self.clock.advance(hours=1)
        started = self.act("start")
        self.assertEqual(("running", "2026-01-01T01:00:00Z", "2026-01-01T01:00:00Z", None),
                         (started["status"], started["started_at"], started["updated_at"], started["finished_at"]))
        self.clock.advance(hours=2)
        records = [{"id": "r-1", "payload": {"email": "subject@example.test"}}]
        done = self.act("complete", records=records)
        self.assertEqual(("succeeded", records, "2026-01-01T03:00:00Z", "2026-01-01T01:00:00Z"),
                         (done["status"], done["records"], done["finished_at"], done["started_at"]))

    def test_complete_records_keep_first_of_each_id(self):
        self.create()
        self.act("start")
        batch = [{"id": "r-1", "payload": {"v": 1}}, {"id": "r-1", "payload": {"v": 2}},
                 {"id": "r-2", "payload": {"v": 3}}]
        done = self.act("complete", records=batch)
        self.assertEqual([{"id": "r-1", "payload": {"v": 1}}, {"id": "r-2", "payload": {"v": 3}}], done["records"])
        with self.assertRaisesRegex(ValidationError, "records must be an array"):
            self.service.retrieval_task_action("req-1", "task-1", "complete",
                                               {"actor": "a", "records": {}}, "bad-records")
        with self.assertRaisesRegex(ValidationError, "exactly id and payload"):
            self.service.retrieval_task_action("req-1", "task-1", "complete",
                                               {"actor": "a", "records": [{"id": "r"}]}, "bad-record")

    def test_fail_requires_reason_and_records_terminal_view(self):
        self.create()
        with self.assertRaisesRegex(ValidationError, "fail must contain exactly actor, reason"):
            self.act("fail")
        self.act("start")
        with self.assertRaisesRegex(ValidationError, "reason must be a non-empty string of at most 1000"):
            self.act("fail", key="fail-empty", reason="")
        failed = self.act("fail", reason="system timeout")
        self.assertEqual(("failed", "system timeout", None), (failed["status"], failed["reason"], failed["records"]))
        self.assertIsNotNone(failed["finished_at"])

    def test_action_bodies_are_strict(self):
        self.create()
        with self.assertRaisesRegex(ValidationError, "start must contain exactly actor"):
            self.act("start", note="extra")
        with self.assertRaisesRegex(ValidationError, "complete must contain exactly actor, records"):
            self.act("complete")
        with self.assertRaisesRegex(ValidationError, "actor must be a non-empty string"):
            self.act("start", actor="")

    def test_illegal_task_transitions_change_nothing(self):
        self.create()
        with self.assertRaisesRegex(
                IllegalTransitionError,
                "illegal transition from queued to succeeded; legal successors: running"):
            self.act("complete", records=[])
        self.act("start")
        with self.assertRaisesRegex(IllegalTransitionError,
                                    "illegal transition from running to running; legal successors: failed, succeeded"):
            self.act("start", key="start-again")
        self.act("complete", records=[])
        for action, body in (("start", {}), ("complete", {"records": []}), ("fail", {"reason": "late"})):
            with self.assertRaisesRegex(IllegalTransitionError, "legal successors: none"):
                self.act(action, key=f"late-{action}", **body)
        task = self.service.retrieval_tasks("req-1")["tasks"][0]
        self.assertEqual(("succeeded", "2026-01-01T00:00:00Z"), (task["status"], task["updated_at"]))

    def test_missing_request_or_task_is_not_found(self):
        self.create()
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.service.retrieval_tasks("ghost")
        with self.assertRaisesRegex(NotFoundError, "retrieval task ghost was not found"):
            self.act("start", task_id="ghost")
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.service.retrieval_task_action("ghost", "task-1", "start", {"actor": "a"}, "ghost-start")

    def test_idempotency_replays_without_reapplying(self):
        self.create()
        first = self.act("start")
        self.assertEqual(first, self.act("start", key="task-1-start", actor="someone-else"))
        self.assertEqual("running", self.service.retrieval_tasks("req-1")["tasks"][0]["status"])
        with self.assertRaisesRegex(ValidationError, "Idempotency-Key"):
            self.service.retrieval_task_action("req-1", "task-1", "complete",
                                               {"actor": "a", "records": []}, None)
        with self.assertRaises(ConflictError):
            self.act("complete", key="task-1-start", records=[])

    def test_listing_is_sorted_with_totals_and_progress(self):
        empty = self.service.retrieval_tasks("req-1")
        self.assertEqual({"total": 0, "queued": 0, "running": 0, "succeeded": 0, "failed": 0,
                          "completed": 0, "progress_percent": 0}, empty["totals"])
        self.create("task-c")
        self.create("task-a")
        self.create("task-b")
        self.act("start", "task-a")
        self.act("complete", "task-a", records=[{"id": "r-1", "payload": {}}])
        self.act("start", "task-b")
        self.act("fail", "task-b", reason="unreachable")
        listing = self.service.retrieval_tasks("req-1")
        self.assertEqual(["task-a", "task-b", "task-c"], [task["task_id"] for task in listing["tasks"]])
        self.assertEqual({"total": 3, "queued": 1, "running": 0, "succeeded": 1, "failed": 1,
                          "completed": 2, "progress_percent": 66}, listing["totals"])
        self.assertEqual([{"id": "r-1", "payload": {}}], listing["tasks"][0]["records"])
        self.assertEqual("unreachable", listing["tasks"][1]["reason"])
        self.assertIsNone(listing["tasks"][2]["records"])
        self.act("start", "task-c")
        self.act("complete", "task-c", records=[])
        self.assertEqual(100, self.service.retrieval_tasks("req-1")["totals"]["progress_percent"])

    def test_tasks_never_touch_the_request(self):
        self.create()
        self.act("start")
        self.act("complete", records=[{"id": "r-1", "payload": {"email": "subject@example.test"}}])
        request = self.service.get_request("req-1")
        self.assertEqual(("received", [], None), (request["state"], request["records"], request["collection"]))
        self.assertEqual(1, self.service.evidence("req-1")["count"])
        self.assertEqual(0, self.service.subject_records("user-42")["count"])


class SlaAlertTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.clock = FixedClock("2026-01-01T00:00:00Z")
        self.service = RightsFlow(str(Path(self.directory.name) / "test.db"), clock=self.clock)
        self.service.create_policy({"id": "eu-access", "retention_days": 30, "action": "delete"}, "policy-1")
        self.service.create_request({"id": "req-1", "subject_id": "user-42", "request_type": "access",
                                     "policy_id": "eu-access", "sla_days": 30, "actor": "agent-7"}, "create-req-1")

    def tearDown(self):
        self.directory.cleanup()

    def create(self, request_id="req-1", key=None, **overrides):
        body = {"actor": "monitor-1", "reason": "past the contractual deadline"}
        body.update(overrides)
        return self.service.create_sla_alert(request_id, body, key or f"alert-{request_id}")

    def acknowledge(self, alert_id, key=None, **overrides):
        body = {"actor": "dpo", "note": "team notified"}
        body.update(overrides)
        return self.service.acknowledge_sla_alert(alert_id, body, key or f"ack-{alert_id}")

    def test_create_records_exactly_the_overdue_fact(self):
        self.service.create_request({"id": "req-2", "subject_id": "user-7", "request_type": "erasure",
                                     "policy_id": "eu-access", "sla_days": 30, "actor": "agent-7"}, "create-req-2")
        self.clock.advance(days=31)
        alert = self.create()
        self.assertEqual(
            {"alert_id", "request_id", "subject_id", "actor", "reason",
             "due_at", "detected_at", "overdue_seconds", "status"},
            set(alert))
        self.assertEqual(("req-1", "user-42", "monitor-1", "past the contractual deadline", "open"),
                         (alert["request_id"], alert["subject_id"], alert["actor"],
                          alert["reason"], alert["status"]))
        self.assertEqual(("2026-01-31T00:00:00Z", "2026-02-01T00:00:00Z", 86400),
                         (alert["due_at"], alert["detected_at"], alert["overdue_seconds"]))
        self.assertTrue(alert["alert_id"])
        other = self.create("req-2")
        self.assertNotEqual(alert["alert_id"], other["alert_id"])

    def test_create_leaves_request_evidence_and_records_untouched(self):
        self.clock.advance(days=40)
        self.create()
        request = self.service.get_request("req-1")
        self.assertEqual(("received", None, None), (request["state"], request["closed_at"], request["retention"]))
        self.assertEqual(1, self.service.evidence("req-1")["count"])
        self.assertEqual(0, self.service.subject_records("user-42")["count"])

    def test_create_requires_measured_at_strictly_after_due(self):
        self.clock.advance(days=29)
        with self.assertRaisesRegex(ConflictError, "not overdue"):
            self.create(key="early")
        self.clock.advance(days=1)  # exactly at due_at
        with self.assertRaisesRegex(ConflictError, "not overdue"):
            self.create(key="at-due")
        self.clock.advance(seconds=1)
        self.assertEqual(1, self.create()["overdue_seconds"])

    def test_create_rejects_terminal_states_and_missing_requests(self):
        self.clock.advance(days=31)
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.create("ghost")
        self.service.transition("req-1", {"action": "cancel", "actor": "subject", "reason": "withdrawn"}, "cancel-1")
        with self.assertRaisesRegex(ConflictError, "cancelled"):
            self.create()

    def test_create_validates_the_body_strictly(self):
        self.clock.advance(days=31)
        with self.assertRaisesRegex(ValidationError, "exactly actor and reason"):
            self.create(extra="nope")
        with self.assertRaisesRegex(ValidationError, "exactly actor and reason"):
            self.service.create_sla_alert("req-1", {"actor": "m"}, "missing-reason")
        with self.assertRaisesRegex(ValidationError, "actor must be a non-empty string of at most 200"):
            self.create(actor="")
        with self.assertRaisesRegex(ValidationError, "actor must be a non-empty string of at most 200"):
            self.create(actor="x" * 201)
        with self.assertRaisesRegex(ValidationError, "reason must be a non-empty string of at most 1000"):
            self.create(reason="x" * 1001)

    def test_one_alert_per_request_and_due_at(self):
        self.clock.advance(days=31)
        first = self.create()
        with self.assertRaisesRegex(ConflictError, "already exists"):
            self.create(key="another-key")
        replayed = self.create(key="alert-req-1", reason="different body, same key")
        self.assertEqual(first, replayed)
        self.assertEqual(1, self.service.sla_alerts("req-1")["totals"]["total"])

    def test_listing_is_empty_then_counts_by_status(self):
        empty = self.service.sla_alerts("req-1")
        self.assertEqual({"request_id": "req-1", "alerts": [],
                          "totals": {"total": 0, "open": 0, "acknowledged": 0, "count": 0}}, empty)
        with self.assertRaisesRegex(NotFoundError, "request ghost was not found"):
            self.service.sla_alerts("ghost")
        self.clock.advance(days=31)
        created = self.create()
        listing = self.service.sla_alerts("req-1")
        self.assertEqual({"total": 1, "open": 1, "acknowledged": 0, "count": 1}, listing["totals"])
        alert = listing["alerts"][0]
        self.assertEqual(created["alert_id"], alert["alert_id"])
        self.assertEqual((None, None, None),
                         (alert["acknowledged_at"], alert["acknowledged_by"], alert["acknowledged_note"]))
        self.clock.advance(hours=2)
        self.acknowledge(created["alert_id"])
        listing = self.service.sla_alerts("req-1")
        self.assertEqual({"total": 1, "open": 0, "acknowledged": 1, "count": 1}, listing["totals"])
        self.assertEqual("acknowledged", listing["alerts"][0]["status"])

    def test_acknowledge_records_the_fact_without_changing_the_overdue_data(self):
        self.clock.advance(days=31)
        created = self.create()
        self.clock.advance(hours=3)
        acknowledged = self.acknowledge(created["alert_id"])
        self.assertEqual(("acknowledged", "2026-02-01T03:00:00Z", "dpo", "team notified"),
                         (acknowledged["status"], acknowledged["acknowledged_at"],
                          acknowledged["acknowledged_by"], acknowledged["acknowledged_note"]))
        self.assertEqual((created["due_at"], created["detected_at"], created["overdue_seconds"]),
                         (acknowledged["due_at"], acknowledged["detected_at"], acknowledged["overdue_seconds"]))
        self.assertEqual(1, self.service.evidence("req-1")["count"])
        self.assertEqual("received", self.service.get_request("req-1")["state"])

    def test_acknowledge_conflicts_on_repeat_and_404s_on_unknown_alerts(self):
        self.clock.advance(days=31)
        created = self.create()
        self.acknowledge(created["alert_id"])
        with self.assertRaisesRegex(ConflictError, "already acknowledged"):
            self.acknowledge(created["alert_id"], key="ack-again")
        with self.assertRaisesRegex(NotFoundError, "SLA alert ghost was not found"):
            self.acknowledge("ghost")
        replayed = self.acknowledge(created["alert_id"], key=f"ack-{created['alert_id']}")
        self.assertEqual("acknowledged", replayed["status"])

    def test_acknowledge_validates_the_body_strictly(self):
        self.clock.advance(days=31)
        created = self.create()
        with self.assertRaisesRegex(ValidationError, "exactly actor and note"):
            self.acknowledge(created["alert_id"], reason="wrong field")
        with self.assertRaisesRegex(ValidationError, "actor must be a non-empty string of at most 200"):
            self.acknowledge(created["alert_id"], actor="")
        with self.assertRaisesRegex(ValidationError, "note must be a non-empty string of at most 2000"):
            self.acknowledge(created["alert_id"], note="")

    def test_idempotency_rules_apply_to_both_endpoints(self):
        self.clock.advance(days=31)
        with self.assertRaisesRegex(ValidationError, "Idempotency-Key"):
            self.service.create_sla_alert("req-1", {"actor": "m", "reason": "late"}, None)
        created = self.create()
        with self.assertRaises(ConflictError):
            self.service.acknowledge_sla_alert(created["alert_id"], {"actor": "dpo", "note": "n"}, "alert-req-1")
        with self.assertRaisesRegex(ValidationError, "Idempotency-Key"):
            self.service.acknowledge_sla_alert(created["alert_id"], {"actor": "dpo", "note": "n"}, None)


if __name__ == "__main__":
    unittest.main()

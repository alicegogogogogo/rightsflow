from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

from . import evidence as evidence_module
from . import model
from .clock import Clock, SystemClock, format_timestamp, parse_timestamp
from .errors import ConflictError, IllegalTransitionError, NotFoundError, ValidationError
from .store import Store

TERMINAL = frozenset(model.TERMINAL_STATES)


class RightsFlow:
    """Data subject request orchestration, hash-chained evidence, retention, and SLA."""

    def __init__(self, database: str, clock: Clock | None = None):
        self.store = Store(database)
        self.clock = clock if clock is not None else SystemClock()

    # ------------------------------------------------------------------ internals

    def _now(self) -> datetime:
        return self.clock.now().astimezone(timezone.utc)

    def _idempotent(self, key: str | None, operation: str, action: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        if not key:
            raise ValidationError("Idempotency-Key header is required")
        with self.store.transaction() as connection:
            row = connection.execute("SELECT operation, response FROM idempotency WHERE key = ?", (key,)).fetchone()
            if row:
                if row["operation"] != operation:
                    raise ConflictError("idempotency key was already used for another operation")
                return self.store.decode(row["response"])
            response = action()
            connection.execute("INSERT INTO idempotency(key, operation, response) VALUES (?, ?, ?)",
                               (key, operation, self.store.encode(response)))
            return response

    def _insert(self, statement: str, parameters: tuple[Any, ...], message: str) -> None:
        try:
            self.store.connection.execute(statement, parameters)
        except Exception as error:
            if "UNIQUE constraint" in str(error):
                raise ConflictError(message) from error
            raise

    def _documents(self) -> Iterator[dict[str, Any]]:
        rows = self.store.connection.execute("SELECT document FROM requests ORDER BY id").fetchall()
        return (self.store.decode(row["document"]) for row in rows)

    def _load(self, request_id: str) -> tuple[dict[str, Any], str | None]:
        row = self.store.connection.execute(
            "SELECT document, head_hash FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if not row:
            raise NotFoundError(f"request {request_id} was not found")
        return self.store.decode(row["document"]), row["head_hash"]

    def _records(self, request_id: str) -> list[dict[str, Any]]:
        rows = self.store.connection.execute(
            "SELECT record_id, subject_id, payload, anonymized FROM records"
            " WHERE request_id = ? ORDER BY record_id",
            (request_id,),
        ).fetchall()
        return [{"id": row["record_id"], **_record_view(row, self.store)} for row in rows]

    def _project(self, document: dict[str, Any], head_hash: str | None) -> dict[str, Any]:
        return {
            "id": document["id"], "subject_id": document["subject_id"],
            "request_type": document["request_type"], "policy_id": document["policy_id"],
            "actor": document["actor"], "state": document["state"],
            "received_at": document["received_at"], "updated_at": document["updated_at"],
            "closed_at": document["closed_at"], "closed_reason": document["closed_reason"],
            "sla_days": document["sla_days"], "sla_due_at": document["sla_due_at"],
            "sla": self._sla(document), "legal_transitions": model.successors(document["state"]),
            "collection": document["collection"], "records": self._records(document["id"]),
            "retention": document["retention"], "history": document["history"],
            "evidence_head": head_hash,
        }

    def _sla(self, document: dict[str, Any]) -> dict[str, Any]:
        """SLA timing reads the injected clock only.

        A closed request measures to its `closed_at`; an open one measures to the
        clock's current instant. Nothing here consults the wall clock.
        """
        received = parse_timestamp(document["received_at"], "received_at")
        due = parse_timestamp(document["sla_due_at"], "sla_due_at")
        measured = parse_timestamp(document["closed_at"], "closed_at") if document["closed_at"] else self._now()
        return {
            "due_at": document["sla_due_at"], "measured_at": format_timestamp(measured),
            "elapsed_seconds": int((measured - received).total_seconds()),
            "remaining_seconds": max(0, int((due - measured).total_seconds())),
            "overdue_seconds": max(0, int((measured - due).total_seconds())),
            "breached": measured > due,
        }

    def _append_evidence(
        self, request_id: str, entry_type: str, occurred_at: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        row = self.store.connection.execute(
            "SELECT sequence, hash FROM evidence WHERE request_id = ? ORDER BY sequence DESC LIMIT 1",
            (request_id,),
        ).fetchone()
        previous_hash = row["hash"] if row else None
        sequence = row["sequence"] + 1 if row else 1
        entry = evidence_module.make_entry(sequence, request_id, entry_type, occurred_at, payload, previous_hash)
        self.store.connection.execute(
            "INSERT INTO evidence(request_id, sequence, type, occurred_at, content, previous_hash, hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (request_id, sequence, entry_type, occurred_at, self.store.encode(entry["content"]),
             previous_hash, entry["hash"]),
        )
        self.store.connection.execute("UPDATE requests SET head_hash = ? WHERE id = ?", (entry["hash"], request_id))
        return entry

    # --------------------------------------------------------------------- policy

    def create_policy(self, raw: Any, key: str | None) -> dict[str, Any]:
        policy = model.parse_policy(raw)

        def create() -> dict[str, Any]:
            self._insert("INSERT INTO policies(id, document) VALUES (?, ?)",
                         (policy["id"], self.store.encode(policy)), f"policy {policy['id']} already exists")
            return policy

        return self._idempotent(key, f"create-policy:{policy['id']}", create)

    def _policy(self, policy_id: str) -> dict[str, Any]:
        row = self.store.connection.execute("SELECT document FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if not row:
            raise NotFoundError(f"policy {policy_id} was not found")
        return self.store.decode(row["document"])

    # -------------------------------------------------------------------- request

    def create_request(self, raw: Any, key: str | None) -> dict[str, Any]:
        spec = model.parse_request(raw)
        self._policy(spec["policy_id"])

        def create() -> dict[str, Any]:
            now = self._now()
            received_at = format_timestamp(now)
            due_at = format_timestamp(now + timedelta(days=spec["sla_days"]))
            document = {
                "id": spec["id"], "subject_id": spec["subject_id"], "request_type": spec["request_type"],
                "policy_id": spec["policy_id"], "actor": spec["actor"], "state": "received",
                "received_at": received_at, "updated_at": received_at,
                "closed_at": None, "closed_reason": None,
                "sla_days": spec["sla_days"], "sla_due_at": due_at,
                "collection": None, "retention": None,
                "history": [_history_entry(1, None, None, "received", spec["actor"], None, None, None, received_at)]}
            self._insert(
                "INSERT INTO requests(id, subject_id, state, document, head_hash) VALUES (?, ?, ?, ?, NULL)",
                (document["id"], document["subject_id"], document["state"], self.store.encode(document)),
                f"request {document['id']} already exists",
            )
            entry = self._append_evidence(document["id"], "request_received", received_at, {
                "subject_id": spec["subject_id"], "request_type": spec["request_type"],
                "policy_id": spec["policy_id"], "sla_days": spec["sla_days"],
                "sla_due_at": due_at, "actor": spec["actor"],
            })
            return self._project(document, entry["hash"])

        return self._idempotent(key, f"create-request:{spec['id']}", create)

    def get_request(self, request_id: str) -> dict[str, Any]:
        document, head_hash = self._load(request_id)
        return self._project(document, head_hash)

    def transition(self, request_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        change = model.parse_transition(raw)
        target = model.ACTION_TARGETS[change["action"]]

        def apply() -> dict[str, Any]:
            document, _ = self._load(request_id)
            source = document["state"]
            if target not in model.TRANSITIONS.get(source, ()):
                legal = ", ".join(model.successors(source)) or "none"
                raise IllegalTransitionError(f"illegal transition from {source} to {target}; legal successors: {legal}")
            return self._apply_change(request_id, document, change, format_timestamp(self._now()))

        return self._idempotent(key, f"transition:{request_id}:{change['action']}", apply)

    def _apply_change(
        self, request_id: str, document: dict[str, Any], change: dict[str, Any], occurred_at: str
    ) -> dict[str, Any]:
        """Mutate the request document, append history and evidence, and project.

        Shared by direct transitions and by review execution, so a review-applied
        `reject`/`fulfill` is indistinguishable from a direct one: same history
        entry, same evidence payload, same closure and retention snapshot.
        """
        source = document["state"]
        target = model.ACTION_TARGETS[change["action"]]
        if change["action"] == "collect":
            for record in change["records"]:
                self.store.connection.execute(
                    "INSERT INTO records(request_id, record_id, subject_id, payload, anonymized)"
                    " VALUES (?, ?, ?, ?, 0)",
                    (request_id, record["id"], document["subject_id"], self.store.encode(record["payload"])),
                )
            document["collection"] = change["details"]

        document["history"].append(_history_entry(
            len(document["history"]) + 1, change["action"], source, target, change["actor"],
            change["note"], change["reason"], change["details"], occurred_at))
        document["state"] = target
        document["updated_at"] = occurred_at
        if target in TERMINAL:
            policy = self._policy(document["policy_id"])
            expires = parse_timestamp(occurred_at, "occurred_at") + timedelta(days=policy["retention_days"])
            document["closed_at"] = occurred_at
            document["closed_reason"] = change["reason"]
            document["retention"] = {
                "policy_id": policy["id"], "retention_days": policy["retention_days"],
                "action": policy["action"], "expires_at": format_timestamp(expires),
                "applied_at": None, "affected_records": 0,
            }
        self.store.connection.execute(
            "UPDATE requests SET document = ?, state = ? WHERE id = ?",
            (self.store.encode(document), document["state"], request_id),
        )
        entry = self._append_evidence(request_id, "transition", occurred_at, {
            "action": change["action"], "from": source, "to": target, "actor": change["actor"],
            "note": change["note"], "reason": change["reason"], "details": change["details"],
        })
        return self._project(document, entry["hash"])

    # ------------------------------------------------------------------- reviews

    def create_review(self, request_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        """Propose a dual-review `reject`/`fulfill`; nothing changes until two approvals."""
        spec = model.parse_review(raw)
        target = model.ACTION_TARGETS[spec["action"]]

        def create() -> dict[str, Any]:
            document, head_hash = self._load(request_id)
            source = document["state"]
            if target not in model.TRANSITIONS.get(source, ()):
                legal = ", ".join(model.successors(source)) or "none"
                raise IllegalTransitionError(f"illegal transition from {source} to {target}; legal successors: {legal}")
            existing = self.store.connection.execute(
                "SELECT 1 FROM reviews WHERE request_id = ? AND review_id = ?",
                (request_id, spec["review_id"]),
            ).fetchone()
            if existing:
                raise ConflictError(f"review {spec['review_id']} already exists on request {request_id}")
            pending = self.store.connection.execute(
                "SELECT 1 FROM reviews WHERE request_id = ? AND action = ? AND status = 'pending'",
                (request_id, spec["action"]),
            ).fetchone()
            if pending:
                raise ConflictError(
                    f"a pending review for action {spec['action']} already exists on request {request_id}")
            self._insert(
                "INSERT INTO reviews(request_id, review_id, action, actor, reason, note, status,"
                " snapshot_state, snapshot_evidence_head, created_at, applied_at, transition_result)"
                " VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, NULL, NULL)",
                (request_id, spec["review_id"], spec["action"], spec["actor"], spec["reason"], spec["note"],
                 source, head_hash, format_timestamp(self._now())),
                f"review {spec['review_id']} already exists on request {request_id}",
            )
            return self._review_view(self._load_review(request_id, spec["review_id"]))

        return self._idempotent(key, f"create-review:{request_id}:{spec['review_id']}", create)

    def decide_review(self, request_id: str, review_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        """Record one independent decision; the second approval executes the change."""
        spec = model.parse_review_decision(raw)

        def apply() -> dict[str, Any]:
            review = self._load_review(request_id, review_id)
            if review["status"] != "pending":
                raise ConflictError(f"review {review_id} is {review['status']}")
            if spec["actor"] == review["actor"]:
                raise ConflictError(f"actor {spec['actor']} proposed review {review_id} and cannot decide it")
            duplicate = self.store.connection.execute(
                "SELECT 1 FROM review_decisions WHERE request_id = ? AND review_id = ? AND actor = ?",
                (request_id, review_id, spec["actor"]),
            ).fetchone()
            if duplicate:
                raise ConflictError(f"actor {spec['actor']} already decided review {review_id}")

            document, head_hash = self._load(request_id)
            if (document["state"] != review["snapshot_state"]
                    or head_hash != review["snapshot_evidence_head"]):
                # The request moved on since the proposal: the review dies undecided.
                self.store.connection.execute(
                    "UPDATE reviews SET status = 'stale' WHERE request_id = ? AND review_id = ?",
                    (request_id, review_id),
                )
                return self._review_view(self._load_review(request_id, review_id))

            decided_at = format_timestamp(self._now())
            sequence = self.store.connection.execute(
                "SELECT COUNT(*) AS total FROM review_decisions WHERE request_id = ? AND review_id = ?",
                (request_id, review_id),
            ).fetchone()["total"] + 1
            self.store.connection.execute(
                "INSERT INTO review_decisions(request_id, review_id, sequence, actor, decision, note, decided_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (request_id, review_id, sequence, spec["actor"], spec["decision"], spec["note"], decided_at),
            )

            if spec["decision"] == "deny":
                self.store.connection.execute(
                    "UPDATE reviews SET status = 'denied' WHERE request_id = ? AND review_id = ?",
                    (request_id, review_id),
                )
                return self._review_view(self._load_review(request_id, review_id))

            approvals = self.store.connection.execute(
                "SELECT COUNT(*) AS total FROM review_decisions"
                " WHERE request_id = ? AND review_id = ? AND decision = 'approve'",
                (request_id, review_id),
            ).fetchone()["total"]
            if approvals < 2:
                return self._review_view(self._load_review(request_id, review_id))

            change = {"action": review["action"], "actor": review["actor"], "note": review["note"],
                      "reason": review["reason"], "details": None, "records": []}
            result = self._apply_change(request_id, document, change, decided_at)
            self.store.connection.execute(
                "UPDATE reviews SET status = 'applied', applied_at = ?, transition_result = ?"
                " WHERE request_id = ? AND review_id = ?",
                (decided_at, self.store.encode(result), request_id, review_id),
            )
            return self._review_view(self._load_review(request_id, review_id))

        return self._idempotent(key, f"decide-review:{request_id}:{review_id}:{spec['actor']}", apply)

    def get_review(self, request_id: str, review_id: str) -> dict[str, Any]:
        return self._review_view(self._load_review(request_id, review_id))

    def reviews(self, request_id: str) -> dict[str, Any]:
        self._load(request_id)
        rows = self.store.connection.execute(
            "SELECT * FROM reviews WHERE request_id = ? ORDER BY created_at, review_id", (request_id,)
        ).fetchall()
        return {"request_id": request_id, "reviews": [self._review_view(row) for row in rows]}

    def _load_review(self, request_id: str, review_id: str) -> Any:
        self._load(request_id)
        row = self.store.connection.execute(
            "SELECT * FROM reviews WHERE request_id = ? AND review_id = ?", (request_id, review_id)
        ).fetchone()
        if not row:
            raise NotFoundError(f"review {review_id} was not found")
        return row

    def _review_view(self, row: Any) -> dict[str, Any]:
        decisions = self.store.connection.execute(
            "SELECT actor, decision, note, decided_at FROM review_decisions"
            " WHERE request_id = ? AND review_id = ? ORDER BY sequence",
            (row["request_id"], row["review_id"]),
        ).fetchall()
        return {
            "request_id": row["request_id"], "review_id": row["review_id"],
            "action": row["action"], "actor": row["actor"],
            "reason": row["reason"], "note": row["note"], "status": row["status"],
            "snapshot_state": row["snapshot_state"], "snapshot_evidence_head": row["snapshot_evidence_head"],
            "created_at": row["created_at"], "applied_at": row["applied_at"],
            "decisions": [dict(decision) for decision in decisions],
            "transition_result": self.store.decode(row["transition_result"])
            if row["transition_result"] is not None else None,
        }

    # ------------------------------------------------------------------- evidence

    def evidence(self, request_id: str) -> dict[str, Any]:
        self._load(request_id)
        rows = self.store.connection.execute(
            "SELECT content, previous_hash, hash FROM evidence WHERE request_id = ? ORDER BY sequence",
            (request_id,),
        ).fetchall()
        entries = [{"content": self.store.decode(row["content"]), "previous_hash": row["previous_hash"],
                    "hash": row["hash"]} for row in rows]
        return {"request_id": request_id, "entries": entries, **evidence_module.verify_chain(entries)}

    def verify_evidence(self, raw: Any) -> dict[str, Any]:
        return evidence_module.verify_chain(evidence_module.parse_entries(raw))

    # ------------------------------------------------------------- audit export

    def audit_export(self, request_id: str | None = None, include_records: bool = False) -> dict[str, Any]:
        """Read-only snapshot of requests, evidence integrity, and records.

        Nothing is written: the export is computed and returned, and the only
        clock read stamps `generated_at`. A named request must exist (`404`);
        without one the export simply covers every request, including none.
        """
        if request_id is not None:
            self._load(request_id)
            request_scope, evidence_scope, record_scope = (
                " WHERE id = ?", " WHERE request_id = ?", " WHERE request_id = ?")
            parameters: tuple[Any, ...] = (request_id,)
        else:
            request_scope = evidence_scope = record_scope = ""
            parameters = ()

        request_rows = self.store.connection.execute(
            f"SELECT id, document, head_hash FROM requests{request_scope} ORDER BY id", parameters
        ).fetchall()
        requests_view: list[dict[str, Any]] = []
        evidence_view: list[dict[str, Any]] = []
        entries_by_request: dict[str, list[dict[str, Any]]] = {}
        for row in request_rows:
            document = self.store.decode(row["document"])
            requests_view.append({
                "id": document["id"], "subject_id": document["subject_id"], "state": document["state"],
                "received_at": document["received_at"], "updated_at": document["updated_at"],
                "evidence_head": row["head_hash"], "first_invalid_sequence": None,
            })
            entries_by_request[document["id"]] = []

        evidence_rows = self.store.connection.execute(
            f"SELECT request_id, content, previous_hash, hash FROM evidence{evidence_scope}"
            " ORDER BY request_id, sequence", parameters
        ).fetchall()
        for row in evidence_rows:
            entry = {"content": self.store.decode(row["content"]),
                     "previous_hash": row["previous_hash"], "hash": row["hash"]}
            evidence_view.append(entry)
            entries_by_request[row["request_id"]].append(entry)

        for request in requests_view:
            request["first_invalid_sequence"] = evidence_module.verify_chain(
                entries_by_request[request["id"]]
            )["first_invalid_sequence"]

        record_rows = self.store.connection.execute(
            f"SELECT request_id, record_id, subject_id, payload, anonymized FROM records{record_scope}"
            " ORDER BY request_id, record_id", parameters
        ).fetchall()
        records_view: list[dict[str, Any]] = []
        for row in record_rows:
            record = {"request_id": row["request_id"], "record_id": row["record_id"],
                      "subject_id": row["subject_id"], "anonymized": bool(row["anonymized"])}
            if include_records:
                record["payload"] = self.store.decode(row["payload"])
            records_view.append(record)

        filter_view = {"request_id": request_id} if request_id is not None else None
        digest_payload = {"filter": filter_view, "requests": requests_view,
                          "evidence": evidence_view, "records": records_view}
        return {
            "generated_at": format_timestamp(self._now()),
            "filter": filter_view,
            "requests": requests_view,
            "evidence": evidence_view,
            "records": records_view,
            "totals": {"requests": len(requests_view),
                       "evidence": len(evidence_view),
                       "records": len(records_view)},
            "export_digest": evidence_module.sha256_hex(evidence_module.canonical_json(digest_payload)),
        }

    # ------------------------------------------------------------------ retention

    def policy_due(self, policy_id: str, at: str | None = None) -> dict[str, Any]:
        policy = self._policy(policy_id)
        reference = parse_timestamp(at, "at") if at is not None else self._now()
        candidates = (self._due_entry(document, reference) for document in self._documents()
                      if document["policy_id"] == policy_id)
        due = sorted((entry for entry in candidates if entry is not None), key=lambda item: item["request_id"])
        return {
            "policy_id": policy["id"], "retention_days": policy["retention_days"],
            "action": policy["action"], "at": format_timestamp(reference), "due": due,
        }

    def _is_due(self, document: dict[str, Any], reference: datetime) -> bool:
        return self._due_entry(document, reference) is not None

    def _due_entry(self, document: dict[str, Any], reference: datetime) -> dict[str, Any] | None:
        """The retention window is inclusive: due once `reference >= expires_at`."""
        retention = document["retention"]
        if not retention or retention["applied_at"] is not None:
            return None
        if reference < parse_timestamp(retention["expires_at"], "expires_at"):
            return None
        count = self.store.connection.execute(
            "SELECT COUNT(*) AS total FROM records WHERE request_id = ?", (document["id"],)
        ).fetchone()["total"]
        return {
            "request_id": document["id"], "subject_id": document["subject_id"], "state": document["state"],
            "closed_at": document["closed_at"], "expires_at": retention["expires_at"],
            "action": retention["action"], "record_count": count, "applied": False,
        }

    def enforce_policy(self, policy_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) != {"at"}:
            raise ValidationError("body must contain exactly at")
        reference = parse_timestamp(raw["at"], "at")

        def apply() -> dict[str, Any]:
            self._policy(policy_id)
            results = []
            for document in self._documents():
                if document["policy_id"] != policy_id or not self._is_due(document, reference):
                    continue
                retention = document["retention"]
                if retention["action"] == "delete":
                    cursor = self.store.connection.execute(
                        "DELETE FROM records WHERE request_id = ?", (document["id"],)
                    )
                else:
                    cursor = self.store.connection.execute(
                        "UPDATE records SET subject_id = ?, anonymized = 1 WHERE request_id = ? AND anonymized = 0",
                        (_pseudonym(document["subject_id"], document["id"]), document["id"]),
                    )
                retention["applied_at"] = format_timestamp(reference)
                retention["affected_records"] = cursor.rowcount
                self.store.connection.execute(
                    "UPDATE requests SET document = ? WHERE id = ?", (self.store.encode(document), document["id"])
                )
                results.append({
                    "request_id": document["id"], "subject_id": document["subject_id"],
                    "action": retention["action"], "affected_records": cursor.rowcount,
                })
            results.sort(key=lambda item: item["request_id"])
            remaining = len(self.policy_due(policy_id, format_timestamp(reference))["due"])
            return {"policy_id": policy_id, "at": format_timestamp(reference),
                    "results": results, "due_remaining": remaining}

        return self._idempotent(key, f"enforce-policy:{policy_id}", apply)

    # -------------------------------------------------------------------- records

    def subject_records(self, subject_id: str) -> dict[str, Any]:
        rows = self.store.connection.execute(
            "SELECT request_id, record_id, subject_id, payload, anonymized FROM records"
            " WHERE subject_id = ? ORDER BY request_id, record_id",
            (subject_id,),
        ).fetchall()
        records = [{"request_id": row["request_id"], "record_id": row["record_id"],
                    **_record_view(row, self.store)} for row in rows]
        return {"subject_id": subject_id, "count": len(records), "records": records}

    # ----------------------------------------------------------- retrieval tasks

    def create_retrieval_task(self, request_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        """Track a cross-system retrieval that feeds `collect` without touching the request."""
        spec = model.parse_retrieval_task(raw)
        self._load(request_id)

        def create() -> dict[str, Any]:
            now = format_timestamp(self._now())
            self._insert(
                "INSERT INTO retrieval_tasks(request_id, task_id, system, query, actor, status,"
                " records, reason, created_at, updated_at, started_at, finished_at)"
                " VALUES (?, ?, ?, ?, ?, 'queued', NULL, NULL, ?, ?, NULL, NULL)",
                (request_id, spec["id"], spec["system"], spec["query"], spec["actor"], now, now),
                f"retrieval task {spec['id']} already exists",
            )
            return self._task_view(self._load_task(request_id, spec["id"]))

        return self._idempotent(key, f"create-retrieval-task:{request_id}:{spec['id']}", create)

    def retrieval_task_action(
        self, request_id: str, task_id: str, action: str, raw: Any, key: str | None
    ) -> dict[str, Any]:
        change = model.parse_retrieval_action(action, raw)
        target = model.TASK_ACTION_TARGETS[action]

        def apply() -> dict[str, Any]:
            task = self._load_task(request_id, task_id)
            source = task["status"]
            if target not in model.TASK_TRANSITIONS.get(source, ()):
                legal = ", ".join(sorted(model.TASK_TRANSITIONS.get(source, ()))) or "none"
                raise IllegalTransitionError(
                    f"illegal transition from {source} to {target}; legal successors: {legal}")
            occurred_at = format_timestamp(self._now())
            self.store.connection.execute(
                "UPDATE retrieval_tasks SET status = ?, records = ?, reason = ?,"
                " updated_at = ?, started_at = ?, finished_at = ? WHERE request_id = ? AND task_id = ?",
                (target,
                 self.store.encode(change["records"]) if action == "complete" else task["records"],
                 change.get("reason") if action == "fail" else task["reason"],
                 occurred_at,
                 occurred_at if action == "start" else task["started_at"],
                 occurred_at if action in ("complete", "fail") else task["finished_at"],
                 request_id, task_id),
            )
            return self._task_view(self._load_task(request_id, task_id))

        return self._idempotent(key, f"retrieval-task-{action}:{request_id}:{task_id}", apply)

    def retrieval_tasks(self, request_id: str) -> dict[str, Any]:
        self._load(request_id)
        rows = self.store.connection.execute(
            "SELECT * FROM retrieval_tasks WHERE request_id = ? ORDER BY task_id", (request_id,)
        ).fetchall()
        tasks = [self._task_view(row) for row in rows]
        counts = {status: sum(1 for task in tasks if task["status"] == status)
                  for status in ("queued", "running", "succeeded", "failed")}
        completed = counts["succeeded"] + counts["failed"]
        total = len(tasks)
        return {
            "request_id": request_id, "tasks": tasks,
            "totals": {"total": total, **counts, "completed": completed,
                       "progress_percent": completed * 100 // total if total else 0},
        }

    def _load_task(self, request_id: str, task_id: str) -> Any:
        self._load(request_id)
        row = self.store.connection.execute(
            "SELECT * FROM retrieval_tasks WHERE request_id = ? AND task_id = ?", (request_id, task_id)
        ).fetchone()
        if not row:
            raise NotFoundError(f"retrieval task {task_id} was not found")
        return row

    def _task_view(self, row: Any) -> dict[str, Any]:
        return {
            "request_id": row["request_id"], "task_id": row["task_id"], "system": row["system"],
            "status": row["status"],
            "records": self.store.decode(row["records"]) if row["records"] is not None else None,
            "reason": row["reason"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "started_at": row["started_at"], "finished_at": row["finished_at"],
        }

    # ---------------------------------------------------------------- SLA alerts

    def create_sla_alert(self, request_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        """Record one overdue fact for an open request.

        The alert is stored on its own; nothing here changes the request state,
        appends evidence, or triggers retention. Only the injected clock decides
        whether the request is overdue, and the deadline is strict: measuring
        exactly at `due_at` is not overdue.
        """
        spec = model.parse_sla_alert(raw)

        def create() -> dict[str, Any]:
            document, _ = self._load(request_id)
            if document["state"] in TERMINAL:
                raise ConflictError(
                    f"request {request_id} is {document['state']}; SLA alerts require an open request")
            measured = self._now()
            due = parse_timestamp(document["sla_due_at"], "sla_due_at")
            if measured <= due:
                raise ConflictError(f"request {request_id} is not overdue")
            detected_at = format_timestamp(measured)
            alert_id = f"sla-{uuid.uuid4().hex}"
            self._insert(
                "INSERT INTO sla_alerts(alert_id, request_id, subject_id, actor, reason,"
                " due_at, detected_at, overdue_seconds, status,"
                " acknowledged_at, acknowledged_by, acknowledged_note)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, NULL, NULL)",
                (alert_id, request_id, document["subject_id"],
                 spec["actor"], spec["reason"], document["sla_due_at"], detected_at,
                 int((measured - due).total_seconds())),
                f"an SLA alert already exists for request {request_id} due at {document['sla_due_at']}",
            )
            view = self._alert_view(self._load_alert(alert_id))
            return {field: view[field] for field in (
                "alert_id", "request_id", "subject_id", "actor", "reason",
                "due_at", "detected_at", "overdue_seconds", "status")}

        return self._idempotent(key, f"create-sla-alert:{request_id}", create)

    def sla_alerts(self, request_id: str) -> dict[str, Any]:
        self._load(request_id)
        rows = self.store.connection.execute(
            "SELECT * FROM sla_alerts WHERE request_id = ?", (request_id,)
        ).fetchall()
        alerts = [self._alert_view(row) for row in rows]
        alerts.sort(key=lambda alert: (parse_timestamp(alert["detected_at"], "detected_at"), alert["alert_id"]))
        open_count = sum(1 for alert in alerts if alert["status"] == "open")
        acknowledged = sum(1 for alert in alerts if alert["status"] == "acknowledged")
        total = len(alerts)
        return {
            "request_id": request_id, "alerts": alerts,
            "totals": {"total": total, "open": open_count, "acknowledged": acknowledged, "count": total},
        }

    def acknowledge_sla_alert(self, alert_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        """Mark an open alert acknowledged; the overdue fact itself never changes."""
        spec = model.parse_sla_acknowledgement(raw)

        def apply() -> dict[str, Any]:
            row = self._load_alert(alert_id)
            if row["status"] == "acknowledged":
                raise ConflictError(f"SLA alert {alert_id} was already acknowledged")
            self.store.connection.execute(
                "UPDATE sla_alerts SET status = 'acknowledged', acknowledged_at = ?,"
                " acknowledged_by = ?, acknowledged_note = ? WHERE alert_id = ?",
                (format_timestamp(self._now()), spec["actor"], spec["note"], alert_id),
            )
            return self._alert_view(self._load_alert(alert_id))

        return self._idempotent(key, f"acknowledge-sla-alert:{alert_id}", apply)

    def _load_alert(self, alert_id: str) -> Any:
        row = self.store.connection.execute(
            "SELECT * FROM sla_alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if not row:
            raise NotFoundError(f"SLA alert {alert_id} was not found")
        return row

    def _alert_view(self, row: Any) -> dict[str, Any]:
        return {
            "alert_id": row["alert_id"], "request_id": row["request_id"], "subject_id": row["subject_id"],
            "actor": row["actor"], "reason": row["reason"],
            "due_at": row["due_at"], "detected_at": row["detected_at"],
            "overdue_seconds": row["overdue_seconds"], "status": row["status"],
            "acknowledged_at": row["acknowledged_at"], "acknowledged_by": row["acknowledged_by"],
            "acknowledged_note": row["acknowledged_note"],
        }


def _history_entry(sequence: int, action: str | None, source: str | None, target: str, actor: str,
                   note: str | None, reason: str | None, details: Any, occurred_at: str) -> dict[str, Any]:
    return {"sequence": sequence, "action": action, "from": source, "to": target, "actor": actor,
            "note": note, "reason": reason, "details": details, "occurred_at": occurred_at}


def _record_view(row: Any, store: Store) -> dict[str, Any]:
    return {"subject_id": row["subject_id"], "payload": store.decode(row["payload"]),
            "anonymized": bool(row["anonymized"])}


def _pseudonym(subject_id: str, request_id: str) -> str:
    return "anon:" + evidence_module.sha256_hex(f"{subject_id}:{request_id}")[:16]

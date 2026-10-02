from __future__ import annotations

from typing import Any

from .errors import ValidationError
from .evidence import records_digest

TERMINAL_STATES = ("fulfilled", "rejected", "cancelled")
REQUEST_TYPES = ("access", "rectification", "erasure", "portability", "restriction")
RETENTION_ACTIONS = ("delete", "anonymize")
REASON_ACTIONS = ("reject", "cancel")
REQUEST_FIELDS = ("id", "subject_id", "request_type", "policy_id", "sla_days", "actor")
POLICY_FIELDS = ("id", "retention_days", "action")
TRANSITION_FIELDS = ("action", "actor", "note", "reason", "details")
TASK_CREATE_FIELDS = ("id", "system", "query", "actor")
TASK_ACTION_FIELDS = {"start": ("actor",), "complete": ("actor", "records"), "fail": ("actor", "reason")}

ACTION_TARGETS = {
    "verify_identity": "identity_verified",
    "scope": "scoped",
    "collect": "collected",
    "package": "packaged",
    "fulfill": "fulfilled",
    "reject": "rejected",
    "cancel": "cancelled",
}

# The complete transition relation. A state absent from a tuple has no such successor.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "received": ("identity_verified", "rejected", "cancelled"),
    "identity_verified": ("scoped", "rejected", "cancelled"),
    "scoped": ("collected", "rejected", "cancelled"),
    "collected": ("packaged", "rejected", "cancelled"),
    "packaged": ("fulfilled", "cancelled"),
    "fulfilled": (),
    "rejected": (),
    "cancelled": (),
}

TASK_ACTION_TARGETS = {"start": "running", "complete": "succeeded", "fail": "failed"}

# Retrieval tasks have their own lifecycle, independent of the request state machine.
TASK_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "queued": ("running",),
    "running": ("succeeded", "failed"),
    "succeeded": (),
    "failed": (),
}


def successors(state: str) -> list[str]:
    """Legal successor states, lexicographically sorted."""
    return sorted(TRANSITIONS.get(state, ()))


def identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 100:
        raise ValidationError(f"{field} must be a non-empty string of at most 100 characters")
    return value


def text(value: Any, field: str, maximum: int, allow_null: bool = False) -> str | None:
    if value is None and allow_null:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{field} must be a non-empty string of at most {maximum} characters")
    return value


def integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise ValidationError(f"{field} must be between {minimum} and {maximum}")
    return value


def parse_policy(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != set(POLICY_FIELDS):
        raise ValidationError("policy must contain exactly id, retention_days, and action")
    if raw["action"] not in RETENTION_ACTIONS:
        raise ValidationError(f"action must be one of {', '.join(RETENTION_ACTIONS)}")
    return {"id": identifier(raw["id"], "policy id"), "action": raw["action"],
            "retention_days": integer(raw["retention_days"], "retention_days", 0, 3650)}


def parse_request(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != set(REQUEST_FIELDS):
        raise ValidationError(
            "request must contain exactly id, subject_id, request_type, policy_id, sla_days, and actor")
    if raw["request_type"] not in REQUEST_TYPES:
        raise ValidationError(f"request_type must be one of {', '.join(REQUEST_TYPES)}")
    return {"id": identifier(raw["id"], "request id"), "subject_id": identifier(raw["subject_id"], "subject_id"),
            "request_type": raw["request_type"], "policy_id": identifier(raw["policy_id"], "policy_id"),
            "sla_days": integer(raw["sla_days"], "sla_days", 1, 365), "actor": text(raw["actor"], "actor", 200)}


def parse_transition(raw: Any) -> dict[str, Any]:
    """Validate one transition command and normalize its details.

    `collect` carries raw records; they are normalized to a count plus a digest so
    that no collected payload ever reaches the request document or the hash chain.
    """
    if not isinstance(raw, dict):
        raise ValidationError("transition must be an object")
    unknown = sorted(set(raw) - set(TRANSITION_FIELDS))
    if unknown:
        raise ValidationError(f"unknown field(s): {', '.join(unknown)}")
    for required in ("action", "actor"):
        if required not in raw:
            raise ValidationError(f"transition must contain {required}")
    action = raw["action"]
    if action not in ACTION_TARGETS:
        raise ValidationError(f"action must be one of {', '.join(sorted(ACTION_TARGETS))}")

    reason = raw.get("reason")
    if action in REASON_ACTIONS:
        if not isinstance(reason, str) or not reason:
            raise ValidationError(f"{action} requires a non-empty reason")
        reason = text(reason, "reason", 1000)
    elif reason is not None:
        raise ValidationError("reason is only allowed for reject and cancel")

    details, records = raw.get("details"), []
    if action == "collect":
        records, normalized = _collect_details(details)
    elif action == "package":
        normalized = _package_details(details)
    elif details is not None and details != {}:
        raise ValidationError("details is only allowed for collect and package")
    else:
        normalized = None

    return {"action": action, "note": text(raw.get("note"), "note", 2000, allow_null=True),
            "actor": text(raw["actor"], "actor", 200), "reason": reason,
            "details": normalized, "records": records}


def _collect_details(details: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(details, dict) or set(details) != {"records"}:
        raise ValidationError("collect requires details containing exactly records")
    if not isinstance(details["records"], list):
        raise ValidationError("records must be an array")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position, item in enumerate(details["records"], start=1):
        if not isinstance(item, dict) or set(item) != {"id", "payload"}:
            raise ValidationError(f"record {position} must contain exactly id and payload")
        record_id = identifier(item["id"], f"record {position} id")
        if record_id in seen:
            raise ValidationError(f"duplicate record id {record_id}")
        seen.add(record_id)
        if not isinstance(item["payload"], dict):
            raise ValidationError(f"record {record_id} payload must be an object")
        records.append({"id": record_id, "payload": item["payload"]})
    return records, {"record_count": len(records), "records_digest": records_digest(records)}


def _package_details(details: Any) -> dict[str, Any]:
    if not isinstance(details, dict) or set(details) != {"artifact"}:
        raise ValidationError("package requires details containing exactly artifact")
    return {"artifact": text(details["artifact"], "artifact", 200)}


def parse_retrieval_task(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != set(TASK_CREATE_FIELDS):
        raise ValidationError("retrieval task must contain exactly id, system, query, and actor")
    return {"id": identifier(raw["id"], "task id"), "system": text(raw["system"], "system", 100),
            "query": text(raw["query"], "query", 2000), "actor": text(raw["actor"], "actor", 200)}


def parse_retrieval_action(action: str, raw: Any) -> dict[str, Any]:
    fields = TASK_ACTION_FIELDS[action]
    if not isinstance(raw, dict) or set(raw) != set(fields):
        raise ValidationError(f"{action} must contain exactly {', '.join(fields)}")
    parsed: dict[str, Any] = {"actor": text(raw["actor"], "actor", 200)}
    if action == "complete":
        parsed["records"] = _task_records(raw["records"])
    elif action == "fail":
        parsed["reason"] = text(raw["reason"], "reason", 1000)
    return parsed


def _task_records(value: Any) -> list[dict[str, Any]]:
    """Same record shape as `collect`, but a repeated id keeps the first occurrence."""
    if not isinstance(value, list):
        raise ValidationError("records must be an array")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position, item in enumerate(value, start=1):
        if not isinstance(item, dict) or set(item) != {"id", "payload"}:
            raise ValidationError(f"record {position} must contain exactly id and payload")
        record_id = identifier(item["id"], f"record {position} id")
        if not isinstance(item["payload"], dict):
            raise ValidationError(f"record {record_id} payload must be an object")
        if record_id in seen:
            continue
        seen.add(record_id)
        records.append({"id": record_id, "payload": item["payload"]})
    return records

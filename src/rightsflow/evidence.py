from __future__ import annotations

import hashlib
import json
from typing import Any

from .errors import ValidationError


def canonical_json(value: Any) -> str:
    """The single JSON encoding used by every hash in this service."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def records_digest(records: list[dict[str, Any]]) -> str:
    """Digest of a collected batch, so the chain never stores record payloads."""
    return sha256_hex(canonical_json(records))


def link_hash(content: dict[str, Any], previous_hash: str | None) -> str:
    """sha256(previous_hash + canonical_json(content)); a missing link contributes ""."""
    return sha256_hex((previous_hash or "") + canonical_json(content))


def make_entry(sequence: int, request_id: str, entry_type: str, occurred_at: str,
               payload: dict[str, Any], previous_hash: str | None) -> dict[str, Any]:
    content = {"sequence": sequence, "request_id": request_id, "type": entry_type,
               "occurred_at": occurred_at, "payload": payload}
    return {"content": content, "previous_hash": previous_hash, "hash": link_hash(content, previous_hash)}


def parse_entries(raw: Any) -> list[dict[str, Any]]:
    """Validate the envelope of an externally supplied chain before verifying it."""
    if not isinstance(raw, dict) or set(raw) != {"entries"} or not isinstance(raw["entries"], list):
        raise ValidationError("body must contain exactly an entries array")
    for position, entry in enumerate(raw["entries"], start=1):
        if not isinstance(entry, dict) or set(entry) != {"content", "previous_hash", "hash"}:
            raise ValidationError(f"entry {position} must contain exactly content, previous_hash, and hash")
        if not isinstance(entry["content"], dict):
            raise ValidationError(f"entry {position} content must be an object")
        if entry["previous_hash"] is not None and not isinstance(entry["previous_hash"], str):
            raise ValidationError(f"entry {position} previous_hash must be a string or null")
        if not isinstance(entry["hash"], str) or not entry["hash"]:
            raise ValidationError(f"entry {position} hash must be a non-empty string")
    return raw["entries"]


def verify_chain(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute every link; report the first sequence that breaks the chain."""
    content_fields = {"sequence", "request_id", "type", "occurred_at", "payload"}
    previous: str | None = None
    for position, entry in enumerate(entries, start=1):
        content = entry["content"]
        if not isinstance(content, dict) or set(content) != content_fields:
            return _broken(position, "content fields do not match the documented entry shape", len(entries))
        if content["sequence"] != position:
            return _broken(position, "sequence must be contiguous starting at 1", len(entries))
        if entry["previous_hash"] != previous:
            return _broken(position, "previous_hash does not match the preceding hash", len(entries))
        if link_hash(content, entry["previous_hash"]) != entry["hash"]:
            return _broken(position, "hash mismatch", len(entries))
        previous = entry["hash"]
    return {"chain_valid": True, "count": len(entries), "head": previous,
            "first_invalid_sequence": None, "reason": None}


def _broken(position: int, reason: str, count: int) -> dict[str, Any]:
    return {"chain_valid": False, "count": count, "head": None,
            "first_invalid_sequence": position, "reason": reason}

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol

from .errors import ValidationError

UTC = timezone.utc


class Clock(Protocol):
    """Everything time-dependent reads the current instant from a Clock."""

    def now(self) -> datetime: ...


class SystemClock:
    """Wall clock, used when the process runs without --now."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """Deterministic clock: tests and `--now` pin the instant and move it by hand."""

    def __init__(self, start: datetime | str):
        self._instant = parse_timestamp(start, "clock start") if isinstance(start, str) else start.astimezone(UTC)

    def now(self) -> datetime:
        return self._instant

    def advance(self, *, days: int = 0, hours: int = 0, minutes: int = 0, seconds: int = 0) -> datetime:
        self._instant += timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
        return self._instant


def parse_timestamp(value: object, field: str) -> datetime:
    """Parse an ISO 8601 instant that carries an explicit UTC offset (or `Z`)."""
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty ISO 8601 timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{field} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a UTC offset or a Z suffix")
    return parsed.astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    """Render an instant as UTC ISO 8601 with a `Z` suffix (microseconds only when non-zero)."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

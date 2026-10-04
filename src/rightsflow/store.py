from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, subject_id TEXT NOT NULL, state TEXT NOT NULL,
  document TEXT NOT NULL, head_hash TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
  request_id TEXT NOT NULL REFERENCES requests(id), sequence INTEGER NOT NULL,
  type TEXT NOT NULL, occurred_at TEXT NOT NULL, content TEXT NOT NULL,
  previous_hash TEXT, hash TEXT NOT NULL,
  PRIMARY KEY (request_id, sequence)
);
CREATE TABLE IF NOT EXISTS records (
  request_id TEXT NOT NULL REFERENCES requests(id), record_id TEXT NOT NULL,
  subject_id TEXT NOT NULL, payload TEXT NOT NULL, anonymized INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (request_id, record_id)
);
CREATE TABLE IF NOT EXISTS retrieval_tasks (
  request_id TEXT NOT NULL REFERENCES requests(id), task_id TEXT NOT NULL,
  system TEXT NOT NULL, query TEXT NOT NULL, actor TEXT NOT NULL,
  status TEXT NOT NULL, records TEXT, reason TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  started_at TEXT, finished_at TEXT,
  PRIMARY KEY (request_id, task_id)
);
CREATE TABLE IF NOT EXISTS sla_alerts (
  alert_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES requests(id),
  subject_id TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL,
  due_at TEXT NOT NULL, detected_at TEXT NOT NULL, overdue_seconds INTEGER NOT NULL,
  status TEXT NOT NULL,
  acknowledged_at TEXT, acknowledged_by TEXT, acknowledged_note TEXT,
  UNIQUE (request_id, due_at)
);
CREATE TABLE IF NOT EXISTS reviews (
  request_id TEXT NOT NULL REFERENCES requests(id), review_id TEXT NOT NULL,
  action TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT, note TEXT,
  status TEXT NOT NULL,
  snapshot_state TEXT NOT NULL, snapshot_evidence_head TEXT,
  created_at TEXT NOT NULL, applied_at TEXT, transition_result TEXT,
  PRIMARY KEY (request_id, review_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS reviews_pending_action
  ON reviews(request_id, action) WHERE status = 'pending';
CREATE TABLE IF NOT EXISTS review_decisions (
  request_id TEXT NOT NULL, review_id TEXT NOT NULL, sequence INTEGER NOT NULL,
  actor TEXT NOT NULL, decision TEXT NOT NULL, note TEXT, decided_at TEXT NOT NULL,
  PRIMARY KEY (request_id, review_id, actor)
);
CREATE TABLE IF NOT EXISTS idempotency (key TEXT PRIMARY KEY, operation TEXT NOT NULL, response TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS records_by_subject ON records(subject_id);
"""


class Store:
    """SQLite persistence. The store never reads a clock; time is always passed in.

    Each thread gets its own connection so that concurrent HTTP handlers never
    interleave statements on one connection object. Writers still serialize
    through `BEGIN IMMEDIATE`; a busy connection waits instead of failing.
    """

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._local = threading.local()
        self.connection.executescript(SCHEMA)

    @property
    def connection(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self._path, isolation_level=None,
                                         check_same_thread=False, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            self._local.connection = connection
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")

    @staticmethod
    def encode(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def decode(value: str) -> Any:
        return json.loads(value)

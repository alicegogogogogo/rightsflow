from __future__ import annotations

import json
import sqlite3
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
  system TEXT NOT NULL, query TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL,
  records TEXT, reason TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  PRIMARY KEY (request_id, task_id)
);
CREATE TABLE IF NOT EXISTS idempotency (key TEXT PRIMARY KEY, operation TEXT NOT NULL, response TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS records_by_subject ON records(subject_id);
"""


class Store:
    """SQLite persistence. The store never reads a clock; time is always passed in."""

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.executescript(SCHEMA)

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

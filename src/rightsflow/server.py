from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .clock import FixedClock
from .errors import CodedValidationError, NotFoundError, RightsFlowError, ValidationError
from .service import RightsFlow


class Handler(BaseHTTPRequestHandler):
    service: RightsFlow

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> Any:
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ValidationError("Content-Type must be application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 1_000_000:
                raise ValueError
            return json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValidationError("request body must be valid JSON") from error

    def _query_at(self, query: dict[str, list[str]]) -> str | None:
        if set(query) - {"at"}:
            raise ValidationError(f"unknown query parameter(s): {', '.join(sorted(set(query) - {'at'}))}")
        return query["at"][0] if "at" in query else None

    def _query_audit(
        self, query: dict[str, list[str]]
    ) -> tuple[str | None, bool]:
        unknown = sorted(set(query) - {"request_id", "include_records"})
        if unknown:
            raise CodedValidationError(
                "unknown_query", f"unknown query parameter(s): {', '.join(unknown)}")
        repeated = sorted(name for name, values in query.items() if len(values) > 1)
        if repeated:
            raise CodedValidationError(
                "duplicate_query", f"query parameter {repeated[0]} was repeated")
        request_id = query["request_id"][0] if "request_id" in query else None
        if "include_records" in query:
            value = query["include_records"][0]
            if value not in ("true", "false"):
                raise CodedValidationError(
                    "invalid_include_records", "include_records must be true or false")
            include_records = value == "true"
        else:
            include_records = False
        return request_id, include_records

    def _dispatch(self) -> tuple[int, Any]:
        split = urlsplit(self.path)
        parts = tuple(part for part in split.path.split("/") if part)
        query = parse_qs(split.query)
        key = self.headers.get("Idempotency-Key")
        command, service = self.command, self.service
        if command == "GET" and parts == ("health",):
            return 200, {"status": "ok"}
        if command == "POST" and parts == ("policies",):
            return 201, service.create_policy(self._body(), key)
        if command == "POST" and parts == ("requests",):
            return 201, service.create_request(self._body(), key)
        if command == "POST" and parts == ("evidence", "verify"):
            return 200, service.verify_evidence(self._body())
        if command == "GET" and parts == ("audit", "export"):
            # Blank values must survive so that `include_records=` is an illegal value.
            request_id, include_records = self._query_audit(parse_qs(split.query, keep_blank_values=True))
            return 200, service.audit_export(request_id, include_records)
        if command == "GET" and len(parts) == 2 and parts[0] == "requests":
            return 200, service.get_request(parts[1])
        if len(parts) == 3 and parts[0] == "requests" and parts[2] == "retrieval-tasks":
            if command == "GET":
                return 200, service.retrieval_tasks(parts[1])
            if command == "POST":
                return 201, service.create_retrieval_task(parts[1], self._body(), key)
        if (command == "POST" and len(parts) == 5 and parts[0] == "requests"
                and parts[2] == "retrieval-tasks" and parts[4] in ("start", "complete", "fail")):
            return 200, service.retrieval_task_action(parts[1], parts[3], parts[4], self._body(), key)
        if len(parts) >= 3 and parts[0] == "requests" and parts[2] == "reviews":
            if len(parts) == 3:
                if command == "POST":
                    return 201, service.create_review(parts[1], self._body(), key)
                if command == "GET":
                    return 200, service.reviews(parts[1])
            if len(parts) == 4 and command == "GET":
                return 200, service.get_review(parts[1], parts[3])
            if len(parts) == 5 and parts[4] == "decisions" and command == "POST":
                return 200, service.decide_review(parts[1], parts[3], self._body(), key)
            raise NotFoundError("route was not found")
        if len(parts) != 3:
            raise NotFoundError("route was not found")
        route = (command, parts[0], parts[2])
        if route == ("POST", "requests", "sla-alerts"):
            return 201, service.create_sla_alert(parts[1], self._body(), key)
        if route == ("GET", "requests", "sla-alerts"):
            return 200, service.sla_alerts(parts[1])
        if route == ("POST", "sla-alerts", "acknowledge"):
            return 200, service.acknowledge_sla_alert(parts[1], self._body(), key)
        if route == ("GET", "requests", "evidence"):
            return 200, service.evidence(parts[1])
        if route == ("POST", "requests", "transitions"):
            return 200, service.transition(parts[1], self._body(), key)
        if route == ("GET", "policy", "due"):
            return 200, service.policy_due(parts[1], self._query_at(query))
        if route == ("POST", "policies", "enforce"):
            return 200, service.enforce_policy(parts[1], self._body(), key)
        if route == ("GET", "subjects", "records"):
            return 200, service.subject_records(parts[1])
        raise NotFoundError("route was not found")

    def _handle(self) -> None:
        try:
            status, response = self._dispatch()
            self._json(status, response)
        except RightsFlowError as error:
            payload = {"error": {"code": error.code, "message": str(error)}}
            error_code = getattr(error, "error_code", None)
            if error_code is not None:
                payload["error"]["error_code"] = error_code
            self._json(error.status, payload)
        except Exception:
            self._json(500, {"error": {"code": "internal_error", "message": "internal server error"}})

    do_GET = _handle
    do_POST = _handle


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RightsFlow HTTP service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--database", default="rightsflow.db")
    parser.add_argument("--now", default=None, help="freeze the injected clock at this ISO 8601 instant")
    arguments = parser.parse_args()
    clock = FixedClock(arguments.now) if arguments.now else None
    Handler.service = RightsFlow(arguments.database, clock=clock)
    server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)
    print(f"RightsFlow listening on http://{arguments.host}:{arguments.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

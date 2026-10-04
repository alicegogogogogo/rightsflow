# RightsFlow

RightsFlow is a small backend for orchestrating **data subject requests (DSAR)**:
a lifecycle state machine per request, a **hash-chained evidence entry** for every
state change, **retention policies** (`delete`/`anonymize`) for collected records,
and **SLA** timing measured only against an injected clock.

## Requirements

- Python 3.11 or newer
- no third-party runtime dependencies

## Run the service

```bash
PYTHONPATH=src python -m rightsflow.server --host 127.0.0.1 --port 8080 --database rightsflow.db
```

The process prints `RightsFlow listening on http://127.0.0.1:8080` once it has
bound the port. Add `--now 2026-01-01T00:00:00Z` to freeze the injected clock:
every timestamp the service writes then equals that instant, so a session is
byte-for-byte reproducible. Without `--now` it uses a UTC system clock.

## Request lifecycle

A request is always in exactly one state. `fulfilled`, `rejected`, and
`cancelled` are terminal and accept no further transition.

| action | target state | notes |
| --- | --- | --- |
| `verify_identity` | `identity_verified` | |
| `scope` | `scoped` | |
| `collect` | `collected` | requires `details.records` |
| `package` | `packaged` | requires `details.artifact` |
| `fulfill` | `fulfilled` | closes the request |
| `reject` | `rejected` | requires `reason`, closes the request |
| `cancel` | `cancelled` | requires `reason`, closes the request |

The complete transition relation — any pair not listed here is illegal:

```
received          -> identity_verified | rejected | cancelled
identity_verified -> scoped            | rejected | cancelled
scoped            -> collected         | rejected | cancelled
collected         -> packaged          | rejected | cancelled
packaged          -> fulfilled         | cancelled
fulfilled / rejected / cancelled -> (none)
```

`GET /requests/{id}` exposes the legal successors of the current state as
`legal_transitions`, sorted lexicographically. Any other pair — a transition out
of a terminal state, or a repeat of the current state — is HTTP `409` with code
`illegal_transition`, and **nothing is applied**: no state change, no evidence entry.

```json
{"error":{"code":"illegal_transition","message":"illegal transition from received to collected; legal successors: cancelled, identity_verified, rejected"}}
```

From a closed request the successor list is the literal string `none`, e.g.
`illegal transition from fulfilled to scoped; legal successors: none`.

`reason` is **required** for `reject`/`cancel` and **forbidden** elsewhere; `details` is
required for `collect`/`package` and is otherwise absent or `{}`, else `400 validation_error`.

## Dual-person review (optional)

`reject` and `fulfill` may optionally be gated behind two independent reviewers. A
review **proposes** one of those actions and records reviewer decisions; it never
changes the request itself until a second independent approval applies the change.
Opening or deciding a review does not alter the direct
`POST /requests/{id}/transitions` behavior in any way.

`POST /requests/{id}/reviews` *(key required)* — the body must contain exactly
`{"review_id","action","actor","reason","note"}`, where `action` is `reject` or
`fulfill`. The `reason`/`note` rules mirror the direct transition: `reject`
requires a non-empty `reason` (≤1000), `fulfill` **forbids** `reason`, and `note`
is `null` or a string of at most 2000; `actor` is ≤200. The proposed action must
be a legal successor of the request's current state, else `409
illegal_transition` (nothing is created). On creation the current `state` and
`evidence_head` are snapshotted. A second pending review for the same request and
action is `409 conflict`; a reused `review_id` is `409 conflict`; a missing
request is `404 not_found`. Answer `201`:

```json
{"request_id":"req-1","review_id":"rev-1","action":"reject","actor":"proposer","reason":"unfounded","note":null,
 "status":"pending","state_snapshot":"received","evidence_head_snapshot":"f8e51c51…14b7f4",
 "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","applied_at":null,
 "decisions":[],"transition_result":null}
```

`POST /requests/{id}/reviews/{review_id}/decisions` *(key required)* — the body
must contain exactly `{"actor","decision","note"}`; `decision` is `approve` or
`deny` (any other value, a non-string, or an extra field is `400
validation_error`), `note` is `null` or ≤2000. A decision on a missing request or
review is `404 not_found`. The lifecycle:

- The **proposing actor may not decide**; the same actor may not decide twice.
  Either is `409 conflict` and records nothing.
- The **first independent approval only records the decision** — the review stays
  `pending`, and the request and evidence chain are untouched.
- The **second approval atomically applies** the proposed state change. The
  review becomes `applied`, `applied_at` is the injected clock, and the change is
  byte-for-byte the same one a direct transition makes: one `history` entry, one
  `transition` evidence entry (with the proposal's `actor`/`note`/`reason`), the
  same `closed_reason` and retention snapshot. `transition_result` carries the
  full materialized request that a direct transition would return. Concurrent
  second approvals are serialized so that exactly one change, one history entry,
  and one evidence entry result; the losing approval is `409 conflict` and is not
  recorded.
- **Any deny** terminates the review as `denied`: the decision is recorded, but no
  request state, evidence, or retention data changes.
- If a decision arrives after the request has moved away from the snapshot
  (`state` **or** `evidence_head` differs), the review terminates as `stale` and
  that decision is **not recorded** — this rule is unconditional and fires even
  for the proposer.
- A further decision on a `denied`, `applied`, or `stale` review is `409 conflict`.

Decisions are returned in commit order. `GET /requests/{id}/reviews/{review_id}`
returns the single review (full decisions and `transition_result`); a missing
request or review is `404 not_found`. `GET /requests/{id}/reviews` returns
`{"request_id","reviews":[...]}` sorted by `created_at` then `review_id`.

Both POSTs require an `Idempotency-Key`: a repeated key replays the stored
response verbatim (a replayed second approval does not apply twice), and reusing
a key for a different operation is `409 conflict`.

## Evidence chain

Entry 1 is written when the request is created (`type` `request_received`); every
later entry records one transition (`type` `transition`). An entry is:

```json
{"content":{"sequence":1,"request_id":"req-1","type":"request_received","occurred_at":"2026-01-01T00:00:00Z",
 "payload":{"subject_id":"user-42","request_type":"access","policy_id":"eu-standard","sla_days":30,"sla_due_at":"2026-01-31T00:00:00Z","actor":"agent-7"}},
 "previous_hash":null,"hash":"f8e51c51f44b1ed50323920c018b1a1cd7c78ae7406719df4b2d3a5aec14b7f4"}
```

`transition` payloads are `{"action","from","to","actor","note","reason","details"}`, where `details` is the normalized details object (or `null`).

```
canonical_json(value) = json.dumps(value, ensure_ascii=False,
                                   separators=(",", ":"), sort_keys=True)
hash(entry)           = sha256( (entry.previous_hash or "") + canonical_json(entry.content) )
```

The digest is over the UTF-8 bytes of that concatenation and is lowercase
hexadecimal (64 characters). **There is no separator** between the previous hash
and the canonical JSON. The first entry has `previous_hash: null`, and `null`
contributes the **empty string**, i.e. `sha256("" + canonical_json(content))`.
`sort_keys=True` sorts keys recursively at every depth; array order is preserved,
so `collect` batch order changes the digest. Only `content` is hashed. For the
entry above the hashed string is exactly

```
{"occurred_at":"2026-01-01T00:00:00Z","payload":{"actor":"agent-7","policy_id":"eu-standard","request_type":"access","sla_days":30,"sla_due_at":"2026-01-31T00:00:00Z","subject_id":"user-42"},"request_id":"req-1","sequence":1,"type":"request_received"}
```
prefixed by the empty string; its SHA-256 is `f8e51c51…14b7f4`.

`POST /evidence/verify` re-computes a supplied chain and reports the **first**
broken link, checking in order: `content.sequence` against its 1-based position
(`sequence must be contiguous starting at 1`), `previous_hash` against the
preceding `hash` (`previous_hash does not match the preceding hash`), and the
digest against `hash` (`hash mismatch`):

```json
{"chain_valid":true,"count":6,"head":"43033d7907cdd4befdab57663c39415be0164afd89fb6fdf7342be7993c68e4a","first_invalid_sequence":null,"reason":null}
{"chain_valid":false,"count":6,"head":null,"first_invalid_sequence":3,"reason":"hash mismatch"}
```

`GET /requests/{id}/evidence` verifies the stored chain the same way and returns
`chain_valid` beside the entries. The chain is an **integrity** check, not a
signature: rewriting one entry *and* recomputing every later hash yields a
different but consistent chain, which only an external anchor of the head can catch.

`collect` carries raw records, but the chain, history, and request document store only
their shape — `{"record_count":2,"records_digest":"6a6866690fcbf8a017949d60f4b153c09c151cd2109e1cc2710b3f32343bb250"}`,
where `records_digest = sha256(canonical_json(records))` over the array as supplied.
Payloads live only in the record store, where retention can erase them.

## SLA

`POST /requests` takes `sla_days` (1–365); the service stores `received_at` and
`sla_due_at = received_at + sla_days days`. Every read reports

```json
"sla":{"due_at":"2026-01-31T00:00:00Z","measured_at":"2026-01-01T00:00:00Z","elapsed_seconds":0,"remaining_seconds":2592000,"overdue_seconds":0,"breached":false}
```

`measured_at` is `closed_at` for a closed request and the **injected clock's**
current instant for an open one; no code path consults the wall clock, so SLA
output depends only on the injected clock. `elapsed_seconds = measured_at -
received_at`; `remaining_seconds = max(0, due_at - measured_at)` and
`overdue_seconds = max(0, measured_at - due_at)`, so exactly one is non-zero.
`breached = measured_at > due_at`, and a late close stays breached forever while
its `measured_at` freezes at closure.

## Retention policies

A policy is `{"id","retention_days":0–3650,"action":"delete"|"anonymize"}`. A
request must name an existing policy when it is created (`404 not_found`
otherwise), and the policy is snapshotted onto the request when it closes:

```json
"retention":{"policy_id":"eu-standard","retention_days":30,"action":"delete","expires_at":"2026-01-31T00:00:00Z","applied_at":null,"affected_records":0}
```

The window starts at `closed_at` (the transition into `fulfilled`, `rejected`, or
`cancelled`), **not** at `received_at`, and
`expires_at = closed_at + retention_days days`; `retention_days: 0` expires at
`closed_at` itself. A request is **due** when it is closed, not yet applied, and
`at >= expires_at` — inclusive, so it is due exactly at `expires_at`. An open
request has `retention: null` and is never due.

`POST /policies/{id}/enforce` applies the action to every request due at the
supplied `at`. `delete` removes the record rows, so
`GET /subjects/{subject_id}/records` reports `count: 0` while the request keeps
`collection.records_digest` as proof of what was once collected. `anonymize` keeps
each record's id and payload but rewrites its `subject_id` to the pseudonym
`"anon:" + sha256(f"{subject_id}:{request_id}").hexdigest()[:16]` and sets
`anonymized: true`, so lookups under the original subject id return `count: 0`
while lookups under the pseudonym return the records. Enforcement records
`applied_at` and `affected_records`, changes **no** request state, and appends
**nothing** to the chain, which is immutable by design and keeps the digest of data
retention has erased. A repeat with the same `Idempotency-Key` replays the first
response; a later call with a new key applies nothing and reports `"results": []`.
Each request is applied at most once.

## HTTP API

Bodies are JSON with `Content-Type: application/json` (anything else is `400`).
Unknown body fields and unknown query parameters are rejected with `400`. Every
state-changing `POST` requires an `Idempotency-Key` header: repeating a key
returns the first response verbatim and changes nothing, and reusing a key for a
different operation is `409 conflict`. Errors always use
`{"error":{"code":"validation_error","message":"human readable detail"}}` with
`400 validation_error`, `404 not_found`, `409 conflict`, or `409 illegal_transition`.
`GET /health` → `{"status":"ok"}`.

`POST /policies` *(key required)* — body
`{"id":"eu-standard","retention_days":30,"action":"delete"}` → `201` with the
stored policy; a duplicate `id` is `409`.

`POST /requests` *(key required)* — the body must contain exactly
`{"id":"req-1","subject_id":"user-42","request_type":"access","policy_id":"eu-standard","sla_days":30,"actor":"agent-7"}`.
Answer `201`, starting in `received` with one evidence entry. `request_type` is
one of `access`, `rectification`, `erasure`, `portability`, `restriction`; a
duplicate `id` is `409`.

`POST /requests/{id}/transitions` *(key required)* — `action` and `actor` (≤200
chars) are required; `note` (≤2000), `reason` (≤1000), and `details` are optional,
e.g. `{"action":"verify_identity","actor":"dpo"}`. Answers `200` with the updated
request.

```json
{"action":"collect","actor":"system","details":{"records":[{"id":"r-1","payload":{"email":"subject@example.test"}},{"id":"r-2","payload":{"phone":"555"}}]}}
{"action":"package","actor":"system","details":{"artifact":"bundle-1"}}
{"action":"cancel","actor":"subject","reason":"withdrawn"}
```

`collect` requires `details` to contain exactly `records`: an array (possibly
empty) of objects with exactly `id` (unique in the batch) and an object `payload`;
`package` requires exactly `artifact`, a non-empty string.

## Retrieval tasks

Before `collect`, a request can track **independent cross-system retrieval
tasks** that record where source data is being fetched from. A task has its own
lifecycle — `queued → running → succeeded | failed` — and never writes request
data: no state change, no evidence entry, no effect on SLA or retention. Its
`records` simply become available for a later `collect`.

`POST /requests/{id}/retrieval-tasks` *(key required)* — the body must contain
exactly `{"id","system","query","actor"}`, all non-empty strings of at most
100, 100, 2000, and 200 characters. The `id` is unique within the request and
doubles as the `task_id`. Answer `201` with the task in `queued`:

```json
{"request_id":"req-1","task_id":"t-1","system":"crm","status":"queued","records":null,"reason":null,
 "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","started_at":null,"finished_at":null}
```

Every timestamp comes from the injected clock; one that has not happened yet is
`null`. A duplicate `task_id` is `409 conflict`.

`POST /requests/{id}/retrieval-tasks/{task_id}/start|complete|fail` *(key
required)* — the bodies are exactly `{"actor"}`, `{"actor","records"}`, and
`{"actor","reason"}`, and the only legal transitions are `queued → running`,
`running → succeeded`, and `running → failed`. `records` has the same shape as
`collect`'s — objects with exactly `id` and an object `payload` — except that a
repeated `id` keeps the **first** occurrence instead of failing. `reason` is a
non-empty string of at most 1000 characters. Skipping a step, repeating
`start`, or acting on a terminal task is `409 illegal_transition` and changes
nothing; a missing request or task is `404 not_found`.

`GET /requests/{id}/retrieval-tasks` — the tasks sorted by `task_id`, where a
`succeeded` task carries its `records`, a `failed` task its `reason`, and every
other field is `null`, plus aggregate `totals`:

```json
{"request_id":"req-1","tasks":[...],
 "totals":{"total":3,"queued":1,"running":0,"succeeded":1,"failed":1,"completed":2,"progress_percent":66}}
```

`completed = succeeded + failed`; `progress_percent` is the completed share
rounded down — `100` once every task is terminal, `0` when there are no tasks.

## SLA alerts

An **SLA alert** records one overdue fact about an open request. Alerts live in
their own store: creating or acknowledging one never changes the request state,
appends no evidence entry, and triggers no retention action.

`POST /requests/{id}/sla-alerts` *(key required)* — the body must contain
exactly `{"actor","reason"}`, non-empty strings of at most 200 and 1000
characters. The request must exist (`404 not_found`), must not be in a terminal
state (`fulfilled`/`rejected`/`cancelled` → `409 conflict`), and must be
**strictly** overdue against the injected clock: `measured_at > due_at`, so
measuring exactly at `due_at` is `409 conflict`. Answer `201`:

```json
{"alert_id":"sla-…","request_id":"req-1","subject_id":"user-42","actor":"monitor-1","reason":"past the contractual deadline",
 "due_at":"2026-01-31T00:00:00Z","detected_at":"2026-02-01T00:00:00Z","overdue_seconds":86400,"status":"open"}
```

`alert_id` is globally unique, `detected_at` equals `measured_at`, and
`overdue_seconds` is the whole-second difference `measured_at - due_at`. A
request keeps at most one alert per `due_at`; a second attempt is `409
conflict`.

`GET /requests/{id}/sla-alerts` — the alerts sorted by `detected_at` then
`alert_id`, plus aggregate `totals` where `count` equals `total`:

```json
{"request_id":"req-1","alerts":[...],
 "totals":{"total":1,"open":0,"acknowledged":1,"count":1}}
```

A request with no alerts answers an empty array and zero totals; a missing
request is `404 not_found`.

`POST /sla-alerts/{alert_id}/acknowledge` *(key required)* — the body must
contain exactly `{"actor","note"}`. Answer `200` with the alert now in
`acknowledged`, carrying `acknowledged_at` (the injected clock),
`acknowledged_by`, and `acknowledged_note`; `due_at`, `detected_at`, and
`overdue_seconds` are unchanged. A missing alert is `404 not_found` and a
repeat acknowledgement is `409 conflict`.

`GET /requests/{id}` — the materialized request:

```json
{"id":"req-1","subject_id":"user-42","request_type":"access","policy_id":"eu-standard","actor":"agent-7",
 "state":"fulfilled","received_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","closed_at":"2026-01-01T00:00:00Z",
 "closed_reason":null,"sla_days":30,"sla_due_at":"2026-01-31T00:00:00Z","sla":{...},"legal_transitions":[],
 "collection":{"record_count":2,"records_digest":"6a6866690fcbf8a017949d60f4b153c09c151cd2109e1cc2710b3f32343bb250"},
 "records":[{"id":"r-1","subject_id":"user-42","payload":{"email":"subject@example.test"},"anonymized":false}],
 "retention":{"policy_id":"eu-standard","retention_days":30,"action":"delete","expires_at":"2026-01-31T00:00:00Z","applied_at":null,"affected_records":0},
 "history":[{...}],"evidence_head":"43033d7907cdd4befdab57663c39415be0164afd89fb6fdf7342be7993c68e4a"}
```

Each `history` entry is `{"sequence","action","from","to","actor","note","reason","details","occurred_at"}`;
the intake entry has `action: null` (it is not a POSTable action) and `details` holds the normalized digest object.

`GET /requests/{id}/evidence` — `{"request_id","entries","count","chain_valid","head","first_invalid_sequence","reason"}`.
`POST /evidence/verify` — body `{"entries":[<entry>, ...]}`, no state change and no
idempotency key. Re-sending the single entry printed under *Evidence chain* above
answers `chain_valid: true, count: 1`; changing any byte of its `content` answers
`first_invalid_sequence: 1, reason: "hash mismatch"`; an empty array reports `count: 0`.

## Audit export

`GET /audit/export` is a **read-only** summary of every request, the evidence
chains, and the records still held by the store. It writes nothing, never
touches the disk, and changes no public behavior; `generated_at` is the injected
clock's current UTC instant. The optional query parameters are `request_id`
(default: all requests) and `include_records` (default: `false`; only the literal
strings `true` and `false` are accepted). An unknown parameter, a repeated
parameter, or an illegal `include_records` is `400 validation_error` with an
`error_code` of `unknown_query`, `duplicate_query`, or `invalid_include_records`,
checked in that order. A named `request_id` that does not exist is `404
not_found` with message `request {id} was not found`; an empty store (or no
match) is `200` with empty arrays.

```json
{"generated_at":"2026-01-01T00:00:00Z","filter":null,
 "requests":[{"id":"req-1","subject_id":"user-42","state":"received","received_at":"2026-01-01T00:00:00Z",
   "updated_at":"2026-01-01T00:00:00Z","evidence_head":"f8e5…b7f4","first_invalid_sequence":null}],
 "evidence":[{"content":{...},"previous_hash":null,"hash":"f8e5…b7f4"}],
 "records":[{"request_id":"req-1","record_id":"r-1","subject_id":"user-42","anonymized":false}],
 "totals":{"requests":1,"evidence":1,"records":1},
 "export_digest":"…"}
```

`requests` are sorted by `id`; `evidence` by `request_id` then `sequence`;
`records` by `request_id` then `record_id`. Each request carries its stored
`evidence_head` and the `first_invalid_sequence` of its stored chain, verified in
the same order as `POST /evidence/verify` (so `null` means the chain is intact).
A record always carries `request_id`, `record_id`, `subject_id`, and
`anonymized`; `payload` is present only when `include_records=true`.
`filter` is `{"request_id": "..."}` when that parameter was supplied and `null`
otherwise. `export_digest` is

```
sha256(canonical_json({"filter":…,"requests":…,"evidence":…,"records":…}))
```

over the UTF-8 bytes: keys sorted recursively, arrays in their returned order,
and deliberately **without** `generated_at`, so the digest pins the snapshot but
not the moment it was taken.


`GET /policy/{id}/due?at=2026-01-31T00:00:00Z` — `at` is optional and defaults to
the injected clock; the response carries `policy_id`, `retention_days`, `action`,
`at`, and `due`, sorted by `request_id`:

```json
{"request_id":"req-1","subject_id":"user-42","state":"fulfilled","closed_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-31T00:00:00Z","action":"delete","record_count":2,"applied":false}
```

`POST /policies/{id}/enforce` *(key required)* — body `{"at":"2026-01-31T00:00:00Z"}`:

```json
{"policy_id":"eu-standard","at":"2026-01-31T00:00:00Z","due_remaining":0,"results":[{"request_id":"req-1","subject_id":"user-42","action":"delete","affected_records":2}]}
```

`GET /subjects/{subject_id}/records`:

```json
{"subject_id":"user-42","count":2,"records":[{"request_id":"req-1","record_id":"r-1","subject_id":"user-42","payload":{"email":"subject@example.test"},"anonymized":false}]}
```

## Tests

`PYTHONPATH=src python -m unittest discover -s tests -v`

`tests/test_service.py` covers the state machine, the hash formula (recomputed
independently by the test), tamper detection, SLA timing under a frozen clock,
idempotency, retention, retrieval tasks, and SLA alerts; `tests/test_server.py`
exercises the HTTP surface on an ephemeral port. The suite runs in about two
seconds and needs no network.

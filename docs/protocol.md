# Protocol, schemas and public API

## Encoding and persistent state

JSON commitments use UTF-8 encoding of `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. A digest is lowercase SHA-256 hex over those bytes. Raw record commitments use SHA-256 over the fetched bytes directly. Object key order and insignificant input whitespace do not change canonical commitments; array order and string content do.

Identifiers match `[a-zA-Z0-9_.-]{1,64}`. Addresses use the canonical checksum representation returned by `genlayer.Address`. Revisions and generations are integers in `1..2**64-1`; booleans are rejected as integers. Parties contain at most six canonical addresses. SHA-256 values contain exactly 64 lowercase hexadecimal characters.

Class-level `TreeMap` fields persist policies, sources, pair decisions, reservations, certificates, approvals, deliveries and acknowledgements. `DynArray` persists JSON history entries. Counters use `u8`, `u64` and `u256`; native quantities are integer atto-units. JSON record schemas remain bounded by transaction input and history page limits.

## Authorities and records

The registry owner registers each immutable authority with a principal address, channel identifier, HTTPS URL prefix and complete public control record. The principal signs source attestations. This configuration approves a retrieval channel; it does not establish that the channel's publisher or asserted observation is truthful. Validators must inspect production/control evidence. Private records and secrets do not belong in these inputs.

A control record has exactly:

```json
{
  "record_id": "alpha-control",
  "url": "https://publisher.example/records/control.txt",
  "sha256": "<lowercase SHA-256 of the full raw record>",
  "size_bytes": 400,
  "spans": [{"span_id": "all", "start": 0, "end": 400, "sha256": "<same full raw hash>"}]
}
```

The example URL and hash placeholders must be replaced with retrievable real records. HTTPS records allow at most 2,048 URL characters, no embedded credentials, fragment or nonstandard port. `size_bytes` is `1..49152`. There are one through four spans, each with a unique identifier and `0 <= start < end <= size_bytes`. A full `all` span with the record hash is mandatory. Offsets refer to raw bytes; UTF-8 is decoded only after hashes and spans are verified.

A source record has those same fields plus exactly `source_id`, `authority_id`, `revision`, `scope`, `channel` and `candidate_origin_ids`. Its record ID is `<source_id>.<revision>`. Scope is a nonempty string of at most 256 characters. One through four distinct candidate origin IDs suggest possible origins; model selection must be grounded in the retrieved evidence. A matching candidate label alone proves no origin. The source channel and URL must match its registered authority. New revisions increment by one and retain the same authority ID; existing revision data cannot change.

The manifest commits every full registered source record and every referenced registered authority, including its control record:

```python
manifest = {
    "sources": sorted(source_records, key=lambda s: s["source_id"]),
    "authorities": sorted(unique_authorities, key=lambda a: a["authority_id"]),
}
source_manifest_digest = digest(manifest)
```

## Policies and request locks

An independence definition is an object with exactly `definition`, `scope` and `rule_ids`. The definition has at most 2,048 characters; the encoded object has at most 3,072 bytes. The required rule IDs, in registration order, are:

```json
["COPY_OR_DERIVATION", "SHARED_CONTROL", "INDEPENDENT_PRODUCTION", "UNKNOWN_CONTROL", "UNKNOWN_ANCESTRY", "CONTRARY_EVIDENCE", "SCOPE_MISMATCH"]
```

The first policy registrant becomes that policy's owner. Only that owner can create subsequent immutable revisions. Identical current configuration is an idempotent replay. A new policy revision does not silently replace a request's locked revision; explicit policy quarantine revokes its use.

`open_batch` takes the following serialized object:

```python
body = {
    "envelope": {
        "request_id": "event-001",
        "owner": request_owner_address,
        "parties": [],
        "policy_id": "event-independence",
        "policy_revision": 1,
        "subject_id": "event-001",
        "subject_digest": digest(subject),
        "source_manifest_digest": digest(manifest),
        "consumer_address": event_resolver_address,
        "consequence_digest": digest(intended_consequence),
        "generation": 1,
        "deadline": transaction_time_seconds + 86400,
    },
    "sources": [{"source_id": s["source_id"], "revision": s["revision"]} for s in manifest["sources"]],
}
```

Every field shown is required; unexpected fields are rejected. The owner must be the transaction signer. A deadline is strictly future and within seven days of the supported GenVM transaction datetime. The application never reads a local wall clock in contract execution. A subject namespace binds owner, subject ID, policy ID and primary consumer. Its first generation is one; successors increment by one. A successor updates historical `superseded_by` metadata and immediately makes its predecessor noncurrent.

The exact batch digest commits `{envelope, manifest}`. The returned batch contains the envelope, full locked manifest, sorted source IDs, status, batch digest and superseded-by ID. Identical repeated request operations return that batch; conflicting request-ID reuse is an expected error.

## Pair adjudication and certificate

`reserve_pair` requires the exact configured native charge. It durably records payer, operation ID and attempt before semantic execution in a separate transaction. The treasury `accept_fee()` call emits with the charge on finalized status. A treasury is a contract with that payable interface, not an externally owned account. Its child receipt must succeed before treating the fee as received. Returned value can reach Rhizome through the inherited SDK refund handler; Studio retained the deliberately failed fee at its receiver without automatically emitting a refund. The hosted recovery fixture uses an explicit receiver-assisted return. A return does not erase the committed reservation or charged counter. Choose and verify a compatible receiver before accepting assessments. `get_limits.retained_fee_balance_atto` exposes the actual Rhizome balance; the registry owner can use `retry_treasury_transfer` to forward retained fees to the immutable treasury. Recovery emits once per operation ID, requires sufficient balance, preserves the gross charge counter, and must be confirmed through the finalized child receipt. An incompatible immutable treasury requires a new deployment; recovery cannot change its address. A model failure cannot undo this already committed attempt. The request owner can reserve directly or authorize a sponsor through `authorize_assessment_payer`. The authorized reservation payer alone can assess it. Its payer or the request owner can release a hold; revoking sponsor authorization prevents further assessment and new reservations. Release frees the reservation, retains the attempt and does not refund the economic charge. Protocol validator rotation is independent of the three paid reservations.

Each complete assessment produces:

| Field | Meaning |
| --- | --- |
| `relation` | `SHARED_ORIGIN`, `INDEPENDENT` or `UNKNOWN` |
| `left_origin_ids`, `right_origin_ids` | Sorted, deduplicated, source-grounded candidate IDs |
| `rule_ids` | Sorted applicable controlling rule IDs |
| `scope_verified`, `control_verified` | Explicit boolean coverage |
| `available` | Whether every committed record was retrieved and verified |
| `unresolved_reason` | Empty for a known relation; otherwise a visible reason |
| `witnesses` | Complete-record locators containing record ID, `all` span ID, raw hash, byte start/end |
| `pair_ids` | Lexicographically ordered source IDs |

Independent relations require nonempty disjoint origin sets, affirmative scope/control and exactly the `INDEPENDENT_PRODUCTION` rule. Shared relations require a common supported origin and a controlling copy/derivation or shared-control rule. Validators independently derive these material fields and complete-record witnesses. Equivalent narrative prose is excluded from canonical state. Complete-record witnesses avoid choosing arbitrary adequate excerpts differently across validators.

Retrieval failures remain `UNKNOWN` with `SOURCE_UNAVAILABLE`, `SOURCE_CHANGED`, `SPAN_MISMATCH`, `TEXT_UNDECODABLE`, `EVIDENCE_OVERSIZED` or `CONTEXT_OVERSIZED`. A substantive unknown result uses `UNKNOWN_RELATION`. Malformed model output raises `[LLM_ERROR]` and fails validator approval. `Return`, deterministic `[EXPECTED]` `UserError` and `VMError` are handled separately; VM errors never establish a fact or an absence certificate.

The sealed result retains every envelope field and adds `schema_version`, `source_contract`, `batch_digest`, `lifecycle_status`, `relation_matrix`, `certified_subset`, `certified_origin_count`, `required_count`, `threshold_met`, `coverage_complete`, `unresolved`, `unresolved_reason`, `diagnostics`, `controlling_rule_ids`, `witnesses`, `superseded_by` and `certificate_digest`. Pair keys are `<left>|<right>`. The certificate digest commits every other sealed-result field. `get_certificate` returns `{sealed_result, current_metadata}` so current metadata never mutates the sealed core or its digest.

`SEALED` is a complete, supported, internally consistent matrix. It can still fall below the policy threshold. `UNRESOLVED` reports zero certified origins and retains diagnostic information; it can never meet a consumer threshold. Terminal reasons include `UNKNOWN_RELATIONS`, `CONTRADICTORY_RELATIONS`, `DEADLINE_ELAPSED`, `RETRY_EXHAUSTED` and `EVIDENCE_INVALIDATED`. A partial matrix can terminate only as visibly incomplete unresolved evidence.

## Public writes

All writes reject attached value except `reserve_pair` (the inherited SDK refund handler also accepts returned value). String objects below are canonical serialized JSON. Successful return values are not a substitute for checking transaction execution and finality.

| Method and arguments | Permission and behavior |
| --- | --- |
| `register_policy(policy_id, independence_definition, required_count)` | First registrant creates policy; existing policy owner adds a revision. Count `1..6`. Returns policy. |
| `register_authority(authority_id, principal_address, channel, url_prefix, control_record)` | Registry owner only. Immutable authority, identical replay allowed. Returns authority. |
| `attest_source(source_record)` | Registered principal only. Immutable sequential revision, identical replay allowed. Returns source. |
| `open_batch(request_id, policy_id, source_manifest)` | Anyone can sign a new owned request. Locks current evidence; returns batch. |
| `authorize_assessment_payer(request_id, payer_address, authorized)` | Request owner only; grant/revoke a request-specific sponsor. The owner remains authorized. |
| `retry_treasury_transfer(operation_id, amount_atto)` | Registry owner only; idempotent finalized forwarding of retained fees to the immutable treasury. Returns emission record, not payment confirmation. |
| `reserve_pair(request_id, left_id, right_id, operation_id)` | Request owner or explicitly authorized sponsor can pay and reserve an active pair. Exact fee; maximum three attempts. Returns reservation. |
| `release_pair(request_id, left_id, right_id)` | Reservation payer or request owner. Retains charged attempt. |
| `assess_pair(request_id, left_id, right_id)` | Active reservation payer with current request-owner authorization. Independent semantic consensus; returns pair decision. |
| `seal_batch(request_id)` | Anyone; complete matrix and no pending assessment. Returns certificate wrapper. |
| `resolve_unavailable(request_id)` | Anyone; requires expiry, exhausted pair or finalized evidence invalidation. Tentative restrictions cannot permanently terminate a batch. Returns unresolved wrapper. |
| `quarantine_record(kind, record_id, revision, reason_digest)` | Source principal/policy owner or registry owner for source/policy; registry owner for request/authority. Irreversible, identical replay allowed. |
| `confirm_finalized_record(kind, record_id, revision, commitment)` | Authenticated self message only; original record writes emit after finalization. Checks exact immutable record commitment and advances confirmed revision/generation indices monotonically. |
| `get_finalized_policy(policy_id, revision)` / `get_finalized_batch(request_id)` | Proof-backed views; require the creating record's finalized-parent confirmation before exposing metadata. |
| `is_finalized_current(request_id)` | Proof-backed freshness; reports confirmed invalidation or `FINALITY_PENDING` while confirmations lag. Tentative changes do not become confirmed restrictions. |
| `register_consumer(policy_id, revision, minimum_count, unresolved_consequence)` | Called by the consumer contract through its owner-configured finalized emission. Threshold cannot be below source policy; consequence is `REFUSE_RESOLUTION` or `KEEP_RESTRICTED`. |
| `approve_delivery(request_id, consequence_digest)` | Registered consumer signs exact batch/consequence approval. Conflicting approval is rejected. |
| `publish_to(request_id, consumer, operation_id)` | Anyone after approval and terminal current certificate. Journals and emits authenticated finalized delivery. Identical replay can retry failed callback. |
| `acknowledge_delivery(operation_id, delivery_digest, outcome)` | Exact destination consumer only. Outcome `APPLIED`, `REFUSED`, `STALE` or `QUARANTINED`. |

Request/authority quarantine uses revision zero. Source/policy quarantine uses its immutable positive revision. No clear method exists. Historical policy revisions remain usable until explicitly quarantined; source successors invalidate all requests bound to older source revisions.

## Public views

| Method | Return |
| --- | --- |
| `get_policy(policy_id, revision)` | Immutable policy record |
| `get_source(source_id, revision)` | Immutable attested source record |
| `get_batch(request_id)` | Locked batch with lifecycle and superseded-by metadata |
| `get_pair(request_id, left_id, right_id)` | `{decision, attempts, reservation}`; unassessed decision/reservation is null |
| `get_certificate(request_id)` | `{sealed_result, current_metadata}`; terminal requests only |
| `is_current(request_id)` | `{current, reason, generation, superseded_by, batch_digest}` |
| `get_delivery(consumer, operation_id)` | `{delivery, acknowledgement}`; missing values are null |
| `list_history(offset, limit)` | History page with `items`, `next_offset`, `total` |
| `list_source_requests(source_id, revision, offset, limit)` | Reverse source-revision request page |
| `list_policy_requests(policy_id, revision, offset, limit)` | Reverse policy-revision request page |
| `get_limits()` | Published execution limits, fee/treasury, request/delivery/charge counters |

Offsets are `0..2**64-1`, limits `1..50`. Requests beyond an index return an empty page; records remain available by immutable key.

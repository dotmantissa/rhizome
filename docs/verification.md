# Verification record

## Corrected deployment qualification

The current `reviewer-v5` contracts match committed source `92d39d9` byte for byte; all four deployment receipts finalized successfully with independent validators. The working source passes 119 direct tests and 41 client/history tests, including 38 security regressions. All four pinned contract lints pass.

The current [partial report](../verification/reviewer-v5/verification-summary.json) checks finalized transactions, authenticated finality confirmations and accepted semantic assessments as the hosted suite progresses. The release remains unqualified until all sixteen scenarios pass the strict gate. [Local recovery checks](../verification/reviewer-v5/local-transport-recovery-tests.log) record all 160 passing tests, including bounded identical signed-byte retries after typed DNS failures and immediate exact-hash receipt recovery after an ambiguous submission. Missing receipts stop recovery without another nonce check, signature or write. The [reservation recovery](../verification/reviewer-v5/reservation-recovery.json), [assessment DNS reconciliation](../verification/reviewer-v5/assessment-dns-reconciliation.json) and [publication TLS reconciliation](../verification/reviewer-v5/publication-tls-reconciliation.json) preserve the public operation evidence without creating another paid reservation.

[Fresh public replay](../verification/reviewer-v5/public-recovery-replay.log) succeeds in partial mode without credentials or the private journal. The same snapshot correctly fails the strict gate because hosted qualification remains incomplete.

The previous `reviewer-v4` run stopped at the hosted synchronous `LATEST_FINAL` timeout and remains unqualified. The current source uses authenticated self-confirmations emitted after each creating parent finalizes, with exact commitment checks and monotonic revision/generation indices. Eight new direct regressions cover forged confirmations, tentative replays, admission/delegation gates, reordered confirmations and confirmation lag.

The complete sixteen-scenario hosted suite is running against these fresh addresses. It includes both adapters' rejected/corrected input handling, three rejected outsider reservations, sponsor revocation/owner recovery, real failed fee transfers/refunds/retries, and hosted latest/finalized snapshot divergence with controlled restoration. The reversible restriction fixture extends the full production source; both consumers use exact release bytes. Controlled restoration is explicitly labelled and does not establish a production appeal. The sections below retain the original `treasury-v3` execution history; those receipts cannot qualify the corrected source.

## Environment and source identity

The target is hosted StudioNet, chain ID `61999`, RPC `https://studio.genlayer.com/api`. All four contract files pin `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`. The deployment artifact records source commit `ac4252b`, exact raw source hashes, constructors, separate owners and finalized deployment transaction IDs.

All four deployment transactions finalized with successful execution and at least two independent agreeing validators. The verifier fetched `gen_getContractCode`, base64-decoded the result and compared the complete source bytes. `eth_getCode` exposes EVM code and returned empty bytes for the Python contract; that initial verifier mistake was corrected without duplicating the source deployment.

The isolated local environment uses Python 3.14.4, `genlayer-test==0.29.2`, `genvm-linter==0.11.0`, `genlayer-py==0.16.3`, `pytest==9.1.1` and `requests==2.32.5`. Dependencies are recorded in [requirements.lock](../requirements.lock). The installed direct host uses the SDK corresponding to the pinned runner, explicitly selected as `v0.2.16`.

## Completed local checks

```bash
.venv/bin/genvm-lint check contracts/assessment_treasury.py --json
.venv/bin/genvm-lint check contracts/rhizome.py --json
.venv/bin/genvm-lint check contracts/event_resolver.py --json
.venv/bin/genvm-lint check contracts/insurance_gate.py --json
.venv/bin/python -m pytest tests/direct -q
```

All four linter checks passed. The latest recovery direct run passed **73 tests in 12.85 seconds**, recorded in [direct-recovery.log](../verification/direct-recovery.log). The earlier treasury run passed 72 tests in 11.52 seconds. Coverage includes all 32,768 binary six-source graphs, all ternary three-source relation matrices, contradictory shared transitive closure and cross-pair origin overlap, unknown cross-cluster coverage, immutable source/request revisions, permissions, fee/bounds/deadline recovery and both consumer bodies. The added malformed-model regression verifies that failed parsing retains the paid reservation, requires payer release and exhausts after three attempts.

Fifteen synthetic client and receipt-history tests pass with `.venv/bin/python -m pytest tests/unit -q`. They verify identical signed-byte retries on explicit rate-limit refusals, bounded refusal retries, numeric/date `Retry-After` handling, safe read retries, no rebroadcast after an ambiguous write timeout, recovery from saved finalized receipts without new RPC requests, refusal to decode accepted or failed outcomes as finalized returns, continued polling through a temporary `UNDETERMINED` status, and rejection of a finalized leader success when consensus reports `MAJORITY_DISAGREE` or `NO_MAJORITY`. Receipt-history accounting separately verifies that rotated validator observations survive and identical carried snapshots are deduplicated. These tests qualify client recovery behavior and do not claim application or network consensus.

Explicit `direct_vm.run_validator()` probes reject inflated valid-JSON decisions, omitted parent-control rules, forged/omitted witnesses, changed bytes, instruction injection, invented origins and malformed material fields. Direct tests use labelled synthetic fault injection and direct finalized-dispatch simulation. Ordinary direct leader execution is not evidence of network consensus. The hosted suite provides actual model, retrieval, independent validators and authenticated finalized callback verification.

## Completed hosted verification

All **11 hosted scenarios passed** on the same verified `treasury-v3` deployment. [integration-results.json](../verification/treasury-v3/integration-results.json) records `complete: true`; [integration-live.log](../verification/treasury-v3/integration-live.log) and the outcome history preserve interrupted and failed attempts. The final continuation completed eight scenarios and retained three already verified passes. The strict [verification-summary.json](../verification/treasury-v3/verification-summary.json) independently validates **185 distinct finalized transactions**, including their consequential child receipts.

The scenarios verified both consumers' positive actions, a separate two-origin insurance policy, copied-wire refusal, genuine unknown ancestry/control with bounded paid recovery, hidden common-parent control, instruction injection, all fifteen six-source pairs, duplicate/reordered/forged callbacks, source revision/quarantine, treasury payout/replay and genuinely changing public bytes. The eight sealed results certified respectively three, two, one, zero, one, one, six and zero origins for the event-positive, insurance-positive, copied-wire, exhausted-unknown, hidden-parent, injected-report, six-source and changing-byte requests.

The final revision/quarantine tests intentionally make earlier positive certificates noncurrent. Their sealed cores, positive action records and earlier finalized receipts remain immutable historical evidence; importing the deployed contract should not be interpreted as a promise that those old sources are still eligible.

[receipts](../verification/treasury-v3/receipts), public record commitments, request files and exported operation inputs preserve reproducible evidence. The local journal is excluded from Git.

The evidence fixture is explicitly synthetic: copied wire production, separate instrument/personnel observations, hidden common-parent control, independent principals on the same host, unknown ancestry and injected instructions. Every byte is publicly retrievable through the configured HTTPS mirror and committed by registered test principals. The fixture does not claim real scientific measurements. The application, signatures, deployed contracts, web retrieval, model execution and hosted validator protocol are real.

The first treasury-v3 run stopped on an HTTP 429 before a consumer binding was acknowledged. Recovery checked that the signer nonce had not changed and the existing request was current, then resumed the same deployment and journaled operation. The original failed run remains in the appended live log. New requests use seven-day deadlines; existing committed request data is preserved. The client paces requests below the hourly limit and retries only explicit write refusals, while ambiguous write transport failures still require reconciliation.

Actual refusal headers later reported reset delays of two through four seconds. The client now honors `Retry-After` with a one-second buffer, avoiding fixed 60-second retries at the same phase of repeated rate windows. Finalized return decoding and receipt reuse reduce redundant reads during recovery. The first three scenarios passed: three independent origins with both consumer actions, a separate two-origin insurance policy/action, and copied wire reports with event refusal. The continuation completed the remaining scenarios from their existing operation IDs.

Finality, consensus agreement and execution are checked separately. An unknown-evidence assessment reached `UNDETERMINED` and later `FINALIZED` with `MAJORITY_DISAGREE`; the leader had returned successfully, but its state changes were not applied and the paid reservation remained pending. The driver preserves this refused receipt, verifies payer release and proceeds within the three paid reservations. At least one genuine retrieved semantic unknown decision must agree before this exhaustion scenario qualifies. Refused consensus output never counts as an accepted assessment.

`FINALIZED` can also contain an agreed failed execution; expected refused actions require that failure, whereas deployments, semantic assessments and authenticated callback chains require success. Failed source verification and interrupted setup runs remain visible in the logs instead of being rewritten as successes.

## Declared budgets and measurement limits

Each assessment accepts at most four records, 48 KiB per record, 12 KiB complete raw packet, 18 KiB full prompt and 4 KiB output. UTF-8 decoded text is bounded by the complete packet; the prompt byte limit also serves as a conservative upper bound on tokenizer input size without relying on a particular model tokenizer. At most one substantive model evaluation is performed per leader or validator role execution. The protocol may run leader self-validation and rotate or repeat node executions; the application ceiling does not bound total protocol work. The three-attempt counter bounds paid reservations. A rolled-back assessment leaves its reservation pending, so the payer can invoke assessment again under that hold or release it before a new paid reservation. The counter does not cap total VM executions; the verification driver releases failed holds and stays within three reservations. Six-source batches split all fifteen independent pair tasks into separate bounded assessments and seal only after complete inspection.

Finalized receipts expose actual `execution_stats`, provider token usage, gas/resource fields, processing times and validator identities. The report retains serialized execution observations from consensus round history and current roles, including leader self-validation, dissent and errors. Identical carried snapshots are counted once with their round references. Refused-consensus telemetry is retained separately from accepted material decisions. Provider input/output token observations remain separate from the exact application prompt bytes; they can include provider reasoning or repeated instrumentation. Missing telemetry is not treated as zero. Without provider request IDs, repeated role observations do not establish distinct billable calls or total spending. The completed measurements are recorded below. Current limits are enforced conservative ceilings; a successful small packet does not establish throughput at the maximum allowed size. No native GenVM whole-process memory ceiling is inferred from prompt size alone.

## Measured hosted results

| Measurement | Observed result |
| --- | --- |
| Accepted pair assessments | 25: 24 with available model evidence and one retrieval-only `SOURCE_CHANGED` |
| Finalized consensus refusals | One `MAJORITY_DISAGREE`; paid hold released before the final successful retry |
| Distinct agreeing assessment validators | 19 |
| Paid reservations/native assessment charges | 26 / 26 atto |
| Owner treasury payout | One atto received by the verified receiver; identical replay emitted no child |
| Reconstructed fixture prompts | 25, including the refused assessment; 5,775–6,159 UTF-8 bytes, median 6,121 |
| Complete fixture packets | 1,132–1,296 raw bytes, median 1,284 |
| Participant processing observations | 281; 0–54,882 ms, median 5,376 ms |
| Provider input-token observations | 219; 1,763–6,281, median 2,092 |
| Provider output-token observations | 219; 43–1,993, median 79 |

The prompt measurements cover available-evidence fixture tasks, including the consensus-refused attempt. The UUID mismatch terminates during retrieval and has no model prompt. Timing and token rows include historical role observations, dissent, errors and protocol repetition. They do not establish unique provider requests, billable spend or model-only latency. The JSON summary preserves observation identifiers and round references for review.

## Trust and release gate

Authority principal configuration, source authenticity, completeness of disclosed control evidence and hosted Studio administration are external trust assumptions. Source hashes prove byte identity. Pair consensus establishes agreement under the locked policy and the inspected evidence; undisclosed real-world control may remain unobservable. The consumer supplies its own event or underwriting decision.

The release evidence includes completed substantive hosted consensus, both real consumer integrations, strict receipt/replay validation, exact deployed source identity and credential/author review. Source checks compare all four complete contract byte streams, rather than relying on an explorer page or deployment status alone.

## Recoverable deployment corrections

The original live reservation failed before method execution because `reserve_pair` lacked payable SDK metadata. The corrected `payable-v2` reservation finalized successfully, but its treasury transfer to an externally owned account finalized with `NO_MAJORITY` after missing-contract execution errors. These outcomes are preserved in the earlier receipt directories. The historical `treasury-v3` deployment uses the payable reservation and an independently deployed `AssessmentTreasury.accept_fee` receiver. Source addresses are immutable; consumers were deployed against the corrected Rhizome address. No failed application scenario is relabelled as successful.

The final verification summary is produced with:

```bash
RHIZOME_RUN=reviewer-v5 .venv/bin/python -m scripts.verification_report
```

The current report requires all sixteen passing hosted scenarios and at least two distinct agreeing validators for each accepted assessment. It verifies finalized child provenance and exact authenticated finality-confirmation commitments, all three paid unknown reservations and authenticated release of refused consensus, certificate digests/complete matrices/maximal subsets, consumer/action bindings, actual treasury payment and replay, and initial/later public byte commitments. Exported inputs must match receipt senders, values, destinations, decoded GenVM calldata and deployment source bytes. Exact fixture prompts are reconstructed from pinned source and public inputs. It exports public operation inputs to `operation-inputs.json`, which allows the report to run from a fresh checkout without the ignored local journal. `--partial` is a diagnostic option that retains `complete: false`.

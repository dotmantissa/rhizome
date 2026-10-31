# Rhizome

Rhizome adjudicates whether evidence comes from independent production origins. It returns a complete pair relation matrix, a conservative certified origin count, and the largest pairwise-certified independent subset. Copied wire reports, rehosted datasets and commonly controlled publishers cannot supply extra corroboration merely by appearing at different URLs.

The count says how independently evidence was produced. Applications remain responsible for judging an event, pricing risk or choosing another consequence. The included event resolver requires three origins; the independent insurance gate can require two. Both use authenticated messages emitted only after source transactions finalize.

## Contract package

| Contract | Purpose | Constructor |
| --- | --- | --- |
| [AssessmentTreasury](contracts/assessment_treasury.py) | Payable fee receiver and owner-authorized finalized payments to compatible receivers | `AssessmentTreasury()` |
| [Rhizome](contracts/rhizome.py) | Evidence registry, bounded semantic pair adjudication, matrix sealing and certificate delivery | `Rhizome(treasury_address: str, assessment_fee_atto: int)` |
| [EventResolver](contracts/event_resolver.py) | Owner-configured event resolution gated by at least three origins | `EventResolver(rhizome_address: str)` |
| [InsuranceGate](contracts/insurance_gate.py) | Separately owned underwriting gate with at least two origins | `InsuranceGate(rhizome_address: str)` |

Each file is independently deployable and pins `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`. The supplied Studio deployment uses a one-atto assessment charge to exercise native transfer accounting. Production deployments choose their own payable treasury contract implementing `accept_fee()` and a positive integer charge. The supplied treasury reports collected fees and current balance; its owner can pay another compatible receiver through an idempotent finalized emission.

Studio deployment addresses, exact source hashes, constructor arguments, owners and finalized transaction IDs are recorded in [verification/treasury-v3/deployment.json](verification/treasury-v3/deployment.json). Open the deployed primitive in [GenLayer Studio](https://studio.genlayer.com/?import-contract=0x84453D386fd5f5Cb2956FFcD755fB2649Cd4269f). Verification results and their limits are described in [docs/verification.md](docs/verification.md).

## Consensus boundary

Each assessment inspects the two complete source records and their disclosed control records. The leader and validators independently fetch committed bytes, verify byte-span hashes, and perform the same substantive model task. Validators compare relation, origin IDs, controlling rules, scope, control coverage and canonical complete-record witnesses. Malformed model output, hallucinated origins and VM errors never receive validator approval. A hash proves byte identity; authority comes from explicit registry configuration and principal signatures, and truth remains an external trust assumption.

Sealing is deterministic. It requires a complete pair matrix, checks shared-origin transitive closure and conflicting origin IDs, enumerates all subsets of up to six sources, and retains the lexicographically first maximum independent subset. Unknown cross-cluster relations, unsupported control or inconsistent ancestry produce `UNRESOLVED` with zero certified origins. A diagnostic subset is retained separately and cannot authorize a consumer action.

## Setup and local verification

The checked environment is Linux with Python 3.14.4. `requirements.txt` pins direct dependencies; `requirements.lock` records the verified environment.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/genvm-lint check contracts/assessment_treasury.py --json
.venv/bin/genvm-lint check contracts/rhizome.py --json
.venv/bin/genvm-lint check contracts/event_resolver.py --json
.venv/bin/genvm-lint check contracts/insurance_gate.py --json
.venv/bin/python -m pytest tests/direct -q
.venv/bin/python -m pytest tests/unit -q
```

If the distribution omits `ensurepip`, create the environment with `python3 -m venv --without-pip .venv`, then run `python3 -m pip --python .venv install -r requirements.lock`. Set `TMPDIR` to a writable directory with space when the system temporary filesystem is too small. The linter downloads the SDK corresponding to the pinned runner; direct tests explicitly select SDK `v0.2.16`.

Direct tests use labelled synthetic web/model fault injection and explicit `direct_vm.run_validator()` probes. They verify state, permissions, bounds, validator rejection and all 32,768 binary independence graphs on six sources. They do not replace hosted consensus verification. The [Studio tests](tests/integration/test_studio.py) execute real deployed contracts, real web retrieval and real model/validator consensus using publicly retrievable, explicitly synthetic records signed by separate configured test principals.

The completed verification passed **73 direct tests, 15 client/history tests and all 11 hosted scenarios**. The strict [receipt report](verification/treasury-v3/verification-summary.json) checks 185 distinct finalized transactions, 24 accepted model assessments, a genuine changing-byte refusal, the complete fifteen-pair matrix and both consumer actions. Final revision/quarantine tests intentionally invalidate earlier positive certificates; their successful historical action receipts remain preserved.

## Builder integration

Start with the [authority and state diagram](docs/architecture.md), [public API and schemas](docs/protocol.md), and [two consumer integration flows](docs/integration.md). [Replayable request files](verification/treasury-v3/requests) and [finalized receipts](verification/treasury-v3/receipts) preserve the exact evidence bindings and network outcomes.

Evidence principals attest immutable source revisions. Policy owners define immutable policies. Request owners commit the subject, complete manifest, intended consequence, generation and deadline before evaluation. Consumers independently configure their threshold and approve the exact batch/consequence they accept. Any caller can publish a terminal current certificate after that approval, but only the authenticated Rhizome contract can deliver it to these adapters.

Quarantine is irreversible for a record. A successor source revision or subject generation retains historical records while restricting old actions. Consumers check freshness at action time and retain acknowledgements for duplicate and reordered callbacks. Their view reads provide freshness information; the finalized callback supplies finality evidence.

## Execution limits

Two through six sources, fifteen distinct pairs, at most three paid reservations per pair, four records per assessment, at most 48 KiB per record and 12 KiB for the complete pair packet. The full prompt is capped at 18 KiB and output at 4 KiB. Each leader or validator role execution performs at most one model evaluation; leader self-validation and protocol rotation can execute a node more than once. Oversized complete packets terminate conservatively without truncation. Histories and reverse revision indexes expose pages of at most fifty items. Numeric quantities use sized integer storage.

There is no primitive upgrade entry point. Incompatible schema changes require a new deployment and explicit consumer rebinding. Hosted Studio deployment and administrator controls remain part of the environment's trust model; omitting a contract upgrade method does not remove those external privileges.

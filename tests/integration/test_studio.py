"""Real Studio multi-validator tests. No web, model or contract mocks.

The public evidence is explicitly synthetic and signed by configured test
principals. Every transaction is finalized and its execution outcome verified.
Replay identifiers and complete receipts are recorded under verification/.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
import pytest
import requests
from scripts.studio import Studio, ProtocolFailure, VERIFICATION, agreeing_validators, successful, finalized_result
from tests.evidence import canonical, digest, source_packet, record, DEFINITION

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def live():
    assert os.environ.get("RHIZOME_CREDENTIALS_FILE"), "provide a secure external credentials file"
    studio = Studio()
    deployment = studio.deploy()
    source = deployment["contracts"]["rhizome"]["address"]
    resolver = deployment["contracts"]["event_resolver"]["address"]
    insurance = deployment["contracts"]["insurance_gate"]["address"]
    assert studio.accounts["resolver"].address != studio.accounts["insurance"].address
    for policy, count, role in [("event-independence", 3, "deployer"), ("insurance-independence", 2, "insurance")]:
        studio.submit("policy-" + policy, source, "register_policy", [policy, canonical(DEFINITION), count], role=role)
    catalog = {}
    specifications = [("alpha", "independent", "deployer"), ("beta", "independent", "resolver"), ("gamma", "independent", "insurance"),
                      ("wire-a", "copy", "deployer"), ("wire-b", "copy", "resolver"),
                      ("parent-a", "parent", "deployer"), ("parent-b", "parent", "insurance"),
                      ("inject", "injection", "deployer"), ("unknown", "unknown", "insurance"),
                      ("delta", "independent", "delta"), ("epsilon", "independent", "epsilon"), ("zeta", "independent", "zeta")]
    authorities_pending = []
    for name, mode, role in specifications:
        principal = studio.accounts[role].address
        cr, cb, sr, sb = source_packet(name, principal, mode)
        for metadata, raw in [(cr, cb), (sr, sb)]:
            response = requests.get(metadata["url"], headers={"Accept-Encoding": "identity"}, timeout=30)
            assert response.status_code == 200 and response.content == raw, "public committed bytes are unavailable"
        authority = {"authority_id": sr["authority_id"], "principal": principal, "channel": sr["channel"],
                     "url_prefix": "https://httpbingo.org/base64/", "control_record": cr}
        tx = studio.submit("authority-" + name, source, "register_authority", [sr["authority_id"], principal, sr["channel"], authority["url_prefix"], canonical(cr)], wait_for_finality=False)
        authorities_pending.append(("authority-" + name, tx))
        catalog[name] = {"source": sr, "authority": authority, "role": role}
    for label, tx in authorities_pending:
        studio.wait(tx, label)
    sources_pending = []
    for name, _, role in specifications:
        tx = studio.submit("attest-" + name, source, "attest_source", [canonical(catalog[name]["source"])], role=role, wait_for_finality=False)
        sources_pending.append(("attest-" + name, tx))
    for label, tx in sources_pending:
        studio.wait(tx, label)
    (VERIFICATION / "public-evidence.json").write_text(json.dumps({"classification": "SYNTHETIC TEST RECORDS", "catalog": catalog}, indent=2) + "\n")
    return studio, source, resolver, insurance, catalog


def open_request(live, request_id, names, policy, consumer, subject=None, generation=1):
    studio, source, _, _, catalog = live
    sources = [catalog[name]["source"] for name in sorted(names)]
    authorities = [catalog[name]["authority"] for name in sorted(names)]
    manifest = {"sources": sources, "authorities": sorted(authorities, key=lambda a: a["authority_id"])}
    saved_path = VERIFICATION / "requests" / (request_id + ".json")
    saved_path.parent.mkdir(exist_ok=True)
    if saved_path.exists():
        body = json.loads(saved_path.read_text())
    else:
        envelope = {"request_id": request_id, "owner": studio.accounts["deployer"].address, "parties": [],
                    "policy_id": policy, "policy_revision": 1, "subject_id": subject or request_id,
                    "subject_digest": digest({"synthetic_subject": subject or request_id}), "source_manifest_digest": digest(manifest),
                    "consumer_address": consumer, "consequence_digest": digest({"intended_consequence": "test independence gate", "subject": subject or request_id}),
                    "generation": generation, "deadline": int(time.time()) + 604800}
        body = {"envelope": envelope, "sources": [{"source_id": s["source_id"], "revision": s["revision"]} for s in sources]}
        saved_path.write_text(json.dumps(body, indent=2) + "\n")
    receipt = studio.submit("open-" + request_id, source, "open_batch", [request_id, policy, canonical(body)])
    return finalized_result(receipt)


def assess(live, request_id, left, right, attempt=1):
    studio, source, _, _, _ = live
    label = request_id + "-" + left + "-" + right + "-" + str(attempt)
    reservation = studio.submit("reserve-" + label, source, "reserve_pair", [request_id, left, right, label], value=1)
    studio.drain(reservation, "reserve-" + label)
    receipt = studio.submit("assess-" + label, source, "assess_pair", [request_id, left, right])
    assert len(agreeing_validators(receipt)) >= 2, "semantic execution needs two independent agreeing validators"
    decision = finalized_result(receipt)
    assert decision["pair_ids"] == sorted([left, right])
    return decision, receipt


def assess_pairs(live, request_id, pairs):
    """Batch independent pairs; verify every reservation, fee child and decision."""
    studio, source, _, _, _ = live
    pairs = list(pairs)
    assert 1 <= len(pairs) <= 15
    pending = []
    for left, right in pairs:
        label = request_id + "-" + left + "-" + right + "-1"
        tx = studio.submit("reserve-" + label, source, "reserve_pair", [request_id, left, right, label],
                           value=1, wait_for_finality=False)
        pending.append(("reserve-" + label, tx))
    for label, tx in pending:
        studio.drain(studio.wait(tx, label), label)
    pending = []
    for left, right in pairs:
        label = "assess-" + request_id + "-" + left + "-" + right + "-1"
        tx = studio.submit(label, source, "assess_pair", [request_id, left, right], wait_for_finality=False)
        pending.append((label, tx, left, right))
    results = []
    for label, tx, left, right in pending:
        receipt = studio.wait(tx, label)
        assert len(agreeing_validators(receipt)) >= 2
        decision = finalized_result(receipt)
        assert decision["pair_ids"] == sorted([left, right])
        results.append((decision, receipt))
    return results


def configure_and_bind(live, batch, consumer, role, minimum, action):
    studio, _, _, _, _ = live
    env = batch["envelope"]
    config = studio.submit("configure-" + role + "-" + env["policy_id"], consumer, "configure_policy", [env["policy_id"], env["policy_revision"], minimum], role=role)
    studio.drain(config, "configure-" + role + "-" + env["policy_id"])
    consequence = {"subject_id": env["subject_id"], "action": action, "value": "eligible"}
    binding = {**env, "batch_digest": batch["batch_digest"]}
    tx = studio.submit("bind-" + role + "-" + env["request_id"], consumer, "bind_request", [canonical(binding), canonical(consequence)], role=role)
    studio.drain(tx, "bind-" + role + "-" + env["request_id"])


def deliver(live, request_id, consumer, operation):
    studio, source, _, _, _ = live
    receipt = studio.submit("publish-" + operation, source, "publish_to", [request_id, consumer, operation])
    # Verify source finalized emission rather than treating a view as a receipt.
    leaders = receipt["consensus_data"]["leader_receipt"]
    messages = [m for l in leaders if l.get("mode", "leader") == "leader" for m in l.get("pending_transactions", [])]
    assert messages and all(m["on"] == "finalized" for m in messages)
    studio.drain(receipt, "publish-" + operation)
    acknowledgement = studio.read(source, "get_delivery", [consumer, operation])["acknowledgement"]
    assert acknowledgement is not None, "finalized consumer acknowledgement missing"
    return acknowledgement


def test_01_three_independent_measurements_and_shared_infrastructure(live):
    studio, source, resolver, insurance, _ = live
    batch = open_request(live, "event-permitted", ["alpha", "beta", "gamma"], "event-independence", resolver)
    for consumer, role, action in [(resolver, "resolver", "RESOLVED"), (insurance, "insurance", "UNDERWRITING_ENABLED")]:
        configure_and_bind(live, batch, consumer, role, 3, action)
    for decision, receipt in assess_pairs(live, "event-permitted", [("alpha", "beta"), ("alpha", "gamma"), ("beta", "gamma")]):
        assert decision["relation"] == "INDEPENDENT", decision
        assert len(decision["witnesses"]) == 4
    studio.submit("seal-event-permitted", source, "seal_batch", ["event-permitted"])
    certificate = studio.read(source, "get_certificate", ["event-permitted"])["sealed_result"]
    assert certificate["certified_origin_count"] == 3 and certificate["certified_subset"] == ["alpha", "beta", "gamma"]
    for consumer, role, action in [(resolver, "resolver", "RESOLVED"), (insurance, "insurance", "UNDERWRITING_ENABLED")]:
        assert deliver(live, "event-permitted", consumer, role + "-permitted")["outcome"] == "APPLIED"
        assert studio.read(consumer, "get_subject", ["event-permitted"])["permitted"]
        studio.submit("action-" + role + "-permitted", consumer, "apply_action", ["event-permitted", role + "-action-permitted"], role=role)
        assert studio.read(consumer, "get_action", [role + "-action-permitted"])["action"] == action


def test_02_insurance_uses_separate_policy_and_key(live):
    studio, source, _, insurance, _ = live
    batch = open_request(live, "insurance-permitted", ["alpha", "beta"], "insurance-independence", insurance)
    configure_and_bind(live, batch, insurance, "insurance", 2, "UNDERWRITING_ENABLED")
    decision, _ = assess(live, "insurance-permitted", "alpha", "beta")
    assert decision["relation"] == "INDEPENDENT"
    studio.submit("seal-insurance-permitted", source, "seal_batch", ["insurance-permitted"])
    assert deliver(live, "insurance-permitted", insurance, "insurance-two-origin")["outcome"] == "APPLIED"
    studio.submit("action-insurance-two-origin", insurance, "apply_action", ["insurance-permitted", "insurance-action-two-origin"], role="insurance")


def test_03_copied_wire_reports_refuse_event_resolution(live):
    studio, source, resolver, _, _ = live
    batch = open_request(live, "event-refused", ["wire-a", "wire-b"], "event-independence", resolver)
    configure_and_bind(live, batch, resolver, "resolver", 3, "RESOLVED")
    decision, _ = assess(live, "event-refused", "wire-a", "wire-b")
    assert decision["relation"] == "SHARED_ORIGIN", decision
    assert "COPY_OR_DERIVATION" in decision["rule_ids"] and decision["left_origin_ids"] == ["wire-origin"]
    studio.submit("seal-event-refused", source, "seal_batch", ["event-refused"])
    certificate = studio.read(source, "get_certificate", ["event-refused"])["sealed_result"]
    assert certificate["certified_origin_count"] <= 1 and not certificate["threshold_met"]
    assert deliver(live, "event-refused", resolver, "resolver-refused")["outcome"] == "REFUSED"
    studio.submit("action-resolver-refused", resolver, "apply_action", ["event-refused", "resolver-action-refused"], role="resolver", expected_error=True)


def test_04_unknown_ownership_retry_exhaustion_refuses_insurance(live):
    studio, source, _, insurance, _ = live
    batch = open_request(live, "insurance-unresolved", ["alpha", "unknown"], "insurance-independence", insurance)
    configure_and_bind(live, batch, insurance, "insurance", 2, "UNDERWRITING_ENABLED")
    semantic_unknowns = 0
    for attempt in range(1, 4):
        try:
            decision, _ = assess(live, "insurance-unresolved", "alpha", "unknown", attempt)
        except ProtocolFailure as failure:
            assert failure.receipt["status_name"] == "FINALIZED"
            assert failure.receipt["result_name"] in ("MAJORITY_DISAGREE", "NO_MAJORITY")
            release_label = "release-insurance-unresolved-" + str(attempt)
            if any(row.get("event") == "FINALIZED" and row.get("operation") == release_label for row in studio.records):
                studio.submit(release_label, source, "release_pair", ["insurance-unresolved", "alpha", "unknown"])
                continue
            held = studio.read(source, "get_pair", ["insurance-unresolved", "alpha", "unknown"])
            assert held["attempts"] == attempt
            assert held["reservation"]["status"] in ("PENDING", "RELEASED")
            assert held["reservation"]["operation_id"] == "insurance-unresolved-alpha-unknown-" + str(attempt)
            studio.submit(release_label, source, "release_pair", ["insurance-unresolved", "alpha", "unknown"])
            released = studio.read(source, "get_pair", ["insurance-unresolved", "alpha", "unknown"])
            assert released["reservation"]["status"] == "RELEASED" and released["attempts"] == attempt
            continue
        assert decision["relation"] == "UNKNOWN", decision
        assert decision["available"] and not decision["control_verified"], decision
        assert {"UNKNOWN_CONTROL", "UNKNOWN_ANCESTRY"} <= set(decision["rule_ids"]), decision
        semantic_unknowns += 1
    assert semantic_unknowns >= 1, "retrieved semantic unknown evidence required; outages alone do not qualify"
    studio.submit("resolve-insurance-unresolved", source, "resolve_unavailable", ["insurance-unresolved"])
    certificate = studio.read(source, "get_certificate", ["insurance-unresolved"])["sealed_result"]
    assert certificate["unresolved_reason"] == "RETRY_EXHAUSTED" and certificate["certified_origin_count"] == 0
    assert deliver(live, "insurance-unresolved", insurance, "insurance-unresolved")["outcome"] == "REFUSED"
    studio.submit("action-insurance-refused", insurance, "apply_action", ["insurance-unresolved", "insurance-action-refused"], role="insurance", expected_error=True)


@pytest.mark.parametrize("request_id,names,rule", [
    ("hidden-parent", ["parent-a", "parent-b"], "SHARED_CONTROL"),
    ("injected-report", ["inject", "wire-a"], "COPY_OR_DERIVATION"),
])
def test_05_parent_company_and_injected_instruction(live, request_id, names, rule):
    studio, source, resolver, _, _ = live
    open_request(live, request_id, names, "event-independence", resolver)
    decision, _ = assess(live, request_id, *sorted(names))
    assert decision["relation"] == "SHARED_ORIGIN" and rule in decision["rule_ids"], decision
    studio.submit("seal-" + request_id, source, "seal_batch", [request_id])
    assert studio.read(source, "get_certificate", [request_id])["sealed_result"]["certified_origin_count"] <= 1


def test_06_complete_six_source_matrix(live):
    studio, source, resolver, _, _ = live
    names = sorted(["alpha", "beta", "gamma", "delta", "epsilon", "zeta"])
    open_request(live, "six-independent", names, "event-independence", resolver)
    import itertools
    pairs = list(itertools.combinations(names, 2))
    for decision, _ in assess_pairs(live, "six-independent", pairs):
        assert decision["relation"] == "INDEPENDENT", decision
    studio.submit("seal-six-independent", source, "seal_batch", ["six-independent"])
    certificate = studio.read(source, "get_certificate", ["six-independent"])["sealed_result"]
    assert len(certificate["relation_matrix"]) == 15 and certificate["certified_subset"] == names
    assert certificate["certified_origin_count"] == 6 and certificate["coverage_complete"]


def test_07_duplicate_reordered_and_forged_callbacks(live):
    studio, source, resolver, insurance, _ = live
    original = studio.read(insurance, "get_acknowledgement", ["insurance-permitted"])
    receipt = studio.submit("publish-insurance-permitted-again", source, "publish_to", ["event-permitted", insurance, "insurance-permitted"])
    studio.drain(receipt, "publish-insurance-permitted-again")
    assert studio.read(insurance, "get_acknowledgement", ["insurance-permitted"]) == original
    # The original certificate remains current for its primary resolver. A
    # secondary consumer independently locks a newer generation for the subject.
    open_request(live, "insurance-event-gen1", ["alpha", "beta", "gamma"], "event-independence", insurance, subject="event-permitted")
    newer = open_request(live, "insurance-event-gen2", ["alpha", "beta", "gamma"], "event-independence", insurance, subject="event-permitted", generation=2)
    configure_and_bind(live, newer, insurance, "insurance", 3, "UNDERWRITING_ENABLED")
    assert deliver(live, "event-permitted", insurance, "insurance-reordered-old")["outcome"] == "STALE"
    state = studio.read(insurance, "get_subject", ["event-permitted"])
    assert state["generation"] == 2 and state["status"] == "PENDING" and not state["permitted"]
    payload = studio.read(source, "get_delivery", [resolver, "resolver-permitted"])["delivery"]
    studio.submit("forged-eoa-callback", resolver, "receive_certificate", [canonical(payload)], role="insurance", expected_error=True)


def test_08_source_revision_and_quarantine_at_action_time(live):
    studio, source, resolver, insurance, catalog = live
    successor = source_packet("beta", studio.accounts["resolver"].address, revision=2)[2]
    studio.submit("attest-beta-revision2", source, "attest_source", [canonical(successor)], role="resolver")
    studio.submit("replay-beta-old-revision", source, "attest_source", [canonical(catalog["beta"]["source"])], role="resolver")
    assert not studio.read(source, "is_current", ["event-permitted"])["current"]
    studio.submit("stale-source-action", resolver, "apply_action", ["event-permitted", "stale-source-action"], role="resolver", expected_error=True)
    studio.submit("quarantine-alpha", source, "quarantine_record", ["source", "alpha", 1, digest("synthetic revocation probe")])
    studio.submit("refresh-resolver-subject", resolver, "refresh_subject", ["event-permitted"], role="resolver")
    assert not studio.read(resolver, "get_subject", ["event-permitted"])["permitted"]
    invalidated = studio.submit("resolve-finalized-superseded-request", source, "resolve_unavailable", ["insurance-event-gen1"])
    assert finalized_result(invalidated)["sealed_result"]["unresolved_reason"] == "EVIDENCE_INVALIDATED"
    studio.submit("integer-bound-policy", source, "register_policy", ["invalid-count", canonical(DEFINITION), 7], expected_error=True)


def test_09_treasury_accounting_and_owner_payout(live):
    studio, source, _, _, _ = live
    limits = studio.read(source, "get_limits")
    treasury = limits["treasury"]
    totals = studio.read(treasury, "get_totals")
    assert totals["received_atto"] == limits["charged_atto"] > 0
    assert totals["balance_atto"] == totals["received_atto"]
    code = (Path(__file__).resolve().parents[2] / "contracts" / "assessment_treasury.py").read_bytes()
    recipient_receipt = studio.submit("deploy-fee-recipient", args=[], role="resolver", code=code)
    assert len(agreeing_validators(recipient_receipt)) >= 2
    recipient = recipient_receipt["to_address"]
    studio.submit("unauthorized-treasury-payout", treasury, "payout", ["unauthorized", recipient, 1],
                  role="insurance", expected_error=True)
    payout = studio.submit("treasury-owner-payout", treasury, "payout", ["treasury-payout", recipient, 1])
    studio.drain(payout, "treasury-owner-payout")
    replay = studio.submit("treasury-payout-identical-replay", treasury, "payout", ["treasury-payout", recipient, 1])
    assert replay.get("triggered_transactions", []) == []
    assert studio.read(recipient, "get_totals")["received_atto"] == 1
    assert studio.read(treasury, "get_totals")["balance_atto"] == totals["balance_atto"] - 1

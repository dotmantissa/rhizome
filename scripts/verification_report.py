"""Audit preserved Studio artifacts and summarize measured execution.

Run with RHIZOME_RUN=<run> python -m scripts.verification_report. This reads
local replay artifacts only. --partial permits an unfinished run for diagnosis.
"""
import argparse
import ast
import base64
import hashlib
import itertools
import json
from pathlib import Path
import statistics
import rlp
from genlayer_py.abi import calldata
from genlayer_py.contracts.utils import make_calldata_object

from scripts.studio import ROOT, VERIFICATION, agreeing_validators, canonical, digest, successful, write_json

EXPECTED_TESTS = {
    "tests/integration/test_studio.py::" + name for name in (
        "test_01_three_independent_measurements_and_shared_infrastructure",
        "test_02_insurance_uses_separate_policy_and_key",
        "test_03_copied_wire_reports_refuse_event_resolution",
        "test_04_unknown_ownership_retry_exhaustion_refuses_insurance",
        "test_05_parent_company_and_injected_instruction[hidden-parent-names0-SHARED_CONTROL]",
        "test_05_parent_company_and_injected_instruction[injected-report-names1-COPY_OR_DERIVATION]",
        "test_06_complete_six_source_matrix",
        "test_07_duplicate_reordered_and_forged_callbacks",
        "test_08_source_revision_and_quarantine_at_action_time",
        "test_09_treasury_accounting_and_owner_payout",
    )
} | {"tests/integration/test_source_changes.py::test_changed_public_bytes_cannot_certify_origins",
     "tests/integration/test_audit_security.py::test_10_authorized_payer_revocation_and_owner_recovery",
     "tests/integration/test_audit_security.py::test_11_invalid_consumer_inputs_do_not_poison_configuration",
     "tests/integration/test_recovery.py::test_12_failed_fee_refunds_forward_once_to_fixed_treasury",
     "tests/integration/test_recovery.py::test_13_tentative_restriction_preserves_permission_and_delivery_retries[resolver-RESOLVED]",
     "tests/integration/test_recovery.py::test_13_tentative_restriction_preserves_permission_and_delivery_retries[insurance-UNDERWRITING_ENABLED]"}


def leader(receipt):
    return next(item for item in receipt.get("consensus_data", {}).get("leader_receipt", [])
                if item.get("mode", "leader") == "leader")


def validator_addresses(receipt):
    return sorted({item.get("node_config", {}).get("address") for item in agreeing_validators(receipt)
                   if item.get("node_config", {}).get("address")})


def timing_summary(values):
    return {"samples": len(values), "min": min(values), "median": statistics.median(values),
            "max": max(values)} if values else None


def execution_observations(receipt):
    """Retain historical roles without recounting carried-over snapshots."""
    snapshots = []
    for index, round_result in enumerate(receipt.get("consensus_history", {}).get("consensus_results", [])):
        label = str(round_result["consensus_round"])
        if not label.isdigit():
            label = str(index) + ":" + label
        snapshots.extend((label, item) for item in round_result.get("leader_result", []) + round_result.get("validator_results", []))
    data = receipt.get("consensus_data", {})
    snapshots.extend(("current", item) for item in data.get("leader_receipt", []) + data.get("validators", []))
    observations = {}
    for label, participant in snapshots:
        key = digest(participant)
        observation = observations.setdefault(key, {"observation_id": key, "rounds": [], "receipt": participant})
        if label not in observation["rounds"]:
            observation["rounds"].append(label)
    return list(observations.values())


def check_replay_input(receipt, payload):
    """Bind exported inputs to the actual sender, value and GenVM calldata."""
    assert receipt["from_address"] == payload["sender"], "replay signer differs from receipt"
    assert int(receipt["value"]) == payload["value"], "replay value differs from receipt"
    encoded = rlp.decode(bytes.fromhex(receipt["tx_data"].removeprefix("0x")))
    assert encoded[-1] == b"\x00" and not receipt["leader_only"], "full consensus required"
    if payload["code_sha256"] is not None:
        assert len(encoded) == 3 and hashlib.sha256(encoded[0]).hexdigest() == payload["code_sha256"], "deployment source differs"
        decoded = calldata.decode(encoded[1])
        assert decoded == make_calldata_object(method=None, args=payload["args"], kwargs=None), "constructor inputs differ"
    else:
        assert receipt["to_address"] == payload["address"], "replay destination differs from receipt"
        assert len(encoded) == 2 and calldata.decode(encoded[0]) == make_calldata_object(method=payload["method"], args=payload["args"], kwargs=None), "method inputs differ"


def report(partial=False):
    deployment = json.loads((VERIFICATION / "deployment.json").read_text())
    outcomes_path = VERIFICATION / "integration-results.json"
    outcomes = json.loads(outcomes_path.read_text()) if outcomes_path.exists() else {}
    complete = bool(outcomes.get("complete")) and set(outcomes.get("expected_tests", [])) == EXPECTED_TESTS and all(
        outcomes.get("tests", {}).get(name, {}).get("outcome") == "passed" for name in outcomes["expected_tests"])
    if not partial:
        assert complete, "hosted suite is incomplete; use --partial only for diagnosis"
    for name, contract in deployment["contracts"].items():
        assert hashlib.sha256((ROOT / "contracts" / (name + ".py")).read_bytes()).hexdigest() == contract["code_sha256"], name
    receipts = {path.stem: json.loads(path.read_text()) for path in (VERIFICATION / "receipts").glob("*.json")}
    by_hash = {receipt["hash"]: receipt for receipt in receipts.values()}
    expected_refusals = {"action-resolver-refused", "action-insurance-refused", "forged-eoa-callback",
                         "stale-source-action", "integer-bound-policy", "unauthorized-treasury-payout",
                         "audit-unauthorized-reservation", "audit-revoked-assessment",
                         "audit-unauthorized-reservation-2", "audit-unauthorized-reservation-3",
                         "audit-invalid-consumer-policy", "audit-invalid-consumer-binding",
                         "audit-invalid-resolver-policy", "audit-invalid-resolver-binding",
                         "refund-fee-failure", "refund-retry-fee-failure"}
    for name, contract in deployment["contracts"].items():
        receipt = receipts["deploy-" + name]
        assert receipt["hash"] == contract["deployment_tx"] and successful(receipt), name
        assert len(validator_addresses(receipt)) >= 2, name + ": independent deployment validators missing"
    assessments = []
    protocol_refusals = []
    expected_failures = []
    all_addresses = set()
    participant_times = []
    token_observations = []
    for name, receipt in sorted(receipts.items()):
        assert receipt["status_name"] == "FINALIZED", name
        if not partial:
            for child in receipt.get("triggered_transactions", []):
                child_hash = child if isinstance(child, str) else child.get("hash", child.get("tx_id"))
                assert child_hash in by_hash, name + ": finalized child receipt missing"
                child_receipt = by_hash[child_hash]
                probe = name in ("recovery-restrict-resolver", "recovery-restrict-insurance")
                expected_on = "accepted" if probe else "finalized"
                assert child_receipt["triggered_by"] == receipt["hash"] and child_receipt["triggered_on"] == expected_on, name + ": emission provenance differs"
                if probe:
                    assert receipt["to_address"] == receipts["deploy-restriction-source"]["to_address"], "accepted probes must come from the controlled fixture"
                assert child_receipt["from_address"] == receipt["to_address"], name + ": child sender differs from emitting contract"
        protocol_refused = receipt.get("result_name") not in (None, "MAJORITY_AGREE")
        if protocol_refused:
            assert name.startswith("assess-insurance-unresolved-alpha-unknown-"), name + ": unexpected protocol refusal"
            assert receipt["result_name"] in ("MAJORITY_DISAGREE", "NO_MAJORITY"), name
            attempt = int(name.rsplit("-", 1)[1])
            assert attempt in (1, 2, 3), name
            release = receipts.get("release-insurance-unresolved-" + str(attempt))
            if not partial:
                assert release is not None and successful(release), name + ": payer release missing"
            protocol_refusals.append({"operation": name, "transaction": receipt["hash"],
                                      "result_name": receipt["result_name"], "paid_attempt": attempt,
                                      "payer_release_transaction": release["hash"] if release else None,
                                      "protocol_rounds": receipt.get("num_of_rounds"),
                                      "rotation_count": receipt.get("rotation_count")})
        elif not successful(receipt):
            if not partial:
                assert name in expected_refusals, name + ": unexpected failed execution"
            expected_failures.append({"operation": name, "transaction": receipt["hash"],
                                      "error": leader(receipt).get("genvm_result"),
                                      "result": leader(receipt).get("result")})
        if not name.startswith("assess-"):
            continue
        # History retains rotated validators and carried-over leader snapshots.
        observations = execution_observations(receipt)
        participants = [value["receipt"] for value in observations]
        participant_times.extend(item["processing_time"] for item in participants if isinstance(item.get("processing_time"), (int, float)))
        for observation in observations:
            participant = observation["receipt"]
            telemetry = participant.get("execution_stats") or {}
            for provider, tokens in telemetry.get("llm", {}).get("tokens", {}).items():
                token_observations.append({"operation": name, "mode": participant["mode"],
                                           "observation_id": observation["observation_id"], "rounds": observation["rounds"],
                                           "address": participant.get("node_config", {}).get("address"),
                                           "provider": provider, **tokens})
        if protocol_refused:
            continue  # Leader output never qualifies as an accepted assessment.
        assert successful(receipt), name + ": semantic execution failed"
        addresses = validator_addresses(receipt)
        assert len(addresses) >= 2, name + ": fewer than two independent agreeing validators"
        all_addresses.update(addresses)
        readable = leader(receipt).get("result", {}).get("payload", {}).get("readable")
        decision = json.loads(readable) if readable else None
        assert decision is not None, name + ": material return missing"
        if name.startswith("assess-insurance-unresolved-"):
            assert decision["available"] and decision["relation"] == "UNKNOWN", name + ": semantic unknown evidence required"
            assert not decision["control_verified"] and {"UNKNOWN_CONTROL", "UNKNOWN_ANCESTRY"} <= set(decision["rule_ids"]), name + ": unknown ownership/ancestry not established"
        assessments.append({"operation": name, "transaction": receipt["hash"], "decision": decision,
                            "independent_agreeing_validators": addresses,
                            "protocol_rounds": receipt.get("num_of_rounds"), "rotation_count": receipt.get("rotation_count"),
                            "participants": [{"mode": item["mode"], "address": item.get("node_config", {}).get("address"),
                                              "observation_id": observation["observation_id"], "rounds": observation["rounds"],
                                              "vote": item.get("vote"), "execution_result": item.get("execution_result"),
                                              "processing_time_ms": item.get("processing_time"), "execution_stats": item.get("execution_stats")}
                                             for observation in observations for item in [observation["receipt"]]]})
    # Reconstruct the exact application prompt from committed fixture bytes and
    # the public journal. No web/model execution or output is simulated here.
    journal_path = VERIFICATION / "live-journal.jsonl"
    replay_path = VERIFICATION / "operation-inputs.json"
    if journal_path.exists():
        journal = [json.loads(line) for line in journal_path.read_text().splitlines()]
        write_json(replay_path, {"classification": "PUBLIC SIGNER ADDRESSES AND EXACT TRANSACTION INPUTS",
                                 "operations": [row for row in journal if row["event"] in ("INTENT", "SUBMITTED")]})
    else:
        journal = json.loads(replay_path.read_text())["operations"]
    intents = {row["operation"]: row["payload"] for row in journal if row["event"] == "INTENT"}
    for operation, receipt in receipts.items():
        if operation in intents:
            check_replay_input(receipt, intents[operation])
    if not partial:
        assert expected_refusals <= set(receipts), "expected action/authority refusal receipts missing"
    for refusal in protocol_refusals:
        attempt = refusal["paid_attempt"]
        reservation = receipts["reserve-insurance-unresolved-alpha-unknown-" + str(attempt)]
        held = json.loads(leader(reservation)["result"]["payload"]["readable"])
        assert successful(reservation) and held["attempt"] == attempt and held["status"] == "PENDING"
        assert held["payer"] == intents[refusal["operation"]]["sender"]
        release = intents.get("release-insurance-unresolved-" + str(attempt))
        if release:
            assert release["sender"] == held["payer"] and release["method"] == "release_pair"
            assert release["args"] == ["insurance-unresolved", "alpha", "unknown"]
        elif not partial:
            raise AssertionError("payer release input missing")
    if not partial:
        assert any(item["operation"].startswith("assess-insurance-unresolved-") for item in assessments), "genuine accepted unknown assessment missing"
        for attempt in range(1, 4):
            reservation = receipts["reserve-insurance-unresolved-alpha-unknown-" + str(attempt)]
            held = json.loads(leader(reservation)["result"]["payload"]["readable"])
            assert successful(reservation) and held["attempt"] == attempt
    changing_path = VERIFICATION / "changed-source-record.json"
    if changing_path.exists():
        capture = json.loads(changing_path.read_text())
        metadata = capture["metadata"]
        attestation = intents.get("attest-changing-bytes")
        if attestation:
            assert json.loads(attestation["args"][0]) == metadata, "changing-byte capture differs from signed attestation"
        elif not partial:
            raise AssertionError("changing-byte attestation input missing")
        initial = bytes.fromhex(capture["initial_raw_hex"])
        assert len(initial) == metadata["size_bytes"] and hashlib.sha256(initial).hexdigest() == metadata["sha256"], "initial changing-byte commitment differs"
        if "independent_later_raw_hex" in capture:
            later = bytes.fromhex(capture["independent_later_raw_hex"])
            assert hashlib.sha256(later).hexdigest() != metadata["sha256"], "later public bytes did not change"
        elif not partial:
            raise AssertionError("later changing-byte capture missing")
    elif not partial:
        raise AssertionError("changing-byte public capture missing")
    if not partial:
        changed = next(item["decision"] for item in assessments if item["operation"] == "assess-changed-public-bytes-changed-delta-1")
        assert not changed["available"] and changed["relation"] == "UNKNOWN" and changed["unresolved_reason"] == "SOURCE_CHANGED" and changed["witnesses"] == [], "changed bytes supplied authority"
    certificates, actions = [], []
    for operation, receipt in sorted(receipts.items()):
        intent = intents.get(operation)
        if not intent or not successful(receipt):
            continue
        readable = leader(receipt).get("result", {}).get("payload", {}).get("readable")
        if intent["method"] in ("seal_batch", "resolve_unavailable"):
            certificate = json.loads(readable)["sealed_result"]
            request_id = certificate["request_id"]
            body = json.loads((VERIFICATION / "requests" / (request_id + ".json")).read_text())
            assert all(certificate[key] == value for key, value in body["envelope"].items()), operation
            assert certificate["source_contract"] == intent["address"], operation
            allowed_sources = {deployment["contracts"]["rhizome"]["address"]}
            if "deploy-restriction-source" in receipts:
                allowed_sources.add(receipts["deploy-restriction-source"]["to_address"])
            assert certificate["source_contract"] in allowed_sources, operation
            assert certificate["certificate_digest"] == digest({key: value for key, value in certificate.items() if key != "certificate_digest"}), operation
            ids = sorted(source["source_id"] for source in body["sources"])
            matrix = certificate["relation_matrix"]
            complete_matrix = set(matrix) == {a + "|" + b for a, b in itertools.combinations(ids, 2)}
            assert certificate["coverage_complete"] == complete_matrix, operation
            if certificate["lifecycle_status"] == "SEALED":
                assert complete_matrix and not certificate["unresolved"], operation
                # Independent specification by combinations, distinct from the
                # contract's bitmask enumeration and retained test outcomes.
                best = next(list(candidate) for size in range(len(ids), -1, -1)
                            for candidate in itertools.combinations(ids, size)
                            if all(matrix[a + "|" + b]["relation"] == "INDEPENDENT"
                                   for a, b in itertools.combinations(candidate, 2)))
                assert certificate["certified_subset"] == best, operation
                assert certificate["certified_origin_count"] == len(best), operation
                assert all(pair["available"] and pair["scope_verified"] and pair["control_verified"]
                           for pair in matrix.values()), operation
                assert certificate["threshold_met"] == (len(best) >= certificate["required_count"]), operation
            else:
                assert certificate["lifecycle_status"] == "UNRESOLVED" and certificate["unresolved"], operation
                assert certificate["certified_subset"] == [] and certificate["certified_origin_count"] == 0, operation
                assert not certificate["threshold_met"], operation
            certificates.append({"operation": operation, "transaction": receipt["hash"],
                                 "request_id": request_id, "status": certificate["lifecycle_status"],
                                 "certified_subset": certificate["certified_subset"],
                                 "certified_origin_count": certificate["certified_origin_count"],
                                 "threshold_met": certificate["threshold_met"],
                                 "certificate_digest": certificate["certificate_digest"]})
        elif intent["method"] == "apply_action":
            action = json.loads(readable)
            assert action["subject_id"] == intent["args"][0] and action["operation_id"] == intent["args"][1], operation
            consumer_name = "event_resolver" if action["action"] == "RESOLVED" else "insurance_gate"
            assert action["action"] in ("RESOLVED", "UNDERWRITING_ENABLED"), operation
            allowed_consumers = {deployment["contracts"][consumer_name]["address"]}
            recovery_deploy = "deploy-recovery-resolver" if consumer_name == "event_resolver" else "deploy-recovery-insurance"
            if recovery_deploy in receipts:
                allowed_consumers.add(receipts[recovery_deploy]["to_address"])
            assert intent["address"] in allowed_consumers, operation
            assert intent["sender"] == deployment["contracts"][consumer_name]["deployer"], operation
            actions.append({"transaction": receipt["hash"], "consumer": consumer_name, **action})
    verified_payouts = []
    payout_operations = {"treasury-owner-payout", "treasury-payout-identical-replay", "deploy-fee-recipient"}
    if not partial or payout_operations <= set(receipts):
        assert payout_operations <= set(receipts), "treasury payment evidence missing"
        payout = receipts["treasury-owner-payout"]
        replay = receipts["treasury-payout-identical-replay"]
        receiver = receipts["deploy-fee-recipient"]
        assert successful(payout) and successful(replay) and successful(receiver)
        assert len(validator_addresses(receiver)) >= 2, "payment receiver deployment validators missing"
        treasury = deployment["contracts"]["assessment_treasury"]
        intent = intents["treasury-owner-payout"]
        assert intent["address"] == treasury["address"] and intent["sender"] == treasury["deployer"], "payout owner binding differs"
        record = json.loads(leader(payout)["result"]["payload"]["readable"])
        assert intent["args"] == [record["operation_id"], receiver["to_address"], record["amount_atto"]]
        assert record["recipient"] == receiver["to_address"] and record["status"] == "EMITTED_ON_FINALIZED"
        assert json.loads(leader(replay)["result"]["payload"]["readable"]) == record and replay.get("triggered_transactions", []) == [], "payout replay emitted or changed record"
        children = payout["triggered_transactions"]
        assert len(children) == 1, "exactly one payment child required"
        child_hash = children[0] if isinstance(children[0], str) else children[0].get("hash", children[0].get("tx_id"))
        child = by_hash[child_hash]
        assert successful(child) and child["to_address"] == record["recipient"] and int(child["value"]) == record["amount_atto"]
        child_data = rlp.decode(bytes.fromhex(child["tx_data"].removeprefix("0x")))
        assert calldata.decode(child_data[0]) == {"method": "accept_fee"}, "payment receiver method differs"
        verified_payouts.append({"transaction": payout["hash"], "payment_child": child_hash,
                                "replay_transaction": replay["hash"], **record})
    reservations = [payload for operation, payload in intents.items()
                    if payload["method"] == "reserve_pair" and operation in receipts and successful(receipts[operation])]
    recoveries = []
    if not partial:
        refund_source = receipts["deploy-refund-rhizome"]["to_address"]
        refund_treasury = receipts["deploy-rejecting-treasury"]["to_address"]
        assert intents["deploy-refund-rhizome"]["code_sha256"] == deployment["contracts"]["rhizome"]["code_sha256"], "refund probe must execute exact production source"
        assert intents["deploy-refund-rhizome"]["args"] == [refund_treasury, 1]
        assert intents["deploy-rejecting-treasury"]["code_sha256"] == hashlib.sha256((ROOT / "tests/contracts/rejecting_treasury.py").read_bytes()).hexdigest()
        for operation, parent in (("refund-fee-failure", "refund-reservation"),
                                  ("refund-retry-fee-failure", "refund-retry-refused")):
            failure = receipts[operation]
            assert not successful(failure) and failure["triggered_by"] == receipts[parent]["hash"]
            assert failure["from_address"] == refund_source and failure["to_address"] == refund_treasury and int(failure["value"]) == 1
        recovered = receipts["refund-retry-success"]
        replay = receipts["refund-retry-replay"]
        record = json.loads(leader(recovered)["result"]["payload"]["readable"])
        assert successful(recovered) and successful(replay) and record["treasury"] == refund_treasury
        assert record["amount_atto"] == 1 and record["status"] == "EMITTED_ON_FINALIZED"
        assert json.loads(leader(replay)["result"]["payload"]["readable"]) == record and replay.get("triggered_transactions", []) == []
        assert len(recovered["triggered_transactions"]) == 1
        child_hash = recovered["triggered_transactions"][0]
        child_hash = child_hash if isinstance(child_hash, str) else child_hash.get("hash", child_hash.get("tx_id"))
        child = by_hash[child_hash]
        assert successful(child) and child["from_address"] == refund_source and child["to_address"] == refund_treasury and int(child["value"]) == 1
        recoveries.append({"kind": "failed_fee_refund_and_retry", "source": refund_source, "treasury": refund_treasury,
                           "failure": receipts["refund-fee-failure"]["hash"], "retry_failure": receipts["refund-retry-fee-failure"]["hash"],
                           "recovery": recovered["hash"], "payment_child": child_hash, "replay": replay["hash"]})
        probe_source = receipts["deploy-restriction-source"]["to_address"]
        assert intents["deploy-restriction-source"]["code_sha256"] == hashlib.sha256((VERIFICATION / "recovery-probe-source.py").read_bytes()).hexdigest()
        for role, contract_name in (("resolver", "event_resolver"), ("insurance", "insurance_gate")):
            deploy = "deploy-recovery-" + role
            assert intents[deploy]["code_sha256"] == deployment["contracts"][contract_name]["code_sha256"]
            assert intents[deploy]["args"] == [probe_source]
            restricted = receipts["recovery-restrict-" + role]
            assert restricted["to_address"] == probe_source and len(restricted["triggered_transactions"]) == 2
            children = [receipts["recovery-restrict-" + role + "-child-" + str(n)] for n in range(2)]
            values = [json.loads(leader(receipt)["result"]["payload"]["readable"]) for receipt in children]
            deferred = next(value for value in values if "outcome" in value)
            refresh = next(value for value in values if "status" in value)
            assert deferred["outcome"] == "DEFERRED" and refresh["status"] == "CERTIFIED" and refresh["permitted"] is False
            assert all(receipt["triggered_on"] == "accepted" and receipt["triggered_by"] == restricted["hash"] for receipt in children)
            assert all(receipt["to_address"] == receipts[deploy]["to_address"] for receipt in children)
            assert successful(receipts["recovery-restore-" + role])
            published = receipts["publish-recovery-deferred-" + role]
            delivered = receipts["publish-recovery-deferred-" + role + "-child-0"]
            assert successful(published) and json.loads(leader(delivered)["result"]["payload"]["readable"])["outcome"] == "APPLIED"
            assert successful(receipts["recovery-action-" + role])
            recoveries.append({"kind": "controlled_tentative_restriction_restoration", "consumer": role,
                               "restriction": restricted["hash"], "accepted_children": [receipt["hash"] for receipt in children],
                               "restore": receipts["recovery-restore-" + role]["hash"], "retry": published["hash"],
                               "action": receipts["recovery-action-" + role]["hash"], "production_appeal_proof": False})
    catalog_path = VERIFICATION / "public-evidence.json"
    catalog = json.loads(catalog_path.read_text())["catalog"] if catalog_path.exists() else {}
    tree = ast.parse((ROOT / "contracts" / "rhizome.py").read_text())
    evaluate = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "evaluate_pair")
    instructions = next(ast.literal_eval(node.value) for node in evaluate.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "instructions" for target in node.targets))
    budgets = []
    for item in assessments + protocol_refusals:
        payload = intents[item["operation"]]
        request_id, left_id, right_id = payload["args"]
        request = json.loads((VERIFICATION / "requests" / (request_id + ".json")).read_text())
        policy_id = request["envelope"]["policy_id"]
        policy_payload = intents["policy-" + policy_id]
        policy = {"policy_id": policy_id, "revision": 1, "owner": policy_payload["sender"],
                  "independence_definition": json.loads(policy_payload["args"][1]), "required_count": policy_payload["args"][2]}
        if left_id not in catalog or right_id not in catalog:
            continue  # The changing-byte task has no semantic model prompt.
        left, right = catalog[left_id]["source"], catalog[right_id]["source"]
        records = {record["record_id"]: record for record in [left, right, catalog[left_id]["authority"]["control_record"], catalog[right_id]["authority"]["control_record"]]}
        packet = []
        for record in sorted(records.values(), key=lambda value: value["record_id"]):
            assert record["url"].startswith("https://httpbingo.org/base64/"), "unrecognized fixture byte source"
            raw = base64.b64decode(record["url"].split("/base64/", 1)[1], validate=True)
            assert len(raw) == record["size_bytes"] and hashlib.sha256(raw).hexdigest() == record["sha256"]
            packet.append({"record_id": record["record_id"], "sha256": record["sha256"], "text": raw.decode("utf-8")})
        prompt = instructions + "\nPOLICY=" + canonical(policy) + "\nLEFT=" + canonical(left) + "\nRIGHT=" + canonical(right) + "\nRECORDS=" + canonical(packet)
        if item.get("decision", {}).get("available"):
            expected_witnesses = [{"record_id": record["record_id"], "span_id": "all", "raw_sha256": record["sha256"], "start": 0, "end": record["size_bytes"]}
                                  for record in sorted(records.values(), key=lambda value: value["record_id"])]
            assert item["decision"]["witnesses"] == expected_witnesses, item["operation"] + ": committed complete-record witnesses differ"
            for field, source in (("left_origin_ids", left), ("right_origin_ids", right)):
                assert set(item["decision"][field]) <= set(source["candidate_origin_ids"]), item["operation"] + ": unsupported origin ID"
        budgets.append({"operation": item["operation"], "records": len(records),
                        "raw_packet_bytes": sum(value["size_bytes"] for value in records.values()),
                        "application_prompt_utf8_bytes": len(prompt.encode("utf-8")),
                        "canonical_decision_utf8_bytes": len(canonical(item["decision"]).encode("utf-8")) if item.get("decision") else None})
    summary = {"complete": complete, "network": deployment["network"], "chain_id": deployment["chain_id"],
               "runner": deployment["runner"], "source_commit": deployment["source_commit"],
               "hosted_tests_passed": sum(value["outcome"] == "passed" for value in outcomes.get("tests", {}).values()),
               "expected_hosted_tests": len(outcomes.get("expected_tests", [])), "finalized_receipt_files": len(receipts),
               "distinct_finalized_transactions": len({value["hash"] for value in receipts.values()}),
               "semantic_assessments": len(assessments), "independent_semantic_validator_addresses": sorted(all_addresses),
               "finalized_protocol_refusals": protocol_refusals,
               "paid_assessment_reservations": len(reservations), "native_assessment_charges_atto": sum(value["value"] for value in reservations),
               "verified_treasury_payouts": verified_payouts,
               "verified_hosted_recoveries": recoveries,
               "model_assessments_with_available_evidence": sum(item["decision"]["available"] for item in assessments),
               "retrieval_only_assessments": sum(not item["decision"]["available"] for item in assessments),
               "verified_certificates": certificates, "verified_consumer_actions": actions,
               "participant_processing_time_ms": timing_summary(participant_times),
               "reported_provider_input_tokens": timing_summary([value["input"] for value in token_observations if isinstance(value.get("input"), int)]),
               "reported_provider_output_tokens": timing_summary([value["output"] for value in token_observations if isinstance(value.get("output"), int)]),
               "token_usage_observations": token_observations,
               "fixture_packet_bytes": timing_summary([value["raw_packet_bytes"] for value in budgets]),
               "fixture_application_prompt_bytes": timing_summary([value["application_prompt_utf8_bytes"] for value in budgets]),
               "bounds_measurements": budgets, "semantic_receipts": assessments, "refused_execution_receipts": expected_failures,
               "measurement_limits": "Fixture prompt bytes are reconstructed exactly from the pinned source and committed inputs. Processing times include distinct serialized execution observations from round history and current roles, including leader self-validation, dissent and errors; identical carried-over snapshots are counted once and retain their round references. These are recorded observations, not unique provider request IDs or model-only latency. The application bounds one model evaluation per VM attempt, while host/protocol retries may repeat attempts. Provider token telemetry may include reasoning or repeated instrumentation and does not establish distinct billable calls or total spending. Missing telemetry is not counted as zero. Whole-process memory is not exposed. Small fixture measurements do not qualify maximum-sized packet throughput."}
    write_json(VERIFICATION / "verification-summary.json", summary)
    return {key: value for key, value in summary.items() if key not in ("bounds_measurements", "semantic_receipts", "refused_execution_receipts", "token_usage_observations", "verified_certificates", "verified_consumer_actions")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--partial", action="store_true")
    print(json.dumps(report(parser.parse_args().partial), indent=2))

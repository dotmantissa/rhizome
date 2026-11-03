"""Real hosted refund and nonfinal/final storage recovery qualification.

The restriction fixture extends the complete production Rhizome source with an
owner-controlled reversible restriction and accepted probes. All evidence,
semantic evaluation, consumer bytes and storage snapshots execute on Studio.
This controlled restoration is not a claim of a successful production appeal.
"""
import base64
import hashlib
import json
from pathlib import Path

import pytest
from scripts.studio import VERIFICATION, agreeing_validators, finalized_result, write_json
from tests.evidence import DEFINITION, canonical, digest
from tests.integration.test_studio import live, open_request, assess_pairs, configure_and_bind, deliver

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


def deploy_probe(studio, label, code, args=(), role="deployer"):
    receipt = studio.submit(label, code=code, args=list(args), role=role)
    assert len(agreeing_validators(receipt)) >= 2
    address = receipt["to_address"]
    actual = studio.client().provider.make_request("gen_getContractCode", [address])["result"]
    assert base64.b64decode(actual, validate=True) == code
    return address


def provision(studio, source, catalog, policy, count):
    label = "policy-" + policy
    pending = [(label, studio.submit(label, source, "register_policy", [policy, canonical(DEFINITION), count], wait_for_finality=False))]
    for name in ("delta", "epsilon", "zeta"):
        authority = catalog[name]["authority"]
        label = policy + "-authority-" + name
        tx = studio.submit(label, source, "register_authority",
                           [authority["authority_id"], authority["principal"], authority["channel"],
                            authority["url_prefix"], canonical(authority["control_record"])], wait_for_finality=False)
        pending.append((label, tx))
    for label, tx in pending:
        studio.drain(studio.wait(tx, label), label)
    pending = []
    for name in ("delta", "epsilon", "zeta"):
        label = policy + "-attest-" + name
        tx = studio.submit(label, source, "attest_source", [canonical(catalog[name]["source"])],
                           role=catalog[name]["role"], wait_for_finality=False)
        pending.append((label, tx))
    for label, tx in pending:
        studio.drain(studio.wait(tx, label), label)


def one_child(studio, receipt, label, expected_error=False):
    assert len(receipt["triggered_transactions"]) == 1
    child = receipt["triggered_transactions"][0]
    tx = child if isinstance(child, str) else child.get("hash", child.get("tx_id"))
    return studio.wait(tx, label, expected_error=expected_error)


def test_12_failed_fee_refunds_forward_once_to_fixed_treasury(live):
    studio, _, _, insurance, catalog = live
    treasury = deploy_probe(studio, "deploy-assisted-refund-treasury", (ROOT / "tests/contracts/refunding_treasury.py").read_bytes())
    source = deploy_probe(studio, "deploy-assisted-refund-rhizome", (ROOT / "contracts/rhizome.py").read_bytes(), [treasury, 1])
    provision(studio, source, catalog, "refund-assisted-independence", 2)
    probe = studio, source, None, insurance, catalog
    request = "refund-assisted-recovery"
    open_request(probe, request, ["delta", "epsilon"], "refund-assisted-independence", insurance)
    reserved = studio.submit("refund-assisted-reservation", source, "reserve_pair",
                             [request, "delta", "epsilon", "assisted-refund-hold"], value=1)
    failed = one_child(studio, reserved, "refund-assisted-fee-failure", expected_error=True)
    studio.drain(failed, "refund-assisted-fee-failure")
    # Studio credits failed receivers but does not schedule the SDK refund.
    # The controlled receiver explicitly returns the actual failed fee value.
    returned = studio.submit("refund-assisted-return-initial", treasury, "return_failed_fee", ["initial-fee-return", source])
    studio.drain(returned, "refund-assisted-return-initial")
    before = refund_checkpoint(studio, "initial-return", source)
    assert before["retained_fee_balance_atto"] == before["charged_atto"] == 1
    retry = studio.submit("refund-assisted-retry-refused", source, "retry_treasury_transfer", ["refused-retry", 1])
    retry_failed = one_child(studio, retry, "refund-assisted-retry-fee-failure", expected_error=True)
    studio.drain(retry_failed, "refund-assisted-retry-fee-failure")
    returned_retry = studio.submit("refund-assisted-return-retry", treasury, "return_failed_fee", ["retry-fee-return", source])
    studio.drain(returned_retry, "refund-assisted-return-retry")
    assert refund_checkpoint(studio, "retry-return", source)["retained_fee_balance_atto"] == 1
    studio.submit("refund-assisted-enable-treasury", treasury, "enable")
    recovered = studio.submit("refund-assisted-retry-success", source, "retry_treasury_transfer", ["successful-retry", 1])
    studio.drain(recovered, "refund-assisted-retry-success")
    replay = studio.submit("refund-assisted-retry-replay", source, "retry_treasury_transfer", ["successful-retry", 1])
    assert replay.get("triggered_transactions", []) == []
    assert studio.read(treasury, "get_totals") == {"received_atto": 1, "balance_atto": 1}
    assert studio.read(source, "get_limits")["retained_fee_balance_atto"] == 0
    assert studio.read(source, "get_pair", [request, "delta", "epsilon"])["attempts"] == 1
    write_json(VERIFICATION / "refund-recovery.json", {
        "classification": "REAL HOSTED FAILED TRANSFERS AND RECEIVER-ASSISTED RETURNS THROUGH SDK HANDLER; NOT AUTOMATIC PROTOCOL REFUNDS",
        "source": source, "production_source_sha256": hashlib.sha256((ROOT / "contracts/rhizome.py").read_bytes()).hexdigest(),
        "treasury": treasury, "initial_failure": failed["hash"], "retry_failure": retry_failed["hash"],
        "receiver_assisted_returns": [returned["hash"], returned_retry["hash"]],
        "recovery": recovered["hash"], "replay": replay["hash"], "retained_balance_atto": 0,
    })


def refund_checkpoint(studio, phase, source):
    """Preserve original live intermediate balances across an interrupted replay."""
    path = VERIFICATION / ("refund-assisted-checkpoint-" + phase + ".json")
    if path.exists():
        saved = json.loads(path.read_text())
        assert saved["source"] == source and saved["phase"] == phase
        return saved["original_live_limits"]
    result = studio.read(source, "get_limits")
    write_json(path, {"classification": "ORIGINAL LIVE INTERMEDIATE BALANCE; HISTORICAL CHECKPOINT ON RESUME",
                      "source": source, "phase": phase, "original_live_limits": result})
    return result


def restriction_probe_code():
    source = (ROOT / "contracts/rhizome.py").read_text()
    assert source.count("    treasury_retries: TreeMap[str, str]") == 1
    source = source.replace("    treasury_retries: TreeMap[str, str]", "    treasury_retries: TreeMap[str, str]\n    recovery_probe_restricted: bool\n    recovery_probe_finalized_restricted: bool")
    target = '        return {"current": not reason, "reason": reason, "generation": envelope["generation"], "superseded_by": batch["superseded_by"], "batch_digest": batch["batch_digest"]}'
    assert source.count(target) == 1
    source = source.replace(target, '        if self.recovery_probe_restricted:\n            reason = "CONTROLLED_RECOVERY_PROBE"\n' + target)
    final_return = '        return {"current": not reason and not pending, "reason": reason or ("FINALITY_PENDING" if pending else ""), "generation": envelope["generation"],'
    assert source.count(final_return) == 1
    source = source.replace(final_return, '        if self.recovery_probe_finalized_restricted:\n            reason = "CONTROLLED_RECOVERY_PROBE"\n' + final_return)
    return (source + '''

    @gl.public.write
    def restore_recovery_probe(self) -> None:
        self._no_value()
        require(gl.message.sender_address == self.owner, "probe owner only")
        self.recovery_probe_restricted = False
        gl.get_contract_at(gl.message.contract_address).emit(on="finalized").confirm_recovery_probe(False)

    @gl.public.write
    def confirm_recovery_probe(self, restricted: bool) -> None:
        self._no_value()
        require(gl.message.sender_address == gl.message.contract_address, "probe self confirmation required")
        require(type(restricted) is bool and self.recovery_probe_restricted == restricted, "probe confirmation mismatch")
        self.recovery_probe_finalized_restricted = restricted

    @gl.public.write
    def restrict_and_probe(self, request_id: str, consumer: str, operation_id: str) -> None:
        self._no_value()
        require(gl.message.sender_address == self.owner, "probe owner only")
        identifier(operation_id)
        consumer = str(Address(consumer))
        # Preserve exactly the payload which ordinary finalized publication
        # will produce after restoration. The accepted callback reads genuinely
        # different latest and finalized snapshots of this deployed source.
        payload = {"certificate": self.get_certificate(request_id),
                   "delivery_binding": self._load(self.delivery_approvals, request_id + ":" + consumer),
                   "operation_id": operation_id}
        payload["delivery_digest"] = digest(payload)
        self.deliveries[consumer + ":" + operation_id] = canonical(payload)
        self.recovery_probe_restricted = True
        gl.get_contract_at(gl.message.contract_address).emit(on="finalized").confirm_recovery_probe(True)
        gl.get_contract_at(Address(consumer)).emit(on="accepted").receive_certificate(canonical(payload))
        gl.get_contract_at(Address(consumer)).emit(on="accepted").refresh_subject(payload["certificate"]["sealed_result"]["subject_id"])
''').encode()


@pytest.fixture(scope="session")
def recovery_live(live):
    studio, _, _, _, catalog = live
    deployment = json.loads((VERIFICATION / "deployment.json").read_text())
    code = restriction_probe_code()
    (VERIFICATION / "recovery-probe-source.py").write_bytes(code)
    source = deploy_probe(studio, "deploy-restriction-source", code,
                          [deployment["contracts"]["assessment_treasury"]["address"], 1])
    resolver = deploy_probe(studio, "deploy-recovery-resolver", (ROOT / "contracts/event_resolver.py").read_bytes(), [source], role="resolver")
    insurance = deploy_probe(studio, "deploy-recovery-insurance", (ROOT / "contracts/insurance_gate.py").read_bytes(), [source], role="insurance")
    provision(studio, source, catalog, "recovery-independence", 3)
    probe = studio, source, resolver, insurance, catalog
    batch = open_request(probe, "tentative-recovery", ["delta", "epsilon", "zeta"], "recovery-independence", resolver)
    for consumer, role, action in [(resolver, "resolver", "RESOLVED"), (insurance, "insurance", "UNDERWRITING_ENABLED")]:
        configure_and_bind(probe, batch, consumer, role, 3, action)
    for decision, _ in assess_pairs(probe, "tentative-recovery", [("delta", "epsilon"), ("delta", "zeta"), ("epsilon", "zeta")]):
        assert decision["relation"] == "INDEPENDENT"
    studio.submit("seal-tentative-recovery", source, "seal_batch", ["tentative-recovery"])
    for consumer, role in [(resolver, "resolver"), (insurance, "insurance")]:
        assert deliver(probe, "tentative-recovery", consumer, "recovery-initial-" + role)["outcome"] == "APPLIED"
    return probe


@pytest.mark.parametrize("role,action", [("resolver", "RESOLVED"), ("insurance", "UNDERWRITING_ENABLED")])
def test_13_tentative_restriction_preserves_permission_and_delivery_retries(recovery_live, role, action):
    studio, source, resolver, insurance, _ = recovery_live
    consumer = resolver if role == "resolver" else insurance
    operation = "recovery-deferred-" + role
    label = "recovery-restrict-" + role
    restricted = studio.submit(label, source, "restrict_and_probe", ["tentative-recovery", consumer, operation])
    studio.drain(restricted, label)
    children = [json.loads((VERIFICATION / "receipts" / (label + "-child-" + str(n) + ".json")).read_text()) for n in range(len(restricted["triggered_transactions"]))]
    children = [receipt for receipt in children if receipt["triggered_on"] == "accepted"]
    assert len(children) == 2
    results = [finalized_result(receipt) for receipt in children]
    deferred = next(result for result in results if "outcome" in result)
    refreshed = next(result for result in results if "status" in result)
    assert deferred["outcome"] == "DEFERRED"
    assert refreshed["status"] == "CERTIFIED" and not refreshed["permitted"]
    assert studio.read(source, "get_delivery", [consumer, operation])["acknowledgement"] is None
    restored = studio.submit("recovery-restore-" + role, source, "restore_recovery_probe")
    studio.drain(restored, "recovery-restore-" + role)
    assert studio.read(consumer, "get_subject", ["tentative-recovery"])["permitted"]
    assert deliver(recovery_live, "tentative-recovery", consumer, operation)["outcome"] == "APPLIED"
    result = studio.submit("recovery-action-" + role, consumer, "apply_action", ["tentative-recovery", "recovery-action-" + role], role=role)
    assert finalized_result(result)["action"] == action
    write_json(VERIFICATION / ("tentative-recovery-" + role + ".json"), {
        "classification": "REAL HOSTED SNAPSHOT DIVERGENCE AND CONTROLLED RESTORATION; NOT PRODUCTION APPEAL PROOF",
        "source": source, "consumer": consumer, "restriction": restricted["hash"],
        "accepted_probe_children": [receipt["hash"] for receipt in children], "deferred": deferred,
        "refresh": refreshed, "action": result["hash"],
    })

"""Explicit validator replay probes using labelled synthetic adversarial inputs."""
import copy
import json
import re
import pytest
from tests.evidence import canonical, material


def web_packet(vm, packets, change=None):
    vm.clear_mocks()
    for cr, cb, source, sb in packets:
        vm.mock_web(re.escape(cr["url"]), {"status": 200, "body": cb})
        vm.mock_web(re.escape(source["url"]), {"status": 200, "body": change if change is not None else sb})


def test_independent_validator_and_canonical_witnesses(rhizome, prepare, assess, direct_vm):
    prepare()
    result = assess(result=material())
    assert result["relation"] == "INDEPENDENT"
    assert len(result["witnesses"]) == 4
    assert all(w["span_id"] == "all" and w["start"] == 0 for w in result["witnesses"])
    assert direct_vm.run_validator()
    certificate = rhizome.seal_batch("batch-1")
    assert certificate["sealed_result"]["certified_subset"] == ["alpha", "beta"]
    assert rhizome.seal_batch("batch-1") == certificate


@pytest.mark.parametrize("mode,decision", [
    ("copy", material("SHARED_ORIGIN")),
    ("parent", material("SHARED_ORIGIN", rule="SHARED_CONTROL")),
    ("independent", material()),
    ("unknown", material("UNKNOWN")),
    ("injection", material("SHARED_ORIGIN")),
])
def test_specialized_evidence_vectors(rhizome, prepare, assess, direct_vm, mode, decision):
    prepare(modes=[mode, mode])
    result = assess(result=decision)
    assert direct_vm.run_validator()
    certificate = rhizome.seal_batch("batch-1")["sealed_result"]
    assert certificate["certified_origin_count"] == (2 if mode == "independent" else 0 if mode == "unknown" else 1)
    if mode == "unknown":
        assert certificate["unresolved"]


def test_valid_json_wrong_substantive_result_rejected(rhizome, prepare, assess, direct_vm):
    prepare(modes=["copy", "copy"])
    actual = assess(result=material("SHARED_ORIGIN"))
    inflated = {**actual, **material()}
    assert not direct_vm.run_validator(leader_result=inflated)


def test_omitted_parent_exception_rejected(rhizome, prepare, assess, direct_vm):
    prepare(modes=["parent", "parent"])
    actual = assess(result=material("SHARED_ORIGIN", rule="SHARED_CONTROL"))
    forged = {**actual, **material()}
    assert not direct_vm.run_validator(leader_result=forged)
    omitted_rule = {**actual, "rule_ids": ["COPY_OR_DERIVATION"]}
    assert not direct_vm.run_validator(leader_result=omitted_rule)


def test_forged_span_and_omitted_adverse_relation_rejected(rhizome, prepare, assess, direct_vm):
    prepare(modes=["copy", "copy"])
    actual = assess(result=material("SHARED_ORIGIN"))
    forged = copy.deepcopy(actual)
    forged["witnesses"][0]["start"] = 99
    assert not direct_vm.run_validator(leader_result=forged)
    missing = {**actual, "witnesses": actual["witnesses"][:-1]}
    assert not direct_vm.run_validator(leader_result=missing)


def test_changed_source_bytes_independently_retrieved(rhizome, prepare, assess, direct_vm):
    data = prepare()
    actual = assess(result=material())
    web_packet(direct_vm, data["packets"], b"changed bytes")
    direct_vm.mock_llm("You adjudicate", canonical(material()))
    assert not direct_vm.run_validator(leader_result=actual)


def test_instruction_injection_cannot_inflate_count(rhizome, prepare, assess, direct_vm):
    prepare(modes=["injection", "copy"])
    actual = assess(result=material("SHARED_ORIGIN"))
    assert direct_vm.run_validator()
    assert not direct_vm.run_validator(leader_result={**actual, **material()})


def test_hallucinated_origin_fails_validation(rhizome, prepare, assess, direct_vm):
    data = prepare()
    actual = assess(result=material())
    web_packet(direct_vm, data["packets"])
    hallucinated = {**material(), "left_origin_ids": ["not-committed"]}
    direct_vm.mock_llm("You adjudicate", canonical(hallucinated))
    assert not direct_vm.run_validator(leader_result=actual)


@pytest.mark.parametrize("mutation", [
    lambda v: v.update(relation="INDEPENDENT", control_verified=False),
    lambda v: v.update(scope_verified="true"),
    lambda v: v.update(left_origin_ids=["wire-origin"], right_origin_ids=["wire-origin"]),
    lambda v: v.update(extra="ignored"),
    lambda v: v.update(rule_ids=["invented-rule"]),
    lambda v: v.update(left_origin_ids="alpha-origin"),
])
def test_malformed_material_output_never_agrees(rhizome, prepare, assess, direct_vm, mutation):
    data = prepare()
    actual = assess(result=material())
    web_packet(direct_vm, data["packets"])
    bad = material()
    mutation(bad)
    direct_vm.mock_llm("You adjudicate", canonical(bad))
    assert not direct_vm.run_validator(leader_result=actual)


def test_unavailable_remains_unavailable(rhizome, prepare, assess, direct_vm):
    data = prepare()
    web_packet(direct_vm, data["packets"], b"wrong bytes")
    actual = assess()
    assert actual["unresolved_reason"] == "SOURCE_CHANGED"
    assert not actual["available"] and not actual["witnesses"]
    assert direct_vm.run_validator()
    forged = {**actual, **material(), "available": True, "unresolved_reason": ""}
    assert not direct_vm.run_validator(leader_result=forged)


def test_return_usererror_and_vmerror_are_explicit(rhizome, prepare, assess, direct_vm, module):
    prepare()
    actual = assess(result=material())
    from genlayer import gl
    assert not direct_vm.run_validator(leader_error=Exception("[LLM_ERROR] invalid material result"))
    assert not module.independent_validator(gl.vm.VMError("oom"), lambda: actual)
    assert not module.independent_validator(gl.vm.UserError("[EXPECTED] mismatch"), lambda: actual)
    def expected_failure():
        raise gl.vm.UserError("[EXPECTED] same")
    assert module.independent_validator(gl.vm.UserError("[EXPECTED] same"), expected_failure)
    assert not module.independent_validator(gl.vm.UserError("[EXPECTED] other"), expected_failure)


def test_complete_declared_packet_oversize_rejected_before_model(rhizome, prepare, assess, direct_vm):
    data = prepare()
    # Oversized declared records are still valid per-record, but cannot be truncated
    # into a partial assessment. Recommit the complete metadata in a successor.
    batch = rhizome.get_batch("batch-1")
    for source in batch["manifest"]["sources"]:
        source["size_bytes"] = 48000
    rhizome.batches["batch-1"] = canonical(batch)
    result = assess()
    assert result["unresolved_reason"] == "EVIDENCE_OVERSIZED"
    assert not direct_vm._captured_validators


def test_paid_reservation_survives_source_unavailability_and_exhausts(rhizome, prepare, direct_vm):
    prepare()
    for attempt in range(1, 4):
        direct_vm.value = 1
        rhizome.reserve_pair("batch-1", "alpha", "beta", "attempt-" + str(attempt))
        direct_vm.value = 0
        # Source unavailability cannot undo a separately committed reservation.
        direct_vm.clear_mocks()
        direct_vm.mock_web("httpbingo", {"status": 503, "body": b""})
        result = rhizome.assess_pair("batch-1", "alpha", "beta")
        assert result["relation"] == "UNKNOWN"
    direct_vm.value = 1
    with direct_vm.expect_revert("pair retry exhausted"):
        rhizome.reserve_pair("batch-1", "alpha", "beta", "attempt-4")
    direct_vm.value = 0
    result = rhizome.resolve_unavailable("batch-1")["sealed_result"]
    assert result["unresolved_reason"] == "RETRY_EXHAUSTED"
    assert result["certified_origin_count"] == 0


def test_malformed_model_keeps_paid_hold_and_requires_payer_release(rhizome, prepare, direct_vm):
    prepare()
    for attempt in range(1, 4):
        direct_vm.value = 1
        rhizome.reserve_pair("batch-1", "alpha", "beta", "malformed-" + str(attempt))
        direct_vm.value = 0
        direct_vm.mock_llm("You adjudicate", '{"relation":"INDEPENDENT"}')
        with direct_vm.expect_revert("LLM_ERROR"):
            rhizome.assess_pair("batch-1", "alpha", "beta")
        held = rhizome.get_pair("batch-1", "alpha", "beta")
        assert held["reservation"]["status"] == "PENDING" and held["attempts"] == attempt
        assert rhizome.get_limits()["charged_atto"] == attempt
        assert held["decision"] is None
        rhizome.release_pair("batch-1", "alpha", "beta")
    direct_vm.value = 1
    with direct_vm.expect_revert("pair retry exhausted"):
        rhizome.reserve_pair("batch-1", "alpha", "beta", "malformed-4")
    direct_vm.value = 0
    assert rhizome.resolve_unavailable("batch-1")["sealed_result"]["unresolved_reason"] == "RETRY_EXHAUSTED"


def test_reservation_authority_idempotence_and_conflicts(rhizome, prepare, direct_vm, direct_bob):
    prepare(names=("alpha", "beta", "gamma"))
    direct_vm.value = 1
    original = rhizome.reserve_pair("batch-1", "alpha", "beta", "op")
    direct_vm.value = 0
    assert rhizome.reserve_pair("batch-1", "alpha", "beta", "op") == original
    with direct_vm.expect_revert("conflicting reservation operation"):
        rhizome.reserve_pair("batch-1", "alpha", "gamma", "op")
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("reservation payer only"):
        rhizome.release_pair("batch-1", "alpha", "beta")
    with direct_vm.expect_revert("active payer reservation"):
        rhizome.assess_pair("batch-1", "alpha", "beta")
    direct_vm.sender = rhizome.owner
    rhizome.release_pair("batch-1", "alpha", "beta")
    assert rhizome.get_pair("batch-1", "alpha", "beta")["attempts"] == 1


@pytest.mark.parametrize("payment", [0, 2, 1 << 256])
def test_exact_charge_bounds(rhizome, prepare, direct_vm, payment):
    prepare()
    direct_vm.value = payment
    with direct_vm.expect_revert("exact assessment charge"):
        rhizome.reserve_pair("batch-1", "alpha", "beta", "op")

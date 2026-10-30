import copy
import json
import pytest
from tests.evidence import address, canonical, digest, DEFINITION, source_packet


def test_constructor_and_limits(rhizome):
    limits = rhizome.get_limits()
    assert limits["max_sources"] == 6
    assert limits["max_distinct_pairs"] == 15
    assert limits["max_records_per_assessment"] == 4
    assert limits["assessment_fee_atto"] == 1


def test_sdk_payment_dispatch_schema(module):
    # Direct calls bypass the runtime method resolver. Check the SDK schema
    # consumed by dispatch as well as the separate fee-accounting body tests.
    from genlayer.py.get_schema import get_schema
    schema = get_schema(module.Rhizome)
    payable = {name for name, method in schema["methods"].items() if method.get("payable")}
    assert payable == {"reserve_pair"}


@pytest.mark.parametrize("fee", [0, -1, 1 << 256, True])
def test_constructor_integer_bounds(direct_vm, direct_deploy, direct_owner, fee):
    with direct_vm.expect_revert("integer out of bounds"):
        direct_deploy("contracts/rhizome.py", address(direct_owner), fee, sdk_version="v0.2.16")


def test_policy_ownership_revision_and_identical_replay(rhizome, direct_vm, direct_bob):
    first = rhizome.register_policy("p", canonical(DEFINITION), 3)
    assert rhizome.register_policy("p", canonical(DEFINITION), 3) == first
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("policy owner only"):
        rhizome.register_policy("p", canonical(DEFINITION), 2)
    direct_vm.sender = rhizome.owner
    newer = rhizome.register_policy("p", canonical(DEFINITION), 4)
    assert newer["revision"] == 2 and rhizome.get_policy("p", 1) == first


@pytest.mark.parametrize("count", [0, 7, -1, True, 1 << 64])
def test_policy_bounds(rhizome, direct_vm, count):
    with direct_vm.expect_revert("integer out of bounds"):
        rhizome.register_policy("p", canonical(DEFINITION), count)


def test_authority_and_issuer_permissions(rhizome, direct_vm, direct_owner, direct_bob):
    cr, _, source, _ = source_packet("alpha", address(direct_bob))
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("registry owner only"):
        rhizome.register_authority("alpha-authority", address(direct_bob), source["channel"], "https://httpbingo.org/base64/", canonical(cr))
    direct_vm.sender = direct_owner
    rhizome.register_authority("alpha-authority", address(direct_bob), source["channel"], "https://httpbingo.org/base64/", canonical(cr))
    with direct_vm.expect_revert("authority principal only"):
        rhizome.attest_source(canonical(source))
    direct_vm.sender = direct_bob
    assert rhizome.attest_source(canonical(source)) == source
    assert rhizome.attest_source(canonical(source)) == source
    bad = {**source, "url": "https://attacker.invalid/changed"}
    with direct_vm.expect_revert("unapproved source channel"):
        rhizome.attest_source(canonical(bad))


def test_source_revisions_locked_and_conflicts(rhizome, prepare, direct_vm, direct_owner):
    state = prepare()
    source = copy.deepcopy(state["packets"][0][2])
    changed = {**source, "candidate_origin_ids": ["forged"]}
    with direct_vm.expect_revert("conflicting source revision"):
        rhizome.attest_source(canonical(changed))
    successor = source_packet("alpha", address(direct_owner), revision=2)[2]
    rhizome.attest_source(canonical(successor))
    assert rhizome.get_source("alpha", 1) == source
    assert not rhizome.is_current("batch-1")["current"]
    rhizome.attest_source(canonical(source))
    assert not rhizome.is_current("batch-1")["current"]
    assert rhizome.list_source_requests("alpha", 1, 0, 10)["items"] == ["batch-1"]


def test_request_uniqueness_and_manifest_commitment(rhizome, prepare, direct_vm):
    state = prepare()
    assert rhizome.open_batch("batch-1", "measurements", canonical(state["body"])) == state["batch"]
    changed = copy.deepcopy(state["body"])
    changed["envelope"]["subject_digest"] = digest("conflict")
    with direct_vm.expect_revert("conflicting request ID reuse"):
        rhizome.open_batch("batch-1", "measurements", canonical(changed))
    changed["envelope"]["request_id"] = "batch-2"
    changed["envelope"]["source_manifest_digest"] = "0" * 64
    with direct_vm.expect_revert("manifest digest mismatch"):
        rhizome.open_batch("batch-2", "measurements", canonical(changed))


def test_successor_generation_never_clears_newer(rhizome, prepare, direct_vm):
    state = prepare()
    body = copy.deepcopy(state["body"])
    body["envelope"].update({"request_id": "batch-2", "generation": 2})
    rhizome.open_batch("batch-2", "measurements", canonical(body))
    assert rhizome.get_batch("batch-1")["superseded_by"] == "batch-2"
    assert not rhizome.is_current("batch-1")["current"]
    assert rhizome.is_current("batch-2")["current"]
    rhizome.open_batch("batch-1", "measurements", canonical(state["body"]))
    assert rhizome.is_current("batch-2")["current"]


@pytest.mark.parametrize("mutation,error", [
    (lambda b: b["sources"].append(b["sources"][0]), "sorted unique"),
    (lambda b: b["sources"].reverse(), "sorted unique"),
    (lambda b: b["sources"].pop(), "two through six"),
    (lambda b: b["envelope"].update(generation=True), "integer out of bounds"),
    (lambda b: b["envelope"].update(deadline=1), "deadline"),
    (lambda b: b["envelope"].update(extra="ignored"), "unexpected schema"),
])
def test_request_bounds_and_schema(rhizome, prepare, direct_vm, mutation, error):
    state = prepare()
    body = copy.deepcopy(state["body"])
    body["envelope"]["request_id"] = "bad-request"
    mutation(body)
    with direct_vm.expect_revert(error):
        rhizome.open_batch("bad-request", "measurements", canonical(body))


def test_no_partial_seal_and_deadline_unresolved(rhizome, prepare, direct_vm):
    prepare()
    with direct_vm.expect_revert("complete pair matrix required"):
        rhizome.seal_batch("batch-1")
    direct_vm.warp("2026-11-10T10:00:00Z")
    certificate = rhizome.resolve_unavailable("batch-1")["sealed_result"]
    assert certificate["lifecycle_status"] == "UNRESOLVED"
    assert not certificate["coverage_complete"] and certificate["certified_origin_count"] == 0
    assert certificate["unresolved_reason"] == "DEADLINE_ELAPSED"


def test_quarantine_permissions_irreversible(rhizome, prepare, direct_vm, direct_bob):
    prepare()
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("quarantine authority"):
        rhizome.quarantine_record("source", "alpha", 1, digest("withdrawal"))
    direct_vm.sender = rhizome.owner
    rhizome.quarantine_record("source", "alpha", 1, digest("withdrawal"))
    assert not rhizome.is_current("batch-1")["current"]
    rhizome.quarantine_record("source", "alpha", 1, digest("withdrawal"))
    with direct_vm.expect_revert("quarantine immutable"):
        rhizome.quarantine_record("source", "alpha", 1, digest("clear"))
    assert rhizome.resolve_unavailable("batch-1")["sealed_result"]["unresolved"]


def test_pagination_bounds(rhizome, prepare, direct_vm):
    prepare()
    assert rhizome.list_history(0, 2)["next_offset"] == 2
    assert rhizome.list_history(10000, 2)["items"] == []
    for offset, limit in [(-1, 1), (0, 0), (0, 51), (1 << 64, 1)]:
        with direct_vm.expect_revert("integer out of bounds"):
            rhizome.list_history(offset, limit)

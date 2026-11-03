"""Synthetic direct probes of the explicitly controlled receiver, not Studio refunds."""
import pytest


@pytest.fixture
def receiver(direct_vm, direct_deploy, direct_owner):
    contract = direct_deploy("tests/contracts/refunding_treasury.py", sdk_version="v0.2.16")
    from genlayer import gl
    from genlayer.py import calldata
    messages = []
    source = "0x" + "12" * 20
    limits = {"treasury": str(gl.message.contract_address), "assessment_fee_atto": 1, "charged_atto": 1}
    def dispatch(vm, request):
        if "PostMessage" in request:
            messages.append(request["PostMessage"])
            return {"ok": None}
        if "CallContract" in request:
            return b"\x00" + calldata.encode(limits)
        return None
    direct_vm._gl_call_hook = dispatch
    direct_vm.deal(gl.message.contract_address, 1)
    return contract, source, limits, messages


def test_return_requires_owner_and_matching_source(receiver, direct_vm, direct_bob, direct_owner):
    contract, source, limits, messages = receiver
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("unpaid owner required"):
        contract.return_failed_fee("initial", source)
    direct_vm.sender = direct_owner
    limits["treasury"] = "0x" + "34" * 20
    with direct_vm.expect_revert("source does not use this fixed treasury"):
        contract.return_failed_fee("initial", source)
    assert messages == []


def test_return_uses_sdk_handler_once_and_rejects_conflict(receiver, direct_vm):
    contract, source, _, messages = receiver
    from genlayer import Address
    record = contract.return_failed_fee("initial", source)
    assert messages == [{"address": Address(source), "calldata": {"method": "__on_errored_message__"}, "value": 1, "on": "finalized"}]
    assert contract.return_failed_fee("initial", source) == record and len(messages) == 1
    with direct_vm.expect_revert("conflicting return operation"):
        contract.return_failed_fee("initial", "0x" + "56" * 20)


def test_return_cannot_emit_without_retained_value(receiver, direct_vm):
    contract, source, _, messages = receiver
    from genlayer import gl
    direct_vm.deal(gl.message.contract_address, 0)
    with direct_vm.expect_revert("no failed value to return"):
        contract.return_failed_fee("initial", source)
    assert messages == []

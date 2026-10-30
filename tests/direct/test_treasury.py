"""Fee receiver dispatch, accounting, payout authority and retry boundaries."""
import sys
import pytest
from tests.evidence import address


@pytest.fixture
def treasury(direct_deploy, direct_vm):
    contract = direct_deploy("contracts/assessment_treasury.py", sdk_version="v0.2.16")
    direct_vm.check_pickling = True
    return contract


def test_receive_dispatch_and_accounting(treasury, direct_vm):
    from genlayer.py.get_schema import get_schema
    schema = get_schema(sys.modules["_contract_assessment_treasury"].AssessmentTreasury)
    assert schema["methods"]["accept_fee"]["payable"]
    direct_vm.value = 3
    treasury.accept_fee()
    direct_vm.value = 2
    treasury.accept_fee()
    assert treasury.get_totals()["received_atto"] == 5


def test_payout_authority_idempotence_and_finalized_emission(treasury, direct_vm, direct_bob):
    from genlayer import gl
    owner = direct_vm.sender
    direct_vm.deal(gl.message.contract_address, 5)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("owner call"):
        treasury.payout("payout", address(direct_bob), 2)
    direct_vm.sender = owner
    messages = []
    def capture(vm, request):
        if "PostMessage" in request:
            messages.append(request["PostMessage"])
            return {"ok": None}
        return None
    direct_vm._gl_call_hook = capture
    result = treasury.payout("payout", address(direct_bob), 2)
    assert messages == [{"address": direct_bob, "calldata": {"method": "accept_fee"}, "value": 2, "on": "finalized"}]
    assert treasury.payout("payout", address(direct_bob), 2) == result
    assert len(messages) == 1
    assert treasury.get_payout("payout") == result
    assert treasury.get_payout("missing") is None
    with direct_vm.expect_revert("conflicting payout"):
        treasury.payout("payout", address(direct_bob), 3)
    with direct_vm.expect_revert("insufficient treasury balance"):
        treasury.payout("too-large", address(direct_bob), 6)


@pytest.mark.parametrize("amount", [0, -1, True, 1 << 256])
def test_payout_integer_bounds(treasury, direct_vm, direct_bob, amount):
    with direct_vm.expect_revert("invalid payout amount"):
        treasury.payout("bounded", address(direct_bob), amount)


def test_receive_and_payout_payment_bounds(treasury, direct_vm, direct_bob):
    with direct_vm.expect_revert("invalid received amount"):
        treasury.accept_fee()
    direct_vm.value = 1
    with direct_vm.expect_revert("unpaid owner call"):
        treasury.payout("bounded", address(direct_bob), 1)

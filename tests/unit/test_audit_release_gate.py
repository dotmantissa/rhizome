"""Old successful receipts must not qualify changed security-critical source."""
from pathlib import Path
import pytest
from scripts import verification_report


def test_historical_eleven_scenarios_do_not_qualify_corrected_release(monkeypatch):
    evidence = Path(__file__).resolve().parents[2] / 'verification' / 'treasury-v3'
    monkeypatch.setattr(verification_report, 'VERIFICATION', evidence)
    with pytest.raises(AssertionError, match='hosted suite is incomplete'):
        verification_report.report()


@pytest.fixture
def native_transfer():
    import rlp
    from genlayer_py.abi import calldata
    from genlayer_py.contracts.utils import make_calldata_object
    from scripts.studio import successful
    import json
    root = Path(__file__).resolve().parents[2]
    # Use a real finalized fee child for the execution envelope, then vary
    # material transfer fields to prove the offline gate binds them exactly.
    child = json.loads((root / "verification/reviewer-v5/receipts/refund-fee-failure.json").read_text())
    parent = json.loads((root / "verification/reviewer-v5/receipts/refund-reservation.json").read_text())
    assert successful(parent) and not successful(child)
    child["tx_data"] = "0x" + rlp.encode([calldata.encode(make_calldata_object(method="__on_errored_message__", args=[], kwargs=None)), b"\x00"]).hex()
    return parent, child


def test_native_child_binds_sdk_handler_without_claiming_automatic_return(native_transfer):
    parent, child = native_transfer
    verification_report.check_native_child(parent, child, child["to_address"], "__on_errored_message__", succeeds=False)
    with pytest.raises(AssertionError, match="execution differs"):
        verification_report.check_native_child(parent, child, child["to_address"], "__on_errored_message__")


@pytest.mark.parametrize("field,value", [
    ("value", 0), ("triggered_on", "accepted"), ("triggered_by", "0xwrong"),
    ("from_address", "0xwrong"), ("to_address", "0xwrong"), ("hash", "0xwrong"),
    ("status_name", "ACCEPTED"),
])
def test_native_child_refuses_changed_transfer_material(native_transfer, field, value):
    parent, child = native_transfer
    destination = child["to_address"]
    child[field] = value
    with pytest.raises(AssertionError):
        verification_report.check_native_child(parent, child, destination, "__on_errored_message__", succeeds=False)


def test_native_child_refuses_another_payable_method(native_transfer):
    parent, child = native_transfer
    with pytest.raises(AssertionError, match="method differs"):
        verification_report.check_native_child(parent, child, child["to_address"], "accept_fee", succeeds=False)

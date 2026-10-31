"""Synthetic receipt snapshots qualify observation accounting, not consensus."""
import copy
import json

import pytest
import rlp
from genlayer_py.abi import calldata

from scripts.verification_report import check_finality_confirmation, digest, execution_observations, finality_confirmation_args


def test_rotation_history_keeps_old_validator_and_deduplicates_carried_leader():
    leader = {"mode": "leader", "processing_time": 1000, "node_config": {"address": "synthetic-leader"}}
    old = {"mode": "validator", "vote": "disagree", "processing_time": 2000,
           "node_config": {"address": "synthetic-validator"}}
    new = {**old, "vote": "agree", "processing_time": 3000}
    receipt = {
        "consensus_history": {"consensus_results": [
            {"consensus_round": "0", "leader_result": [leader], "validator_results": [old]},
            {"consensus_round": "1", "leader_result": [leader], "validator_results": [new]},
        ]},
        "consensus_data": {"leader_receipt": [leader], "validators": [new]},
    }
    observations = execution_observations(receipt)
    assert len(observations) == 3
    carried = next(item for item in observations if item["receipt"]["mode"] == "leader")
    assert carried["rounds"] == ["0", "1", "current"]
    assert {item["receipt"].get("vote") for item in observations} == {None, "agree", "disagree"}


def confirmation_receipts():
    record = {"policy_id": "policy", "revision": 1, "required_count": 3}
    parent = {"hash": "parent", "to_address": "source", "status_name": "FINALIZED",
              "consensus_data": {"leader_receipt": [{"execution_result": "SUCCESS", "result": {
                  "payload": {"readable": json.dumps(record)}}}]}}
    args = ["policy", "policy", 1, digest(record)]
    child = {"hash": "child", "from_address": "source", "to_address": "source", "value": 0,
             "triggered_by": "parent", "triggered_on": "finalized", "status_name": "FINALIZED",
             "consensus_data": {"leader_receipt": [{"execution_result": "SUCCESS"}]},
             "tx_data": "0x" + rlp.encode([calldata.encode({"method": "confirm_finalized_record", "args": args}), b"\x00"]).hex()}
    return parent, child, args


def test_confirmation_is_bound_to_the_finalized_parent_record():
    parent, child, args = confirmation_receipts()
    assert finality_confirmation_args(parent, {"method": "register_policy"}) == args
    check_finality_confirmation(parent, child, args)


@pytest.mark.parametrize("field,value", [("triggered_on", "accepted"), ("triggered_by", "unrelated"),
                                        ("from_address", "outsider"), ("to_address", "other"),
                                        ("value", 1), ("status_name", "ACCEPTED")])
def test_confirmation_rejects_incorrect_parent_provenance(field, value):
    parent, child, args = confirmation_receipts()
    child[field] = value
    with pytest.raises(AssertionError):
        check_finality_confirmation(parent, child, args)


def test_confirmation_rejects_a_different_record_commitment():
    parent, child, args = confirmation_receipts()
    changed = copy.copy(args)
    changed[3] = "0" * 64
    with pytest.raises(AssertionError, match="record commitment differs"):
        check_finality_confirmation(parent, child, changed)

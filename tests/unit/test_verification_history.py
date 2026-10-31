"""Synthetic receipt snapshots qualify observation accounting, not consensus."""
from scripts.verification_report import execution_observations


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

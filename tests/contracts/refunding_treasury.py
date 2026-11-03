# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Controlled hosted receiver: explicitly return failed value through the SDK handler.

Studio retains value at a receiver whose method rolls back. These owner-assisted
returns are real native transfers, not evidence of automatic protocol refunds.
"""
from genlayer import *
import json
import re


class RefundingTreasury(gl.Contract):
    owner: Address
    enabled: bool
    received_atto: u256
    refunds: TreeMap[str, str]

    def __init__(self):
        self.owner = gl.message.sender_address

    @gl.public.write
    def enable(self) -> None:
        if gl.message.sender_address != self.owner or gl.message.value != 0:
            raise gl.vm.UserError("[EXPECTED] unpaid owner required")
        self.enabled = True

    @gl.public.write.payable
    def accept_fee(self) -> None:
        if not self.enabled:
            raise gl.vm.UserError("[EXPECTED] deliberate hosted fee refusal")
        self.received_atto = u256(int(self.received_atto) + int(gl.message.value))

    @gl.public.write
    def return_failed_fee(self, operation_id: str, source_address: str) -> dict:
        if gl.message.sender_address != self.owner or gl.message.value != 0:
            raise gl.vm.UserError("[EXPECTED] unpaid owner required")
        if not isinstance(operation_id, str) or re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", operation_id) is None:
            raise gl.vm.UserError("[EXPECTED] invalid return operation")
        source = Address(source_address)
        record = {"operation_id": operation_id, "source": str(source), "amount_atto": 1,
                  "status": "EMITTED_ON_FINALIZED", "kind": "CONTROLLED_RECEIVER_RETURN"}
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        previous = self.refunds.get(operation_id)
        if previous is not None:
            if previous != encoded:
                raise gl.vm.UserError("[EXPECTED] conflicting return operation")
            return record
        limits = gl.get_contract_at(source).view().get_limits()
        if limits["treasury"] != str(gl.message.contract_address) or limits["assessment_fee_atto"] != 1 or limits["charged_atto"] < 1:
            raise gl.vm.UserError("[EXPECTED] source does not use this fixed treasury")
        if self.balance < 1:
            raise gl.vm.UserError("[EXPECTED] no failed value to return")
        self.refunds[operation_id] = encoded
        gl.get_contract_at(source).emit(value=u256(1), on="finalized").__on_errored_message__()
        return record

    @gl.public.view
    def get_totals(self) -> dict:
        return {"received_atto": int(self.received_atto), "balance_atto": int(self.balance)}

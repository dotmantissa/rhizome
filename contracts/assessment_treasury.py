# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Native assessment-fee receiver with an explicit payable contract interface.

Payout records describe finalized emissions, not recipient execution. Verify the
child receipt before accounting a payout as completed. Failed transfers return
value through the SDK refund handler and can be retried under a new operation.
"""
from genlayer import *
import json
import re


class AssessmentTreasury(gl.Contract):
    owner: Address
    received_atto: u256
    payouts: TreeMap[str, str]

    def __init__(self):
        self.owner = gl.message.sender_address

    @gl.public.write.payable
    def accept_fee(self) -> None:
        if gl.message.value <= 0 or int(self.received_atto) + int(gl.message.value) >= (1 << 256):
            raise gl.vm.UserError("[EXPECTED] invalid received amount")
        self.received_atto = u256(int(self.received_atto) + int(gl.message.value))

    @gl.public.write
    def payout(self, operation_id: str, recipient_address: str, amount_atto: int) -> dict:
        if gl.message.sender_address != self.owner or gl.message.value != 0:
            raise gl.vm.UserError("[EXPECTED] unpaid owner call required")
        if not isinstance(operation_id, str) or re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", operation_id) is None:
            raise gl.vm.UserError("[EXPECTED] invalid operation ID")
        recipient = Address(recipient_address)
        if recipient in (Address("0x" + "0" * 40), gl.message.contract_address):
            raise gl.vm.UserError("[EXPECTED] invalid recipient")
        if type(amount_atto) is not int or not 1 <= amount_atto < (1 << 256):
            raise gl.vm.UserError("[EXPECTED] invalid payout amount")
        result = {"operation_id": operation_id, "recipient": str(recipient),
                  "amount_atto": amount_atto, "status": "EMITTED_ON_FINALIZED"}
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        previous = self.payouts.get(operation_id)
        if previous is not None:
            if previous != encoded:
                raise gl.vm.UserError("[EXPECTED] conflicting payout operation")
            return result
        if self.balance < amount_atto:
            raise gl.vm.UserError("[EXPECTED] insufficient treasury balance")
        self.payouts[operation_id] = encoded
        gl.get_contract_at(recipient).emit(value=u256(amount_atto), on="finalized").accept_fee()
        return result

    @gl.public.view
    def get_totals(self) -> dict:
        return {"owner": str(self.owner), "received_atto": int(self.received_atto),
                "balance_atto": int(self.balance)}

    @gl.public.view
    def get_payout(self, operation_id: str) -> dict | None:
        saved = self.payouts.get(operation_id)
        return json.loads(saved) if saved is not None else None

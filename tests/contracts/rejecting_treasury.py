# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Hosted failure fixture: owner enables fees after genuine failed transfers."""
from genlayer import *


class RejectingTreasury(gl.Contract):
    owner: Address
    enabled: bool
    received_atto: u256

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

    @gl.public.view
    def get_totals(self) -> dict:
        return {"received_atto": int(self.received_atto), "balance_atto": int(self.balance)}

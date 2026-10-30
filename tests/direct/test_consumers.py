"""Deterministic callback tests running the actual three contracts.

The direct harness models finalized message dispatch only. Actual network
finality and validator consensus are verified separately in Studio integration.
"""
import copy
import json
from contextlib import contextmanager
import pytest
from tests.evidence import address, canonical, digest, material


class MessageHarness:
    def __init__(self, vm):
        self.vm = vm
        self.contracts = {}
        self.messages = []
        self.vm._gl_call_hook = self.hook

    def attach(self, contract, contract_address, storage):
        self.contracts[address(contract_address)] = (contract, storage)

    @contextmanager
    def context(self, contract_address, sender, value=0):
        from genlayer import gl, Address
        from genlayer.py.types import u256
        old_message, old_raw = gl.message, dict(gl.message_raw)
        old_storage, old_sender, old_address, old_value = self.vm._storage, self.vm.sender, self.vm._contract_address, self.vm.value
        contract_address, sender = Address(address(contract_address)), Address(address(sender))
        self.vm._storage = self.contracts[address(contract_address)][1]
        self.vm._contract_address = contract_address
        self.vm.sender = sender
        self.vm.value = value
        gl.message = gl.MessageType(contract_address, sender, old_message.origin_address, u256(value), old_message.chain_id)
        gl.message_raw.update(contract_address=contract_address, sender_address=sender, value=value)
        try:
            yield
        finally:
            self.vm._storage, self.vm._contract_address = old_storage, old_address
            self.vm.sender, self.vm.value = old_sender, old_value
            gl.message = old_message
            gl.message_raw.clear()
            gl.message_raw.update(old_raw)

    def call(self, contract_address, sender, method, *args, value=0):
        with self.context(contract_address, sender, value):
            return getattr(self.contracts[address(contract_address)][0], method)(*args)

    def hook(self, vm, request):
        from genlayer import gl
        from genlayer.py import calldata
        if "PostMessage" in request:
            msg = request["PostMessage"]
            self.messages.append({**msg, "sender": str(gl.message.contract_address)})
            return {"ok": None}
        if "CallContract" in request:
            call = request["CallContract"]
            cd = call["calldata"]
            result = self.call(call["address"], gl.message.contract_address, cd["method"], *cd.get("args", []))
            return b"\x00" + calldata.encode(result)
        return None

    def drain(self):
        while self.messages:
            msg = self.messages.pop(0)
            assert msg["on"] == "finalized"
            cd = msg["calldata"]
            if "method" in cd:
                self.call(msg["address"], msg["sender"], cd["method"], *cd.get("args", []), value=int(msg["value"]))


@pytest.fixture
def consumers(rhizome, direct_vm, direct_deploy, direct_owner, direct_bob, direct_charlie):
    from gltest.direct.vm import InmemManager
    from genlayer import gl
    source_address = str(gl.message.contract_address)
    source_storage = direct_vm._storage
    harness = MessageHarness(direct_vm)
    harness.attach(rhizome, source_address, source_storage)
    items = []
    for path, owner in [("contracts/event_resolver.py", direct_bob), ("contracts/insurance_gate.py", direct_charlie)]:
        direct_vm._storage = InmemManager()
        import genlayer.gl.genvm_contracts as gc
        gc.__known_contract__ = None
        direct_vm.sender = owner
        contract = direct_deploy(path, source_address, sdk_version="v0.2.16")
        addr = address(direct_vm._contract_address)
        harness.attach(contract, addr, direct_vm._storage)
        items.append((contract, addr, address(owner)))
    direct_vm._storage = source_storage
    direct_vm.sender = direct_owner
    from genlayer import Address
    gl.message = gl.MessageType(Address(source_address), Address(address(direct_owner)), Address(address(direct_owner)), gl.message.value, gl.message.chain_id)
    gl.message_raw["contract_address"] = Address(source_address)
    direct_vm._contract_address = Address(source_address)
    return harness, source_address, items


def lock(harness, consumer, owner, batch, minimum, action, policy="measurements"):
    harness.call(consumer, owner, "configure_policy", policy, 1, minimum)
    harness.drain()
    consequence = {"subject_id": batch["envelope"]["subject_id"], "action": action, "value": "eligible"}
    expected = {**batch["envelope"], "batch_digest": batch["batch_digest"]}
    harness.call(consumer, owner, "bind_request", canonical(expected), canonical(consequence))
    harness.drain()
    return consequence


def seal_three(rhizome, prepare, assess, direct_vm, consumer):
    data = prepare(names=("alpha", "beta", "gamma"), count=3, consumer=consumer)
    for a, b in [("alpha", "beta"), ("alpha", "gamma"), ("beta", "gamma")]:
        direct_vm.clear_mocks()
        for cr, cb, source, sb in data["packets"]:
            import re
            direct_vm.mock_web(re.escape(cr["url"]), {"status": 200, "body": cb})
            direct_vm.mock_web(re.escape(source["url"]), {"status": 200, "body": sb})
        assess(left=a, right=b, result=material(left=a, right=b), operation=a + "-" + b)
        assert direct_vm.run_validator()
    rhizome.seal_batch("batch-1")
    return data


def test_both_independent_keys_apply_same_certificate_separate_consequences(rhizome, prepare, assess, direct_vm, direct_owner, consumers):
    harness, source_address, items = consumers
    assert items[0][2] != items[1][2]
    data = seal_three(rhizome, prepare, assess, direct_vm, items[0][1])
    harness.drain()
    for index, (_, addr, owner) in enumerate(items):
        action = "RESOLVED" if index == 0 else "UNDERWRITING_ENABLED"
        lock(harness, addr, owner, data["batch"], 3, action)
        harness.call(source_address, direct_owner, "publish_to", "batch-1", addr, "delivery-" + str(index))
        # Publication journals the delivery. No consumer effect before dispatch.
        assert not harness.call(addr, owner, "get_subject", "event-1")["permitted"]
        harness.drain()
        assert harness.call(addr, owner, "get_subject", "event-1")["permitted"]
        result = harness.call(addr, owner, "apply_action", "event-1", "action-" + str(index))
        assert result["action"] == action
        assert harness.call(addr, owner, "apply_action", "event-1", "action-" + str(index)) == result
        with direct_vm.expect_revert("generation action already applied"):
            harness.call(addr, owner, "apply_action", "event-1", "different-action")
        ack = rhizome.get_delivery(addr, "delivery-" + str(index))["acknowledgement"]
        assert ack["outcome"] == "APPLIED"


@pytest.mark.parametrize("index,policy,count,consequence", [(0, "event-policy", 3, "RESOLVED"), (1, "insurance-policy", 2, "UNDERWRITING_ENABLED")])
def test_two_policies_refuse_unresolved_and_unknown_control(rhizome, prepare, assess, direct_vm, direct_owner, consumers, index, policy, count, consequence):
    harness, source_address, items = consumers
    _, addr, owner = items[index]
    data = prepare(modes=["unknown", "unknown"], consumer=addr, count=count, policy_id=policy)
    assess(result=material("UNKNOWN"))
    assert direct_vm.run_validator()
    rhizome.seal_batch("batch-1")
    harness.drain()
    lock(harness, addr, owner, data["batch"], count, consequence, policy)
    harness.call(source_address, direct_owner, "publish_to", "batch-1", addr, "unresolved-delivery")
    harness.drain()
    state = harness.call(addr, owner, "get_subject", "event-1")
    assert not state["permitted"] and state["unresolved"]
    with direct_vm.expect_revert("action refused"):
        harness.call(addr, owner, "apply_action", "event-1", "forbidden")
    assert rhizome.get_delivery(addr, "unresolved-delivery")["acknowledgement"]["outcome"] == "REFUSED"


def test_authenticated_sender_and_binding_forgery(rhizome, prepare, assess, direct_vm, direct_owner, direct_bob, consumers):
    harness, source_address, items = consumers
    _, addr, owner = items[0]
    data = seal_three(rhizome, prepare, assess, direct_vm, addr)
    harness.drain()
    lock(harness, addr, owner, data["batch"], 3, "RESOLVED")
    harness.call(source_address, direct_owner, "publish_to", "batch-1", addr, "delivery")
    payload = json.loads(harness.messages[-1]["calldata"]["args"][0])
    with direct_vm.expect_revert("authenticated Rhizome"):
        harness.call(addr, direct_bob, "receive_certificate", canonical(payload))
    forged = copy.deepcopy(payload)
    forged["delivery_binding"]["consequence_digest"] = "0" * 64
    forged["delivery_digest"] = digest({k: v for k, v in forged.items() if k != "delivery_digest"})
    with direct_vm.expect_revert("consequence binding mismatch"):
        harness.call(addr, source_address, "receive_certificate", canonical(forged))
    harness.drain()


def test_duplicate_delivery_ack_and_conflicting_operation(rhizome, prepare, assess, direct_vm, direct_owner, consumers):
    harness, source_address, items = consumers
    _, addr, owner = items[0]
    data = seal_three(rhizome, prepare, assess, direct_vm, addr)
    harness.drain()
    lock(harness, addr, owner, data["batch"], 3, "RESOLVED")
    harness.call(source_address, direct_owner, "publish_to", "batch-1", addr, "delivery")
    harness.drain()
    first = harness.call(addr, owner, "get_acknowledgement", "delivery")
    harness.call(source_address, direct_owner, "publish_to", "batch-1", addr, "delivery")
    harness.drain()
    assert harness.call(addr, owner, "get_acknowledgement", "delivery") == first
    assert rhizome.get_limits()["delivery_count"] == 1
    forged = copy.deepcopy(rhizome.get_delivery(addr, "delivery")["delivery"])
    forged["delivery_binding"]["consequence_digest"] = "1" * 64
    forged["delivery_digest"] = digest({k: v for k, v in forged.items() if k != "delivery_digest"})
    with direct_vm.expect_revert("conflicting operation reuse"):
        harness.call(addr, source_address, "receive_certificate", canonical(forged))


def test_quarantine_between_finalized_message_and_action(rhizome, prepare, assess, direct_vm, direct_owner, consumers):
    harness, source_address, items = consumers
    _, addr, owner = items[0]
    data = seal_three(rhizome, prepare, assess, direct_vm, addr)
    harness.drain()
    lock(harness, addr, owner, data["batch"], 3, "RESOLVED")
    harness.call(source_address, direct_owner, "publish_to", "batch-1", addr, "delivery")
    harness.drain()
    rhizome.quarantine_record("source", "alpha", 1, digest("adverse-disclosure"))
    with direct_vm.expect_revert("stale or quarantined evidence at action time"):
        harness.call(addr, owner, "apply_action", "event-1", "action")
    state = harness.call(addr, owner, "refresh_subject", "event-1")
    assert not state["permitted"] and state["status"] == "QUARANTINED"


def test_reordered_old_callback_cannot_clear_pending_successor(rhizome, prepare, assess, direct_vm, direct_owner, consumers):
    harness, source_address, items = consumers
    _, addr, owner = items[0]
    data = seal_three(rhizome, prepare, assess, direct_vm, addr)
    harness.drain()
    lock(harness, addr, owner, data["batch"], 3, "RESOLVED")
    harness.call(source_address, direct_owner, "publish_to", "batch-1", addr, "old-delivery")
    old_message = harness.messages.pop()
    successor_body = copy.deepcopy(data["body"])
    successor_body["envelope"].update(request_id="batch-2", generation=2)
    successor = rhizome.open_batch("batch-2", "measurements", canonical(successor_body))
    lock(harness, addr, owner, successor, 3, "RESOLVED")
    harness.messages.append(old_message)
    harness.drain()
    state = harness.call(addr, owner, "get_subject", "event-1")
    assert state["generation"] == 2 and not state["permitted"] and state["status"] == "PENDING"
    assert harness.call(addr, owner, "get_acknowledgement", "old-delivery")["outcome"] == "STALE"

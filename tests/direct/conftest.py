"""Direct tests use synthetic transport/model fault injection, not network consensus."""
import sys
import json
import pytest
from tests.evidence import address, canonical, digest, source_packet, DEFINITION


@pytest.fixture
def rhizome(direct_vm, direct_deploy, direct_owner):
    direct_vm.warp("2026-10-30T10:00:00Z")
    contract = direct_deploy("contracts/rhizome.py", address(direct_owner), 1, sdk_version="v0.2.16")
    direct_vm.check_pickling = True
    return contract


@pytest.fixture
def module(rhizome):
    return sys.modules["_contract_rhizome"]


@pytest.fixture
def prepare(rhizome, direct_vm, direct_owner):
    def build(names=("alpha", "beta"), modes=None, request_id="batch-1", policy_id="measurements", count=2, generation=1, subject="event-1", consumer=None):
        modes = modes or ["independent"] * len(names)
        rhizome.register_policy(policy_id, canonical(DEFINITION), count)
        packets = []
        authorities = []
        for name, mode in zip(names, modes):
            packet = source_packet(name, address(direct_owner), mode)
            cr, cb, source, sb = packet
            authority = rhizome.register_authority(source["authority_id"], address(direct_owner), source["channel"], "https://httpbingo.org/base64/", canonical(cr))
            rhizome.attest_source(canonical(source))
            packets.append(packet)
            authorities.append(authority)
            direct_vm.mock_web(__import__("re").escape(cr["url"]), {"status": 200, "body": cb})
            direct_vm.mock_web(__import__("re").escape(source["url"]), {"status": 200, "body": sb})
        sources = [p[2] for p in packets]
        manifest = {"sources": sources, "authorities": sorted(authorities, key=lambda a: a["authority_id"])}
        envelope = {"request_id": request_id, "owner": address(direct_owner), "parties": [], "policy_id": policy_id, "policy_revision": 1,
                    "subject_id": subject, "subject_digest": digest([subject]), "source_manifest_digest": digest(manifest),
                    "consumer_address": address(consumer or direct_owner), "consequence_digest": digest(["resolve", subject]),
                    "generation": generation, "deadline": 1793440800}
        body = {"envelope": envelope, "sources": [{"source_id": s["source_id"], "revision": s["revision"]} for s in sources]}
        batch = rhizome.open_batch(request_id, policy_id, canonical(body))
        return {"batch": batch, "packets": packets, "body": body, "manifest": manifest}
    return build


@pytest.fixture
def assess(rhizome, direct_vm):
    def run(request_id="batch-1", left="alpha", right="beta", result=None, operation="pair-op"):
        direct_vm.value = 1
        rhizome.reserve_pair(request_id, left, right, operation)
        direct_vm.value = 0
        if result is not None:
            direct_vm.mock_llm(r"You adjudicate", canonical(result))
        decision = rhizome.assess_pair(request_id, left, right)
        return {k: v for k, v in decision.items() if k != "pair_ids"}
    return run


@pytest.fixture(autouse=True)
def sdk_datetime_compatibility(direct_vm, monkeypatch):
    # gltest 0.29.2 warp refreshes sender/value, but omits message_raw datetime.
    # Keep its published time-travel cheatcode consistent with the pinned SDK.
    original = direct_vm.warp
    def warp(timestamp):
        original(timestamp)
        if "genlayer.gl" in sys.modules:
            sys.modules["genlayer.gl"].message_raw["datetime"] = timestamp
    monkeypatch.setattr(direct_vm, "warp", warp)

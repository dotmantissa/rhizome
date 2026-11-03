"""Synthetic transport faults only; these tests do not claim hosted consensus."""
from types import SimpleNamespace

import pytest
import requests

from scripts import studio as module


def test_credentials_are_redacted_in_nested_named_fields():
    value = {"accounts": {"deployer_private_key": "synthetic-key", "github_token": "synthetic-token"},
             "public": "address", "rows": [{"api_key": "synthetic-api", "service_password": "synthetic-password"}]}
    assert module.sanitize(value) == {"accounts": {"deployer_private_key": "REDACTED", "github_token": "REDACTED"},
                                       "public": "address", "rows": [{"api_key": "REDACTED", "service_password": "REDACTED"}]}


@pytest.fixture
def transport(monkeypatch, tmp_path):
    sleeps, calls = [], []
    provider = SimpleNamespace(url="https://rpc.invalid")

    def raise_on_error(result, method):
        if result.get("error"):
            raise RuntimeError("RPC error")

    provider._raise_on_error = raise_on_error
    monkeypatch.setattr(module, "GenLayerClient", lambda **kwargs: SimpleNamespace(
        provider=provider, initialize_consensus_smart_contract=lambda: None))
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    instance = module.Studio.__new__(module.Studio)
    instance.accounts = {"deployer": object()}
    instance.clients = {}
    instance.records = []
    instance.journal = tmp_path / "journal.jsonl"
    instance.last_rpc = 0
    instance.current_operation = "synthetic-write"
    instance.min_rpc_interval = 0

    def run(responses, method="eth_sendRawTransaction"):
        responses = iter(responses)

        def post(url, **kwargs):
            assert kwargs["timeout"] == (10, 45)
            calls.append(kwargs["json"])
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(module.requests, "post", post)
        return instance.client().provider.make_request(method, ["0x010203"])

    return instance, run, calls, sleeps


def response(status=200, result=None):
    value = requests.Response()
    value.status_code = status
    value.url = "https://rpc.invalid"
    value.json = lambda: result or {"result": "synthetic-transaction-hash"}
    return value


@pytest.mark.parametrize("refusal", [response(429), response(result={"error": {"code": -32429}})])
def test_explicit_rate_refusal_retries_identical_signed_request(transport, refusal):
    instance, run, calls, sleeps = transport
    assert run([refusal, response()])["result"] == "synthetic-transaction-hash"
    assert len(calls) == 2 and calls[0] == calls[1]
    assert sleeps == [60]
    assert [row["event"] for row in instance.records] == [
        "SEND_ATTEMPT", "RATE_LIMITED", "SEND_ATTEMPT", "BROADCAST"]


def test_ambiguous_write_timeout_never_rebroadcasts(transport):
    instance, run, calls, _ = transport
    with pytest.raises(requests.Timeout):
        run([requests.Timeout("synthetic timeout"), response()])
    assert len(calls) == 1
    assert instance.records == [{"event": "SEND_ATTEMPT", "operation": "synthetic-write",
                                 "ethereum_hash": "0x" + module.keccak(hexstr="0x010203").hex(),
                                 "recorded_at": instance.records[0]["recorded_at"]}]


def dns_failure():
    import socket
    from urllib3.connection import HTTPSConnection
    error = module.NameResolutionError("rpc.invalid", HTTPSConnection("rpc.invalid"),
                                       socket.gaierror(-3, "synthetic DNS failure"))
    return requests.ConnectionError(module.MaxRetryError(None, "/", error))


def test_dns_failure_retries_the_identical_signed_request(transport):
    instance, run, calls, sleeps = transport
    assert run([dns_failure(), response()])["result"] == "synthetic-transaction-hash"
    assert calls[0] == calls[1] and sleeps == [5]
    assert [row["event"] for row in instance.records] == [
        "SEND_ATTEMPT", "SEND_NOT_TRANSMITTED", "SEND_ATTEMPT", "BROADCAST"]
    assert instance.records[0]["ethereum_hash"] == instance.records[1]["ethereum_hash"]
    assert "0x010203" not in instance.journal.read_text()


def test_dns_retry_followed_by_an_ambiguous_failure_keeps_exact_hash_recovery(transport):
    instance, run, calls, _ = transport
    with pytest.raises(requests.Timeout):
        run([dns_failure(), requests.Timeout("response lost after transmission")])
    assert len(calls) == 2 and calls[0] == calls[1]
    assert [row["event"] for row in instance.records] == [
        "SEND_ATTEMPT", "SEND_NOT_TRANSMITTED", "SEND_ATTEMPT"]


@pytest.mark.parametrize("error", [requests.ConnectionError("connection reset after transmission"),
                                   requests.ConnectionError("NameResolutionError text alone is not proof")])
def test_ambiguous_connection_failure_never_retries_a_write(transport, error):
    instance, run, calls, _ = transport
    with pytest.raises(requests.ConnectionError):
        run([error, response()])
    assert len(calls) == 1
    assert [row["event"] for row in instance.records] == ["SEND_ATTEMPT"]


def test_exhausted_dns_retries_allow_recovery_only_with_the_saved_nonce(transport):
    instance, run, calls, sleeps = transport
    with pytest.raises(requests.ConnectionError):
        run([dns_failure() for _ in range(4)])
    assert len(calls) == 4 and sleeps == [5, 5, 5]
    assert instance.records[-1]["event"] == "SEND_NOT_TRANSMITTED"
    instance.accounts["deployer"] = SimpleNamespace(address="synthetic-sender")
    payload = {"address": "synthetic-contract", "method": "reserve_pair", "args": ["request"],
               "sender": "synthetic-sender", "value": 1, "code_sha256": None}
    instance.records.insert(0, {"event": "INTENT", "operation": "synthetic-write",
                                "payload_digest": module.digest(payload), "nonce": 7})
    writes = []
    instance.client = lambda role="deployer": SimpleNamespace(
        get_current_nonce=lambda **kwargs: 9, write_contract=lambda **kwargs: writes.append(kwargs) or "tx")
    with pytest.raises(AssertionError, match="unreconciled nonce"):
        instance.submit("synthetic-write", "synthetic-contract", "reserve_pair", ["request"], value=1)
    assert not writes
    instance.client = lambda role="deployer": SimpleNamespace(
        get_current_nonce=lambda **kwargs: 7, write_contract=lambda **kwargs: writes.append(kwargs) or "tx")
    assert instance.submit("synthetic-write", "synthetic-contract", "reserve_pair", ["request"],
                           value=1, wait_for_finality=False) == "tx"
    assert len(writes) == 1


def test_read_timeout_can_retry(transport):
    _, run, calls, sleeps = transport
    assert run([requests.Timeout("synthetic timeout"), response()], "gen_getTransaction")["result"]
    assert len(calls) == 2 and sleeps == [5]


def test_consensus_initialization_uses_bounded_read_transport(transport, monkeypatch):
    instance, run, calls, sleeps = transport
    client_factory = module.GenLayerClient

    def initialize_client(**kwargs):
        client = client_factory(**kwargs)
        client.initialize_consensus_smart_contract = lambda: client.provider.make_request(
            "sim_getConsensusContract", ["ConsensusMain"])
        return client

    monkeypatch.setattr(module, "GenLayerClient", initialize_client)
    run([requests.Timeout("synthetic initialization timeout"), response(), response()])
    assert [call["method"] for call in calls] == [
        "sim_getConsensusContract", "sim_getConsensusContract", "eth_sendRawTransaction"]
    assert sleeps == [5]


def test_ambiguous_write_502_preserves_hash_without_retry(transport):
    instance, run, calls, _ = transport
    with pytest.raises(requests.HTTPError):
        run([response(502), response()])
    assert len(calls) == 1
    assert [row["event"] for row in instance.records] == ["SEND_ATTEMPT"]
    assert instance.records[0]["ethereum_hash"] == "0x" + module.keccak(hexstr="0x010203").hex()
    assert "0x010203" not in instance.journal.read_text()


@pytest.mark.parametrize("receipt_available", [True, False])
def test_signed_attempt_recovers_original_receipt_or_stops_without_replacement(transport, receipt_available):
    instance, _, _, _ = transport
    instance.accounts["deployer"] = SimpleNamespace(address="synthetic-sender")
    payload = {"address": "synthetic-contract", "method": "reserve_pair", "args": ["request"],
               "sender": "synthetic-sender", "value": 1, "code_sha256": None}
    instance.records.extend([
        {"event": "INTENT", "operation": "recover", "payload_digest": module.digest(payload), "nonce": 7},
        {"event": "SEND_ATTEMPT", "operation": "recover", "ethereum_hash": "synthetic-eth-hash"},
    ])
    lookups = []

    def get_receipt(tx):
        lookups.append(tx)
        if not receipt_available:
            from web3.exceptions import TransactionNotFound
            raise TransactionNotFound("still unknown")
        return {"status": 1}

    event = SimpleNamespace(process_receipt=lambda receipt, discard: [{"args": {"txId": "original-consensus-id"}}])
    eth = SimpleNamespace(get_transaction_receipt=get_receipt,
                          contract=lambda **kwargs: SimpleNamespace(get_event_by_name=lambda name: event))
    client = SimpleNamespace(w3=SimpleNamespace(eth=eth, to_hex=lambda value: value),
                             chain=SimpleNamespace(consensus_main_contract={"abi": []}))
    instance.client = lambda role="deployer": client
    if receipt_available:
        assert instance.submit("recover", "synthetic-contract", "reserve_pair", ["request"],
                               value=1, wait_for_finality=False) == "original-consensus-id"
        assert instance.records[-1]["event"] == "SUBMITTED" and instance.records[-1]["recovered"]
    else:
        from web3.exceptions import TransactionNotFound
        with pytest.raises(TransactionNotFound):
            instance.submit("recover", "synthetic-contract", "reserve_pair", ["request"], value=1)
        assert instance.records[-1]["event"] == "SEND_ATTEMPT"
    assert lookups == ["synthetic-eth-hash"]


@pytest.mark.parametrize("reconciled", [True, False])
def test_nonce_drift_requires_an_identical_reconciled_intent(transport, reconciled):
    instance, _, _, _ = transport
    instance.accounts["deployer"] = SimpleNamespace(address="synthetic-sender")
    payload = {"address": "synthetic-contract", "method": "reserve_pair", "args": ["request"],
               "sender": "synthetic-sender", "value": 1, "code_sha256": None}
    original = {"event": "INTENT", "operation": "recover", "payload_digest": module.digest(payload), "nonce": 7}
    instance.records.append(original)
    if reconciled:
        instance.records.append({**original, "nonce": 9, "reconciles_nonce": 7})
    writes = []

    def write(**kwargs):
        writes.append(kwargs)
        return "reconciled-tx"

    instance.client = lambda role="deployer": SimpleNamespace(
        get_current_nonce=lambda **kwargs: 9, write_contract=write)
    if reconciled:
        assert instance.submit("recover", "synthetic-contract", "reserve_pair", ["request"],
                               value=1, wait_for_finality=False) == "reconciled-tx"
        assert len(writes) == 1
        assert instance.records[0] == original
    else:
        with pytest.raises(AssertionError, match="unreconciled nonce"):
            instance.submit("recover", "synthetic-contract", "reserve_pair", ["request"], value=1)
        assert writes == []


def test_rate_limit_retries_are_bounded(transport):
    instance, run, calls, sleeps = transport
    with pytest.raises(requests.HTTPError):
        run([response(429) for _ in range(4)])
    assert len(calls) == 4 and sleeps == [60, 60, 60]
    assert [row["event"] for row in instance.records] == ["SEND_ATTEMPT", "RATE_LIMITED"] * 3 + ["SEND_ATTEMPT"]


def test_finalized_receipt_recovery_needs_no_rpc_and_checks_execution(transport, monkeypatch, tmp_path):
    instance, _, _, _ = transport
    monkeypatch.setattr(module, "ROOT", tmp_path)
    receipt = {"hash": "synthetic-tx", "status_name": "FINALIZED", "consensus_data": {
        "leader_receipt": [{"mode": "leader", "execution_result": "SUCCESS"}]}}
    module.write_json(tmp_path / "receipt.json", receipt)
    instance.records.append({"event": "FINALIZED", "operation": "synthetic-finalized",
                             "tx": "synthetic-tx", "receipt": "receipt.json"})
    instance.client = lambda: pytest.fail("finalized recovery must not request RPC")
    assert instance.wait("synthetic-tx", "synthetic-finalized") == receipt
    with pytest.raises(AssertionError, match="execution outcome"):
        instance.wait("synthetic-tx", "synthetic-finalized", expected_error=True)


@pytest.mark.parametrize("status,execution,valid", [("FINALIZED", "SUCCESS", True),
                                                   ("ACCEPTED", "SUCCESS", False),
                                                   ("FINALIZED", "ERROR", False)])
def test_return_value_requires_successful_finality(status, execution, valid):
    receipt = {"status_name": status, "consensus_data": {"leader_receipt": [{
        "mode": "leader", "execution_result": execution,
        "result": {"status": "return" if execution == "SUCCESS" else "error",
                   "payload": {"readable": '{"synthetic_value":3}'}}}]}}
    if valid:
        assert module.finalized_result(receipt) == {"synthetic_value": 3}
    else:
        with pytest.raises(AssertionError, match="successful finality"):
            module.finalized_result(receipt)


def test_server_reset_delay_is_respected_for_identical_write(transport):
    instance, run, calls, sleeps = transport
    refused = response(429)
    refused.headers["Retry-After"] = "4"
    run([refused, response()])
    assert calls[0] == calls[1] and sleeps == [5]
    assert instance.records[1]["retry_delay_seconds"] == 5


def test_retry_after_date_and_malformed_header(monkeypatch):
    monkeypatch.setattr(module.time, "time", lambda: 1000)
    refused = response(429)
    refused.headers["Retry-After"] = "Thu, 01 Jan 1970 00:16:44 GMT"
    assert module.retry_delay(refused) == 5
    refused.headers["Retry-After"] = "synthetic invalid header"
    assert module.retry_delay(refused) == 60


def test_undetermined_observation_can_finalize_without_a_new_write(transport, monkeypatch, tmp_path):
    instance, _, _, sleeps = transport
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "VERIFICATION", tmp_path)
    (tmp_path / "receipts").mkdir()
    undecided = {"hash": "synthetic-tx", "status_name": "UNDETERMINED"}
    finalized = {"hash": "synthetic-tx", "status_name": "FINALIZED", "consensus_data": {
        "leader_receipt": [{"mode": "leader", "execution_result": "SUCCESS"}]}}
    responses = iter([undecided, undecided, finalized])
    polled = []

    def get_transaction(tx):
        polled.append(tx)
        return next(responses)

    instance.client = lambda: SimpleNamespace(get_transaction=get_transaction)
    assert instance.wait("synthetic-tx", "synthetic-recovery") == finalized
    assert polled == ["synthetic-tx"] * 3 and sleeps == [3, 3]
    assert [row["event"] for row in instance.records] == ["UNDECIDED", "FINALIZED"]
    import json
    assert json.loads((tmp_path / "protocol-observations" / "synthetic-recovery-undetermined.json").read_text()) == undecided


@pytest.mark.parametrize("result_name", ["MAJORITY_DISAGREE", "NO_MAJORITY"])
def test_finalized_leader_success_does_not_override_consensus_refusal(result_name):
    receipt = {"hash": "synthetic-tx", "status_name": "FINALIZED", "result_name": result_name,
               "consensus_data": {"leader_receipt": [{"mode": "leader", "execution_result": "SUCCESS"}]}}
    assert not module.successful(receipt)
    with pytest.raises(module.ProtocolFailure) as refusal:
        module.check_outcome(receipt, "synthetic-refused", expected_error=True)
    assert refusal.value.receipt is receipt
    with pytest.raises(AssertionError, match="successful finality"):
        module.finalized_result(receipt)

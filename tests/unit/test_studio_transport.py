"""Synthetic transport faults only; these tests do not claim hosted consensus."""
from types import SimpleNamespace

import pytest
import requests

from scripts import studio as module


@pytest.fixture
def transport(monkeypatch, tmp_path):
    sleeps, calls = [], []
    provider = SimpleNamespace(url="https://rpc.invalid")

    def raise_on_error(result, method):
        if result.get("error"):
            raise RuntimeError("RPC error")

    provider._raise_on_error = raise_on_error
    monkeypatch.setattr(module, "create_client", lambda **kwargs: SimpleNamespace(provider=provider))
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
            calls.append(kwargs["json"])
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        monkeypatch.setattr(module.requests, "post", post)
        return instance.client().provider.make_request(method, ["synthetic-signed-bytes"])

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
    assert [row["event"] for row in instance.records] == ["RATE_LIMITED", "BROADCAST"]


def test_ambiguous_write_timeout_never_rebroadcasts(transport):
    instance, run, calls, _ = transport
    with pytest.raises(requests.Timeout):
        run([requests.Timeout("synthetic timeout"), response()])
    assert len(calls) == 1 and instance.records == []


def test_read_timeout_can_retry(transport):
    _, run, calls, sleeps = transport
    assert run([requests.Timeout("synthetic timeout"), response()], "gen_getTransaction")["result"]
    assert len(calls) == 2 and sleeps == [5]


def test_rate_limit_retries_are_bounded(transport):
    instance, run, calls, sleeps = transport
    with pytest.raises(requests.HTTPError):
        run([response(429) for _ in range(4)])
    assert len(calls) == 4 and sleeps == [60, 60, 60]
    assert all(row["event"] == "RATE_LIMITED" for row in instance.records)


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

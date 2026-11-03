"""Actual Studio deployment client with paced RPC and crash recovery journal.

Usage: RHIZOME_CREDENTIALS_FILE=/secure/keys.json python -m scripts.studio deploy
The key file contains deployer_private_key, resolver_private_key and
insurance_private_key. It must stay outside the repository.
"""
import argparse
import base64
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import requests
from eth_account import Account
from eth_utils import keccak
from urllib3.exceptions import MaxRetryError, NameResolutionError
from genlayer_py.client import GenLayerClient
from genlayer_py.chains import studionet

ROOT = Path(__file__).resolve().parents[1]
RUN = os.environ.get("RHIZOME_RUN", "")
assert not RUN or (len(RUN) <= 64 and all(ch.isalnum() or ch in "-_" for ch in RUN)), "invalid verification run name"
VERIFICATION = ROOT / "verification" / RUN


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def successful(receipt):
    if receipt.get("result_name") not in (None, "MAJORITY_AGREE"):
        return False
    leaders = receipt.get("consensus_data", {}).get("leader_receipt", []) or []
    return any(l.get("execution_result") == "SUCCESS" or l.get("result", {}).get("status") == "return" for l in leaders if l.get("mode", "leader") == "leader")


class ProtocolFailure(RuntimeError):
    """Finalized consensus refusal; the leader's state changes were not applied."""
    def __init__(self, label, receipt):
        self.receipt = receipt
        super().__init__(label + ": finalized protocol refusal " + str(receipt.get("result_name")))


def check_outcome(receipt, label, expected_error=False):
    if receipt.get("result_name") not in (None, "MAJORITY_AGREE"):
        raise ProtocolFailure(label, receipt)
    assert successful(receipt) != expected_error, label + ": execution outcome differs from expected outcome"


def agreeing_validators(receipt):
    return [v for v in receipt.get("consensus_data", {}).get("validators", [])
            if v.get("mode") == "validator" and v.get("vote") == "agree" and v.get("execution_result") == "SUCCESS"]


def finalized_result(receipt):
    """Decode a successful finalized GenVM return without a second RPC read."""
    assert receipt.get("status_name") == "FINALIZED" and successful(receipt), "successful finality required"
    leader = next(item for item in receipt["consensus_data"]["leader_receipt"] if item.get("mode", "leader") == "leader")
    return json.loads(leader["result"]["payload"]["readable"])


def retry_delay(response):
    """Respect the server's rate window, adding a one-second reset buffer."""
    header = response.headers.get("Retry-After")
    if not header:
        return 60
    try:
        seconds = int(header)
    except ValueError:
        try:
            seconds = parsedate_to_datetime(header).timestamp() - time.time()
        except (ValueError, TypeError, OverflowError):
            return 60
    return max(1, seconds) + 1


def dns_failed_before_transmission(error):
    """Recognize the transport's typed DNS failure before a connection exists."""
    return (isinstance(error, requests.ConnectionError) and len(error.args) == 1
            and isinstance(error.args[0], MaxRetryError)
            and isinstance(error.args[0].reason, NameResolutionError))


def sanitize(value):
    if isinstance(value, dict):
        return {k: "REDACTED" if k.lower() in ("private_key", "api_key", "token", "secret", "password")
                or k.lower().endswith(("_private_key", "_api_key", "_token", "_secret", "_password")) else sanitize(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return value


def write_json(path, value):
    """Durably replace an artifact before journaling its completion."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w") as stream:
        stream.write(json.dumps(sanitize(value), default=str, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class Studio:
    def __init__(self, credentials_file=None):
        filename = credentials_file or os.environ["RHIZOME_CREDENTIALS_FILE"]
        secrets = json.loads(Path(filename).read_text())
        self.accounts = {key.removesuffix("_private_key"): Account.from_key(value) for key, value in secrets.items() if key.endswith("_private_key")}
        assert {"deployer", "resolver", "insurance"} <= set(self.accounts), "three consumer/deployer keys required"
        self.clients = {}
        VERIFICATION.mkdir(parents=True, exist_ok=True)
        self.journal = VERIFICATION / "live-journal.jsonl"
        self.records = [json.loads(line) for line in self.journal.read_text().splitlines()] if self.journal.exists() else []
        self.last_rpc = 0.0
        self.current_operation = None
        self.min_rpc_interval = float(os.environ.get("RHIZOME_RPC_INTERVAL", "4.5"))
        (VERIFICATION / "receipts").mkdir(exist_ok=True)

    def log(self, event):
        event = sanitize({**event, "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        with self.journal.open("a") as stream:
            stream.write(canonical(event) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.records.append(event)

    def rate_wait(self, response, method, attempt):
        delay = retry_delay(response)
        self.log({"event": "RATE_LIMITED", "operation": self.current_operation,
                  "method": method, "attempt": attempt + 1, "http_status": response.status_code,
                  "retry_after": response.headers.get("Retry-After"),
                  "rate_limit_remaining": response.headers.get("X-RateLimit-Remaining"),
                  "rate_limit_reset": response.headers.get("X-RateLimit-Reset"),
                  "retry_delay_seconds": delay})
        print("RPC rate limited; retrying the same request after", delay, "seconds", flush=True)
        while delay > 0:
            chunk = min(delay, 60)
            time.sleep(chunk)
            delay -= chunk

    def client(self, role="deployer"):
        if role not in self.clients:
            # Install bounded transport before SDK initialization: create_client()
            # performs an otherwise unbounded consensus-configuration RPC first.
            c = GenLayerClient(chain_config=studionet, account=self.accounts[role])
            def paced(method, params):
                result = None
                for attempt in range(4):
                    gap = self.min_rpc_interval - (time.monotonic() - self.last_rpc)
                    if gap > 0:
                        time.sleep(gap)
                    self.last_rpc = time.monotonic()
                    try:
                        if method == "eth_sendRawTransaction":
                            # Persist the public transaction ID before an ambiguous
                            # timeout/502 can hide a successful broadcast. Never
                            # journal the signed bytes or silently replace a write.
                            self.log({"event": "SEND_ATTEMPT", "operation": self.current_operation,
                                      "ethereum_hash": "0x" + keccak(hexstr=params[0]).hex()})
                        response = requests.post(c.provider.url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=(30, 45), allow_redirects=False)
                        if response.status_code == 429:
                            if attempt == 3:
                                response.raise_for_status()
                            self.rate_wait(response, method, attempt)
                            continue
                        response.raise_for_status()
                        result = response.json()
                        if (result.get("error") or {}).get("code") == -32429 and attempt < 3:
                            self.rate_wait(response, method, attempt)
                            continue
                        c.provider._raise_on_error(result, method)
                        break
                    except (requests.RequestException, ValueError) as error:
                        if method == "eth_sendRawTransaction" and dns_failed_before_transmission(error):
                            self.log({"event": "SEND_NOT_TRANSMITTED", "operation": self.current_operation,
                                      "ethereum_hash": "0x" + keccak(hexstr=params[0]).hex(),
                                      "reason": "DNS_FAILURE_BEFORE_CONNECTION", "attempt": attempt + 1})
                            if attempt == 3:
                                raise
                            print("RPC DNS lookup failed before transmission; retrying identical signed request", flush=True)
                            time.sleep(5)
                            continue
                        if method == "eth_sendRawTransaction" or attempt == 3:
                            raise
                        time.sleep(5)
                if method == "eth_sendRawTransaction" and result.get("result"):
                    self.log({"event": "BROADCAST", "operation": self.current_operation, "ethereum_hash": result["result"]})
                return result
            c.provider.make_request = paced
            c.initialize_consensus_smart_contract()
            self.clients[role] = c
        return self.clients[role]

    def wait(self, tx, label, expected_error=False):
        finalized = [row for row in self.records if row["event"] == "FINALIZED"
                     and row.get("operation") == label and row.get("tx") == tx]
        if finalized:
            saved = json.loads((ROOT / finalized[-1]["receipt"]).read_text())
            assert saved["hash"] == tx and saved["status_name"] == "FINALIZED", "invalid saved finality receipt"
            check_outcome(saved, label, expected_error)
            return saved
        c = self.client()
        observed_undetermined = False
        for _ in range(240):
            receipt = c.get_transaction(tx)
            status = receipt.get("status_name")
            if status == "FINALIZED":
                path = VERIFICATION / "receipts" / (label + ".json")
                write_json(path, receipt)
                ok = successful(receipt)
                self.log({"event": "FINALIZED", "operation": label, "tx": tx, "execution_success": ok, "receipt": str(path.relative_to(ROOT))})
                print(label, "FINALIZED", "success" if ok else "execution error", tx, flush=True)
                check_outcome(receipt, label, expected_error)
                return receipt
            if status == "UNDETERMINED" and not observed_undetermined:
                directory = VERIFICATION / "protocol-observations"
                directory.mkdir(exist_ok=True)
                path = directory / (label + "-undetermined.json")
                write_json(path, receipt)
                self.log({"event": "UNDECIDED", "operation": label, "tx": tx, "status": status,
                          "receipt": str(path.relative_to(ROOT))})
                print(label, "UNDETERMINED; continuing to poll the same transaction", tx, flush=True)
                observed_undetermined = True
            if status == "CANCELED":
                self.log({"event": "UNDECIDED", "operation": label, "tx": tx, "status": status})
                raise RuntimeError(label + ": no protocol finality; inspect transaction " + tx)
            time.sleep(3)
        raise TimeoutError(label + ": still pending, resume by its journaled transaction ID " + tx)

    def submit(self, label, address=None, method=None, args=None, role="deployer", value=0, code=None, expected_error=False, wait_for_finality=True):
        assert len(label) <= 100 and all(ch.isalnum() or ch in "-_." for ch in label)
        c = self.client(role)
        payload = {"address": address, "method": method, "args": args or [], "sender": self.accounts[role].address,
                   "value": value, "code_sha256": hashlib.sha256(code).hexdigest() if code is not None else None}
        payload_digest = digest(payload)
        old = [r for r in self.records if r.get("operation") == label]
        intents = [r for r in old if r["event"] == "INTENT"]
        if intents:
            assert all(row["payload_digest"] == payload_digest for row in intents), "journal operation conflicts with changed input: " + label
        finalized = [r for r in old if r["event"] == "FINALIZED"]
        if finalized:
            saved = json.loads((ROOT / finalized[-1]["receipt"]).read_text())
            assert saved["hash"] == finalized[-1]["tx"] and saved["status_name"] == "FINALIZED", "invalid saved finality receipt"
            check_outcome(saved, label, expected_error)
            return saved if wait_for_finality else saved["hash"]
        submitted = [r for r in old if r["event"] == "SUBMITTED"]
        if submitted:
            return self.wait(submitted[-1]["tx"], label, expected_error) if wait_for_finality else submitted[-1]["tx"]
        sends = [r for r in old if r["event"] in ("BROADCAST", "SEND_ATTEMPT", "SEND_NOT_TRANSMITTED")]
        attempts = [r for r in sends if r["event"] == "SEND_ATTEMPT"]
        not_transmitted = (bool(sends) and sends[-1]["event"] == "SEND_NOT_TRANSMITTED"
                           and sends[-1].get("reason") in ("DNS_FAILURE_BEFORE_CONNECTION", "TLS_HANDSHAKE_TIMEOUT_BEFORE_REQUEST")
                           and bool(attempts) and sends[-1].get("ethereum_hash") == attempts[-1]["ethereum_hash"]
                           and not any(r["event"] == "BROADCAST" for r in sends))
        broadcasts = [] if not_transmitted else [r for r in sends if r["event"] in ("BROADCAST", "SEND_ATTEMPT")]
        if broadcasts:
            # A saved attempt may have reached the server despite a lost response.
            # If its receipt is absent, propagate the lookup error for reconciliation
            # rather than signing a replacement or charging another reservation.
            eth_receipt = c.w3.eth.get_transaction_receipt(broadcasts[-1]["ethereum_hash"])
            event = c.w3.eth.contract(abi=c.chain.consensus_main_contract["abi"]).get_event_by_name("NewTransaction")
            from web3.logs import DISCARD
            events = event.process_receipt(eth_receipt, DISCARD)
            assert events, "broadcast has no consensus transaction; inspect Ethereum receipt"
            tx = c.w3.to_hex(events[0]["args"]["txId"])
            self.log({"event": "SUBMITTED", "operation": label, "tx": tx, "recovered": True})
            return self.wait(tx, label, expected_error) if wait_for_finality else tx
        nonce = c.get_current_nonce(address=self.accounts[role].address)
        if intents:
            # A manually reconciled intent preserves the original history and
            # identical payload while recording the newly verified sender nonce.
            assert nonce == intents[-1]["nonce"], "unreconciled nonce after interrupted broadcast; inspect sender transaction history before replay"
        else:
            self.log({"event": "INTENT", "operation": label, "payload": payload, "payload_digest": payload_digest, "nonce": nonce})
        self.current_operation = label
        try:
            if code is not None:
                tx = c.deploy_contract(code=code, args=args or [], leader_only=False)
            else:
                tx = c.write_contract(address=address, function_name=method, args=args or [], value=value, leader_only=False)
        except (requests.RequestException, ValueError) as error:
            sends = [r for r in self.records if r.get("operation") == label
                     and r["event"] in ("SEND_ATTEMPT", "BROADCAST", "SEND_NOT_TRANSMITTED")]
            if not sends or sends[-1]["event"] == "SEND_NOT_TRANSMITTED":
                raise
            self.log({"event": "RECOVERING_SIGNED_ATTEMPT", "operation": label,
                      "ethereum_hash": sends[-1]["ethereum_hash"], "error_class": type(error).__name__})
            print(label, "transport interrupted; looking up the original signed hash", flush=True)
            # Re-enter only the existing-attempt receipt branch. If the receipt
            # is missing or unreadable, it raises before any nonce check/signing.
            return self.submit(label, address, method, args, role=role, value=value, code=code,
                               expected_error=expected_error, wait_for_finality=wait_for_finality)
        finally:
            self.current_operation = None
        self.log({"event": "SUBMITTED", "operation": label, "tx": tx})
        print(label, "SUBMITTED", tx, flush=True)
        return self.wait(tx, label, expected_error) if wait_for_finality else tx

    def read(self, address, method, args=None, role="deployer"):
        result = self.client(role).read_contract(address=address, function_name=method, args=args or [])
        observation = {"address": address, "method": method, "args": args or [], "result": result}
        directory = VERIFICATION / "observations"
        directory.mkdir(exist_ok=True)
        write_json(directory / (method + "-" + digest(observation) + ".json"), observation)
        return result

    def drain(self, receipt, label):
        children = receipt.get("triggered_transactions", [])
        for index, child in enumerate(children):
            child_hash = child if isinstance(child, str) else child.get("hash", child.get("tx_id"))
            result = self.wait(child_hash, label + "-child-" + str(index))
            self.drain(result, label + "-child-" + str(index))

    def deploy(self):
        source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        saved_deployment = VERIFICATION / "deployment.json"
        if saved_deployment.exists():
            source_commit = json.loads(saved_deployment.read_text())["source_commit"]
        # Bind metadata to committed bytes before submitting any deployment.
        for name in ("assessment_treasury", "rhizome", "event_resolver", "insurance_gate"):
            source_path = "contracts/" + name + ".py"
            committed = subprocess.check_output(["git", "show", source_commit + ":" + source_path], cwd=ROOT)
            assert committed == (ROOT / source_path).read_bytes(), "commit contract source before deployment: " + name
        result = {"network": "studionet", "chain_id": 61999, "rpc": "https://studio.genlayer.com/api",
                  "runner": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6",
                  "source_commit": source_commit, "contracts": {}, "accounts": {r: a.address for r, a in self.accounts.items()}}
        for name, role, args in [("assessment_treasury", "deployer", []),
                                 ("rhizome", "deployer", None),
                                 ("event_resolver", "resolver", None), ("insurance_gate", "insurance", None)]:
            code = (ROOT / "contracts" / (name + ".py")).read_bytes()
            if args is None:
                args = ([result["contracts"]["assessment_treasury"]["address"], 1]
                        if name == "rhizome" else [result["contracts"]["rhizome"]["address"]])
            receipt = self.submit("deploy-" + name, args=args, role=role, code=code)
            address = receipt.get("to_address", receipt.get("recipient"))
            assert address and address != "0x" + "0" * 40
            onchain = self.client().provider.make_request("gen_getContractCode", [address])["result"]
            assert base64.b64decode(onchain, validate=True) == code, "deployed code differs from pinned local contract"
            assert len(agreeing_validators(receipt)) >= 2, "deployment did not show two independent validator agreements"
            result["contracts"][name] = {"address": address, "deployment_tx": receipt["hash"], "code_sha256": hashlib.sha256(code).hexdigest(),
                                          "constructor_args": args, "deployer": self.accounts[role].address}
            write_json(VERIFICATION / "deployment.json", result)
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["deploy", "call", "write"])
    parser.add_argument("--credentials")
    parser.add_argument("--address")
    parser.add_argument("--method")
    parser.add_argument("--args", default="[]")
    parser.add_argument("--operation")
    parser.add_argument("--role", choices=["deployer", "resolver", "insurance"], default="deployer")
    parser.add_argument("--value", type=int, default=0)
    args = parser.parse_args()
    studio = Studio(args.credentials)
    if args.command == "deploy":
        print(json.dumps(studio.deploy(), indent=2))
    elif args.command == "call":
        print(json.dumps(studio.read(args.address, args.method, json.loads(args.args), args.role), indent=2))
    else:
        assert args.operation, "write requires a durable operation ID"
        receipt = studio.submit(args.operation, args.address, args.method, json.loads(args.args), role=args.role, value=args.value)
        studio.drain(receipt, args.operation)


if __name__ == "__main__":
    main()

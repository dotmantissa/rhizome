# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""A standalone event-resolution gate using finalized Rhizome certificates.

The owner supplies the event verdict and intended consequence. Rhizome only
certifies independent evidence origins. A certificate never creates an event
verdict. This consumer requires at least three certified origins.
"""
from genlayer import *
import json
import hashlib
import re

MINIMUM = 3
UNRESOLVED_CONSEQUENCE = "REFUSE_RESOLUTION"
ACTION = "RESOLVED"


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def require(condition, message: str):
    if not condition:
        raise gl.vm.UserError("[EXPECTED] " + message)


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", value) is not None, "invalid identifier")


def read_json(text: str, limit: int) -> dict:
    require(type(text) is str and len(text.encode()) <= limit, "payload byte limit")
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        raise gl.vm.UserError("[EXPECTED] invalid JSON")
    require(type(value) is dict, "object required")
    return value


class EventResolver(gl.Contract):
    owner: Address
    rhizome: Address
    configs: TreeMap[str, str]
    bindings: TreeMap[str, str]
    states: TreeMap[str, str]
    acknowledgements: TreeMap[str, str]
    actions: TreeMap[str, str]
    last_applied_generation: TreeMap[str, u64]
    latest_generation: TreeMap[str, u64]
    history: DynArray[str]
    applied_count: u64
    applied_actions: TreeMap[str, str]

    def __init__(self, rhizome_address: str):
        self.owner = gl.message.sender_address
        self.rhizome = Address(rhizome_address)
        require(self.rhizome != Address("0x" + "0" * 40), "zero source")
        self.applied_count = u64(0)

    def _owner(self):
        require(gl.message.sender_address == self.owner, "consumer owner only")
        require(gl.message.value == 0, "unexpected payment")

    def _policy_key(self, policy_id: str, revision: int) -> str:
        identifier(policy_id)
        require(type(revision) is int and 1 <= revision < (1 << 64), "revision bounds")
        return policy_id + ":" + str(revision)

    def _ack(self, operation_id: str, delivery_digest: str, outcome: str):
        ack = {"operation_id": operation_id, "delivery_digest": delivery_digest, "outcome": outcome}
        self.acknowledgements[operation_id] = canonical(ack)
        gl.get_contract_at(self.rhizome).emit(on="finalized").acknowledge_delivery(operation_id, delivery_digest, outcome)
        return ack

    @gl.public.write
    def configure_policy(self, policy_id: str, revision: int, minimum_count: int) -> None:
        self._owner()
        require(type(minimum_count) is int and MINIMUM <= minimum_count <= 6, "consumer minimum count")
        key = self._policy_key(policy_id, revision)
        policy = gl.get_contract_at(self.rhizome).view().get_finalized_policy(policy_id, revision)
        require(minimum_count >= policy["required_count"], "consumer threshold below source policy")
        config = {"policy_id": policy_id, "policy_revision": revision, "minimum_count": minimum_count,
                  "unresolved_consequence": UNRESOLVED_CONSEQUENCE}
        if key in self.configs:
            require(json.loads(self.configs[key]) == config, "configuration immutable")
        else:
            self.configs[key] = canonical(config)
        gl.get_contract_at(self.rhizome).emit(on="finalized").register_consumer(policy_id, revision, minimum_count, UNRESOLVED_CONSEQUENCE)

    @gl.public.write
    def bind_request(self, expected_binding: str, consequence: str) -> None:
        """Lock exact batch and consequence before a result can permit an action."""
        self._owner()
        expected = read_json(expected_binding, 8192)
        required_fields = {"request_id", "owner", "parties", "policy_id", "policy_revision", "subject_id", "subject_digest",
                           "source_manifest_digest", "consumer_address", "consequence_digest", "generation", "deadline", "batch_digest"}
        require(set(expected) == required_fields, "binding schema")
        identifier(expected["request_id"])
        identifier(expected["subject_id"])
        require(type(expected["generation"]) is int and 1 <= expected["generation"] < (1 << 64), "generation bounds")
        key = self._policy_key(expected["policy_id"], expected["policy_revision"])
        require(key in self.configs, "policy not configured")
        batch = gl.get_contract_at(self.rhizome).view().get_finalized_batch(expected["request_id"])
        require(expected == {**batch["envelope"], "batch_digest": batch["batch_digest"]}, "binding differs from finalized batch")
        require(gl.get_contract_at(self.rhizome).view().is_current(expected["request_id"])["current"], "stale request binding")
        consequence_value = read_json(consequence, 2048)
        require(set(consequence_value) == {"subject_id", "action", "value"} and consequence_value["subject_id"] == expected["subject_id"]
                and consequence_value["action"] == ACTION and type(consequence_value["value"]) is str and 1 <= len(consequence_value["value"]) <= 512, "consequence schema")
        binding = {"expected": expected, "consequence": consequence_value, "consequence_digest": digest(consequence_value)}
        request_id, subject = expected["request_id"], expected["subject_id"]
        if request_id in self.bindings:
            require(json.loads(self.bindings[request_id]) == binding, "request binding immutable")
        else:
            current = int(self.latest_generation.get(subject, u64(0)))
            require(expected["generation"] > current, "stale generation binding")
            self.bindings[request_id] = canonical(binding)
            self.latest_generation[subject] = u64(expected["generation"])
            # A pending successor immediately restricts the previous generation.
            self.states[subject] = canonical({"request_id": request_id, "generation": expected["generation"],
                                              "status": "PENDING", "permitted": False, "unresolved": True})
        gl.get_contract_at(self.rhizome).emit(on="finalized").approve_delivery(request_id, binding["consequence_digest"])

    @gl.public.write
    def receive_certificate(self, payload: str) -> dict:
        require(gl.message.sender_address == self.rhizome, "authenticated Rhizome sender required")
        require(gl.message.value == 0, "unexpected payment")
        data = read_json(payload, 196608)
        require(set(data) == {"certificate", "delivery_binding", "operation_id", "delivery_digest"}, "delivery schema")
        operation_id = data["operation_id"]
        identifier(operation_id)
        delivery_hash = digest({k: v for k, v in data.items() if k != "delivery_digest"})
        require(data["delivery_digest"] == delivery_hash, "forged delivery digest")
        if operation_id in self.acknowledgements:
            old = json.loads(self.acknowledgements[operation_id])
            require(old["delivery_digest"] == delivery_hash, "conflicting operation reuse")
            return self._ack(operation_id, delivery_hash, old["outcome"])
        wrapper = data["certificate"]
        require(set(wrapper) == {"sealed_result", "current_metadata"}, "certificate wrapper")
        certificate = wrapper["sealed_result"]
        require(certificate["schema_version"] == 1 and certificate["source_contract"] == str(self.rhizome), "source schema binding")
        require(certificate["certificate_digest"] == digest({k: v for k, v in certificate.items() if k != "certificate_digest"}), "forged certificate digest")
        request_id = certificate["request_id"]
        require(request_id in self.bindings, "unapproved request")
        local = json.loads(self.bindings[request_id])
        require(all(certificate.get(k) == v for k, v in local["expected"].items()), "certificate request binding mismatch")
        approval = data["delivery_binding"]
        config = json.loads(self.configs[self._policy_key(certificate["policy_id"], certificate["policy_revision"])])
        require(approval == {"request_id": request_id, "consumer": str(gl.message.contract_address), "policy_id": certificate["policy_id"],
                            "policy_revision": certificate["policy_revision"], "batch_digest": certificate["batch_digest"],
                            "subject_digest": certificate["subject_digest"], "generation": certificate["generation"],
                            "consequence_digest": local["consequence_digest"], "minimum_count": config["minimum_count"],
                            "unresolved_consequence": UNRESOLVED_CONSEQUENCE}, "consumer consequence binding mismatch")
        subject = certificate["subject_id"]
        if certificate["generation"] != int(self.latest_generation[subject]):
            return self._ack(operation_id, delivery_hash, "STALE")
        current = gl.get_contract_at(self.rhizome).view().is_current(request_id)
        if not current["current"] or current["batch_digest"] != certificate["batch_digest"]:
            finalized = gl.get_contract_at(self.rhizome).view().is_finalized_current(request_id)
            if finalized["reason"] == "FINALITY_PENDING" or (finalized["current"] and finalized["batch_digest"] == certificate["batch_digest"]):
                # Tentative restrictions may be appealed. Keep the same delivery
                # retryable instead of permanently acknowledging a transient refusal.
                return {"operation_id": operation_id, "delivery_digest": delivery_hash, "outcome": "DEFERRED"}
            self.states[subject] = canonical({"request_id": request_id, "generation": certificate["generation"],
                                              "status": "QUARANTINED", "permitted": False, "unresolved": True})
            return self._ack(operation_id, delivery_hash, "QUARANTINED")
        require(certificate["lifecycle_status"] in ("SEALED", "UNRESOLVED"), "nonterminal certificate")
        permitted = (certificate["lifecycle_status"] == "SEALED" and certificate["coverage_complete"] is True
                     and certificate["unresolved"] is False and type(certificate["certified_origin_count"]) is int
                     and certificate["certified_origin_count"] >= config["minimum_count"]
                     and len(certificate["certified_subset"]) == certificate["certified_origin_count"])
        state = {"request_id": request_id, "generation": certificate["generation"], "status": "CERTIFIED" if permitted else UNRESOLVED_CONSEQUENCE,
                 "permitted": permitted, "unresolved": certificate["unresolved"], "certificate_digest": certificate["certificate_digest"],
                 "batch_digest": certificate["batch_digest"], "certified_origin_count": certificate["certified_origin_count"]}
        self.states[subject] = canonical(state)
        if permitted:
            self.last_applied_generation[subject] = u64(certificate["generation"])
        self.history.append(canonical({"subject_id": subject, "request_id": request_id, "status": state["status"], "operation_id": operation_id}))
        return self._ack(operation_id, delivery_hash, "APPLIED" if permitted else "REFUSED")

    @gl.public.write
    def apply_action(self, subject_id: str, operation_id: str) -> dict:
        self._owner()
        identifier(subject_id)
        identifier(operation_id)
        require(subject_id in self.states, "unknown subject")
        state = json.loads(self.states[subject_id])
        require(state["permitted"] and state["generation"] == int(self.latest_generation[subject_id]), "action refused")
        current = gl.get_contract_at(self.rhizome).view().is_current(state["request_id"])
        require(current["current"] and current["batch_digest"] == state["batch_digest"], "stale or quarantined evidence at action time")
        binding = json.loads(self.bindings[state["request_id"]])
        action = {"subject_id": subject_id, "request_id": state["request_id"], "generation": state["generation"],
                  "batch_digest": state["batch_digest"], "action": ACTION, "value": binding["consequence"]["value"],
                  "consequence_digest": binding["consequence_digest"], "operation_id": operation_id}
        if operation_id in self.actions:
            require(json.loads(self.actions[operation_id]) == action, "conflicting action operation")
            return action
        generation_key = subject_id + ":" + str(state["generation"])
        require(generation_key not in self.applied_actions, "generation action already applied")
        require(int(self.applied_count) < (1 << 64) - 1, "action count overflow")
        self.actions[operation_id] = canonical(action)
        self.applied_actions[generation_key] = operation_id
        self.applied_count = u64(int(self.applied_count) + 1)
        self.history.append(canonical(action))
        return action

    @gl.public.write
    def refresh_subject(self, subject_id: str) -> dict:
        require(gl.message.value == 0, "unexpected payment")
        identifier(subject_id)
        require(subject_id in self.states, "unknown subject")
        state = json.loads(self.states[subject_id])
        current = gl.get_contract_at(self.rhizome).view().is_current(state["request_id"])
        finalized = gl.get_contract_at(self.rhizome).view().is_finalized_current(state["request_id"])
        if not finalized["current"] and finalized["reason"] != "FINALITY_PENDING":
            state.update({"permitted": False, "status": "QUARANTINED", "unresolved": True})
            self.states[subject_id] = canonical(state)
        return {**state, "permitted": state["permitted"] and current["current"], "current_metadata": current}

    @gl.public.view
    def get_subject(self, subject_id: str) -> dict:
        identifier(subject_id)
        require(subject_id in self.states, "unknown subject")
        state = json.loads(self.states[subject_id])
        current = gl.get_contract_at(self.rhizome).view().is_current(state["request_id"])
        return {**state, "permitted": state["permitted"] and current["current"], "current_metadata": current,
                "last_applied_generation": int(self.last_applied_generation.get(subject_id, u64(0)))}

    @gl.public.view
    def get_acknowledgement(self, operation_id: str) -> dict:
        identifier(operation_id)
        require(operation_id in self.acknowledgements, "unknown acknowledgement")
        return json.loads(self.acknowledgements[operation_id])

    @gl.public.view
    def get_action(self, operation_id: str) -> dict:
        identifier(operation_id)
        require(operation_id in self.actions, "unknown action")
        return json.loads(self.actions[operation_id])

    @gl.public.view
    def list_history(self, offset: int, limit: int) -> dict:
        require(type(offset) is int and 0 <= offset < (1 << 64) and type(limit) is int and 1 <= limit <= 50, "pagination bounds")
        end = min(offset + limit, len(self.history))
        return {"items": [json.loads(self.history[i]) for i in range(offset, end)], "next_offset": end, "total": len(self.history)}

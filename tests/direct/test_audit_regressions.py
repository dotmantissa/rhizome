"""Security regressions from the independent audit; synthetic SDK dispatch."""
import json
import pytest
from tests.evidence import address, canonical, material
from tests.direct.test_consumers import consumers, lock, seal_three


def test_unrelated_payer_cannot_hold_or_exhaust_victim_pair(rhizome, prepare, direct_vm, direct_bob):
    prepare()
    direct_vm.sender = direct_bob
    direct_vm.value = 1
    for n in range(3):
        with direct_vm.expect_revert('request owner or authorized payer required'):
            rhizome.reserve_pair('batch-1', 'alpha', 'beta', 'attack-' + str(n))
    direct_vm.value = 0
    state = rhizome.get_pair('batch-1', 'alpha', 'beta')
    assert state == {'decision': None, 'attempts': 0, 'reservation': None}
    assert rhizome.get_limits()['charged_atto'] == 0
    assert rhizome.get_batch('batch-1')['status'] == 'OPEN'
    with direct_vm.expect_revert('no unresolved recovery condition'):
        rhizome.resolve_unavailable('batch-1')


def test_owner_can_recover_delegated_hold_and_complete_assessment(rhizome, prepare, direct_vm, direct_bob, direct_owner):
    prepare()
    rhizome.authorize_assessment_payer('batch-1', address(direct_bob), True)
    direct_vm.sender = direct_bob
    direct_vm.value = 1
    held = rhizome.reserve_pair('batch-1', 'alpha', 'beta', 'sponsor')
    assert held['payer'] == address(direct_bob)
    direct_vm.value = 0
    direct_vm.sender = direct_owner
    rhizome.release_pair('batch-1', 'alpha', 'beta')
    direct_vm.value = 1
    rhizome.reserve_pair('batch-1', 'alpha', 'beta', 'owner-recovery')
    direct_vm.value = 0
    direct_vm.mock_llm('You adjudicate', canonical(material()))
    assert rhizome.assess_pair('batch-1', 'alpha', 'beta')['relation'] == 'INDEPENDENT'
    assert direct_vm.run_validator()
    assert rhizome.seal_batch('batch-1')['sealed_result']['certified_origin_count'] == 2


def test_sponsor_authorization_is_owner_signed_and_revocable(rhizome, prepare, direct_vm, direct_bob, direct_owner):
    prepare()
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert('request owner only'):
        rhizome.authorize_assessment_payer('batch-1', address(direct_bob), True)
    direct_vm.sender = direct_owner
    rhizome.authorize_assessment_payer('batch-1', address(direct_bob), True)
    direct_vm.sender = direct_bob
    direct_vm.value = 1
    rhizome.reserve_pair('batch-1', 'alpha', 'beta', 'revoked-sponsor')
    direct_vm.value = 0
    direct_vm.sender = direct_owner
    rhizome.authorize_assessment_payer('batch-1', address(direct_bob), False)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert('request owner or authorized payer required'):
        rhizome.assess_pair('batch-1', 'alpha', 'beta')
    rhizome.release_pair('batch-1', 'alpha', 'beta')
    direct_vm.value = 1
    with direct_vm.expect_revert('request owner or authorized payer required'):
        rhizome.reserve_pair('batch-1', 'alpha', 'beta', 'revoked-again')
    assert rhizome.get_pair('batch-1', 'alpha', 'beta')['attempts'] == 1


def test_sponsor_cannot_spend_another_requests_retry_budget(rhizome, prepare, direct_vm, direct_bob):
    prepare()
    rhizome.authorize_assessment_payer('batch-1', address(direct_bob), True)
    prepare(request_id='batch-2', subject='other-subject')
    direct_vm.sender = direct_bob
    direct_vm.value = 1
    with direct_vm.expect_revert('request owner or authorized payer required'):
        rhizome.reserve_pair('batch-2', 'alpha', 'beta', 'cross-request')
    assert rhizome.get_pair('batch-2', 'alpha', 'beta')['attempts'] == 0


def test_tentative_restriction_cannot_permanently_terminate_batch(rhizome, prepare, direct_vm):
    from genlayer.py import calldata
    from tests.evidence import digest
    prepare()
    final_current = rhizome.is_current('batch-1')
    rhizome.quarantine_record('request', 'batch-1', 0, digest('tentative-probe'))
    def snapshot(vm, request):
        call = request.get('CallContract')
        if call:
            assert call['state'] == 1 and call['calldata']['method'] == 'is_current'
            return b'\x00' + calldata.encode(final_current)
        return None
    direct_vm._gl_call_hook = snapshot
    with direct_vm.expect_revert('no unresolved recovery condition'):
        rhizome.resolve_unavailable('batch-1')
    assert rhizome.get_batch('batch-1')['status'] == 'OPEN'
    final_current = rhizome.is_current('batch-1')
    assert rhizome.resolve_unavailable('batch-1')['sealed_result']['unresolved_reason'] == 'EVIDENCE_INVALIDATED'


@pytest.mark.parametrize('index,minimum', [(0, 3), (1, 2)])
def test_invalid_policy_rejected_before_local_commit(rhizome, prepare, direct_vm, consumers, index, minimum):
    harness, _, items = consumers
    contract, consumer, owner = items[index]
    prepare(count=4, consumer=consumer)
    with direct_vm.expect_revert('consumer threshold below source policy'):
        harness.call(consumer, owner, 'configure_policy', 'measurements', 1, minimum)
    with harness.context(consumer, owner):
        assert 'measurements:1' not in contract.configs
    assert not harness.messages
    harness.call(consumer, owner, 'configure_policy', 'measurements', 1, 4)
    harness.drain()


@pytest.mark.parametrize('index,action', [(0, 'RESOLVED'), (1, 'UNDERWRITING_ENABLED')])
@pytest.mark.parametrize('field', ['request_id', 'owner', 'parties', 'policy_id', 'policy_revision',
                                 'subject_id', 'subject_digest', 'source_manifest_digest', 'consumer_address',
                                 'consequence_digest', 'generation', 'deadline', 'batch_digest'])
def test_invalid_binding_is_correctable_before_any_state_change(rhizome, prepare, assess, direct_vm, direct_owner, consumers, index, action, field):
    harness, source, items = consumers
    contract, consumer, owner = items[index]
    data = seal_three(rhizome, prepare, assess, direct_vm, consumer)
    harness.drain()
    harness.call(consumer, owner, 'configure_policy', 'measurements', 1, 3)
    harness.drain()
    correct = {**data['batch']['envelope'], 'batch_digest': data['batch']['batch_digest']}
    replacements = {'request_id': 'unknown-request', 'owner': source, 'parties': [owner],
                    'policy_id': 'unknown-policy', 'policy_revision': 2, 'subject_id': 'wrong-subject',
                    'subject_digest': '0' * 64, 'source_manifest_digest': '0' * 64,
                    'consumer_address': source, 'consequence_digest': '0' * 64,
                    'generation': 2, 'deadline': correct['deadline'] + 1, 'batch_digest': '0' * 64}
    bad = {**correct, field: replacements[field]}
    consequence = {'subject_id': 'event-1', 'action': action, 'value': 'eligible'}
    with direct_vm.expect_revert():
        harness.call(consumer, owner, 'bind_request', canonical(bad), canonical(consequence))
    with harness.context(consumer, owner):
        assert 'batch-1' not in contract.bindings and 'event-1' not in contract.states
    assert not harness.messages
    harness.call(consumer, owner, 'bind_request', canonical(correct), canonical(consequence))
    harness.drain()
    harness.call(source, direct_owner, 'publish_to', 'batch-1', consumer, 'corrected-delivery')
    harness.drain()
    assert harness.call(consumer, owner, 'apply_action', 'event-1', 'corrected-action')['action'] == action


def tentative_restriction(vm, harness):
    original = vm._gl_call_hook
    states = []
    def override(context, request):
        call = request.get('CallContract')
        result = original(context, request)
        if call and call['calldata']['method'] == 'is_current':
            states.append(call['state'])
            if call['state'] == 2:
                from genlayer.py import calldata
                result = b'\x00' + calldata.encode({**calldata.decode(result[1:]), 'current': False, 'reason': 'QUARANTINED'})
        return result
    vm._gl_call_hook = override
    return original, states


@pytest.mark.parametrize('index,action', [(0, 'RESOLVED'), (1, 'UNDERWRITING_ENABLED')])
def test_tentative_restriction_refresh_does_not_destroy_finalized_permission(rhizome, prepare, assess, direct_vm, direct_owner, consumers, index, action):
    harness, source, items = consumers
    _, consumer, owner = items[index]
    data = seal_three(rhizome, prepare, assess, direct_vm, consumer)
    harness.drain()
    lock(harness, consumer, owner, data['batch'], 3, action)
    harness.call(source, direct_owner, 'publish_to', 'batch-1', consumer, 'refresh-delivery')
    harness.drain()
    original, states = tentative_restriction(direct_vm, harness)
    refreshed = harness.call(consumer, owner, 'refresh_subject', 'event-1')
    assert not refreshed['permitted'] and refreshed['status'] == 'CERTIFIED'
    assert states == [2, 1]
    direct_vm._gl_call_hook = original
    assert harness.call(consumer, owner, 'get_subject', 'event-1')['permitted']
    assert harness.call(consumer, owner, 'apply_action', 'event-1', 'post-appeal-action')['action'] == action


@pytest.mark.parametrize('index,action', [(0, 'RESOLVED'), (1, 'UNDERWRITING_ENABLED')])
def test_deferred_delivery_retries_same_operation_after_tentative_restriction(rhizome, prepare, assess, direct_vm, direct_owner, consumers, index, action):
    harness, source, items = consumers
    _, consumer, owner = items[index]
    data = seal_three(rhizome, prepare, assess, direct_vm, consumer)
    harness.drain()
    lock(harness, consumer, owner, data['batch'], 3, action)
    harness.call(source, direct_owner, 'publish_to', 'batch-1', consumer, 'deferred-delivery')
    message = harness.messages.pop()
    original, states = tentative_restriction(direct_vm, harness)
    result = harness.call(consumer, source, 'receive_certificate', message['calldata']['args'][0])
    assert result['outcome'] == 'DEFERRED' and not harness.messages and states == [2, 1]
    direct_vm._gl_call_hook = original
    assert rhizome.get_delivery(consumer, 'deferred-delivery')['acknowledgement'] is None
    harness.call(source, direct_owner, 'publish_to', 'batch-1', consumer, 'deferred-delivery')
    harness.drain()
    assert rhizome.get_delivery(consumer, 'deferred-delivery')['acknowledgement']['outcome'] == 'APPLIED'
    assert harness.call(consumer, owner, 'get_subject', 'event-1')['permitted']


def test_refunded_fee_recovery_is_fixed_destination_and_idempotent(rhizome, prepare, direct_vm, direct_bob, direct_owner):
    from genlayer import gl
    prepare()
    direct_vm.value = 1
    rhizome.reserve_pair('batch-1', 'alpha', 'beta', 'refunded-payment')
    rhizome.__on_errored_message__()
    direct_vm.deal(gl.message.contract_address, 1)
    direct_vm.value = 0
    messages = []
    def capture(vm, request):
        if 'PostMessage' in request:
            messages.append(request['PostMessage'])
            return {'ok': None}
        return None
    direct_vm._gl_call_hook = capture
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert('registry owner only'):
        rhizome.retry_treasury_transfer('retry-fee', 1)
    direct_vm.sender = direct_owner
    result = rhizome.retry_treasury_transfer('retry-fee', 1)
    assert messages == [{'address': rhizome.treasury, 'calldata': {'method': 'accept_fee'}, 'value': 1, 'on': 'finalized'}]
    assert rhizome.retry_treasury_transfer('retry-fee', 1) == result and len(messages) == 1
    with direct_vm.expect_revert('conflicting treasury retry operation'):
        rhizome.retry_treasury_transfer('retry-fee', 2)
    with direct_vm.expect_revert('insufficient retained fees'):
        rhizome.retry_treasury_transfer('too-large', 2)
    assert rhizome.get_limits()['charged_atto'] == 1

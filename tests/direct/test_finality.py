"""Synthetic pending/reordered finality messages; actual contract logic."""
import pytest
from tests.evidence import address, canonical, digest, source_packet, DEFINITION
from tests.direct.test_consumers import consumers, lock, seal_three


def defer(vm, kind):
    original, messages = vm._gl_call_hook, []
    def hook(context, request):
        message = request.get('PostMessage')
        if message and message['calldata'].get('method') == 'confirm_finalized_record' and message['calldata']['args'][0] == kind:
            assert message['on'] == 'finalized'
            messages.append(message)
            return {'ok': None}
        return original(context, request)
    vm._gl_call_hook = hook
    return original, messages


def confirm(vm, contract, message):
    from genlayer import gl
    with vm.prank(gl.message.contract_address):
        contract.confirm_finalized_record(*message['calldata']['args'])


def test_finality_confirmation_cannot_be_forged_even_by_registry_owner(rhizome, prepare, direct_vm, direct_bob):
    prepare()
    policy = rhizome.get_policy('measurements', 1)
    with direct_vm.expect_revert('authenticated self confirmation required'):
        rhizome.confirm_finalized_record('policy', 'measurements', 1, digest(policy))
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert('authenticated self confirmation required'):
        rhizome.confirm_finalized_record('policy', 'measurements', 1, digest(policy))
    assert rhizome.get_finalized_policy('measurements', 1) == policy


def test_tentative_policy_replay_cannot_create_a_finality_proof(rhizome, direct_vm):
    original, messages = defer(direct_vm, 'policy')
    policy = rhizome.register_policy('pending-policy', canonical(DEFINITION), 4)
    with direct_vm.expect_revert('record finality confirmation pending'):
        rhizome.get_finalized_policy('pending-policy', 1)
    assert rhizome.register_policy('pending-policy', canonical(DEFINITION), 4) == policy
    assert len(messages) == 1
    direct_vm._gl_call_hook = original
    confirm(direct_vm, rhizome, messages[0])
    assert rhizome.get_finalized_policy('pending-policy', 1) == policy


def test_unfinalized_authority_cannot_admit_a_source(rhizome, direct_vm, direct_owner):
    original, messages = defer(direct_vm, 'authority')
    control, _, source, _ = source_packet('pending', address(direct_owner))
    rhizome.register_authority(source['authority_id'], address(direct_owner), source['channel'], 'https://httpbingo.org/base64/', canonical(control))
    with direct_vm.expect_revert('record finality confirmation pending'):
        rhizome.attest_source(canonical(source))
    assert 'pending:1' not in rhizome.sources
    direct_vm._gl_call_hook = original
    confirm(direct_vm, rhizome, messages[0])
    assert rhizome.attest_source(canonical(source)) == source


def test_unfinalized_batch_cannot_delegate_or_consume_paid_retries(rhizome, prepare, direct_vm, direct_bob):
    original, messages = defer(direct_vm, 'batch')
    data = prepare()
    with direct_vm.expect_revert('record finality confirmation pending'):
        rhizome.authorize_assessment_payer('batch-1', address(direct_bob), True)
    direct_vm.value = 1
    with direct_vm.expect_revert('record finality confirmation pending'):
        rhizome.reserve_pair('batch-1', 'alpha', 'beta', 'premature-hold')
    direct_vm.value = 0
    with direct_vm.expect_revert('record finality confirmation pending'):
        rhizome.resolve_unavailable('batch-1')
    assert rhizome.get_pair('batch-1', 'alpha', 'beta')['attempts'] == rhizome.get_limits()['charged_atto'] == 0
    rhizome.open_batch('batch-1', 'measurements', canonical(data['body']))
    assert len(messages) == 1
    direct_vm._gl_call_hook = original
    confirm(direct_vm, rhizome, messages[0])
    assert rhizome.get_finalized_batch('batch-1')['batch_digest'] == data['batch']['batch_digest']


def test_reordered_source_confirmation_cannot_resurrect_old_evidence(rhizome, prepare, direct_vm, direct_owner):
    prepare()
    original, messages = defer(direct_vm, 'source')
    successor = source_packet('alpha', address(direct_owner), revision=2)[2]
    rhizome.attest_source(canonical(successor))
    assert not rhizome.is_current('batch-1')['current'] and rhizome.is_finalized_current('batch-1')['current']
    direct_vm._gl_call_hook = original
    confirm(direct_vm, rhizome, messages[0])
    assert not rhizome.is_finalized_current('batch-1')['current']
    from genlayer import gl
    with direct_vm.prank(gl.message.contract_address):
        rhizome.confirm_finalized_record('source', 'alpha', 1, digest(rhizome.get_source('alpha', 1)))
    assert rhizome.is_finalized_current('batch-1')['reason'] == 'SOURCE_SUPERSEDED'


def test_reordered_batch_confirmation_cannot_restore_old_generation(rhizome, prepare, direct_vm):
    first = prepare()
    original, messages = defer(direct_vm, 'batch')
    prepare(request_id='batch-2', generation=2)
    assert not rhizome.is_current('batch-1')['current']
    assert rhizome.is_finalized_current('batch-1')['current'] and not rhizome.is_finalized_current('batch-1')['superseded_by']
    direct_vm._gl_call_hook = original
    confirm(direct_vm, rhizome, messages[0])
    from genlayer import gl
    with direct_vm.prank(gl.message.contract_address):
        rhizome.confirm_finalized_record('batch', 'batch-1', 0, first['batch']['batch_digest'])
    assert rhizome.is_finalized_current('batch-1')['superseded_by'] == 'batch-2'


@pytest.mark.parametrize('index,action', [(0, 'RESOLVED'), (1, 'UNDERWRITING_ENABLED')])
def test_confirmation_lag_never_persists_as_consumer_refusal(rhizome, prepare, assess, direct_vm, direct_owner, consumers, index, action):
    harness, source, items = consumers
    _, consumer, owner = items[index]
    data = seal_three(rhizome, prepare, assess, direct_vm, consumer)
    harness.drain()
    lock(harness, consumer, owner, data['batch'], 3, action)
    harness.call(source, direct_owner, 'publish_to', 'batch-1', consumer, 'confirmed-delivery')
    harness.drain()
    rhizome.finalized_source_latest['alpha'] = 0
    assert rhizome.is_finalized_current('batch-1')['reason'] == 'FINALITY_PENDING'
    state = harness.call(consumer, owner, 'refresh_subject', 'event-1')
    assert state['status'] == 'CERTIFIED' and state['permitted']
    assert harness.call(consumer, owner, 'apply_action', 'event-1', 'confirmed-action')['action'] == action

"""Additional hosted release gates for the corrected contracts.

These use real transactions, web retrieval and model consensus. Run only in a
fresh verification namespace alongside the original hosted scenarios.
"""
import pytest
from scripts.studio import agreeing_validators, finalized_result
from tests.evidence import canonical, digest, DEFINITION
from tests.integration.test_studio import live, open_request, configure_and_bind, assess, assess_pairs, deliver

pytestmark = pytest.mark.integration


def test_10_authorized_payer_revocation_and_owner_recovery(live):
    studio, source, _, insurance, _ = live
    batch = open_request(live, 'audit-sponsored', ['delta', 'epsilon'], 'insurance-independence', insurance)
    for attempt in range(3):
        label = 'audit-unauthorized-reservation' + ('-' + str(attempt + 1) if attempt else '')
        studio.submit(label, source, 'reserve_pair',
                      ['audit-sponsored', 'delta', 'epsilon', 'uninvited-payer-' + str(attempt)],
                      role='resolver', value=1, expected_error=True)
    assert studio.read(source, 'get_pair', ['audit-sponsored', 'delta', 'epsilon']) == {
        'decision': None, 'attempts': 0, 'reservation': None}
    payer = studio.accounts['insurance'].address
    studio.submit('audit-authorize-sponsor', source, 'authorize_assessment_payer', ['audit-sponsored', payer, True])
    held = studio.submit('audit-sponsored-reservation', source, 'reserve_pair',
                         ['audit-sponsored', 'delta', 'epsilon', 'sponsored-hold'], role='insurance', value=1)
    studio.drain(held, 'audit-sponsored-reservation')
    studio.submit('audit-revoke-sponsor', source, 'authorize_assessment_payer', ['audit-sponsored', payer, False])
    studio.submit('audit-revoked-assessment', source, 'assess_pair',
                  ['audit-sponsored', 'delta', 'epsilon'], role='insurance', expected_error=True)
    studio.submit('audit-owner-release', source, 'release_pair', ['audit-sponsored', 'delta', 'epsilon'])
    pair = studio.read(source, 'get_pair', ['audit-sponsored', 'delta', 'epsilon'])
    assert pair['attempts'] == 1 and pair['reservation']['status'] == 'RELEASED' and pair['decision'] is None
    decision, receipt = assess(live, 'audit-sponsored', 'delta', 'epsilon', attempt=2)
    assert decision['relation'] == 'INDEPENDENT' and len(agreeing_validators(receipt)) >= 2
    configure_and_bind(live, batch, insurance, 'insurance', 2, 'UNDERWRITING_ENABLED')
    sealed = studio.submit('seal-audit-sponsored', source, 'seal_batch', ['audit-sponsored'])
    assert finalized_result(sealed)['sealed_result']['certified_origin_count'] == 2
    assert deliver(live, 'audit-sponsored', insurance, 'audit-sponsored-delivery')['outcome'] == 'APPLIED'
    studio.submit('action-audit-sponsored', insurance, 'apply_action',
                  ['audit-sponsored', 'audit-sponsored-action'], role='insurance')


def test_11_invalid_consumer_inputs_do_not_poison_configuration(live):
    studio, source, resolver, insurance, _ = live
    policy = studio.submit('policy-audit-independence', source, 'register_policy',
                  ['audit-independence', canonical(DEFINITION), 4])
    studio.drain(policy, 'policy-audit-independence')
    studio.submit('audit-forged-finality-confirmation', source, 'confirm_finalized_record',
                  ['policy', 'audit-independence', 1, digest(finalized_result(policy))], role='resolver', expected_error=True)
    batch = open_request(live, 'audit-binding', ['delta', 'epsilon', 'gamma', 'zeta'], 'audit-independence', insurance)
    studio.submit('audit-invalid-consumer-policy', insurance, 'configure_policy',
                  ['audit-independence', 1, 2], role='insurance', expected_error=True)
    studio.submit('audit-invalid-resolver-policy', resolver, 'configure_policy',
                  ['audit-independence', 1, 3], role='resolver', expected_error=True)
    configured = studio.submit('configure-insurance-audit-independence', insurance, 'configure_policy',
                               ['audit-independence', 1, 4], role='insurance')
    studio.drain(configured, 'configure-insurance-audit-independence')
    expected = {**batch['envelope'], 'batch_digest': '0' * 64}
    consequence = {'subject_id': 'audit-binding', 'action': 'UNDERWRITING_ENABLED', 'value': 'eligible'}
    studio.submit('audit-invalid-consumer-binding', insurance, 'bind_request',
                  [canonical(expected), canonical(consequence)], role='insurance', expected_error=True)
    resolver_config = studio.submit('configure-resolver-audit-independence', resolver, 'configure_policy',
                                   ['audit-independence', 1, 4], role='resolver')
    studio.drain(resolver_config, 'configure-resolver-audit-independence')
    studio.submit('audit-invalid-resolver-binding', resolver, 'bind_request',
                  [canonical(expected), canonical({**consequence, 'action': 'RESOLVED'})], role='resolver', expected_error=True)
    configure_and_bind(live, batch, insurance, 'insurance', 4, 'UNDERWRITING_ENABLED')
    configure_and_bind(live, batch, resolver, 'resolver', 4, 'RESOLVED')
    import itertools
    for decision, receipt in assess_pairs(live, 'audit-binding', itertools.combinations(['delta', 'epsilon', 'gamma', 'zeta'], 2)):
        assert decision['relation'] == 'INDEPENDENT' and len(agreeing_validators(receipt)) >= 2
    studio.submit('seal-audit-binding', source, 'seal_batch', ['audit-binding'])
    assert deliver(live, 'audit-binding', insurance, 'audit-corrected-binding')['outcome'] == 'APPLIED'
    studio.submit('action-audit-binding', insurance, 'apply_action',
                  ['audit-binding', 'audit-corrected-action'], role='insurance')
    assert deliver(live, 'audit-binding', resolver, 'audit-corrected-resolver-binding')['outcome'] == 'APPLIED'
    studio.submit('action-audit-resolver-binding', resolver, 'apply_action',
                  ['audit-binding', 'audit-corrected-resolver-action'], role='resolver')

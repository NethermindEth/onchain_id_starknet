pub mod verify {
    use onchain_id_starknet::claim_issuer::interface::ClaimIssuerABIDispatcherTrait;
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
    use crate::common::{get_test_claim, setup_identity, setup_verifier};

    #[test]
    fn test_should_return_true_when_verifier_does_not_expect_claim_topics() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(is_verified, 'Should have return true');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_but_has_no_trusted_issuer() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, ['CLAIM_TOPIC'].span(), [].span());
        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(!is_verified, 'Should have return false');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_but_has_trusted_issuer_for_another_topic() {
        let setup = setup_identity();
        let verifier = setup_verifier(
            @setup,
            ['CLAIM_TOPIC'].span(),
            [(setup.claim_issuer.contract_address, array!['ANOTHER_CLAIM_TOPIC'])].span(),
        );
        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(!is_verified, 'Should have return false');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_and_has_trusted_issuer_for_topic_when_identity_does_not_have_the_claim() {
        let setup = setup_identity();
        let verifier = setup_verifier(
            @setup,
            ['CLAIM_TOPIC'].span(),
            [(setup.claim_issuer.contract_address, array!['CLAIM_TOPIC'])].span(),
        );
        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(!is_verified, 'Should have return false');
    }

    #[test]
    fn test_should_return_false_when_identity_does_not_have_valid_expected_claim() {
        let setup = setup_identity();
        let verifier = setup_verifier(
            @setup,
            [setup.alice_claim_666.topic].span(),
            [(setup.claim_issuer.contract_address, array![setup.alice_claim_666.topic])].span(),
        );

        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(!is_verified, 'Should have return false');
    }

    #[test]
    fn test_should_return_true_when_identity_has_valid_expected_claim() {
        let setup = setup_identity();
        let verifier = setup_verifier(
            @setup,
            [setup.alice_claim_666.topic].span(),
            [(setup.claim_issuer.contract_address, array![setup.alice_claim_666.topic])].span(),
        );

        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(is_verified, 'Should have return true');
    }

    #[test]
    fn test_should_return_true_when_verifier_expect_multiple_claim_topic_and_allow_multiple_trusted_issuers_when_identity_is_compliant() {
        let setup = setup_identity();
        let verifier = setup_verifier(
            @setup,
            [setup.alice_claim_666.topic, 'CLAIM_TOPIC'].span(),
            [
                (
                    setup.claim_issuer.contract_address,
                    array![setup.alice_claim_666.topic, 'CLAIM_TOPIC'],
                )
            ]
                .span(),
        );

        let test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 'CLAIM_TOPIC', "",
        );

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup
            .alice_identity
            .add_claim(
                test_claim.topic,
                test_claim.scheme,
                test_claim.issuer,
                test_claim.signature,
                test_claim.data.clone(),
                test_claim.uri.clone(),
            );
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(is_verified, 'Should have return true');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_multiple_claim_topic_and_allow_multiple_trusted_issuers_when_identity_is_not_compliant() {
        let setup = setup_identity();
        let verifier = setup_verifier(
            @setup,
            [setup.alice_claim_666.topic, 'CLAIM_TOPIC'].span(),
            [
                (
                    setup.claim_issuer.contract_address,
                    array![setup.alice_claim_666.topic, 'CLAIM_TOPIC'],
                )
            ]
                .span(),
        );

        let is_verified = verifier.verify(setup.alice_identity.contract_address);
        assert(!is_verified, 'Should have return false');
    }
}

pub mod add_claim_topic {
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use onchain_id_starknet::verifiers::verifier::VerifierComponent;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::{setup_identity, setup_verifier};

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());

        verifier.add_claim_topic('CLAIM_TOPIC');
    }

    #[test]
    #[should_panic(expected: 'Topic already exist')]
    fn test_should_panic_when_topic_already_exists() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let verifier = setup_verifier(@setup, [claim_topic].span(), [].span());

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_claim_topic(claim_topic);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    fn test_should_add_claim_topic() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let claim_topic = 'CLAIM_TOPIC';

        let mut spy = spy_events();
        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_claim_topic(claim_topic);
        stop_cheat_caller_address(verifier.contract_address);

        assert(verifier.get_claim_topics() == array![claim_topic], 'Topic not removed');

        spy
            .assert_emitted(
                @array![
                    (
                        verifier.contract_address,
                        VerifierComponent::Event::ClaimTopicAdded(
                            VerifierComponent::ClaimTopicAdded { claim_topic },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: 'Topic length should < 15')]
    fn test_should_panic_when_topic_len_exceed_limit() {
        let setup = setup_identity();
        let verifier = setup_verifier(
            @setup,
            (0..15_u8).into_iter().map(|i| i.into()).collect::<Array<felt252>>().span(),
            [].span(),
        );
        let claim_topic = 'CLAIM_TOPIC';

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_claim_topic(claim_topic);
        stop_cheat_caller_address(verifier.contract_address);
    }
}

pub mod remove_claim_topic {
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use onchain_id_starknet::verifiers::verifier::VerifierComponent;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::{setup_identity, setup_verifier};

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, ['CLAIM_TOPIC'].span(), [].span());

        verifier.remove_claim_topic('CLAIM_TOPIC');
    }

    #[test]
    fn test_should_remove_claim_topic() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let verifier = setup_verifier(@setup, [claim_topic].span(), [].span());

        let mut spy = spy_events();
        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.remove_claim_topic(claim_topic);
        stop_cheat_caller_address(verifier.contract_address);

        assert(verifier.get_claim_topics() == array![], 'Topic not removed');

        spy
            .assert_emitted(
                @array![
                    (
                        verifier.contract_address,
                        VerifierComponent::Event::ClaimTopicRemoved(
                            VerifierComponent::ClaimTopicRemoved { claim_topic },
                        ),
                    ),
                ],
            );
    }
}

pub mod add_trusted_issuer {
    use core::num::traits::Zero;
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use onchain_id_starknet::verifiers::verifier::VerifierComponent;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::{setup_identity, setup_verifier};

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let claim_topic = 'CLAIM_TOPIC';

        verifier.add_trusted_issuer(Zero::zero(), array![claim_topic]);
    }

    #[test]
    #[should_panic(expected: 'Invalid argument - zero address')]
    fn test_should_panic_when_issuer_address_is_zero() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let claim_topic = 'CLAIM_TOPIC';

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_trusted_issuer(Zero::zero(), array![claim_topic]);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Issuer already exist')]
    fn test_should_panic_when_issuer_address_is_already_trusted() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let issuer = setup.claim_issuer.contract_address;
        let verifier = setup_verifier(
            @setup, [claim_topic].span(), [(issuer, array![claim_topic])].span(),
        );

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_trusted_issuer(issuer, array![claim_topic]);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Topics must not be empty')]
    fn test_should_panic_when_claim_topics_array_is_empty() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let issuer = setup.claim_issuer.contract_address;

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_trusted_issuer(issuer, array![]);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Topic length should < 15')]
    fn test_should_panic_when_claim_topics_array_contains_more_than_fifteen_topics() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let issuer = setup.claim_issuer.contract_address;

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier
            .add_trusted_issuer(
                issuer, (0..16_u8).into_iter().map(|x| x.into()).collect::<Array<felt252>>(),
            );
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Trusted issuer should < 50')]
    fn test_should_panic_when_adding_fifty_oneth_trusted_issuer() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let issuer_claim_topics = array![claim_topic];
        let verifier = setup_verifier(
            @setup,
            [].span(),
            (1..51_u8)
                .into_iter()
                .map(
                    |x| (
                        Into::<u8, felt252>::into(x).try_into().unwrap(),
                        issuer_claim_topics.clone(),
                    ),
                )
                .collect::<Array<(starknet::ContractAddress, Array<felt252>)>>()
                .span(),
        );
        let issuer = setup.claim_issuer.contract_address;

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_trusted_issuer(issuer, issuer_claim_topics);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    fn test_should_add_trusted_issuer() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let issuer = setup.claim_issuer.contract_address;
        let verifier = setup_verifier(@setup, [claim_topic].span(), [].span());

        let mut spy = spy_events();
        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.add_trusted_issuer(issuer, array![claim_topic]);
        stop_cheat_caller_address(verifier.contract_address);

        assert(verifier.get_trusted_issuers() == array![issuer], 'Issuer mismatch');
        assert(
            verifier.get_trusted_issuer_claim_topics(issuer) == array![claim_topic],
            'Claim topics does not match',
        );
        assert(
            verifier.get_trusted_issuers_for_claim_topic(claim_topic) == array![issuer],
            'Issuer for claim topic mismatch',
        );

        spy
            .assert_emitted(
                @array![
                    (
                        verifier.contract_address,
                        VerifierComponent::Event::TrustedIssuerAdded(
                            VerifierComponent::TrustedIssuerAdded {
                                trusted_issuer: issuer, claim_topics: array![claim_topic],
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod remove_trusted_issuer {
    use core::num::traits::Zero;
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use onchain_id_starknet::verifiers::verifier::VerifierComponent;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::{setup_identity, setup_verifier};

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let issuer = setup.claim_issuer.contract_address;

        verifier.remove_trusted_issuer(issuer);
    }

    #[test]
    #[should_panic(expected: 'Invalid argument - zero address')]
    fn test_should_panic_when_issuer_address_is_zero() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.remove_trusted_issuer(Zero::zero());
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Trusted issuer does not exist')]
    fn test_should_panic_when_issuer_address_is_not_trusted() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let issuer = setup.claim_issuer.contract_address;

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.remove_trusted_issuer(issuer);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    fn test_should_remove_trusted_issuer() {
        let setup = setup_identity();
        let issuer = setup.claim_issuer.contract_address;
        let claim_topic = 'CLAIM_TOPIC';
        let verifier = setup_verifier(
            @setup, [claim_topic].span(), [(issuer, array![claim_topic])].span(),
        );

        let mut spy = spy_events();

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.remove_trusted_issuer(issuer);
        stop_cheat_caller_address(verifier.contract_address);

        assert(verifier.get_trusted_issuers() == array![], 'Issuer mismatch');
        assert(
            verifier.get_trusted_issuers_for_claim_topic(claim_topic) == array![],
            'Issuer for claim topic mismatch',
        );

        spy
            .assert_emitted(
                @array![
                    (
                        verifier.contract_address,
                        VerifierComponent::Event::TrustedIssuerRemoved(
                            VerifierComponent::TrustedIssuerRemoved { trusted_issuer: issuer },
                        ),
                    ),
                ],
            );
    }
}

pub mod update_issuer_claim_topics {
    use core::num::traits::Zero;
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use onchain_id_starknet::verifiers::verifier::VerifierComponent;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::{setup_identity, setup_verifier};


    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_identity();
        let initial_claim_topic = 'FIRST_TOPIC';
        let new_claim_topics = array!['SECOND_TOPIC', 'THIRD_TOPIC'];
        let issuer = setup.claim_issuer.contract_address;

        let verifier = setup_verifier(
            @setup, [initial_claim_topic].span(), [(issuer, array![initial_claim_topic])].span(),
        );

        verifier.update_issuer_claim_topics(issuer, new_claim_topics);
    }

    #[test]
    #[should_panic(expected: 'Invalid argument - zero address')]
    fn test_should_panic_when_issuer_address_is_zero() {
        let setup = setup_identity();
        let initial_claim_topic = 'FIRST_TOPIC';
        let new_claim_topics = array!['SECOND_TOPIC', 'THIRD_TOPIC'];
        let issuer = setup.claim_issuer.contract_address;

        let verifier = setup_verifier(
            @setup, [initial_claim_topic].span(), [(issuer, array![initial_claim_topic])].span(),
        );

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.update_issuer_claim_topics(Zero::zero(), new_claim_topics);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Trusted issuer does not exist')]
    fn test_should_panic_when_issuer_address_is_not_trusted() {
        let setup = setup_identity();
        let new_claim_topics = array!['SECOND_TOPIC', 'THIRD_TOPIC'];
        let issuer = setup.claim_issuer.contract_address;

        let verifier = setup_verifier(@setup, [].span(), [].span());

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.update_issuer_claim_topics(issuer, new_claim_topics);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Topics must not be empty')]
    fn test_should_panic_when_array_of_topics_is_empty() {
        let setup = setup_identity();
        let initial_claim_topic = 'FIRST_TOPIC';
        let new_claim_topics = array![];
        let issuer = setup.claim_issuer.contract_address;

        let verifier = setup_verifier(
            @setup, [initial_claim_topic].span(), [(issuer, array![initial_claim_topic])].span(),
        );

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.update_issuer_claim_topics(issuer, new_claim_topics);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Topic length should < 15')]
    fn test_should_panic_when_array_contains_more_than_fifteen_topics() {
        let setup = setup_identity();
        let initial_claim_topic = 'FIRST_TOPIC';
        let new_claim_topics = (0..16_u8).into_iter().map(|x| x.into()).collect::<Array<felt252>>();
        let issuer = setup.claim_issuer.contract_address;

        let verifier = setup_verifier(
            @setup, [initial_claim_topic].span(), [(issuer, array![initial_claim_topic])].span(),
        );

        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.update_issuer_claim_topics(issuer, new_claim_topics);
        stop_cheat_caller_address(verifier.contract_address);
    }

    #[test]
    fn test_should_update_issuer_claim_topics() {
        let setup = setup_identity();
        let initial_claim_topic = 'FIRST_TOPIC';
        let issuer = setup.claim_issuer.contract_address;
        let verifier = setup_verifier(
            @setup, [initial_claim_topic].span(), [(issuer, array![initial_claim_topic])].span(),
        );

        let new_claim_topics = array!['SECOND_TOPIC', 'THIRD_TOPIC'];

        let mut spy = spy_events();
        start_cheat_caller_address(
            verifier.contract_address, setup.accounts.owner_account.contract_address,
        );
        verifier.update_issuer_claim_topics(issuer, new_claim_topics.clone());
        stop_cheat_caller_address(verifier.contract_address);

        assert(verifier.get_trusted_issuers() == array![issuer], 'Issuer mismatch');
        assert(
            verifier.get_trusted_issuer_claim_topics(issuer) == new_claim_topics.clone(),
            'Claim topics does not match',
        );
        assert(
            verifier.get_trusted_issuers_for_claim_topic(*new_claim_topics.at(0)) == array![issuer]
                && verifier
                    .get_trusted_issuers_for_claim_topic(*new_claim_topics.at(1)) == array![issuer],
            'Issuer for claim topic mismatch',
        );

        spy
            .assert_emitted(
                @array![
                    (
                        verifier.contract_address,
                        VerifierComponent::Event::ClaimTopicsUpdated(
                            VerifierComponent::ClaimTopicsUpdated {
                                trusted_issuer: issuer, claim_topics: new_claim_topics,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod get_trusted_issuer_claim_topics {
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use crate::common::{setup_identity, setup_verifier};

    #[test]
    #[should_panic(expected: 'Trusted issuer does not exist')]
    fn test_should_panic_when_issuer_is_not_trusted() {
        let setup = setup_identity();
        let issuer = setup.claim_issuer.contract_address;
        let verifier = setup_verifier(@setup, [].span(), [].span());

        verifier.get_trusted_issuer_claim_topics(issuer);
    }

    #[test]
    fn test_should_return_claim_topics() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let issuer = setup.claim_issuer.contract_address;
        let verifier = setup_verifier(
            @setup, [claim_topic].span(), [(issuer, array![claim_topic])].span(),
        );

        assert(
            verifier.get_trusted_issuer_claim_topics(issuer) == array![claim_topic],
            'Claim topics mismatch',
        );
    }
}

pub mod get_trusted_issuers {
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use crate::common::{setup_identity, setup_verifier};

    fn test_should_return_trusted_issuers() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let issuer_claim_topics = array![claim_topic];
        let issuers = (1..10_u8)
            .into_iter()
            .map(|x| Into::<u8, felt252>::into(x).try_into().unwrap())
            .collect::<Array<starknet::ContractAddress>>();

        let verifier = setup_verifier(
            @setup,
            [].span(),
            issuers
                .clone()
                .into_iter()
                .map(|issuer| (issuer, issuer_claim_topics.clone()))
                .collect::<Array<(starknet::ContractAddress, Array<felt252>)>>()
                .span(),
        );

        assert(verifier.get_trusted_issuers() == issuers, 'Issuers mismatch');
    }
}

pub mod get_trusted_issuers_for_claim_topic {
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use crate::common::{setup_identity, setup_verifier};

    fn test_should_return_trusted_issuers_for_claim_topic() {
        let setup = setup_identity();
        let claim_topic = 'CLAIM_TOPIC';
        let issuer_claim_topics = array![claim_topic];
        let issuers = (1..10_u8)
            .into_iter()
            .map(|x| Into::<u8, felt252>::into(x).try_into().unwrap())
            .collect::<Array<starknet::ContractAddress>>();

        let verifier = setup_verifier(
            @setup,
            [].span(),
            issuers
                .clone()
                .into_iter()
                .map(|issuer| (issuer, issuer_claim_topics.clone()))
                .collect::<Array<(starknet::ContractAddress, Array<felt252>)>>()
                .span(),
        );

        assert(
            verifier.get_trusted_issuers_for_claim_topic(claim_topic) == issuers,
            'Issuers mismatch',
        );
    }
}

pub mod is_trusted_issuer {
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use crate::common::{setup_identity, setup_verifier};

    #[test]
    fn test_should_return_false_when_address_is_not_trusted_issuer() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let issuer = setup.claim_issuer.contract_address;

        assert(!verifier.is_trusted_issuer(issuer), 'Should have returned false');
    }

    #[test]
    fn test_should_return_true_when_address_is_not_trusted_issuer() {
        let setup = setup_identity();
        let issuer = setup.claim_issuer.contract_address;
        let claim_topic = 'CLAIM_TOPIC';
        let verifier = setup_verifier(
            @setup, [claim_topic].span(), [(issuer, array![claim_topic])].span(),
        );

        assert(verifier.is_trusted_issuer(issuer), 'Should have returned true');
    }
}

pub mod has_claim_topic {
    use onchain_id_starknet::verifiers::interface::VerifierABIDispatcherTrait;
    use crate::common::{setup_identity, setup_verifier};

    #[test]
    fn test_should_return_false_when_issuer_does_not_have_claim_topic() {
        let setup = setup_identity();
        let verifier = setup_verifier(@setup, [].span(), [].span());
        let claim_topic = 'CLAIM_TOPIC';
        let issuer = setup.claim_issuer.contract_address;

        assert(!verifier.has_claim_topic(issuer, claim_topic), 'Should have returned false');
    }

    #[test]
    fn test_should_return_true_when_issuer_has_claim_topic() {
        let setup = setup_identity();
        let issuer = setup.claim_issuer.contract_address;
        let claim_topic = 'CLAIM_TOPIC';
        let verifier = setup_verifier(
            @setup, [claim_topic].span(), [(issuer, array![claim_topic])].span(),
        );

        assert(verifier.has_claim_topic(issuer, claim_topic), 'Should have returned true');
    }
}

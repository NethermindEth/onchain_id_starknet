pub mod verify {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;

    use onchain_id_starknet::interface::{
        iidentity::{IdentityABIDispatcher, IdentityABIDispatcherTrait},
        iimplementation_authority::IImplementationAuthorityDispatcher,
        iclaim_issuer::{ClaimIssuerABIDispatcher, ClaimIssuerABIDispatcherTrait},
    };
    use onchain_id_starknet::storage::structs::{Signature, StarkSignature};
    use onchain_id_starknet_tests::common::{
        setup_verifier, setup_identity, setup_factory, TestClaim, IdentitySetup, get_test_claim
    };

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use starknet::account::AccountContractDispatcher;


    pub fn get_test_b_claim(setup: @IdentitySetup) -> TestClaim {
        let identity = *setup.alice_identity.contract_address;
        let issuer = identity;
        let claim_topic = 42_felt252;
        let claim_data = "0x0042";
        let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

        let mut serialized_claim_to_sign: Array<felt252> = array![];
        identity.serialize(ref serialized_claim_to_sign);
        claim_topic.serialize(ref serialized_claim_to_sign);
        claim_data.serialize(ref serialized_claim_to_sign);

        let hashed_claim = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
        );

        let (r, s) = (*setup.accounts.alice_key).sign(hashed_claim).unwrap();
        TestClaim {
            claim_id,
            identity,
            issuer: identity,
            topic: claim_topic,
            scheme: 1,
            data: claim_data,
            signature: Signature::StarkSignature(
                StarkSignature { r, s, public_key: *setup.accounts.alice_key.public_key }
            ),
            uri: "https://example.com"
        }
    }

    #[test]
    fn test_should_return_true_when_verifier_does_expect_claim_topics() {
        let setup_verifier = setup_verifier();
        let setup_identity = setup_identity();

        //add the issuer as trusted
        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup_identity.claim_issuer.contract_address.into(),
                array![setup_identity.alice_claim_666.topic]
            );
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        start_cheat_caller_address(
            setup_identity.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );

        let verified = setup_verifier
            .mock_verifier
            .verify(setup_identity.alice_identity.contract_address);
        stop_cheat_caller_address(setup_identity.accounts.alice_account.contract_address);
        assert(verified, 'false but it should be true');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_but_has_no_trusted_issuer() {
        let setup_verifier = setup_verifier();
        let setup_identity = setup_identity();

        //The claim topic has no trusted issuer
        start_cheat_caller_address(
            setup_identity.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );

        let verified = setup_verifier
            .mock_verifier
            .verify(setup_identity.alice_identity.contract_address);
        stop_cheat_caller_address(setup_identity.accounts.alice_account.contract_address);
        assert(!verified, 'true but it should be false');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_but_has_trusted_issuer_for_another_topic() {
        let setup_verifier = setup_verifier();
        let setup_identity = setup_identity();

        //add the issuer as trusted but for a different topic
        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup_identity.claim_issuer.contract_address.into(), array!['some other topic']
            );
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        start_cheat_caller_address(
            setup_identity.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );

        let verified = setup_verifier
            .mock_verifier
            .verify(setup_identity.alice_identity.contract_address);
        stop_cheat_caller_address(setup_identity.accounts.alice_account.contract_address);
        assert(!verified, 'true but it should be false');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_and_has_trusted_issuer_for_topic_when_identity_does_not_have_the_claim() {
        let setup_verifier = setup_verifier();
        let setup_identity = setup_identity();

        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        //first remove all claim_topics
        let topics = setup_verifier.mock_verifier.get_claim_topics();
        for topic in topics {
            setup_verifier.mock_verifier.remove_claim_topic(topic);
        };

        // let the verifier expect a topic which alice has no
        setup_verifier.mock_verifier.add_claim_topic('some other topic');
        //add the issuer as trusted but for a topic wich alice has no

        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup_identity.claim_issuer.contract_address.into(), array!['some other topic']
            );
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        start_cheat_caller_address(
            setup_identity.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );

        let verified = setup_verifier
            .mock_verifier
            .verify(setup_identity.alice_identity.contract_address);
        stop_cheat_caller_address(setup_identity.accounts.alice_account.contract_address);
        assert(!verified, 'true but it should be false');
    }
    #[test]
    fn test_should_return_false_when_identity_does_not_have_valid_expected_claim() {
        let setup = setup_identity();
        let factory_setup = setup_factory();

        let setup_verifier = setup_verifier();

        //add trusted_issuer for the claim
        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup.claim_issuer.contract_address.into(), array![setup.alice_claim_666.topic]
            );
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        //revoke the signature so that it becomes invalid
        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address
        );
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);

        start_cheat_caller_address(
            setup.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        let verified = setup_verifier.mock_verifier.verify(setup.alice_identity.contract_address);
        stop_cheat_caller_address(setup.accounts.alice_account.contract_address);
        assert(!verified, 'true but it should be false');
    }
    #[test]
    fn test_should_return_true_when_identity_has_valid_expected_claim() {
        let setup = setup_identity();
        let setup_verifier = setup_verifier();

        //add the issuer as trusted and verify it
        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup.claim_issuer.contract_address.into(), array![setup.alice_claim_666.topic]
            );
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        start_cheat_caller_address(
            setup.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );

        let verified = setup_verifier.mock_verifier.verify(setup.alice_identity.contract_address);
        stop_cheat_caller_address(setup.accounts.alice_account.contract_address);
        assert(verified, 'false but it should be true');
    }

    #[test]
    fn test_should_return_true_when_verifier_expect_multiple_claim_topic_and_allow_multiple_trusted_issuers_when_identity_is_compliant() {
        let setup = setup_identity();
        let factory_setup = setup_factory();
        let test_claim = get_test_claim(@setup);
        let test_b_claim = get_test_b_claim(@setup);

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address
        );
        setup
            .alice_identity
            .add_claim(
                test_claim.topic,
                test_claim.scheme,
                test_claim.issuer,
                test_claim.signature,
                test_claim.data.clone(),
                test_claim.uri.clone()
            );

        setup
            .alice_identity
            .add_claim(
                test_b_claim.topic,
                test_b_claim.scheme,
                test_b_claim.issuer,
                test_b_claim.signature,
                test_b_claim.data.clone(),
                test_b_claim.uri.clone()
            );
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let setup_verifier = setup_verifier();

        //add the issuer as trusted and
        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_claim_topic(test_claim.topic);
        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup.claim_issuer.contract_address.into(),
                array![test_b_claim.topic, test_claim.topic, setup.alice_claim_666.topic]
            );
        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup.alice_identity.contract_address.into(), array![test_b_claim.topic]
            );

        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);
        //revoke the test_claim that is issued by the claim_issuer but it should be verified as the
        //topic has issued by alice as test_b_claim.
        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address
        );
        setup.claim_issuer.revoke_claim_by_signature(test_claim.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);

        start_cheat_caller_address(
            setup.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );

        let verified = setup_verifier.mock_verifier.verify(setup.alice_identity.contract_address);
        stop_cheat_caller_address(setup.accounts.alice_account.contract_address);
        assert(verified, 'false but it should be true');
    }
    #[test]
    fn test_should_return_flase_when_verifier_expect_multiple_claim_topic_and_allow_multiple_trusted_issuers_when_identity_is_not_compliant() {
        let setup = setup_identity();
        let factory_setup = setup_factory();
        let test_claim = get_test_claim(@setup);
        let test_b_claim = get_test_b_claim(@setup);

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address
        );
        setup
            .alice_identity
            .add_claim(
                test_claim.topic,
                test_claim.scheme,
                test_claim.issuer,
                test_claim.signature,
                test_claim.data.clone(),
                test_claim.uri.clone()
            );
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let setup_verifier = setup_verifier();

        //add the issuer as trusted and
        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_claim_topic(test_claim.topic);
        setup_verifier
            .mock_verifier
            .add_trusted_issuer(
                setup.claim_issuer.contract_address.into(),
                array![test_b_claim.topic, test_claim.topic, setup.alice_claim_666.topic]
            );
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);
        //revoke the test_claim that is issued by the claim_issuer but it should not be verified as
        //the topic has revoked by the only issuer
        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address
        );
        setup.claim_issuer.revoke_claim_by_signature(test_claim.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);

        start_cheat_caller_address(
            setup.accounts.alice_account.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );

        let verified = setup_verifier.mock_verifier.verify(setup.alice_identity.contract_address);
        stop_cheat_caller_address(setup.accounts.alice_account.contract_address);
        assert(!verified, 'true but it should be false');
    }
}


pub mod remove_claim_topic {
    use core::num::traits::Zero;
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;
    use onchain_id_starknet::storage::structs::{Signature, StarkSignature};
    use onchain_id_starknet_tests::common::setup_verifier;

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use starknet::account::AccountContractDispatcher;
    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup.mock_verifier.add_claim_topic('a');
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
        setup.mock_verifier.remove_claim_topic('a');
    }
    #[test]
    fn test_should_remove_claim_topic() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup.mock_verifier.add_claim_topic('a');
        let topics = setup.mock_verifier.get_claim_topics().len();
        setup.mock_verifier.remove_claim_topic('a');
        assert(
            setup.mock_verifier.get_claim_topics().len() == topics - 1, 'claim topic not removed'
        );
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
}

pub mod remove_trusted_issuer {
    use core::num::traits::Zero;
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;
    use onchain_id_starknet_tests::common::setup_verifier;

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use starknet::account::AccountContractDispatcher;
    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_verifier();
        setup
            .mock_verifier
            .remove_trusted_issuer(setup.accounts.alice_account.contract_address.into());
    }
    #[test]
    #[should_panic(expected: 'invalid argument - zero address')]
    fn test_should_panic_when_issuer_address_is_zero() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        let mut topics = array!['a'];
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), topics);
        setup.mock_verifier.remove_trusted_issuer(Zero::zero());
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    #[should_panic(expected: 'trusted issuer does not exist')]
    fn test_should_panic_when_issuer_address_is_not_trusted() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup
            .mock_verifier
            .remove_trusted_issuer(setup.accounts.alice_account.contract_address.into());
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    fn test_should_remove_trusted_issuer() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        let mut topics = array!['a'];
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), topics);
        let trusted_issuers = setup.mock_verifier.get_trusted_issuers().len();
        setup
            .mock_verifier
            .remove_trusted_issuer(setup.accounts.alice_account.contract_address.into());
        assert(
            setup.mock_verifier.get_trusted_issuers().len() == trusted_issuers - 1,
            'issuer is not removed'
        );
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
}

pub mod add_trusted_issuer {
    use core::num::traits::Zero;
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;
    use onchain_id_starknet_tests::common::setup_verifier;

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use starknet::account::AccountContractDispatcher;

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_verifier();
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address, array!['a']);
    }
    #[test]
    #[should_panic(expected: 'invalid argument - zero address')]
    fn test_should_panic_when_issuer_address_is_zero() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup.mock_verifier.add_trusted_issuer(Zero::zero(), array!['name']);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    #[should_panic(expected: 'issuer already exist')]
    fn test_should_panic_when_issuer_address_is_already_trusted() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup
            .mock_verifier
            .add_trusted_issuer(
                setup.accounts.alice_account.contract_address.into(), array!['name']
            );
        setup
            .mock_verifier
            .add_trusted_issuer(
                setup.accounts.alice_account.contract_address.into(), array!['name']
            );
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }

    #[test]
    #[should_panic(expected: 'topics should > 0')]
    fn test_should_panic_when_claim_topics_array_is_empty() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array![]);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    #[should_panic(expected: 'topic lengeth should < 16')]
    fn test_should_panic_when_claim_topics_array_contains_more_than_fifteen_topics() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        let mut topics = array!['a'];
        while topics.len() < 20 {
            topics.append(topics.len().into());
        };
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), topics);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    #[should_panic(expected: 'trusted issuer should < 50')]
    fn test_should_panic_when_adding_fifty_oneth_trusted_issuer() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        let mut count: u8 = 0;
        let mut mock_account_contract = declare("MockAccount").unwrap().contract_class();
        // set deployer key and account
        let mut address_key = KeyPairTrait::<felt252, felt252>::generate();
        let (account_address, _) = mock_account_contract
            .deploy(@array![address_key.public_key])
            .unwrap();
        let mut account = AccountContractDispatcher { contract_address: account_address };
        setup.mock_verifier.add_trusted_issuer(account.contract_address.into(), array!['a']);
        while count < 52 {
            mock_account_contract = declare("MockAccount").unwrap().contract_class();
            // set deployer key and account
            address_key = KeyPairTrait::<felt252, felt252>::generate();
            let (account_address, _) = mock_account_contract
                .deploy(@array![address_key.public_key])
                .unwrap();
            account = AccountContractDispatcher { contract_address: account_address };
            setup.mock_verifier.add_trusted_issuer(account.contract_address.into(), array!['a']);
            count += 1;
        };
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    fn test_should_add_trusted_issuer() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        let mut topics = array!['a'];
        let issuers = setup.mock_verifier.get_trusted_issuers().len();
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), topics);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);

        assert(
            setup.mock_verifier.get_trusted_issuers().len() == issuers + 1, 'issuer is not added'
        );
    }
}

pub mod update_issuer_claim_topics {
    use core::num::traits::Zero;
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;
    use onchain_id_starknet_tests::common::setup_verifier;

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use starknet::account::AccountContractDispatcher;

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_not_owner() {
        let setup = setup_verifier();
        //add the trusted issuer first with the owner
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['a']);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
        //then try to update with non owner
        setup
            .mock_verifier
            .update_issuer_claim_topics(setup.accounts.carol_account.contract_address, array!['b']);
    }
    #[test]
    fn test_should_update_issuer_claim_topics() {
        let setup = setup_verifier();
        //add the trusted issuer first with the owner
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['a']);
        //then try to update with non owner
        setup
            .mock_verifier
            .update_issuer_claim_topics(setup.accounts.alice_account.contract_address, array!['b']);

        let topic = setup
            .mock_verifier
            .get_trusted_issuer_claim_topics(setup.accounts.alice_account.contract_address)
            .at(0);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
        assert(topic == array!['b'].at(0), 'topic not updated')
    }
    #[test]
    #[should_panic(expected: 'invalid argument - zero address')]
    fn test_should_panic_when_issuer_address_is_zero() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );

        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['a']);

        setup.mock_verifier.update_issuer_claim_topics(Zero::zero(), array!['b']);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    #[should_panic(expected: 'trusted issuer does not exist')]
    fn test_should_panic_when_issuer_address_is_not_trusted() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );

        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['a']);
        let mock_account_contract = declare("MockAccount").unwrap().contract_class();
        // set deployer key and account
        let address_key = KeyPairTrait::<felt252, felt252>::generate();
        let (account_address, _) = mock_account_contract
            .deploy(@array![address_key.public_key])
            .unwrap();
        let account = AccountContractDispatcher { contract_address: account_address };

        setup.mock_verifier.update_issuer_claim_topics(account.contract_address, array!['a']);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    #[should_panic(expected: 'topic lengeth should < 16')]
    fn test_should_panic_when_array_contains_more_than_fifteen_topics() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );

        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['a']);

        let mut topics = array!['a'];
        while topics.len() < 20 {
            topics.append(topics.len().into());
        };

        setup
            .mock_verifier
            .update_issuer_claim_topics(
                setup.accounts.alice_account.contract_address.into(), topics
            );
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
    #[test]
    #[should_panic(expected: 'topics should > 0')]
    fn test_should_panic_when_array_of_topics_is_empty() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );

        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['a']);

        setup
            .mock_verifier
            .update_issuer_claim_topics(
                setup.accounts.alice_account.contract_address.into(), array![]
            );
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }
}

pub mod get_trusted_issuer_claim_topic {
    use core::num::traits::Zero;
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;
    use onchain_id_starknet_tests::common::setup_verifier;

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use starknet::account::AccountContractDispatcher;

    #[test]
    #[should_panic(expected: 'trusted issuer does not exist')]
    fn test_should_panic_when_issuer_is_not_trusted() {
        let setup = setup_verifier();
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );

        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['a']);
        let mock_account_contract = declare("MockAccount").unwrap().contract_class();
        // set deployer key and account
        let address_key = KeyPairTrait::<felt252, felt252>::generate();
        let (account_address, _) = mock_account_contract
            .deploy(@array![address_key.public_key])
            .unwrap();
        let account = AccountContractDispatcher { contract_address: account_address };

        setup.mock_verifier.get_trusted_issuer_claim_topics(account.contract_address);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
    }

    #[test]
    fn test_should_return_claim_topics() {
        let setup = setup_verifier();
        //add the trusted issuer first with the owner
        start_cheat_caller_address(
            setup.mock_verifier.contract_address, setup.accounts.owner_account.contract_address
        );
        setup
            .mock_verifier
            .add_trusted_issuer(setup.accounts.alice_account.contract_address.into(), array!['b']);

        let topic = setup
            .mock_verifier
            .get_trusted_issuer_claim_topics(setup.accounts.alice_account.contract_address)
            .at(0);
        stop_cheat_caller_address(setup.mock_verifier.contract_address);
        assert(topic == array!['b'].at(0), 'topic not updated')
    }
}

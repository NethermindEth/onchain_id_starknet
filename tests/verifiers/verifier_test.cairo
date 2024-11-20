pub mod verify {
    use core::poseidon::poseidon_hash_span;

    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;

    use onchain_id_starknet::interface::{
        iidentity::{IdentityABIDispatcherTrait},
        iclaim_issuer::{ClaimIssuerABIDispatcher, ClaimIssuerABIDispatcherTrait},
        iverifier::{VerifierABIDispatcher},
    };
    use onchain_id_starknet::storage::structs::{Signature, StarkSignature};
    use onchain_id_starknet_tests::common::{
        setup_verifier, TestClaim, setup_accounts, get_claim_issuer, get_identity,
        get_claim_issuer_david, get_claim_issuer_alice
    };

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            SignerTrait,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };

    #[test]
    fn test_should_return_true_when_verifier_does_not_expect_claim_topics() {
        let setup_account = setup_accounts();
        let mock_verifier_contract = declare("MockVerifier").unwrap().contract_class();
        let (mock_verifier_address, _) = mock_verifier_contract
            .deploy(@array![setup_account.owner_account.contract_address.into()])
            .unwrap();
        let mut verifier_dispatcher = VerifierABIDispatcher {
            contract_address: mock_verifier_address
        };
        let verified = verifier_dispatcher.verify(setup_account.owner_account.contract_address);
        assert(verified, 'should be verified');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_but_has_no_trusted_issuer() {
        let setup_account = setup_accounts();
        let mock_verifier_contract = declare("MockVerifier").unwrap().contract_class();
        let (mock_verifier_address, _) = mock_verifier_contract
            .deploy(@array![setup_account.owner_account.contract_address.into()])
            .unwrap();
        let mut verifier_dispatcher = VerifierABIDispatcher {
            contract_address: mock_verifier_address
        };
        start_cheat_caller_address(
            verifier_dispatcher.contract_address, setup_account.owner_account.contract_address
        );
        verifier_dispatcher.add_claim_topic(666_felt252);
        stop_cheat_caller_address(verifier_dispatcher.contract_address);

        let (identity, _) = get_identity(setup_account.carol_account, 'carol');
        let verified = verifier_dispatcher.verify(identity.contract_address);
        assert(!verified, 'should not be verified');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_but_has_trusted_issuer_for_another_topic() {
        //The verifier in setup_verififer has claim_666 and a trusted issuer
        let setup_verifier = setup_verifier();
        let (identity, factory_setup) = get_identity(
            setup_verifier.accounts.carol_account, 'carol'
        );

        let claim_issuer = get_claim_issuer(@factory_setup);
        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer, array![888_felt252]);
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        let verified = setup_verifier.mock_verifier.verify(identity.contract_address);

        assert(!verified, 'should not be verified');
    }

    #[test]
    fn test_should_return_false_when_verifier_expect_one_claim_topic_and_has_trusted_issuer_for_topic_when_identity_does_not_have_the_claim() {
        let setup_verifier = setup_verifier();
        let (identity, factory_setup) = get_identity(
            setup_verifier.accounts.carol_account, 'carol'
        );

        let claim_issuer = get_claim_issuer(@factory_setup);

        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer, array![666_felt252]);
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);
        let verified = setup_verifier.mock_verifier.verify(identity.contract_address);

        assert(!verified, 'should not be verified');
    }
    #[test]
    fn test_should_return_false_when_identity_does_not_have_valid_expected_claim() {
        let setup_verifier = setup_verifier();
        let (identity, factory_setup) = get_identity(
            setup_verifier.accounts.carol_account, 'carol'
        );

        let claim_issuer = get_claim_issuer(@factory_setup);
        start_cheat_caller_address(
            identity.contract_address, setup_verifier.accounts.carol_account.contract_address
        );
        let claim_topic = 666_felt252;
        let issuer = claim_issuer;
        let claim_data = "0x00666";
        let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

        let mut serialized_claim_to_sign: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign);
        claim_topic.serialize(ref serialized_claim_to_sign);
        claim_data.serialize(ref serialized_claim_to_sign);

        let hashed_claim = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
        );

        let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

        let claim_666 = TestClaim {
            claim_id,
            identity: identity.contract_address,
            issuer: claim_issuer,
            topic: claim_topic,
            scheme: 1,
            data: claim_data,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key
                }
            ),
            uri: "https://example.com"
        };

        identity
            .add_claim(
                claim_666.topic,
                claim_666.scheme,
                claim_666.issuer,
                claim_666.signature,
                claim_666.data.clone(),
                claim_666.uri.clone()
            );
        stop_cheat_caller_address(identity.contract_address);

        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer, array![666_felt252]);
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        let claim_issuer_dispatcher = ClaimIssuerABIDispatcher { contract_address: claim_issuer };
        start_cheat_caller_address(claim_issuer_dispatcher.contract_address, claim_issuer);
        claim_issuer_dispatcher.revoke_claim_by_signature(claim_666.signature);
        stop_cheat_caller_address(claim_issuer_dispatcher.contract_address);
        let verified = setup_verifier.mock_verifier.verify(identity.contract_address);

        assert(!verified, 'true but it should be false');
    }
    #[test]
    fn test_should_return_true_when_identity_has_valid_expected_claim() {
        let setup_verifier = setup_verifier();
        let (identity, factory_setup) = get_identity(
            setup_verifier.accounts.carol_account, 'carol'
        );

        let claim_issuer = get_claim_issuer(@factory_setup);
        start_cheat_caller_address(
            identity.contract_address, setup_verifier.accounts.carol_account.contract_address
        );
        let claim_topic = 666_felt252;
        let issuer = claim_issuer;
        let claim_data = "0x00666";
        let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

        let mut serialized_claim_to_sign: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign);
        claim_topic.serialize(ref serialized_claim_to_sign);
        claim_data.serialize(ref serialized_claim_to_sign);

        let hashed_claim = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
        );

        let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

        let claim_666 = TestClaim {
            claim_id,
            identity: identity.contract_address,
            issuer: claim_issuer,
            topic: claim_topic,
            scheme: 1,
            data: claim_data,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key
                }
            ),
            uri: "https://example.com"
        };

        identity
            .add_claim(
                claim_666.topic,
                claim_666.scheme,
                claim_666.issuer,
                claim_666.signature,
                claim_666.data.clone(),
                claim_666.uri.clone()
            );
        stop_cheat_caller_address(identity.contract_address);

        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer, array![666_felt252]);
        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);
        let verified = setup_verifier.mock_verifier.verify(identity.contract_address);

        assert(verified, 'should be verified');
    }

    #[test]
    fn test_should_return_true_when_verifier_expect_multiple_claim_topic_and_allow_multiple_trusted_issuers_when_identity_is_compliant() {
        let setup_verifier = setup_verifier();
        let (identity, factory_setup) = get_identity(
            setup_verifier.accounts.carol_account, 'carol'
        );

        let claim_issuer_issuer = get_claim_issuer(@factory_setup);
        let claim_issuer_david = get_claim_issuer_david(@factory_setup);
        let claim_issuer_alice = get_claim_issuer_alice(@factory_setup);

        start_cheat_caller_address(
            identity.contract_address, setup_verifier.accounts.carol_account.contract_address
        );
        //let the default issuer first issue topic claim_666

        let claim_topic = 666_felt252;
        let issuer = claim_issuer_issuer;
        let claim_data = "0x00666";
        let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

        let mut serialized_claim_to_sign: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign);
        claim_topic.serialize(ref serialized_claim_to_sign);
        claim_data.serialize(ref serialized_claim_to_sign);

        let hashed_claim = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
        );

        let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

        let claim_666_issuer = TestClaim {
            claim_id,
            identity: identity.contract_address,
            issuer: claim_issuer_issuer,
            topic: claim_topic,
            scheme: 1,
            data: claim_data,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key
                }
            ),
            uri: "https://example.com"
        };
        let claim_topic = 666_felt252;
        let issuer_alice = claim_issuer_alice;
        let claim_data_alice = "0x00666";
        let claim_id_alice = poseidon_hash_span(array![issuer_alice.into(), claim_topic].span());

        let mut serialized_claim_to_sign_alice: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign_alice);
        claim_topic.serialize(ref serialized_claim_to_sign_alice);
        claim_data_alice.serialize(ref serialized_claim_to_sign_alice);

        let hashed_claim_alice = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
        );

        let (r_alice, s_alice) = factory_setup.accounts.alice_key.sign(hashed_claim_alice).unwrap();

        let claim_666_alice = TestClaim {
            claim_id: claim_id_alice,
            identity: identity.contract_address,
            issuer: claim_issuer_alice,
            topic: claim_topic,
            scheme: 1,
            data: claim_data_alice,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r: r_alice, s: s_alice, public_key: factory_setup.accounts.alice_key.public_key
                }
            ),
            uri: "https://example.com"
        };

        let claim_topic_david = 888_felt252;
        let issuer_david = claim_issuer_david;
        let claim_data_david = "0x00888";
        let claim_id_david = poseidon_hash_span(array![issuer_david.into(), claim_topic].span());

        let mut serialized_claim_to_sign_david: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign_david);
        claim_topic_david.serialize(ref serialized_claim_to_sign_david);
        claim_data_david.serialize(ref serialized_claim_to_sign_david);

        let hashed_claim_david = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign_david.span())]
                .span()
        );

        let (r_david, s_david) = factory_setup.accounts.david_key.sign(hashed_claim_david).unwrap();

        let claim_888_david = TestClaim {
            claim_id: claim_id_david,
            identity: identity.contract_address,
            issuer: claim_issuer_david,
            topic: claim_topic_david,
            scheme: 1,
            data: claim_data_david,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r: r_david, s: s_david, public_key: factory_setup.accounts.david_key.public_key
                }
            ),
            uri: "https://example.com"
        };

        identity
            .add_claim(
                claim_666_alice.topic,
                claim_666_alice.scheme,
                claim_666_alice.issuer,
                claim_666_alice.signature,
                claim_666_alice.data.clone(),
                claim_666_alice.uri.clone()
            );

        identity
            .add_claim(
                claim_666_issuer.topic,
                claim_666_issuer.scheme,
                claim_666_issuer.issuer,
                claim_666_issuer.signature,
                claim_666_issuer.data.clone(),
                claim_666_issuer.uri.clone()
            );

        identity
            .add_claim(
                claim_888_david.topic,
                claim_888_david.scheme,
                claim_888_david.issuer,
                claim_888_david.signature,
                claim_888_david.data.clone(),
                claim_888_david.uri.clone()
            );

        stop_cheat_caller_address(identity.contract_address);

        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_claim_topic(888_felt252);
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer_issuer, array![666_felt252]);

        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer_alice, array![666_felt252]);
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer_david, array![888_felt252]);

        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        let claim_issuer_dispatcher = ClaimIssuerABIDispatcher {
            contract_address: claim_issuer_alice
        };
        //lets alice revoke, however still should be valid since claim_issuer issued the same claim
        start_cheat_caller_address(claim_issuer_dispatcher.contract_address, claim_issuer_alice);
        claim_issuer_dispatcher.revoke_claim_by_signature(claim_666_alice.signature);
        stop_cheat_caller_address(claim_issuer_dispatcher.contract_address);

        let verified = setup_verifier.mock_verifier.verify(identity.contract_address);
        assert(verified, 'should be verified');
    }
    #[test]
    fn test_should_return_flase_when_verifier_expect_multiple_claim_topic_and_allow_multiple_trusted_issuers_when_identity_is_not_compliant() {
        let setup_verifier = setup_verifier();
        let (identity, factory_setup) = get_identity(
            setup_verifier.accounts.carol_account, 'carol'
        );

        let claim_issuer_issuer = get_claim_issuer(@factory_setup);
        let claim_issuer_david = get_claim_issuer_david(@factory_setup);
        let claim_issuer_alice = get_claim_issuer_alice(@factory_setup);

        start_cheat_caller_address(
            identity.contract_address, setup_verifier.accounts.carol_account.contract_address
        );
        //let the default issuer first issue topic claim_666

        let claim_topic = 666_felt252;
        let issuer = claim_issuer_issuer;
        let claim_data = "0x00666";
        let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

        let mut serialized_claim_to_sign: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign);
        claim_topic.serialize(ref serialized_claim_to_sign);
        claim_data.serialize(ref serialized_claim_to_sign);

        let hashed_claim = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
        );

        let (r, s) = factory_setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();

        let claim_666_issuer = TestClaim {
            claim_id,
            identity: identity.contract_address,
            issuer: claim_issuer_issuer,
            topic: claim_topic,
            scheme: 1,
            data: claim_data,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r, s, public_key: factory_setup.accounts.claim_issuer_key.public_key
                }
            ),
            uri: "https://example.com"
        };
        let claim_topic = 666_felt252;
        let issuer_alice = claim_issuer_alice;
        let claim_data_alice = "0x00666";
        let claim_id_alice = poseidon_hash_span(array![issuer_alice.into(), claim_topic].span());

        let mut serialized_claim_to_sign_alice: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign_alice);
        claim_topic.serialize(ref serialized_claim_to_sign_alice);
        claim_data_alice.serialize(ref serialized_claim_to_sign_alice);

        let hashed_claim_alice = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span()
        );

        let (r_alice, s_alice) = factory_setup.accounts.alice_key.sign(hashed_claim_alice).unwrap();

        let claim_666_alice = TestClaim {
            claim_id: claim_id_alice,
            identity: identity.contract_address,
            issuer: claim_issuer_alice,
            topic: claim_topic,
            scheme: 1,
            data: claim_data_alice,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r: r_alice, s: s_alice, public_key: factory_setup.accounts.alice_key.public_key
                }
            ),
            uri: "https://example.com"
        };

        let claim_topic_david = 888_felt252;
        let issuer_david = claim_issuer_david;
        let claim_data_david = "0x00888";
        let claim_id_david = poseidon_hash_span(array![issuer_david.into(), claim_topic].span());

        let mut serialized_claim_to_sign_david: Array<felt252> = array![];
        identity.contract_address.serialize(ref serialized_claim_to_sign_david);
        claim_topic_david.serialize(ref serialized_claim_to_sign_david);
        claim_data_david.serialize(ref serialized_claim_to_sign_david);

        let hashed_claim_david = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign_david.span())]
                .span()
        );

        let (r_david, s_david) = factory_setup.accounts.david_key.sign(hashed_claim_david).unwrap();

        let claim_888_david = TestClaim {
            claim_id: claim_id_david,
            identity: identity.contract_address,
            issuer: claim_issuer_david,
            topic: claim_topic_david,
            scheme: 1,
            data: claim_data_david,
            signature: Signature::StarkSignature(
                StarkSignature {
                    r: r_david, s: s_david, public_key: factory_setup.accounts.david_key.public_key
                }
            ),
            uri: "https://example.com"
        };

        identity
            .add_claim(
                claim_666_alice.topic,
                claim_666_alice.scheme,
                claim_666_alice.issuer,
                claim_666_alice.signature,
                claim_666_alice.data.clone(),
                claim_666_alice.uri.clone()
            );

        identity
            .add_claim(
                claim_666_issuer.topic,
                claim_666_issuer.scheme,
                claim_666_issuer.issuer,
                claim_666_issuer.signature,
                claim_666_issuer.data.clone(),
                claim_666_issuer.uri.clone()
            );

        identity
            .add_claim(
                claim_888_david.topic,
                claim_888_david.scheme,
                claim_888_david.issuer,
                claim_888_david.signature,
                claim_888_david.data.clone(),
                claim_888_david.uri.clone()
            );

        stop_cheat_caller_address(identity.contract_address);

        start_cheat_caller_address(
            setup_verifier.mock_verifier.contract_address,
            setup_verifier.accounts.owner_account.contract_address
        );
        setup_verifier.mock_verifier.add_claim_topic(888_felt252);
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer_issuer, array![666_felt252]);

        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer_alice, array![666_felt252]);
        setup_verifier.mock_verifier.add_trusted_issuer(claim_issuer_david, array![888_felt252]);

        stop_cheat_caller_address(setup_verifier.mock_verifier.contract_address);

        let claim_issuer_dispatcher = ClaimIssuerABIDispatcher {
            contract_address: claim_issuer_david
        };
        //lets david revoke, this should not be valid as david is the only issuer of claim_888
        start_cheat_caller_address(claim_issuer_dispatcher.contract_address, claim_issuer_david);
        claim_issuer_dispatcher.revoke_claim_by_signature(claim_888_david.signature);
        stop_cheat_caller_address(claim_issuer_dispatcher.contract_address);
        let verified = setup_verifier.mock_verifier.verify(identity.contract_address);
        assert(!verified, 'false but it should be true');
    }
}


pub mod remove_claim_topic {
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;
    use onchain_id_starknet_tests::common::setup_verifier;

    use snforge_std::{
        start_cheat_caller_address, stop_cheat_caller_address,
        signature::{
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
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
        start_cheat_caller_address, stop_cheat_caller_address,
        signature::{
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
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
            KeyPairTrait,
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
            KeyPairTrait,
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
    use onchain_id_starknet::interface::iverifier::VerifierABIDispatcherTrait;
    use onchain_id_starknet_tests::common::setup_verifier;

    use snforge_std::{
        declare, DeclareResultTrait, ContractClassTrait, start_cheat_caller_address,
        stop_cheat_caller_address,
        signature::{
            KeyPairTrait,
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

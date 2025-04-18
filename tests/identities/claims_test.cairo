pub mod add_claim {
    pub mod when_self_attested_claim {
        use core::poseidon::poseidon_hash_span;
        use onchain_id_starknet::identity::identity::Identity::SNIP12MetadataImpl;
        use onchain_id_starknet::identity::interface::ierc735;
        use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
        use onchain_id_starknet::storage::signature::{ClaimMessage, Signature, StarkSignature};
        use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
        use snforge_std::signature::SignerTrait;
        use snforge_std::signature::stark_curve::{
            StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl,
        };
        use snforge_std::{
            EventSpyAssertionsTrait, spy_events, start_cheat_caller_address,
            stop_cheat_caller_address,
        };
        use crate::common::{IdentitySetup, TestClaim, setup_identity};

        fn get_self_attested_claim(setup: @IdentitySetup) -> TestClaim {
            let identity = *setup.alice_identity.contract_address;
            let issuer = identity;
            let claim_topic = 42_felt252;
            let claim_data = [0x0042].span();
            let claim_id = poseidon_hash_span(array![issuer.into(), claim_topic].span());

            let hashed_claim = ClaimMessage { identity, topic: claim_topic, data: claim_data }
                .get_message_hash(issuer);

            let (r, s) = (*setup.accounts.alice_key).sign(hashed_claim).unwrap();
            let signature = Signature::StarkSignature(
                StarkSignature { r, s, public_key: *setup.accounts.alice_key.public_key },
            );
            let mut serialized_signature = Default::default();
            signature.serialize(ref serialized_signature);

            TestClaim {
                claim_id,
                identity,
                issuer: identity,
                topic: claim_topic,
                scheme: 1,
                data: claim_data,
                signature: serialized_signature.span(),
                uri: "https://example.com",
            }
        }

        #[test]
        fn test_should_add_claim_when_claim_not_valid() {
            let setup = setup_identity();
            let identity = setup.alice_identity.contract_address;
            let claim_topic = 42_felt252;
            let claim_id = poseidon_hash_span(array![identity.into(), claim_topic].span());

            let signature = Signature::StarkSignature(
                StarkSignature {
                    r: '', s: '', public_key: setup.accounts.claim_issuer_key.public_key,
                },
            );
            let mut serialized_signature = Default::default();
            signature.serialize(ref serialized_signature);

            let self_attested_claim = TestClaim {
                claim_id,
                identity,
                issuer: identity,
                topic: claim_topic,
                scheme: 1,
                data: [0xC0FFEE].span(),
                signature: serialized_signature.span(),
                uri: "https://example.com",
            };
            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup
                .alice_identity
                .add_claim(
                    self_attested_claim.topic,
                    self_attested_claim.scheme,
                    self_attested_claim.issuer,
                    self_attested_claim.signature,
                    self_attested_claim.data,
                    self_attested_claim.uri.clone(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            let claim_id = core::poseidon::poseidon_hash_span(
                [self_attested_claim.issuer.into(), self_attested_claim.topic].span(),
            );
            assert_eq!(
                setup.alice_identity.get_claim(claim_id),
                (
                    self_attested_claim.topic,
                    self_attested_claim.scheme,
                    self_attested_claim.issuer,
                    self_attested_claim.signature,
                    self_attested_claim.data,
                    self_attested_claim.uri.clone(),
                ),
                "Claim not added",
            );

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc735::ERC735Event::ClaimAdded(
                                ierc735::ClaimAdded {
                                    claim_id: self_attested_claim.claim_id,
                                    topic: self_attested_claim.topic,
                                    scheme: self_attested_claim.scheme,
                                    issuer: self_attested_claim.issuer,
                                    signature: self_attested_claim.signature,
                                    data: self_attested_claim.data,
                                    uri: self_attested_claim.uri,
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        fn test_should_add_claim_when_claim_valid_when_caller_is_identity() {
            let setup = setup_identity();
            let self_attested_claim = get_self_attested_claim(@setup);

            let mut calldata = array![
                self_attested_claim.topic,
                self_attested_claim.scheme,
                self_attested_claim.issuer.into(),
            ];
            self_attested_claim.signature.serialize(ref calldata);
            self_attested_claim.data.serialize(ref calldata);
            self_attested_claim.uri.serialize(ref calldata);

            start_cheat_caller_address(
                setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
            );
            let execution_id = setup
                .alice_identity
                .execute(
                    setup.alice_identity.contract_address, selector!("add_claim"), calldata.span(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.alice_identity.approve(execution_id, true);
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            let claim_id = core::poseidon::poseidon_hash_span(
                [self_attested_claim.issuer.into(), self_attested_claim.topic].span(),
            );
            assert_eq!(
                setup.alice_identity.get_claim(claim_id),
                (
                    self_attested_claim.topic,
                    self_attested_claim.scheme,
                    self_attested_claim.issuer,
                    self_attested_claim.signature,
                    self_attested_claim.data,
                    self_attested_claim.uri.clone(),
                ),
                "Claim not added",
            );

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc735::ERC735Event::ClaimAdded(
                                ierc735::ClaimAdded {
                                    claim_id: self_attested_claim.claim_id,
                                    topic: self_attested_claim.topic,
                                    scheme: self_attested_claim.scheme,
                                    issuer: self_attested_claim.issuer,
                                    signature: self_attested_claim.signature,
                                    data: self_attested_claim.data,
                                    uri: self_attested_claim.uri,
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        fn test_should_add_claim_when_claim_valid_when_caller_is_claim_or_management_key() {
            let setup = setup_identity();
            let self_attested_claim = get_self_attested_claim(@setup);

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup
                .alice_identity
                .add_claim(
                    self_attested_claim.topic,
                    self_attested_claim.scheme,
                    self_attested_claim.issuer,
                    self_attested_claim.signature,
                    self_attested_claim.data,
                    self_attested_claim.uri.clone(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            let claim_id = core::poseidon::poseidon_hash_span(
                [self_attested_claim.issuer.into(), self_attested_claim.topic].span(),
            );
            assert_eq!(
                setup.alice_identity.get_claim(claim_id),
                (
                    self_attested_claim.topic,
                    self_attested_claim.scheme,
                    self_attested_claim.issuer,
                    self_attested_claim.signature,
                    self_attested_claim.data,
                    self_attested_claim.uri.clone(),
                ),
                "Claim not added",
            );

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc735::ERC735Event::ClaimAdded(
                                ierc735::ClaimAdded {
                                    claim_id: self_attested_claim.claim_id,
                                    topic: self_attested_claim.topic,
                                    scheme: self_attested_claim.scheme,
                                    issuer: self_attested_claim.issuer,
                                    signature: self_attested_claim.signature,
                                    data: self_attested_claim.data,
                                    uri: self_attested_claim.uri,
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        #[should_panic(expected: 'Sender not have claim key')]
        fn test_should_panic_if_caller_is_not_claim_key() {
            let setup = setup_identity();
            let self_attested_claim = get_self_attested_claim(@setup);

            start_cheat_caller_address(
                setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
            );
            setup
                .alice_identity
                .add_claim(
                    self_attested_claim.topic,
                    self_attested_claim.scheme,
                    self_attested_claim.issuer,
                    self_attested_claim.signature,
                    self_attested_claim.data,
                    self_attested_claim.uri.clone(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);
        }
    }

    pub mod when_issued_by_claim_issuer {
        use core::poseidon::poseidon_hash_span;
        use onchain_id_starknet::identity::interface::ierc735;
        use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
        use onchain_id_starknet::storage::signature::{Signature, StarkSignature};
        use snforge_std::signature::SignerTrait;
        use snforge_std::signature::stark_curve::{
            StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl,
        };
        use snforge_std::{
            EventSpyAssertionsTrait, spy_events, start_cheat_caller_address,
            stop_cheat_caller_address,
        };
        use crate::common::{get_test_claim, setup_identity};

        #[test]
        #[should_panic(expected: 'Invalid claim')]
        fn test_should_panic_when_invalid_claim() {
            let setup = setup_identity();
            let mut test_claim = get_test_claim(
                @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
            );

            let mut serialized_claim_to_sign: Array<felt252> = array![];
            test_claim.identity.serialize(ref serialized_claim_to_sign);
            test_claim.topic.serialize(ref serialized_claim_to_sign);
            let claim_data: ByteArray = "0xBadBabe0000";
            claim_data.serialize(ref serialized_claim_to_sign);
            let hashed_invalid_claim = poseidon_hash_span(
                array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())]
                    .span(),
            );
            let (r, s) = setup.accounts.claim_issuer_key.sign(hashed_invalid_claim).unwrap();
            let invalid_signature = Signature::StarkSignature(
                StarkSignature { r, s, public_key: setup.accounts.claim_issuer_key.public_key },
            );
            let mut serialized_signature = Default::default();
            invalid_signature.serialize(ref serialized_signature);

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup
                .alice_identity
                .add_claim(
                    test_claim.topic,
                    test_claim.scheme,
                    test_claim.issuer,
                    serialized_signature.span(),
                    test_claim.data,
                    test_claim.uri.clone(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);
        }

        #[test]
        fn test_should_add_claim_when_caller_identity() {
            let setup = setup_identity();
            let mut test_claim = get_test_claim(
                @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
            );

            let mut calldata = array![
                test_claim.topic, test_claim.scheme, test_claim.issuer.into(),
            ];
            test_claim.signature.serialize(ref calldata);
            test_claim.data.serialize(ref calldata);
            test_claim.uri.serialize(ref calldata);
            start_cheat_caller_address(
                setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
            );
            let execution_id = setup
                .alice_identity
                .execute(
                    setup.alice_identity.contract_address, selector!("add_claim"), calldata.span(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);
            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.alice_identity.approve(execution_id, true);
            stop_cheat_caller_address(setup.alice_identity.contract_address);
            let (topic, scheme, issuer, mut signature, data, uri) = setup
                .alice_identity
                .get_claim(test_claim.claim_id);

            assert!(topic == test_claim.topic, "Stored claim topic does not match");
            assert!(scheme == test_claim.scheme, "Stored scheme does not match");
            assert!(issuer == test_claim.issuer, "Stored issuer does not match");

            let mut test_signature_span = test_claim.signature;
            if let Signature::StarkSignature(stored_sig) =
                Serde::<Signature>::deserialize(ref signature)
                .unwrap() {
                if let Signature::StarkSignature(actual_sig) =
                    Serde::<Signature>::deserialize(ref test_signature_span)
                    .unwrap() {
                    assert!(
                        stored_sig.r == actual_sig.r
                            && stored_sig.s == actual_sig.s
                            && stored_sig.public_key == actual_sig.public_key,
                        "Stored signature does not match",
                    );
                }
            }
            assert!(data == test_claim.data, "Stored data does not match");
            assert!(uri == test_claim.uri.clone(), "Stored uri does not match");

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc735::ERC735Event::ClaimAdded(
                                ierc735::ClaimAdded {
                                    claim_id: test_claim.claim_id,
                                    topic: test_claim.topic,
                                    scheme: test_claim.scheme,
                                    issuer: test_claim.issuer,
                                    signature: test_claim.signature,
                                    data: test_claim.data,
                                    uri: test_claim.uri,
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        fn test_should_add_claim_when_caller_management_or_claim_key() {
            let setup = setup_identity();
            let mut test_claim = get_test_claim(
                @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
            );

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup
                .alice_identity
                .add_claim(
                    test_claim.topic,
                    test_claim.scheme,
                    test_claim.issuer,
                    test_claim.signature,
                    test_claim.data,
                    test_claim.uri.clone(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            let (topic, scheme, issuer, mut signature, data, uri) = setup
                .alice_identity
                .get_claim(test_claim.claim_id);

            assert!(topic == test_claim.topic, "Stored claim topic does not match");
            assert!(scheme == test_claim.scheme, "Stored scheme does not match");
            assert!(issuer == test_claim.issuer, "Stored issuer does not match");
            let mut test_signature_span = test_claim.signature;
            if let Signature::StarkSignature(stored_sig) =
                Serde::<Signature>::deserialize(ref signature)
                .unwrap() {
                if let Signature::StarkSignature(actual_sig) =
                    Serde::<Signature>::deserialize(ref test_signature_span)
                    .unwrap() {
                    assert!(stored_sig == actual_sig, "Stored signature does not match");
                }
            }
            assert!(data == test_claim.data, "Stored data does not match");
            assert!(uri == test_claim.uri.clone(), "Stored uri does not match");

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc735::ERC735Event::ClaimAdded(
                                ierc735::ClaimAdded {
                                    claim_id: test_claim.claim_id,
                                    topic: test_claim.topic,
                                    scheme: test_claim.scheme,
                                    issuer: test_claim.issuer,
                                    signature: test_claim.signature,
                                    data: test_claim.data,
                                    uri: test_claim.uri,
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        #[should_panic(expected: 'Sender not have claim key')]
        fn test_should_panic_if_caller_is_not_claim_key() {
            let setup = setup_identity();
            let mut test_claim = get_test_claim(
                @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
            );

            start_cheat_caller_address(
                setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
            );
            setup
                .alice_identity
                .add_claim(
                    test_claim.topic,
                    test_claim.scheme,
                    test_claim.issuer,
                    test_claim.signature,
                    test_claim.data,
                    test_claim.uri.clone(),
                );
            stop_cheat_caller_address(setup.alice_identity.contract_address);
        }
    }
}

pub mod update_claim {
    use onchain_id_starknet::identity::identity::Identity::SNIP12MetadataImpl;
    use onchain_id_starknet::identity::interface::ierc735;
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use onchain_id_starknet::storage::signature::{ClaimMessage, Signature, StarkSignature};
    use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{
        StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl,
    };
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::{get_test_claim, setup_identity};

    #[test]
    fn test_should_replace_existing_claim() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
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
                test_claim.data,
                test_claim.uri.clone(),
            );
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        /// Second time adding with same topic and issuer should change existing claim
        test_claim.data = [0xBadCafe].span();
        let hashed_claim = ClaimMessage {
            identity: test_claim.identity, topic: test_claim.topic, data: test_claim.data,
        }
            .get_message_hash(test_claim.issuer);
        let (r, s) = setup.accounts.claim_issuer_key.sign(hashed_claim).unwrap();
        let signature = Signature::StarkSignature(
            StarkSignature { r, s, public_key: setup.accounts.claim_issuer_key.public_key },
        );
        let mut serialized_signature = Default::default();
        signature.serialize(ref serialized_signature);
        test_claim.signature = serialized_signature.span();

        let mut spy = spy_events();

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
                test_claim.data,
                test_claim.uri.clone(),
            );
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let (topic, scheme, issuer, mut returned_signature, data, uri) = setup
            .alice_identity
            .get_claim(test_claim.claim_id);

        assert!(topic == test_claim.topic, "Stored claim topic does not match");
        assert!(scheme == test_claim.scheme, "Stored scheme does not match");
        assert!(issuer == test_claim.issuer, "Stored issuer does not match");
        if let Signature::StarkSignature(stored_sig) =
            Serde::<Signature>::deserialize(ref returned_signature)
            .unwrap() {
            if let Signature::StarkSignature(actual_sig) = signature {
                assert!(stored_sig == actual_sig, "Stored signature does not match");
            }
        }
        assert!(data == test_claim.data, "Stored data does not match");
        assert!(uri == test_claim.uri.clone(), "Stored uri does not match");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc735::ERC735Event::ClaimChanged(
                            ierc735::ClaimChanged {
                                claim_id: test_claim.claim_id,
                                topic: test_claim.topic,
                                scheme: test_claim.scheme,
                                issuer: test_claim.issuer,
                                signature: test_claim.signature,
                                data: test_claim.data,
                                uri: test_claim.uri,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod remove_claim {
    use core::num::traits::Zero;
    use onchain_id_starknet::identity::interface::ierc735;
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::{get_test_claim, setup_identity};

    #[test]
    fn test_should_remove_existing_claim_when_caller_is_identity_contract() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
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
                test_claim.data,
                test_claim.uri.clone(),
            );

        let mut spy = spy_events();

        setup
            .alice_identity
            .execute(
                setup.alice_identity.contract_address,
                selector!("remove_claim"),
                array![test_claim.claim_id].span(),
            );
        // Remove claim
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let (topic, scheme, issuer, signature, data, uri) = setup
            .alice_identity
            .get_claim(test_claim.claim_id);

        assert!(topic == Zero::zero(), "Stored claim topic not cleaned");
        assert!(scheme == Zero::zero(), "Stored scheme not cleaned");
        assert!(issuer == Zero::zero(), "Stored issuer not cleaned");
        assert!(signature == [].span(), "Signature not cleaned");
        assert!(data == [].span(), "Stored data not cleaned");
        assert!(uri == Default::default(), "Stored uri not cleaned");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc735::ERC735Event::ClaimRemoved(
                            ierc735::ClaimRemoved {
                                claim_id: test_claim.claim_id,
                                topic: test_claim.topic,
                                scheme: test_claim.scheme,
                                issuer: test_claim.issuer,
                                signature: test_claim.signature,
                                data: test_claim.data,
                                uri: test_claim.uri,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: 'Sender not have claim key')]
    fn test_should_panic_when_caller_is_not_a_claim_key() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
        );
        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
        );
        setup.alice_identity.remove_claim(test_claim.claim_id);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }

    #[test]
    #[should_panic(expected: 'There is no claim with this ID')]
    fn test_should_panic_when_claim_does_not_exist() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
        );
        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.remove_claim(test_claim.claim_id);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }

    #[test]
    fn test_should_remove_claim_when_caller_has_claim_or_management_key() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(
            @setup, setup.alice_identity.contract_address, 42_felt252, [0x0042].span(),
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
                test_claim.data,
                test_claim.uri.clone(),
            );

        let mut spy = spy_events();
        setup.alice_identity.remove_claim(test_claim.claim_id);
        // Remove claim
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let (topic, scheme, issuer, signature, data, uri) = setup
            .alice_identity
            .get_claim(test_claim.claim_id);

        assert!(topic == Zero::zero(), "Stored claim topic not cleaned");
        assert!(scheme == Zero::zero(), "Stored scheme not cleaned");
        assert!(issuer == Zero::zero(), "Stored issuer not cleaned");
        assert(signature == [].span(), 'Signature not cleaned');
        assert!(data == [].span(), "Stored data not cleaned");
        assert!(uri == Default::default(), "Stored uri not cleaned");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc735::ERC735Event::ClaimRemoved(
                            ierc735::ClaimRemoved {
                                claim_id: test_claim.claim_id,
                                topic: test_claim.topic,
                                scheme: test_claim.scheme,
                                issuer: test_claim.issuer,
                                signature: test_claim.signature,
                                data: test_claim.data,
                                uri: test_claim.uri,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod get_claim {
    use core::num::traits::Zero;
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use onchain_id_starknet::storage::signature::Signature;
    use crate::common::setup_identity;

    #[test]
    fn test_should_return_default_values_when_claim_does_not_exist() {
        let setup = setup_identity();
        let (topic, scheme, issuer, signature, data, uri) = setup
            .alice_identity
            .get_claim('non_existing_claim');
        assert!(topic == Zero::zero());
        assert!(scheme == Zero::zero());
        assert!(issuer == Zero::zero());
        assert!(signature == [].span());
        assert!(data == [].span());
        assert!(uri == Default::default());
    }

    #[test]
    fn test_should_return_claim_data() {
        let setup = setup_identity();
        let (topic, scheme, issuer, mut signature, data, uri) = setup
            .alice_identity
            .get_claim(setup.alice_claim_666.claim_id);

        assert!(topic == setup.alice_claim_666.topic);
        assert!(scheme == setup.alice_claim_666.scheme);
        assert!(issuer == setup.alice_claim_666.issuer);
        let mut alice_claim_666_signature_span = setup.alice_claim_666.signature;
        if let Signature::StarkSignature(stored_sig) =
            Serde::<Signature>::deserialize(ref signature)
            .unwrap() {
            if let Signature::StarkSignature(actual_sig) =
                Serde::<Signature>::deserialize(ref alice_claim_666_signature_span)
                .unwrap() {
                assert!(
                    stored_sig.r == actual_sig.r
                        && stored_sig.s == actual_sig.s
                        && stored_sig.public_key == actual_sig.public_key,
                    "Stored signature does not match",
                );
            }
        }
        assert!(data == setup.alice_claim_666.data);
        assert!(uri == setup.alice_claim_666.uri);
    }
}

pub mod get_claims_by_topic {
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use crate::common::setup_identity;

    #[test]
    fn test_should_return_empty_array_when_there_are_no_claim_topics() {
        let setup = setup_identity();
        let claim_ids = setup.alice_identity.get_claim_ids_by_topics('non_existing_topic');
        assert!(claim_ids == [].span());
    }

    #[test]
    fn test_should_return_array_of_claim_ids_existing_for_topic() {
        let setup = setup_identity();
        let claim_ids = setup.alice_identity.get_claim_ids_by_topics(setup.alice_claim_666.topic);
        assert!(claim_ids == [setup.alice_claim_666.claim_id].span());
    }
}

pub mod revoke_claim_by_signature_test {
    use onchain_id_starknet::claim_issuer::ClaimIssuer;
    use onchain_id_starknet::interface::iclaim_issuer::ClaimIssuerABIDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;

    #[test]
    #[should_panic(expected: 'Sender not have management key')]
    fn test_should_panic_when_non_management_key() {
        let setup = setup_identity();
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
    }

    #[test]
    #[should_panic(expected: 'Claim already revoked')]
    fn test_should_panic_when_management_key_when_claim_already_revoked() {
        let setup = setup_identity();
        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        // Revoking already revoked claim should panic
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
    }

    #[test]
    fn test_should_revoke_claim_when_management_key_when_claim_not_revoked() {
        let setup = setup_identity();

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup.claim_issuer.revoke_claim_by_signature(setup.alice_claim_666.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
        let is_valid_claim = setup
            .claim_issuer
            .is_claim_valid(
                setup.alice_claim_666.identity,
                setup.alice_claim_666.topic,
                setup.alice_claim_666.signature,
                setup.alice_claim_666.data,
            );

        assert!(!is_valid_claim, "Claim not revoked");
        spy
            .assert_emitted(
                @array![
                    (
                        setup.claim_issuer.contract_address,
                        ClaimIssuer::Event::ClaimRevoked(
                            ClaimIssuer::ClaimRevoked {
                                signature: setup.alice_claim_666.signature,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod revoke_claim {
    use onchain_id_starknet::claim_issuer::ClaimIssuer;
    use onchain_id_starknet::interface::iclaim_issuer::ClaimIssuerABIDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;

    #[test]
    #[should_panic(expected: 'Sender not have management key')]
    fn test_should_panic_when_non_management_key() {
        let setup = setup_identity();
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
    }

    #[test]
    #[should_panic(expected: 'Claim already revoked')]
    fn test_should_panic_when_management_key_when_claim_already_revoked() {
        let setup = setup_identity();
        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
        // Revoking already revoked claim should panic
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
    }

    #[test]
    fn test_should_revoke_claim_when_management_key_when_claim_not_revoked() {
        let setup = setup_identity();

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup
            .claim_issuer
            .revoke_claim(setup.alice_claim_666.claim_id, setup.alice_claim_666.identity);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);
        let is_valid_claim = setup
            .claim_issuer
            .is_claim_valid(
                setup.alice_claim_666.identity,
                setup.alice_claim_666.topic,
                setup.alice_claim_666.signature,
                setup.alice_claim_666.data,
            );

        assert!(!is_valid_claim, "Claim not revoked");
        spy
            .assert_emitted(
                @array![
                    (
                        setup.claim_issuer.contract_address,
                        ClaimIssuer::Event::ClaimRevoked(
                            ClaimIssuer::ClaimRevoked {
                                signature: setup.alice_claim_666.signature,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod is_claim_valid {
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::interface::iclaim_issuer::ClaimIssuerABIDispatcherTrait;
    use onchain_id_starknet::storage::signature::{Signature, StarkSignature};
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{
        StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl,
    };
    use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
    use crate::common::{get_test_claim, setup_identity};

    #[test]
    fn test_should_return_false_when_key_does_not_have_claim_or_management_purpose() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(@setup);

        let mut data_to_hash = array![test_claim.identity.into(), test_claim.topic];
        test_claim.data.serialize(ref data_to_hash);
        let hashed_claim = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(data_to_hash.span())].span(),
        );
        test_claim.issuer = setup.accounts.bob_account.contract_address;
        let (r, s) = setup.accounts.bob_key.sign(hashed_claim).unwrap();
        let signature = Signature::StarkSignature(
            StarkSignature { r, s, public_key: setup.accounts.bob_key.public_key },
        );
        let mut serialized_signature = Default::default();
        signature.serialize(ref serialized_signature);

        test_claim.signature = serialized_signature.span();

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(!is_claim_valid, "Claim should be invalid for non-management, non-claim key");
    }

    #[test]
    fn test_should_return_false_when_key_has_claim_purpose_when_signature_revoked() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(@setup);

        start_cheat_caller_address(
            setup.claim_issuer.contract_address,
            setup.accounts.claim_issuer_account.contract_address,
        );
        setup.claim_issuer.revoke_claim_by_signature(test_claim.signature);
        stop_cheat_caller_address(setup.claim_issuer.contract_address);

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(!is_claim_valid, "Claim should be invalid when signature is revoked");
    }

    #[test]
    fn test_should_return_false_when_invalid_signature() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(@setup);

        let mut serialized_claim_to_sign: Array<felt252> = array![];
        test_claim.identity.serialize(ref serialized_claim_to_sign);
        test_claim.topic.serialize(ref serialized_claim_to_sign);
        // different than message we are passing
        let claim_data: ByteArray = "0xBadBabe0000";
        claim_data.serialize(ref serialized_claim_to_sign);
        let hashed_invalid_claim = poseidon_hash_span(
            array!['Starknet Message', poseidon_hash_span(serialized_claim_to_sign.span())].span(),
        );
        let (r, s) = setup.accounts.claim_issuer_key.sign(hashed_invalid_claim).unwrap();
        let signature = Signature::StarkSignature(
            StarkSignature { r, s, public_key: setup.accounts.claim_issuer_key.public_key },
        );
        let mut serialized_signature = Default::default();
        signature.serialize(ref serialized_signature);
        test_claim.signature = serialized_signature.span();

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(!is_claim_valid, "Claim should be invalid when signature is invalid");
    }

    #[test]
    fn test_should_return_true_when_valid_signature() {
        let setup = setup_identity();
        let mut test_claim = get_test_claim(@setup);

        let is_claim_valid = setup
            .claim_issuer
            .is_claim_valid(
                test_claim.identity, test_claim.topic, test_claim.signature, test_claim.data,
            );
        assert!(
            is_claim_valid,
            "Claim should be valid when signature is valid when key has (claim/management) purpose",
        );
    }
}


pub mod read_key_methods {
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use crate::common::setup_identity;

    #[test]
    fn test_should_return_full_key_details() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );
        let (purposes, key_type, key_hash) = setup.alice_identity.get_key(alice_address_hash);
        assert!(key_hash == alice_address_hash, "returned key hash does not match");
        assert!(key_type == 1, "returned key type does not match");
        assert!(purposes == array![1].span(), "returned key purposes does not match");
    }

    #[test]
    fn test_should_return_existing_key_purposes() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );
        let purposes = setup.alice_identity.get_key_purposes(alice_address_hash);
        assert!(purposes == array![1].span(), "returned key purposes does not match");
    }

    #[test]
    fn test_should_return_existing_keys_with_given_purpose() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );
        let alice_pubkey_hash = poseidon_hash_span(
            array![setup.accounts.alice_key.public_key].span(),
        );
        let keys = setup.alice_identity.get_keys_by_purpose(1);
        assert!(
            keys == array![alice_address_hash, alice_pubkey_hash].span(),
            "returned keys for purpose does not match",
        );
    }

    #[test]
    fn test_should_return_true_if_key_has_given_purpose() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );
        let key_has_purpose = setup.alice_identity.key_has_purpose(alice_address_hash, 1);
        assert!(key_has_purpose, "key does not have expected purposes");
    }

    #[test]
    fn test_should_return_true_if_key_does_not_have_given_purpose_but_is_a_management_key() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );
        let key_has_purpose = setup.alice_identity.key_has_purpose(alice_address_hash, 2);
        assert!(key_has_purpose, "key does not have expected purposes");
    }

    #[test]
    fn test_should_return_false_if_key_does_not_have_given_purpose() {
        let setup = setup_identity();
        let bob_address_hash = poseidon_hash_span(
            array![setup.accounts.bob_account.contract_address.into()].span(),
        );
        let key_has_purpose = setup.alice_identity.key_has_purpose(bob_address_hash, 2);
        assert!(!key_has_purpose, "key shouldnt have given purpose");
    }
}

pub mod add_key {
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::identity::interface::ierc734;
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;

    #[test]
    #[should_panic(expected: 'Sender not have management key')]
    fn test_should_panic_when_caller_not_has_management_key() {
        let setup = setup_identity();
        let bob_address_hash = poseidon_hash_span(
            array![setup.accounts.bob_account.contract_address.into()].span(),
        );
        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
        );
        setup.alice_identity.add_key(bob_address_hash, 1, 1);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }

    #[test]
    fn test_should_add_purpose_to_existing_key() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.add_key(alice_address_hash, 2, 1);
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let (purposes, key_type, key_hash) = setup.alice_identity.get_key(alice_address_hash);
        assert!(key_hash == alice_address_hash, "returned key hash does not match");
        assert!(key_type == 1, "returned key type does not match");
        assert!(purposes == array![1, 2].span(), "returned key purposes does not match");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::KeyAdded(
                            ierc734::KeyAdded { key: alice_address_hash, purpose: 2, key_type: 1 },
                        ),
                    ),
                ],
            );
    }

    #[test]
    fn test_should_create_new_key_with_given_purpose() {
        let setup = setup_identity();
        let bob_address_hash = poseidon_hash_span(
            array![setup.accounts.bob_account.contract_address.into()].span(),
        );

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.add_key(bob_address_hash, 1, 1);
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let (purposes, key_type, key_hash) = setup.alice_identity.get_key(bob_address_hash);
        assert!(key_hash == bob_address_hash, "returned key hash does not match");
        assert!(key_type == 1, "returned key type does not match");
        assert!(purposes == array![1].span(), "returned key purposes does not match");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::KeyAdded(
                            ierc734::KeyAdded { key: bob_address_hash, purpose: 1, key_type: 1 },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: 'Key already has given purpose')]
    fn test_should_panic_when_key_already_has_given_purpose() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.add_key(alice_address_hash, 1, 1);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }
}

pub mod remove_key {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::identity::interface::ierc734;
    use onchain_id_starknet::identity::interface::iidentity::IdentityABIDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;

    #[test]
    #[should_panic(expected: 'Sender not have management key')]
    fn test_should_panic_when_caller_not_has_management_key() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );

        setup.alice_identity.remove_key(alice_address_hash, 1);
    }

    #[test]
    fn test_should_remove_purpose_from_existing_key() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.remove_key(alice_address_hash, 1);
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let (purposes, key_type, key_hash) = setup.alice_identity.get_key(alice_address_hash);
        assert!(key_hash == Zero::zero(), "returned key hash does not match");
        assert!(key_type == Zero::zero(), "returned key type does not match");
        assert!(purposes == array![].span(), "returned key purposes does not match");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::KeyRemoved(
                            ierc734::KeyRemoved {
                                key: alice_address_hash, purpose: 1, key_type: 1,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: 'Key is not registered')]
    fn test_should_panic_when_key_does_not_exist() {
        let setup = setup_identity();
        let bob_address_hash = poseidon_hash_span(
            array![setup.accounts.bob_account.contract_address.into()].span(),
        );

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.remove_key(bob_address_hash, 2);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Key doesnt have such purpose')]
    fn test_should_panic_when_key_does_not_have_given_purpose() {
        let setup = setup_identity();
        let alice_address_hash = poseidon_hash_span(
            array![setup.accounts.alice_account.contract_address.into()].span(),
        );

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.remove_key(alice_address_hash, 2);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }
}

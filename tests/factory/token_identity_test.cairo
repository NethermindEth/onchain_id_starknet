pub mod add_remove_token_factory {
    use core::num::traits::Zero;
    use onchain_id_starknet::factory::factory::IdFactory;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_factory;

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_add_when_caller_not_owner() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.identity_factory.add_token_factory(setup.accounts.alice_account.contract_address);
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_remove_when_caller_not_owner() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.identity_factory.remove_token_factory(setup.accounts.alice_account.contract_address);
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'token factory address zero')]
    fn test_should_panic_when_add_when_token_factory_is_zero() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.identity_factory.add_token_factory(Zero::zero());
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'token factory address zero')]
    fn test_should_panic_when_remove_when_token_factory_is_zero() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.identity_factory.remove_token_factory(Zero::zero());
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'already a factory')]
    fn test_should_panic_when_add_when_address_already_token_factory() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.identity_factory.add_token_factory(setup.accounts.alice_account.contract_address);
        /// adding twice should panic
        setup.identity_factory.add_token_factory(setup.accounts.alice_account.contract_address);
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'not a factory')]
    fn test_should_panic_when_remove_when_address_is_not_token_factory() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.identity_factory.remove_token_factory(setup.accounts.bob_account.contract_address);
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    fn test_should_add_token_factory() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        let mut spy = spy_events();

        setup.identity_factory.add_token_factory(setup.accounts.alice_account.contract_address);
        stop_cheat_caller_address(setup.identity_factory.contract_address);
        assert!(
            setup.identity_factory.is_token_factory(setup.accounts.alice_account.contract_address),
            "Alice is not added as token factory",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::TokenFactoryAdded(
                            IdFactory::TokenFactoryAdded {
                                factory: setup.accounts.alice_account.contract_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    fn test_should_remove_token_factory() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );

        setup.identity_factory.add_token_factory(setup.accounts.alice_account.contract_address);
        assert!(
            setup.identity_factory.is_token_factory(setup.accounts.alice_account.contract_address),
            "Alice is not added as token factory",
        );

        let mut spy = spy_events();
        setup.identity_factory.remove_token_factory(setup.accounts.alice_account.contract_address);
        stop_cheat_caller_address(setup.identity_factory.contract_address);

        assert!(
            !setup.identity_factory.is_token_factory(setup.accounts.alice_account.contract_address),
            "Alice is still a token factory",
        );
        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::TokenFactoryRemoved(
                            IdFactory::TokenFactoryRemoved {
                                factory: setup.accounts.alice_account.contract_address,
                            },
                        ),
                    ),
                ],
            );
    }
}

pub mod create_token_identity {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::factory::IdFactory;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_factory;

    #[test]
    #[should_panic(expected: 'only factory or owner can call')]
    fn test_should_panic_when_caller_not_authorized() {
        let setup = setup_factory();
        let alice_account_address = setup.accounts.alice_account.contract_address;
        start_cheat_caller_address(setup.identity_factory.contract_address, alice_account_address);
        setup
            .identity_factory
            .create_token_identity(alice_account_address, alice_account_address, 'test_salt');
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'token address zero')]
    fn test_should_panic_when_token_address_is_zero() {
        let setup = setup_factory();

        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_token_identity(
                Zero::zero(), setup.accounts.alice_account.contract_address, 'test_salt',
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'token owner address zero')]
    fn test_should_panic_when_owner_is_zero() {
        let setup = setup_factory();

        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_token_identity(
                setup.accounts.alice_account.contract_address, Zero::zero(), 'test_salt',
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'salt cannot be zero')]
    fn test_should_panic_when_salt_is_zero() {
        let setup = setup_factory();
        let alice_account_address = setup.accounts.alice_account.contract_address;
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_token_identity(alice_account_address, alice_account_address, Zero::zero());
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    fn test_should_create_token_identity() {
        let setup = setup_factory();
        let alice_account_address = setup.accounts.alice_account.contract_address;
        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        let deployed_identity = setup
            .identity_factory
            .create_token_identity(
                alice_account_address, setup.accounts.bob_account.contract_address, 'salt1',
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
        let token_identity_address = setup.identity_factory.get_identity(alice_account_address);
        assert!(deployed_identity == token_identity_address, "token identity address mismatch");
        let token = setup.identity_factory.get_token(token_identity_address);
        assert!(token == alice_account_address, "token address not eq alice address");
        assert!(
            setup
                .identity_factory
                .is_salt_taken(poseidon_hash_span(array!['Token', 'salt1'].span())),
            "salt not taken",
        );
        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::TokenLinked(
                            IdFactory::TokenLinked {
                                token: token, identity: token_identity_address,
                            },
                        ),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(
                            IdFactory::Deployed { deployed_address: token_identity_address },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: 'salt already taken')]
    fn test_should_panic_when_salt_is_taken() {
        let setup = setup_factory();
        let alice_account_address = setup.accounts.alice_account.contract_address;
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_token_identity(
                alice_account_address, setup.accounts.bob_account.contract_address, 'salt1',
            );
        // using same nonce twice should panic
        setup
            .identity_factory
            .create_token_identity(
                alice_account_address, setup.accounts.bob_account.contract_address, 'salt1',
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'address already linked token')]
    fn test_should_panic_when_token_already_linked_to_identity() {
        let setup = setup_factory();
        let alice_account_address = setup.accounts.alice_account.contract_address;
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_token_identity(
                alice_account_address, setup.accounts.bob_account.contract_address, 'salt1',
            );
        // already linked should panic
        setup
            .identity_factory
            .create_token_identity(
                alice_account_address, setup.accounts.bob_account.contract_address, 'salt2',
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }
}

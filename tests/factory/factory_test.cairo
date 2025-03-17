pub mod constructor {
    use core::num::traits::Zero;
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
    use crate::common::setup_factory;
    #[test]
    #[should_panic]
    fn test_should_panic_when_deployment_when_implementation_authority_zero_address() {
        let setup = setup_factory();
        let factory_contract = declare("IdFactory").unwrap().contract_class();
        factory_contract
            .deploy(@array![Zero::zero(), setup.accounts.owner_account.contract_address.into()])
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_deployment_when_owner_is_zero_address() {
        let setup = setup_factory();
        let factory_contract = declare("IdFactory").unwrap().contract_class();
        factory_contract
            .deploy(@array![setup.implementation_authority.contract_address.into(), Zero::zero()])
            .unwrap();
    }
}

pub mod create_identity {
    use core::num::traits::Zero;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};
    use crate::common::{setup_factory, setup_identity};

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_is_not_authorized() {
        let setup = setup_factory();
        setup.identity_factory.create_identity(Zero::zero(), 'salt');
    }

    #[test]
    #[should_panic(expected: 'wallet is zero address')]
    fn test_should_panic_when_wallet_zero_address() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.identity_factory.create_identity(Zero::zero(), 'salt');
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'salt cannot be zero')]
    fn test_should_panic_when_salt_is_zero() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_identity(setup.accounts.david_account.contract_address, Zero::zero());
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'salt already taken')]
    fn test_should_panic_when_salt_is_taken() {
        let setup = setup_factory();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_identity(setup.accounts.carol_account.contract_address, 'salt_used');
        setup
            .identity_factory
            .create_identity(setup.accounts.david_account.contract_address, 'salt_used');
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: 'wallet already linked')]
    fn test_should_panic_when_wallet_already_linked_to_an_identity() {
        let setup = setup_identity();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_identity(setup.accounts.alice_account.contract_address, 'new_salt');
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }
}

pub mod create_identity_with_management_keys {
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::factory::IdFactory;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use onchain_id_starknet::identity::interface::ierc734;
    use onchain_id_starknet::identity::interface::iidentity::{
        IdentityABIDispatcher, IdentityABIDispatcherTrait,
    };
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;

    #[test]
    #[should_panic(expected: 'empty list of managent keys')]
    fn test_should_panic_when_no_management_keys_are_provided() {
        let setup = setup_identity();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .identity_factory
            .create_identity_with_management_keys(
                setup.accounts.david_account.contract_address, 'salt1', array![],
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    #[should_panic(expected: "wallet is also listed in management keys")]
    fn test_should_panic_when_wallet_is_included_in_management_keys() {
        let setup = setup_identity();
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        let dummy_key_1_hash = poseidon_hash_span(array!['dummy_key_1'].span());
        let david_account_address_hash = poseidon_hash_span(
            array![setup.accounts.david_account.contract_address.into()].span(),
        );
        setup
            .identity_factory
            .create_identity_with_management_keys(
                setup.accounts.david_account.contract_address,
                'salt1',
                array![dummy_key_1_hash, david_account_address_hash],
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
    }

    #[test]
    fn test_should_deploy_identity_with_management_keys_and_link_wallet_to_identity() {
        let setup = setup_identity();
        let dummy_key_1_hash = poseidon_hash_span(array!['dummy_key_1'].span());
        let dummy_key_2_hash = poseidon_hash_span(array!['dummy_key_2'].span());
        start_cheat_caller_address(
            setup.identity_factory.contract_address, setup.accounts.owner_account.contract_address,
        );
        let mut spy = spy_events();
        let deployed_address = setup
            .identity_factory
            .create_identity_with_management_keys(
                setup.accounts.david_account.contract_address,
                'salt1',
                array![dummy_key_1_hash, dummy_key_2_hash],
            );
        stop_cheat_caller_address(setup.identity_factory.contract_address);
        let factory_address_hash = poseidon_hash_span(
            array![setup.identity_factory.contract_address.into()].span(),
        );
        spy
            .assert_emitted(
                @array![
                    (
                        deployed_address,
                        ierc734::ERC734Event::KeyAdded(
                            ierc734::KeyAdded {
                                key: factory_address_hash, purpose: 1, key_type: 1,
                            },
                        ),
                    ),
                    (
                        deployed_address,
                        ierc734::ERC734Event::KeyAdded(
                            ierc734::KeyAdded { key: dummy_key_1_hash, purpose: 1, key_type: 1 },
                        ),
                    ),
                    (
                        deployed_address,
                        ierc734::ERC734Event::KeyAdded(
                            ierc734::KeyAdded { key: dummy_key_2_hash, purpose: 1, key_type: 1 },
                        ),
                    ),
                    (
                        deployed_address,
                        ierc734::ERC734Event::KeyRemoved(
                            ierc734::KeyRemoved {
                                key: factory_address_hash, purpose: 1, key_type: 1,
                            },
                        ),
                    ),
                ],
            );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(IdFactory::Deployed { deployed_address }),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::WalletLinked(
                            IdFactory::WalletLinked {
                                wallet: setup.accounts.david_account.contract_address,
                                identity: deployed_address,
                            },
                        ),
                    ),
                ],
            );

        let david_identity = IdentityABIDispatcher { contract_address: deployed_address };
        assert!(
            !david_identity.key_has_purpose(factory_address_hash, 1), "Factory key not removed",
        );
        assert!(david_identity.key_has_purpose(dummy_key_1_hash, 1), "dummy key 1 not registered");
        assert!(david_identity.key_has_purpose(dummy_key_2_hash, 1), "dummy key 2 not registered");
    }
}

pub mod link_unlink_wallet {
    pub mod link_wallet {
        use core::num::traits::Zero;
        use onchain_id_starknet::factory::factory::IdFactory;
        use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
        use snforge_std::{
            EventSpyAssertionsTrait, spy_events, start_cheat_caller_address,
            stop_cheat_caller_address,
        };
        use crate::common::setup_identity;

        #[test]
        #[should_panic(expected: 'wallet is zero address')]
        fn test_should_revert_when_new_wallet_is_zero_address() {
            let setup = setup_identity();
            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.identity_factory.link_wallet(Zero::zero());
            stop_cheat_caller_address(setup.identity_factory.contract_address);
        }

        #[test]
        #[should_panic(expected: 'wallet not linked to identity')]
        fn test_should_revert_when_caller_is_not_linked_wallet() {
            let setup = setup_identity();
            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.david_account.contract_address,
            );
            setup.identity_factory.link_wallet(setup.accounts.david_account.contract_address);
            stop_cheat_caller_address(setup.identity_factory.contract_address);
        }

        #[test]
        #[should_panic(expected: 'wallet already linked')]
        fn test_should_revert_when_new_wallet_already_linked_identity() {
            let setup = setup_identity();
            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.bob_account.contract_address,
            );
            setup.identity_factory.link_wallet(setup.accounts.alice_account.contract_address);
            stop_cheat_caller_address(setup.identity_factory.contract_address);
        }

        #[test]
        #[should_panic(expected: 'address already linked token')]
        fn test_should_revert_when_new_wallet_already_linked_to_token_identity() {
            let setup = setup_identity();

            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.bob_account.contract_address,
            );
            setup.identity_factory.link_wallet(setup.token_address);
            stop_cheat_caller_address(setup.identity_factory.contract_address);
        }

        #[test]
        fn test_should_link_new_wallet_to_existing_identity() {
            let setup = setup_identity();

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.identity_factory.link_wallet(setup.accounts.david_account.contract_address);
            stop_cheat_caller_address(setup.identity_factory.contract_address);

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.identity_factory.contract_address,
                            IdFactory::Event::WalletLinked(
                                IdFactory::WalletLinked {
                                    wallet: setup.accounts.david_account.contract_address,
                                    identity: setup.alice_identity.contract_address,
                                },
                            ),
                        ),
                    ],
                );

            let wallets = setup.identity_factory.get_wallets(setup.alice_identity.contract_address);
            assert!(
                wallets == [
                    setup.accounts.alice_account.contract_address,
                    setup.accounts.david_account.contract_address,
                ]
                    .span(),
                "key not linked",
            );
        }
    }

    pub mod unlink_wallet {
        use core::num::traits::Zero;
        use onchain_id_starknet::factory::factory::IdFactory;
        use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
        use snforge_std::{
            EventSpyAssertionsTrait, spy_events, start_cheat_caller_address,
            stop_cheat_caller_address,
        };
        use crate::common::setup_identity;

        #[test]
        #[should_panic(expected: 'wallet is zero address')]
        fn test_should_panic_when_wallet_to_unlink_is_zero_address() {
            let setup = setup_identity();
            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.identity_factory.unlink_wallet(Zero::zero());
            stop_cheat_caller_address(setup.identity_factory.contract_address);
        }

        #[test]
        #[should_panic(expected: 'cant remove caller address')]
        fn test_should_panic_when_wallet_to_unlink_is_caller() {
            let setup = setup_identity();
            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.identity_factory.unlink_wallet(setup.accounts.alice_account.contract_address);
            stop_cheat_caller_address(setup.identity_factory.contract_address);
        }
        #[test]
        #[should_panic(expected: 'only linked wallet can unlink')]
        fn test_should_panic_when_caller_is_not_linked() {
            let setup = setup_identity();
            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.david_account.contract_address,
            );
            setup.identity_factory.unlink_wallet(setup.accounts.alice_account.contract_address);
            stop_cheat_caller_address(setup.identity_factory.contract_address);
        }

        #[test]
        fn test_should_unlink_wallet() {
            let setup = setup_identity();

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.identity_factory.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.identity_factory.link_wallet(setup.accounts.david_account.contract_address);
            let wallets_mid = setup
                .identity_factory
                .get_wallets(setup.alice_identity.contract_address);
            assert!(
                wallets_mid == [
                    setup.accounts.alice_account.contract_address,
                    setup.accounts.david_account.contract_address,
                ]
                    .span(),
                "key not linked",
            );
            setup.identity_factory.unlink_wallet(setup.accounts.david_account.contract_address);
            stop_cheat_caller_address(setup.identity_factory.contract_address);

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.identity_factory.contract_address,
                            IdFactory::Event::WalletUnlinked(
                                IdFactory::WalletUnlinked {
                                    wallet: setup.accounts.david_account.contract_address,
                                    identity: setup.alice_identity.contract_address,
                                },
                            ),
                        ),
                    ],
                );
            let wallets_after = setup
                .identity_factory
                .get_wallets(setup.alice_identity.contract_address);
            assert!(
                wallets_after == [setup.accounts.alice_account.contract_address].span(),
                "key not unlinked",
            );
        }
    }
}


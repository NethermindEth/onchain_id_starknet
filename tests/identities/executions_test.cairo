use onchain_id_starknet::mocks::mock_simple_storage::ISimpleStorageDispatcher;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

fn deploy_simple_storage() -> ISimpleStorageDispatcher {
    let mock_simple_storage_contract = declare("MockSimpleStorage").unwrap().contract_class();
    let (mock_simple_storage_address, _) = mock_simple_storage_contract.deploy(@array![]).unwrap();
    ISimpleStorageDispatcher { contract_address: mock_simple_storage_address }
}

pub mod execute {
    pub mod when_management_key {
        use core::poseidon::poseidon_hash_span;
        use onchain_id_starknet::interface::ierc734;
        use onchain_id_starknet::interface::iidentity::IdentityABIDispatcherTrait;
        use onchain_id_starknet::mocks::mock_simple_storage::ISimpleStorageDispatcherTrait;
        use snforge_std::{
            EventSpyAssertionsTrait, spy_events, start_cheat_caller_address,
            stop_cheat_caller_address,
        };
        use crate::common::setup_identity;
        use super::super::deploy_simple_storage;

        #[test]
        fn test_should_execute_immediately_when_non_self_call() {
            let setup = setup_identity();
            let simple_storage_dispatcher = deploy_simple_storage();

            let to = simple_storage_dispatcher.contract_address;
            let selector = selector!("set_value");
            let calldata = array!['test_val_to_store'];
            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
            stop_cheat_caller_address(setup.alice_identity.contract_address);
            assert!(
                simple_storage_dispatcher.get_value() == 'test_val_to_store',
                "Didnt execute the call",
            );

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::Approved(
                                ierc734::Approved { execution_id, approved: true },
                            ),
                        ),
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::Executed(
                                ierc734::Executed {
                                    execution_id, to, selector, data: calldata.span(),
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        fn test_should_execute_immediately_when_self_call() {
            let setup = setup_identity();

            let alice_address_hash = poseidon_hash_span(
                array![setup.accounts.alice_account.contract_address.into()].span(),
            );
            let to = setup.alice_identity.contract_address;
            let selector = selector!("add_key");
            let calldata = array![alice_address_hash, 3, 1];

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
            stop_cheat_caller_address(setup.alice_identity.contract_address);
            assert!(
                setup.alice_identity.get_key_purposes(alice_address_hash) == array![1, 3].span(),
                "Key purposes does not match",
            );

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::Approved(
                                ierc734::Approved { execution_id, approved: true },
                            ),
                        ),
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::Executed(
                                ierc734::Executed {
                                    execution_id, to, selector, data: calldata.span(),
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        #[ignore]
        /// NOTE: In starknet we cannot garcefully handle failed calls. see
        /// {https://book.cairo-lang.org/appendix-08-system-calls.html?highlight=call_con#call_contract}
        fn test_should_emit_execution_failed_event_on_failing_call() {
            let setup = setup_identity();

            let alice_address_hash = poseidon_hash_span(
                array![setup.accounts.alice_account.contract_address.into()].span(),
            );
            let to = setup.alice_identity.contract_address;
            let selector = selector!("add_key");
            let calldata = array![alice_address_hash, 1, 1];

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
            stop_cheat_caller_address(setup.alice_identity.contract_address);
            assert!(
                setup.alice_identity.get_key_purposes(alice_address_hash) == array![1, 3].span(),
                "Key purposes does not match",
            );

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::Approved(
                                ierc734::Approved { execution_id, approved: true },
                            ),
                        ),
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::ExecutionFailed(
                                ierc734::ExecutionFailed {
                                    execution_id, to, selector, data: calldata.span(),
                                },
                            ),
                        ),
                    ],
                );
        }
    }

    pub mod when_action_key {
        use core::poseidon::poseidon_hash_span;
        use onchain_id_starknet::interface::ierc734;
        use onchain_id_starknet::interface::iidentity::IdentityABIDispatcherTrait;
        use onchain_id_starknet::mocks::mock_simple_storage::ISimpleStorageDispatcherTrait;
        use snforge_std::{
            EventSpyAssertionsTrait, spy_events, start_cheat_caller_address,
            stop_cheat_caller_address,
        };
        use crate::common::setup_identity;
        use super::super::deploy_simple_storage;

        #[test]
        fn test_should_create_execution_request_when_target_is_identity_contract() {
            let setup = setup_identity();

            let alice_address_hash = poseidon_hash_span(
                array![setup.accounts.alice_account.contract_address.into()].span(),
            );

            let carol_address_hash = poseidon_hash_span(
                array![setup.accounts.carol_account.contract_address.into()].span(),
            );

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.alice_identity.add_key(carol_address_hash, 2, 1);
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            let to = setup.alice_identity.contract_address;
            let selector = selector!("add_key");
            let calldata = array![alice_address_hash, 3, 1];

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.carol_account.contract_address,
            );
            let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::ExecutionRequested(
                                ierc734::ExecutionRequested {
                                    execution_id, to, selector, data: calldata.span(),
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        fn test_should_execute_immediately_when_target_is_another_contract() {
            let setup = setup_identity();
            let simple_storage_dispatcher = deploy_simple_storage();

            let carol_address_hash = poseidon_hash_span(
                array![setup.accounts.carol_account.contract_address.into()].span(),
            );

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.alice_account.contract_address,
            );
            setup.alice_identity.add_key(carol_address_hash, 2, 1);
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            let to = simple_storage_dispatcher.contract_address;
            let selector = selector!("set_value");
            let calldata = array!['test_val_to_store'];

            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address,
                setup.accounts.carol_account.contract_address,
            );
            let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            assert!(
                simple_storage_dispatcher.get_value() == 'test_val_to_store',
                "Didnt execute the call",
            );

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::Approved(
                                ierc734::Approved { execution_id, approved: true },
                            ),
                        ),
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::Executed(
                                ierc734::Executed {
                                    execution_id, to, selector, data: calldata.span(),
                                },
                            ),
                        ),
                    ],
                );
        }

        #[test]
        #[ignore]
        /// NOTE: In starknet we cannot garcefully handle failed calls. see
        /// {https://book.cairo-lang.org/appendix-08-system-calls.html?highlight=call_con#call_contract}
        fn test_should_emit_execution_failed_on_failed_transaction() {
            assert(true, '');
        }
    }

    pub mod when_non_action_key {
        use onchain_id_starknet::interface::ierc734;
        use onchain_id_starknet::interface::iidentity::IdentityABIDispatcherTrait;
        use snforge_std::{
            EventSpyAssertionsTrait, spy_events, start_cheat_caller_address,
            stop_cheat_caller_address,
        };
        use crate::common::setup_identity;
        use super::super::deploy_simple_storage;

        #[test]
        fn test_should_create_pending_execution_request() {
            let setup = setup_identity();
            let simple_storage_dispatcher = deploy_simple_storage();

            let to = simple_storage_dispatcher.contract_address;
            let selector = selector!("set_value");
            let calldata = array!['test_val_to_store'];
            let mut spy = spy_events();

            start_cheat_caller_address(
                setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
            );
            let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
            stop_cheat_caller_address(setup.alice_identity.contract_address);

            spy
                .assert_emitted(
                    @array![
                        (
                            setup.alice_identity.contract_address,
                            ierc734::ERC734Event::ExecutionRequested(
                                ierc734::ExecutionRequested {
                                    execution_id, to, selector, data: calldata.span(),
                                },
                            ),
                        ),
                    ],
                );
        }
    }
}

pub mod approve {
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::interface::ierc734;
    use onchain_id_starknet::interface::iidentity::IdentityABIDispatcherTrait;
    use onchain_id_starknet::mocks::mock_simple_storage::ISimpleStorageDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use crate::common::setup_identity;
    use super::deploy_simple_storage;

    #[test]
    #[should_panic(expected: 'Non-existing execution')]
    fn test_should_revert_when_execution_request_not_found() {
        let setup = setup_identity();
        setup.alice_identity.approve(2, true);
    }

    #[test]
    #[should_panic(expected: 'Request already executed')]
    fn test_should_revert_when_execution_request_is_already_executed() {
        let setup = setup_identity();
        let simple_storage_dispatcher = deploy_simple_storage();

        let to = simple_storage_dispatcher.contract_address;
        let selector = selector!("set_value");
        let calldata = array!['test_val_to_store'];

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
        // approving already executed execution should panic
        setup.alice_identity.approve(execution_id, true);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Sender not have action key')]
    fn test_should_revert_when_target_is_another_contract_as_non_action_nor_management_key() {
        let setup = setup_identity();
        let simple_storage_dispatcher = deploy_simple_storage();

        let to = simple_storage_dispatcher.contract_address;
        let selector = selector!("set_value");
        let calldata = array!['test_val_to_store'];

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
        );
        let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
        setup.alice_identity.approve(execution_id, true);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Sender not have management key')]
    fn test_should_revert_when_target_is_identity_contract_as_non_management_key() {
        let setup = setup_identity();

        let to = setup.alice_identity.contract_address;
        let selector = selector!("add_key");
        let calldata = array![
            poseidon_hash_span(array![setup.accounts.bob_account.contract_address.into()].span()),
            1,
            1,
        ];

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
        );
        let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.david_account.contract_address,
        );
        setup.alice_identity.approve(execution_id, true);
        stop_cheat_caller_address(setup.alice_identity.contract_address);
    }

    #[test]
    fn test_should_approve_the_execution_request_to_self_when_management_key() {
        let setup = setup_identity();

        let to = setup.alice_identity.contract_address;
        let selector = selector!("add_key");
        let bob_address_hash = poseidon_hash_span(
            array![setup.accounts.bob_account.contract_address.into()].span(),
        );
        let calldata = array![bob_address_hash, 1, 1];

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
        );
        let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let mut spy = spy_events();
        // Approve with management key
        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.alice_account.contract_address,
        );
        setup.alice_identity.approve(execution_id, true);
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        assert!(
            setup.alice_identity.get_key_purposes(bob_address_hash) == array![1].span(),
            "Key purposes does not match",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::Approved(
                            ierc734::Approved { execution_id, approved: true },
                        ),
                    ),
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::Executed(
                            ierc734::Executed { execution_id, to, selector, data: calldata.span() },
                        ),
                    ),
                ],
            );
    }

    #[test]
    fn test_should_approve_the_execution_request_to_another_contract_when_action_key() {
        let setup = setup_identity();
        let simple_storage_dispatcher = deploy_simple_storage();

        let to = simple_storage_dispatcher.contract_address;
        let selector = selector!("set_value");
        let value_to_store = 'test_val_to_store';
        let calldata = array![value_to_store];

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
        );
        let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let mut spy = spy_events();
        // Approve with action key
        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.david_account.contract_address,
        );
        setup.alice_identity.approve(execution_id, true);
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        assert!(simple_storage_dispatcher.get_value() == value_to_store, "Call not executed");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::Approved(
                            ierc734::Approved { execution_id, approved: true },
                        ),
                    ),
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::Executed(
                            ierc734::Executed { execution_id, to, selector, data: calldata.span() },
                        ),
                    ),
                ],
            );
    }

    #[test]
    fn test_should_leave_approve_false() {
        let setup = setup_identity();
        let simple_storage_dispatcher = deploy_simple_storage();

        let to = simple_storage_dispatcher.contract_address;
        let selector = selector!("set_value");
        let value_to_store = 'test_val_to_store';
        let calldata = array![value_to_store];

        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.bob_account.contract_address,
        );
        let execution_id = setup.alice_identity.execute(to, selector, calldata.span());
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        let mut spy = spy_events();
        // Approve with action key
        start_cheat_caller_address(
            setup.alice_identity.contract_address, setup.accounts.david_account.contract_address,
        );
        setup.alice_identity.approve(execution_id, false);
        stop_cheat_caller_address(setup.alice_identity.contract_address);

        assert!(
            simple_storage_dispatcher.get_value() == '', "Call executed when expected otherwise",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.alice_identity.contract_address,
                        ierc734::ERC734Event::Approved(
                            ierc734::Approved { execution_id, approved: false },
                        ),
                    ),
                ],
            );
    }
}

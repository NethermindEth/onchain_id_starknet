use onchain_id_starknet::factory::interface::IIdFactoryDispatcher;
use onchain_id_starknet::gateway::interface::IGatewayDispatcher;
use onchain_id_starknet::proxy::interface::IIdentityImplementationAuthorityDispatcher;
use openzeppelin_access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use crate::common::{FactorySetup, TestAccounts, setup_factory};

pub const YEAR: u64 = 365 * 24 * 60 * 60;

#[derive(Drop)]
pub struct GatewaySetup {
    pub gateway: IGatewayDispatcher,
    pub identity_factory: IIdFactoryDispatcher,
    pub identity_contract: starknet::ClassHash,
    pub implementation_authority: IIdentityImplementationAuthorityDispatcher,
    pub accounts: TestAccounts,
}

pub fn setup_gateway(
    factory_setup: FactorySetup, signers_to_approve: Span<felt252>,
) -> GatewaySetup {
    let gateway_contract = declare("Gateway").unwrap().contract_class();
    let mut gateway_ctor_data: Array<felt252> = array![];
    factory_setup.identity_factory.contract_address.serialize(ref gateway_ctor_data);
    signers_to_approve.serialize(ref gateway_ctor_data);
    factory_setup.accounts.owner_account.contract_address.serialize(ref gateway_ctor_data);
    let (gateway_address, _) = gateway_contract.deploy(@gateway_ctor_data).unwrap();
    start_cheat_caller_address(
        factory_setup.identity_factory.contract_address,
        factory_setup.accounts.owner_account.contract_address,
    );
    IOwnableDispatcher { contract_address: factory_setup.identity_factory.contract_address }
        .transfer_ownership(gateway_address);
    assert!(
        IOwnableDispatcher { contract_address: factory_setup.identity_factory.contract_address }
            .owner() == gateway_address,
        "owner is not gateway",
    );
    stop_cheat_caller_address(factory_setup.identity_factory.contract_address);

    GatewaySetup {
        gateway: IGatewayDispatcher { contract_address: gateway_address },
        identity_factory: factory_setup.identity_factory,
        identity_contract: factory_setup.identity_contract,
        implementation_authority: factory_setup.implementation_authority,
        accounts: factory_setup.accounts,
    }
}

pub mod constructor {
    use core::num::traits::Zero;
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};

    #[test]
    #[should_panic]
    fn test_should_panic_when_factory_address_is_zero() {
        let gateway_contract = declare("Gateway").unwrap().contract_class();
        let mut gateway_ctor_data: Array<felt252> = array![Zero::zero()];
        let empty_array: Array<felt252> = array![];
        empty_array.serialize(ref gateway_ctor_data);
        gateway_ctor_data.append('owner_address');
        gateway_contract.deploy(@gateway_ctor_data).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_should_panic_when_specifying_more_than_ten_signer() {
        let gateway_contract = declare("Gateway").unwrap().contract_class();
        let array_with_more_than_ten_signer = array![
            'signer_1',
            'signer_2',
            'signer_3',
            'signer_4',
            'signer_5',
            'signer_6',
            'signer_7',
            'signer_8',
            'signer_9',
            'signer_10',
            'signer_11',
        ];

        let mut gateway_ctor_data: Array<felt252> = array!['dummy_factory'];
        array_with_more_than_ten_signer.serialize(ref gateway_ctor_data);
        gateway_ctor_data.append('owner_address');
        gateway_contract.deploy(@gateway_ctor_data).unwrap();
    }
}

pub mod approve_signer {
    use core::num::traits::Zero;
    use onchain_id_starknet::gateway::gateway::Gateway;
    use onchain_id_starknet::gateway::interface::IGatewayDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    #[should_panic(expected: "A required parameter was set to the zero address.")]
    fn test_should_panic_when_signer_is_zero() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.approve_signer(Zero::zero());
        stop_cheat_caller_address(setup.gateway.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_is_not_owner() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        setup.gateway.approve_signer(setup.accounts.alice_key.public_key);
    }

    #[test]
    #[should_panic(expected: "The signer attempted to add was already approved.")]
    fn test_should_panic_when_signer_already_approved() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.approve_signer(carol_pub_key);
        stop_cheat_caller_address(setup.gateway.contract_address);
    }

    #[test]
    fn test_should_approve_signer() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let david_pub_key = setup.accounts.david_key.public_key;
        assert!(!setup.gateway.is_approved_signer(david_pub_key), "David is already approved");
        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.approve_signer(david_pub_key);
        stop_cheat_caller_address(setup.gateway.contract_address);
        assert!(setup.gateway.is_approved_signer(david_pub_key), "David is not approved");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.gateway.contract_address,
                        Gateway::Event::SignerApproved(
                            Gateway::SignerApproved { signer: david_pub_key },
                        ),
                    ),
                ],
            );
    }
}

pub mod revoke_signer {
    use core::num::traits::Zero;
    use onchain_id_starknet::gateway::gateway::Gateway;
    use onchain_id_starknet::gateway::interface::IGatewayDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    #[should_panic(expected: "A required parameter was set to the zero address.")]
    fn test_should_panic_when_signer_is_zero() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signer(Zero::zero());
        stop_cheat_caller_address(setup.gateway.contract_address);
    }

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_is_not_owner() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        setup.gateway.revoke_signer(setup.accounts.alice_key.public_key);
    }

    #[test]
    #[should_panic(expected: "The signer attempted to remove was not approved.")]
    fn test_should_panic_when_signer_is_not_approved() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signer(setup.accounts.david_key.public_key);
        stop_cheat_caller_address(setup.gateway.contract_address);
    }

    #[test]
    fn test_should_revoke_signer() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let david_pub_key = setup.accounts.david_key.public_key;
        assert!(!setup.gateway.is_approved_signer(david_pub_key), "David is already approved");

        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        assert!(!setup.gateway.is_approved_signer(david_pub_key), "David is already approved");
        setup.gateway.approve_signer(david_pub_key);
        assert!(setup.gateway.is_approved_signer(david_pub_key), "David is not approved");
        let mut spy = spy_events();
        setup.gateway.revoke_signer(david_pub_key);
        assert!(!setup.gateway.is_approved_signer(david_pub_key), "David is not removed");
        stop_cheat_caller_address(setup.gateway.contract_address);

        spy
            .assert_emitted(
                @array![
                    (
                        setup.gateway.contract_address,
                        Gateway::Event::SignerRevoked(
                            Gateway::SignerRevoked { signer: david_pub_key },
                        ),
                    ),
                ],
            );
    }
}

pub mod deploy_identity_with_salt {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::factory::IdFactory;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use onchain_id_starknet::gateway::gateway::Gateway::SNIP12MetadataImpl;
    use onchain_id_starknet::gateway::interface::{Deployment, IGatewayDispatcherTrait, Signature};
    use onchain_id_starknet::identity::interface::iidentity::{
        IdentityABIDispatcher, IdentityABIDispatcherTrait,
    };
    use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_block_timestamp_global,
        start_cheat_caller_address, stop_cheat_block_timestamp_global, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    #[should_panic(expected: "A required parameter was set to the zero address.")]
    fn test_should_panic_when_input_address_is_zero() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup
            .gateway
            .deploy_identity_with_salt(
                Zero::zero(),
                'salt1',
                starknet::get_block_timestamp() + super::YEAR,
                Signature { r: Zero::zero(), s: Zero::zero(), y_parity: false },
            );
    }

    #[test]
    #[should_panic(expected: 'recover_public_key failed')]
    fn test_should_panic_when_invalid_signature() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup
            .gateway
            .deploy_identity_with_salt(
                setup.accounts.alice_account.contract_address,
                'salt1',
                starknet::get_block_timestamp() + super::YEAR,
                Signature { r: Zero::zero(), s: Zero::zero(), y_parity: false },
            );
    }

    #[test]
    #[should_panic(
        expected: "A requested ONCHAINID deployment was made and signed by a non-approved signer.",
    )]
    fn test_should_panic_when_signature_signed_by_non_authorized_signer() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);

        let (r, s) = setup.accounts.david_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .david_key
            .public_key;

        setup
            .gateway
            .deploy_identity_with_salt(
                setup.accounts.alice_account.contract_address,
                salt,
                expiration,
                Signature { r, s, y_parity },
            );
    }

    #[test]
    fn test_function_should_deploy_the_identity_when_signature_valid_when_signed_by_authorized_signer() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);

        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let mut spy = spy_events();

        setup
            .gateway
            .deploy_identity_with_salt(
                setup.accounts.alice_account.contract_address,
                salt,
                expiration,
                Signature { r, s, y_parity },
            );
        let identity_address = setup
            .identity_factory
            .get_identity(setup.accounts.alice_account.contract_address);
        let identity_dispatcher = IdentityABIDispatcher { contract_address: identity_address };
        assert!(
            identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.alice_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key havent registered in deployment",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(
                            IdFactory::Deployed { deployed_address: identity_address },
                        ),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::WalletLinked(
                            IdFactory::WalletLinked {
                                wallet: setup.accounts.alice_account.contract_address,
                                identity: identity_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    fn test_function_should_deploy_the_identity_when_signature_valid_when_no_expiry() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = Zero::zero();
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);

        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let mut spy = spy_events();

        setup
            .gateway
            .deploy_identity_with_salt(
                setup.accounts.alice_account.contract_address,
                salt,
                expiration,
                Signature { r, s, y_parity },
            );
        let identity_address = setup
            .identity_factory
            .get_identity(setup.accounts.alice_account.contract_address);
        let identity_dispatcher = IdentityABIDispatcher { contract_address: identity_address };
        assert!(
            identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.alice_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key havent registered in deployment",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(
                            IdFactory::Deployed { deployed_address: identity_address },
                        ),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::WalletLinked(
                            IdFactory::WalletLinked {
                                wallet: setup.accounts.alice_account.contract_address,
                                identity: identity_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: "A requested ONCHAINID deployment was made with a revoked signature.")]
    fn test_should_panic_when_signature_is_valid_but_revoked() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;
        let signature = Signature { r, s, y_parity };
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);
        setup
            .gateway
            .deploy_identity_with_salt(
                setup.accounts.alice_account.contract_address, salt, expiration, signature,
            );
    }

    #[test]
    #[should_panic(
        expected: "A requested ONCHAINID deployment was made with an expired signature.",
    )]
    fn test_should_panic_when_signature_is_valid_but_expired() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;
        let signature = Signature { r, s, y_parity };
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);
        start_cheat_block_timestamp_global(expiration + 1);
        setup
            .gateway
            .deploy_identity_with_salt(
                setup.accounts.alice_account.contract_address, salt, expiration, signature,
            );
        stop_cheat_block_timestamp_global();
    }
}

pub mod deploy_identity_with_salt_and_management_keys {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::factory::IdFactory;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use onchain_id_starknet::gateway::gateway::Gateway::SNIP12MetadataImpl;
    use onchain_id_starknet::gateway::interface::{
        DeploymentWithManagementKeys, IGatewayDispatcherTrait, Signature,
    };
    use onchain_id_starknet::identity::interface::iidentity::{
        IdentityABIDispatcher, IdentityABIDispatcherTrait,
    };
    use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_block_timestamp_global,
        start_cheat_caller_address, stop_cheat_block_timestamp_global, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    #[should_panic(expected: "A required parameter was set to the zero address.")]
    fn test_should_panic_when_input_address_is_zero() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup
            .gateway
            .deploy_identity_with_salt_and_management_keys(
                Zero::zero(),
                'salt1',
                [].span(),
                starknet::get_block_timestamp() + super::YEAR,
                Signature { r: Zero::zero(), s: Zero::zero(), y_parity: false },
            );
    }

    #[test]
    #[should_panic(expected: 'recover_public_key failed')]
    fn test_should_panic_when_invalid_signature() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup
            .gateway
            .deploy_identity_with_salt_and_management_keys(
                setup.accounts.alice_account.contract_address,
                'salt1',
                [].span(),
                starknet::get_block_timestamp() + super::YEAR,
                Signature { r: Zero::zero(), s: Zero::zero(), y_parity: false },
            );
    }

    #[test]
    #[should_panic(
        expected: "A requested ONCHAINID deployment was made and signed by a non-approved signer.",
    )]
    fn test_should_panic_when_signature_signed_by_non_authorized_signer() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let management_keys = array![
            poseidon_hash_span(array![setup.accounts.bob_account.contract_address.into()].span()),
        ]
            .span();
        let message = DeploymentWithManagementKeys {
            identity_owner, salt, management_keys, expiration,
        };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);

        let (r, s) = setup.accounts.david_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .bob_key
            .public_key;

        setup
            .gateway
            .deploy_identity_with_salt_and_management_keys(
                setup.accounts.alice_account.contract_address,
                salt,
                management_keys,
                expiration,
                Signature { r, s, y_parity },
            );
    }

    #[test]
    fn test_function_should_deploy_the_identity_when_signature_valid_when_signed_by_authorized_signer() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let management_keys = array![
            poseidon_hash_span(array![setup.accounts.bob_account.contract_address.into()].span()),
        ]
            .span();
        let message = DeploymentWithManagementKeys {
            identity_owner, salt, management_keys, expiration,
        };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let mut spy = spy_events();

        let identity_address_gateway = setup
            .gateway
            .deploy_identity_with_salt_and_management_keys(
                setup.accounts.alice_account.contract_address,
                salt,
                management_keys,
                expiration,
                Signature { r, s, y_parity },
            );

        let identity_address = setup
            .identity_factory
            .get_identity(setup.accounts.alice_account.contract_address);
        assert!(
            identity_address == identity_address_gateway,
            "returned and stored identity_address does not match",
        );
        let identity_dispatcher = IdentityABIDispatcher { contract_address: identity_address };
        assert!(
            !identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.alice_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key registered in deployment",
        );

        assert!(
            identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.bob_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key havent registered in deployment",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(
                            IdFactory::Deployed { deployed_address: identity_address },
                        ),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::WalletLinked(
                            IdFactory::WalletLinked {
                                wallet: setup.accounts.alice_account.contract_address,
                                identity: identity_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    fn test_function_should_deploy_the_identity_when_signature_valid_when_no_expiry() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = Zero::zero();
        let management_keys = array![
            poseidon_hash_span(array![setup.accounts.bob_account.contract_address.into()].span()),
        ]
            .span();
        let message = DeploymentWithManagementKeys {
            identity_owner, salt, management_keys, expiration,
        };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let mut spy = spy_events();

        let identity_address_gateway = setup
            .gateway
            .deploy_identity_with_salt_and_management_keys(
                setup.accounts.alice_account.contract_address,
                salt,
                management_keys,
                expiration,
                Signature { r, s, y_parity },
            );

        let identity_address = setup
            .identity_factory
            .get_identity(setup.accounts.alice_account.contract_address);
        assert!(
            identity_address == identity_address_gateway,
            "returned and stored identity_address does not match",
        );
        let identity_dispatcher = IdentityABIDispatcher { contract_address: identity_address };
        assert!(
            !identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.alice_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key registered in deployment",
        );

        assert!(
            identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.bob_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key havent registered in deployment",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(
                            IdFactory::Deployed { deployed_address: identity_address },
                        ),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::WalletLinked(
                            IdFactory::WalletLinked {
                                wallet: setup.accounts.alice_account.contract_address,
                                identity: identity_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: "A requested ONCHAINID deployment was made with a revoked signature.")]
    fn test_should_panic_when_signature_is_valid_but_revoked() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let management_keys = array![
            poseidon_hash_span(array![setup.accounts.bob_account.contract_address.into()].span()),
        ]
            .span();
        let message = DeploymentWithManagementKeys {
            identity_owner, salt, management_keys, expiration,
        };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();
        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let signature = Signature { r, s, y_parity };

        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);

        setup
            .gateway
            .deploy_identity_with_salt_and_management_keys(
                setup.accounts.alice_account.contract_address,
                salt,
                management_keys,
                expiration,
                signature,
            );
    }

    #[test]
    #[should_panic(
        expected: "A requested ONCHAINID deployment was made with an expired signature.",
    )]
    fn test_should_panic_when_signature_is_valid_but_expired() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let management_keys = array![
            poseidon_hash_span(array![setup.accounts.bob_account.contract_address.into()].span()),
        ]
            .span();
        let message = DeploymentWithManagementKeys {
            identity_owner, salt, management_keys, expiration,
        };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();

        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        start_cheat_block_timestamp_global(expiration + 1);
        setup
            .gateway
            .deploy_identity_with_salt_and_management_keys(
                setup.accounts.alice_account.contract_address,
                salt,
                management_keys,
                expiration,
                Signature { r, s, y_parity },
            );
        stop_cheat_block_timestamp_global();
    }
}

pub mod deploy_identity_for_wallet {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::factory::IdFactory;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use onchain_id_starknet::gateway::interface::IGatewayDispatcherTrait;
    use onchain_id_starknet::identity::interface::iidentity::{
        IdentityABIDispatcher, IdentityABIDispatcherTrait,
    };
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    #[should_panic(expected: "A required parameter was set to the zero address.")]
    fn test_should_panic_when_input_address_is_zero() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup.gateway.deploy_identity_for_wallet(Zero::zero());
    }

    #[test]
    fn test_should_deploy_identity_for_identity_owner_when_sender_not_identity_owner() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.bob_account.contract_address,
        );
        let identity_address_gateway = setup
            .gateway
            .deploy_identity_for_wallet(setup.accounts.alice_account.contract_address);
        stop_cheat_caller_address(setup.gateway.contract_address);

        let identity_address = setup
            .identity_factory
            .get_identity(setup.accounts.alice_account.contract_address);
        assert!(
            identity_address == identity_address_gateway,
            "returned and stored identity_address does not match",
        );
        let identity_dispatcher = IdentityABIDispatcher { contract_address: identity_address };

        assert!(
            identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.alice_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key havent registered in deployment",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(
                            IdFactory::Deployed { deployed_address: identity_address },
                        ),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::WalletLinked(
                            IdFactory::WalletLinked {
                                wallet: setup.accounts.alice_account.contract_address,
                                identity: identity_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    fn test_should_deploy_identity_when_identity_not_yet_deployed_for_this_wallet() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let mut spy = spy_events();

        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.alice_account.contract_address,
        );
        let identity_address_gateway = setup
            .gateway
            .deploy_identity_for_wallet(setup.accounts.alice_account.contract_address);
        stop_cheat_caller_address(setup.gateway.contract_address);

        let identity_address = setup
            .identity_factory
            .get_identity(setup.accounts.alice_account.contract_address);
        assert!(
            identity_address == identity_address_gateway,
            "returned and stored identity_address does not match",
        );
        let identity_dispatcher = IdentityABIDispatcher { contract_address: identity_address };

        assert!(
            identity_dispatcher
                .key_has_purpose(
                    poseidon_hash_span(
                        array![setup.accounts.alice_account.contract_address.into()].span(),
                    ),
                    1,
                ),
            "key havent registered in deployment",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::Deployed(
                            IdFactory::Deployed { deployed_address: identity_address },
                        ),
                    ),
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::WalletLinked(
                            IdFactory::WalletLinked {
                                wallet: setup.accounts.alice_account.contract_address,
                                identity: identity_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: 'Salt already taken')]
    fn test_should_panic_when_identity_already_deployed_for_this_wallet() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup.gateway.deploy_identity_for_wallet(setup.accounts.alice_account.contract_address);
        // second time deploying for same wallet should panic
        setup.gateway.deploy_identity_for_wallet(setup.accounts.alice_account.contract_address);
    }
}

pub mod transfer_factory_ownership {
    use onchain_id_starknet::gateway::interface::IGatewayDispatcherTrait;
    use openzeppelin_access::ownable::OwnableComponent;
    use openzeppelin_access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    fn test_should_transfer_ownership_of_the_factory() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let mut spy = spy_events();

        let factory_ownable_dispatcher = IOwnableDispatcher {
            contract_address: setup.identity_factory.contract_address,
        };
        assert!(
            factory_ownable_dispatcher.owner() == setup.gateway.contract_address,
            "Gateway is not the owner of the IdFactory",
        );
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.transfer_factory_ownership(setup.accounts.bob_account.contract_address);
        stop_cheat_caller_address(setup.gateway.contract_address);

        assert!(
            factory_ownable_dispatcher.owner() == setup.accounts.bob_account.contract_address,
            "Ownership of the IdFactory is not transferred",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        OwnableComponent::Event::OwnershipTransferred(
                            OwnableComponent::OwnershipTransferred {
                                previous_owner: setup.gateway.contract_address,
                                new_owner: setup.accounts.bob_account.contract_address,
                            },
                        ),
                    ),
                ],
            );
    }

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_is_not_the_owner() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup.gateway.transfer_factory_ownership(setup.accounts.bob_account.contract_address);
    }
}

pub mod revoke_signature {
    use onchain_id_starknet::gateway::gateway::Gateway;
    use onchain_id_starknet::gateway::gateway::Gateway::SNIP12MetadataImpl;
    use onchain_id_starknet::gateway::interface::{Deployment, IGatewayDispatcherTrait, Signature};
    use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_is_not_owner() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();
        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let signature = Signature { r, s, y_parity };

        setup.gateway.revoke_signature(signature);
    }

    #[test]
    #[should_panic(expected: "Attempted to revoke a signature that was already revoked.")]
    fn test_should_panic_when_signature_already_revoked() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();
        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let signature = Signature { r, s, y_parity };
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signature(signature);
        // revoking second time should fail
        setup.gateway.revoke_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);
    }

    #[test]
    fn test_should_revoked_signature() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();
        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let signature = Signature { r, s, y_parity };
        let mut spy = spy_events();

        assert!(!setup.gateway.is_revoked_signature(signature), "signature already revoked");
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);

        assert!(setup.gateway.is_revoked_signature(signature), "signature not revoked");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.gateway.contract_address,
                        Gateway::Event::SignatureRevoked(Gateway::SignatureRevoked { signature }),
                    ),
                ],
            );
    }
}

pub mod approve_signature {
    use onchain_id_starknet::gateway::gateway::Gateway;
    use onchain_id_starknet::gateway::gateway::Gateway::SNIP12MetadataImpl;
    use onchain_id_starknet::gateway::interface::{Deployment, IGatewayDispatcherTrait, Signature};
    use openzeppelin_utils::cryptography::snip12::OffchainMessageHash;
    use snforge_std::signature::SignerTrait;
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};

    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_is_not_owner() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();
        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let signature = Signature { r, s, y_parity };
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);

        setup.gateway.approve_signature(signature);
    }

    #[test]
    #[should_panic(expected: "Attempted to approve a signature that was not revoked.")]
    fn test_should_panic_when_signature_is_not_revoked() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();
        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let signature = Signature { r, s, y_parity };
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.approve_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);
    }

    #[test]
    fn test_should_approve_signature_when_signature_is_revoked() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let salt = 'salt_to_use';
        let identity_owner = setup.accounts.alice_account.contract_address;
        let expiration: u64 = starknet::get_block_timestamp() + super::YEAR;
        let message = Deployment { identity_owner, salt, expiration };

        let message_hash = message.get_message_hash(setup.gateway.contract_address);
        let (r, s) = setup.accounts.carol_key.sign(message_hash).unwrap();
        let y_parity = core::ecdsa::recover_public_key(message_hash, r, s, true)
            .unwrap() == setup
            .accounts
            .carol_key
            .public_key;

        let signature = Signature { r, s, y_parity };
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.revoke_signature(signature);
        assert!(setup.gateway.is_revoked_signature(signature), "signature not revoked");

        let mut spy = spy_events();

        setup.gateway.approve_signature(signature);
        stop_cheat_caller_address(setup.gateway.contract_address);

        assert!(!setup.gateway.is_revoked_signature(signature), "signature is not approved");

        spy
            .assert_emitted(
                @array![
                    (
                        setup.gateway.contract_address,
                        Gateway::Event::SignatureApproved(Gateway::SignatureApproved { signature }),
                    ),
                ],
            );
    }
}

pub mod call_factory {
    use core::num::traits::Zero;
    use onchain_id_starknet::factory::factory::IdFactory;
    use onchain_id_starknet::factory::interface::IIdFactoryDispatcherTrait;
    use onchain_id_starknet::gateway::interface::IGatewayDispatcherTrait;
    use snforge_std::{
        EventSpyAssertionsTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address,
    };
    use super::{setup_factory, setup_gateway};
    #[test]
    #[should_panic(expected: 'Caller is not the owner')]
    fn test_should_panic_when_caller_is_not_owner() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        setup.gateway.call_factory(selector!("add_token_factory"), array![Zero::zero()].span())
    }

    #[test]
    #[should_panic(expected: 'Token factory address zero')]
    fn test_should_panic_when_calling_as_owner_with_invalid_parameters() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup.gateway.call_factory(selector!("add_token_factory"), array![Zero::zero()].span());
        stop_cheat_caller_address(setup.gateway.contract_address);
    }

    #[test]
    fn test_should_execute_function_call_with_correct_parameters() {
        let factory_setup = setup_factory();
        let carol_pub_key = factory_setup.accounts.carol_key.public_key;
        let setup = setup_gateway(factory_setup, array![carol_pub_key].span());

        let mut spy = spy_events();
        start_cheat_caller_address(
            setup.gateway.contract_address, setup.accounts.owner_account.contract_address,
        );
        setup
            .gateway
            .call_factory(
                selector!("add_token_factory"),
                array![setup.accounts.bob_account.contract_address.into()].span(),
            );
        stop_cheat_caller_address(setup.gateway.contract_address);

        assert!(
            setup.identity_factory.is_token_factory(setup.accounts.bob_account.contract_address),
            "Not added as token factory",
        );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.identity_factory.contract_address,
                        IdFactory::Event::TokenFactoryAdded(
                            IdFactory::TokenFactoryAdded {
                                factory: setup.accounts.bob_account.contract_address,
                            },
                        ),
                    ),
                ],
            );
    }
}

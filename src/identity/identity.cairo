#[starknet::contract]
pub mod Identity {
    use core::num::traits::Zero;
    use openzeppelin_upgrades::interface::IUpgradeable;
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent;
    use openzeppelin_utils::cryptography::snip12::SNIP12Metadata;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ClassHash, ContractAddress};
    use crate::identity::component::IdentityComponent;
    use crate::version::version;

    #[abi(embed_v0)]
    impl VersionImpl = version::VersionImpl<ContractState>;

    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    component!(path: IdentityComponent, storage: identity, event: IdentityEvent);

    #[abi(embed_v0)]
    impl IdentityImpl = IdentityComponent::IdentityImpl<ContractState>;

    #[abi(embed_v0)]
    impl ERC734Impl = IdentityComponent::ERC734Impl<ContractState>;

    #[abi(embed_v0)]
    impl ERC735Impl = IdentityComponent::ERC735Impl<ContractState>;

    #[abi(embed_v0)]
    impl SNIP12MetadataExternalImpl =
        IdentityComponent::SNIP12MetadataExternalImpl<ContractState>;

    impl IdentityInternalImpl = IdentityComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        implementation_authority: ContractAddress,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        #[substorage(v0)]
        identity: IdentityComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        IdentityEvent: IdentityComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    pub mod Errors {
        pub const IMPLEMENTATION_AUTH_ZERO_ADDRESS: felt252 = 'Impl. Auth. Zero Address';
        pub const CALLER_NOT_IMPLEMENTATION_AUTHORITY: felt252 = 'Caller is not Impl. Auth.';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        implementation_authority: ContractAddress,
        initial_management_key: ContractAddress,
    ) {
        assert(implementation_authority.is_non_zero(), Errors::IMPLEMENTATION_AUTH_ZERO_ADDRESS);
        self.implementation_authority.write(implementation_authority);
        self.identity.initialize(initial_management_key);
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        /// Upgrades the implementation used by this contract.
        ///
        /// # Arguments
        ///
        /// - `new_class_hash` A `ClassHash` representing the implementation to update to.
        ///
        /// # Requirements
        ///
        /// - This function can only be called by the implementation authority.
        /// - The `ClassHash` should already have been declared.
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            assert(
                self.implementation_authority.read() == starknet::get_caller_address(),
                Errors::CALLER_NOT_IMPLEMENTATION_AUTHORITY,
            );
            self.upgradeable.upgrade(new_class_hash);
        }
    }

    pub impl SNIP12MetadataImpl of SNIP12Metadata {
        /// Returns the name of the SNIP-12 metadata.
        fn name() -> felt252 {
            'OnchainID'
        }

        /// Returns the version of the SNIP-12 metadata.
        fn version() -> felt252 {
            version::VERSION
        }
    }
}

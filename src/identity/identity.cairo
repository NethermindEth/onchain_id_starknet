//! The `Identity` contract is a core contract of the OnchainID protocol, providing a robust
//! framework for identity management on the Starknet blockchain. It introduces an upgradeable
//! mechanism that allows the contract to evolve over time while maintaining the integrity of
//! existing identities and claims.
//!
//! # Features
//!
//! - **Upgrade Mechanism**: Allows the contract to upgrade its implementation while ensuring
//!   upgrades to implementation stated by the `IdentityImplementationAuthority`. This ensures that
//!   the contract can adapt to new requirements or improvements without losing existing state.
//!
//! - **Identity Management**: Facilitates management and validation of associated claims,
//! leveraging the underlying `IdentityComponent` for core
//!   functionalities.
//!
//! # Components
//!
//! - **IdentityComponent**: Component that implements core logic of Identity including Key and
//! Claim Management and claim verification.
//!
//! - **UpgradeableComponent**: Component that implements upgrade logic.
//!
//! # Security Notice
//!
//! This contract has not undergone a formal security audit and should be considered experimental.
//! Users should exercise caution when implementing or deploying this code in production
//! environments.

#[starknet::contract]
mod Identity {
    use core::num::traits::Zero;
    use openzeppelin_upgrades::interface::IUpgradeable;
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent;
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

    /// Constructor that initializes this contract.
    ///
    /// # Arguments
    ///
    /// * `implementation_authority` - `ContractAddress` that represent the implementation authority
    /// used by this contract.
    /// * `initial_management_key` - `ContractAddress` representing the initial management key to
    /// register.
    ///
    /// # Requirements
    ///
    /// - `implementation_authority` and  `initial_management_key` must be non-zero.
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
}

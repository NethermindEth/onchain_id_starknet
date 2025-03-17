//! TODO: Implement time windowed upgrades to allow users to have sometime to sync their
//! implementation.
#[starknet::contract]
pub mod ImplementationAuthority {
    use core::num::traits::Zero;
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ClassHash, ContractAddress};
    use crate::proxy::interface::IImplementationAuthority;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        implementation_class_hash: ClassHash,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        UpdatedImplementation: UpdatedImplementation,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }


    #[derive(Drop, starknet::Event)]
    pub struct UpdatedImplementation {
        pub new_class_hash: ClassHash,
    }

    pub mod Errors {
        pub const CLASS_HASH_ZERO: felt252 = 'class hash zero';
    }
    #[constructor]
    fn constructor(
        ref self: ContractState, implementation_class_hash: ClassHash, owner: ContractAddress,
    ) {
        assert(implementation_class_hash.is_non_zero(), Errors::CLASS_HASH_ZERO);
        self.ownable.initializer(owner);
        self.implementation_class_hash.write(implementation_class_hash);
        self.emit(UpdatedImplementation { new_class_hash: implementation_class_hash });
    }

    #[abi(embed_v0)]
    impl ImplementationAuthorityImpl of IImplementationAuthority<ContractState> {
        /// This function updates the class_hash used as implementation by contracts linked to this
        /// implementation authority.
        ///
        /// # Arguments
        ///
        /// * `new_class_hash` - A `ClassHash` to represents the new implementation class hash.
        ///
        /// # Requirements
        ///
        /// Must be called by the owner of the implementation authority.
        /// - `new_class_hash` must be non-zero.
        fn update_implementation(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            assert(new_class_hash.is_non_zero(), Errors::CLASS_HASH_ZERO);
            self.implementation_class_hash.write(new_class_hash);
            self.emit(UpdatedImplementation { new_class_hash });
        }

        /// Returns the current implementation class hash.
        ///
        /// # Returns
        ///
        /// A `ClassHash` representing the current implementation class hash.
        fn get_implementation(self: @ContractState) -> ClassHash {
            self.implementation_class_hash.read()
        }
    }
}

#[starknet::contract]
mod ImplementationAuthority {
    use core::num::traits::Zero;
    use onchain_id_starknet::interface::iimplementation_authority::IImplementationAuthority;
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use starknet::storage::{StoragePointerWriteAccess, StoragePointerReadAccess};
    use starknet::{ContractAddress, ClassHash};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        implementation_class_hash: ClassHash,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage
    }
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        UpdatedImplementation: UpdatedImplementation,
        #[flat]
        OwnableEvent: OwnableComponent::Event
    }


    #[derive(Drop, starknet::Event)]
    struct UpdatedImplementation {
        new_class_hash: ClassHash,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, implementation_class_hash: ClassHash, owner: ContractAddress
    ) {
        assert!(implementation_class_hash.is_non_zero(), "class_hash zero");
        self.ownable.initializer(owner);
        self.implementation_class_hash.write(implementation_class_hash);
        self.emit(UpdatedImplementation { new_class_hash: implementation_class_hash });
    }

    #[abi(embed_v0)]
    impl ImplementationAuthorityImpl of IImplementationAuthority<ContractState> {
        fn update_implementation(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            assert!(new_class_hash.is_non_zero(), "class_hash zero");
            self.implementation_class_hash.write(new_class_hash);
            self.emit(UpdatedImplementation { new_class_hash });
        }

        fn get_implementation(self: @ContractState) -> ClassHash {
            self.implementation_class_hash.read()
        }
    }
}

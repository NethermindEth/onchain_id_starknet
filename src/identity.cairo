#[starknet::contract]
mod Identity {
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent;
    use starknet::ContractAddress;
    use crate::identity_component::IdentityComponent;
    use crate::proxy::version_manager::VersionManagerComponent;
    use crate::version::version::VersionComponent;

    component!(path: VersionComponent, storage: version, event: VersionEvent);

    #[abi(embed_v0)]
    impl VersionImpl = VersionComponent::VersionImpl<ContractState>;

    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    impl UpgradeableImpl = UpgradeableComponent::InternalImpl<ContractState>;

    component!(path: VersionManagerComponent, storage: version_manager, event: VersionManagerEvent);

    #[abi(embed_v0)]
    impl VersionManagerUpgradeableImpl =
        VersionManagerComponent::UpgradeableImpl<ContractState>;
    impl VersionManagerInternalImpl = VersionManagerComponent::InternalImpl<ContractState>;

    component!(path: IdentityComponent, storage: identity, event: IdentityEvent);

    #[abi(embed_v0)]
    impl IdentityABICentralyUpgradeableImpl =
        IdentityComponent::IdentityABICentralyUpgradeableImpl<ContractState>;
    impl IdentityInternalImpl = IdentityComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        version: VersionComponent::Storage,
        #[substorage(v0)]
        version_manager: VersionManagerComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        #[substorage(v0)]
        identity: IdentityComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        VersionEvent: VersionComponent::Event,
        #[flat]
        IdentityEvent: IdentityComponent::Event,
        #[flat]
        VersionManagerEvent: VersionManagerComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        implementation_authority: ContractAddress,
        initial_management_key_hash: ContractAddress,
    ) {
        self.version_manager.initialize(implementation_authority);
        self.identity.initialize(initial_management_key_hash);
    }
}

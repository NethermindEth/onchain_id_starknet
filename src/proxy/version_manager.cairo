#[starknet::interface]
pub trait IUpgradeable<TContractState> {
    fn upgrade(ref self: TContractState) -> bool;
}
//! TODO: Implement time windowed upgrades to allow users to have sometime to sync their
//! implementation.
#[starknet::component]
pub mod VersionManagerComponent {
    use core::num::traits::Zero;
    use onchain_id_starknet::proxy::interface::{
        IImplementationAuthorityDispatcher, IImplementationAuthorityDispatcherTrait,
    };
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent;
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent::InternalTrait as UpgradeableInternalTrait;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ClassHash, ContractAddress};

    #[storage]
    pub struct Storage {
        // TODO: use get_class_hash_at_syscall instead
        VersionManager_implementation_class_hash: ClassHash,
        VersionManager_implementation_authority: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {}

    #[embeddable_as(UpgradeableImpl)]
    pub impl Upgradeable<
        TContractState,
        +HasComponent<TContractState>,
        impl UpgradeImpl: UpgradeableComponent::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of super::IUpgradeable<ComponentState<TContractState>> {
        fn upgrade(ref self: ComponentState<TContractState>) -> bool {
            let ia_class_hash = IImplementationAuthorityDispatcher {
                contract_address: self.VersionManager_implementation_authority.read(),
            }
                .get_implementation();
            let local_class_hash = self.VersionManager_implementation_class_hash.read();
            if ia_class_hash == local_class_hash {
                return false;
            }
            let mut upgrade_component = get_dep_component_mut!(ref self, UpgradeImpl);
            upgrade_component.upgrade(ia_class_hash);
            true
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl UpgradeImpl: UpgradeableComponent::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        fn initialize(
            ref self: ComponentState<TContractState>, implementation_authority: ContractAddress,
        ) {
            assert!(
                implementation_authority.is_non_zero(), "implementation authority address zero",
            );
            let ia_class_hash = IImplementationAuthorityDispatcher {
                contract_address: implementation_authority,
            }
                .get_implementation();
            self.VersionManager_implementation_authority.write(implementation_authority);
            self.VersionManager_implementation_class_hash.write(ia_class_hash);
        }

        fn assert_up_to_date_implementation(self: @ComponentState<TContractState>) {
            let ia_class_hash = IImplementationAuthorityDispatcher {
                contract_address: self.VersionManager_implementation_authority.read(),
            }
                .get_implementation();
            let local_class_hash = self.VersionManager_implementation_class_hash.read();
            assert!(
                ia_class_hash == local_class_hash,
                "Identity implementation is outdated! Trigger upgrade() function to upgrade your identity to latest version",
            );
        }
    }
}

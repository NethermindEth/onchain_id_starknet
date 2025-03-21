#[starknet::contract]
pub mod IdFactory {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{
        IntoIterRange, Map, MutableVecTrait, StoragePathEntry, StoragePointerReadAccess,
        StoragePointerWriteAccess, Vec,
    };
    use crate::factory::interface::IIdFactory;
    use crate::identity::interface::ierc734::{IERC734Dispatcher, IERC734DispatcherTrait};
    use crate::proxy::interface::{
        IIdentityImplementationAuthorityDispatcher, IIdentityImplementationAuthorityDispatcherTrait,
    };
    use crate::storage::vec_ext::{VecDeleteTrait, VecToArrayTrait};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        token_factories: Map<ContractAddress, bool>,
        implementation_authority: ContractAddress,
        salt_taken: Map<felt252, bool>,
        user_identity: Map<ContractAddress, ContractAddress>,
        wallets: Map<ContractAddress, Vec<ContractAddress>>,
        token_identity: Map<ContractAddress, ContractAddress>,
        token_address: Map<ContractAddress, ContractAddress>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Deployed: Deployed,
        WalletLinked: WalletLinked,
        WalletUnlinked: WalletUnlinked,
        TokenLinked: TokenLinked,
        TokenFactoryAdded: TokenFactoryAdded,
        TokenFactoryRemoved: TokenFactoryRemoved,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Deployed {
        #[key]
        pub deployed_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WalletLinked {
        #[key]
        pub wallet: ContractAddress,
        #[key]
        pub identity: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WalletUnlinked {
        #[key]
        pub wallet: ContractAddress,
        #[key]
        pub identity: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenLinked {
        #[key]
        pub token: ContractAddress,
        #[key]
        pub identity: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenFactoryAdded {
        #[key]
        pub factory: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TokenFactoryRemoved {
        #[key]
        pub factory: ContractAddress,
    }

    pub mod Errors {
        pub const TOKEN_FACTORY_IS_ZERO_ADDRESS: felt252 = 'token factory address zero';
        pub const TOKEN_IS_ZERO_ADDRESS: felt252 = 'token address zero';
        pub const TOKEN_OWNER_IS_ZERO_ADDRESS: felt252 = 'token owner address zero';
        pub const OWNER_IS_ZERO_ADDRESS: felt252 = 'owner is zero address';
        pub const IMPLEMENTATION_AUTH_ZERO_ADDRESS: felt252 = 'impl. auth. zero address';
        pub const WALLET_IS_ZERO_ADDRESS: felt252 = 'wallet is zero address';
        pub const ALREADY_FACTORY: felt252 = 'already a factory';
        pub const NOT_FACTORY: felt252 = 'not a factory';
        pub const WALLET_ALREADY_LINKED: felt252 = 'wallet already linked';
        pub const WALLET_NOT_LINKED: felt252 = 'wallet not linked to identity';
        pub const MAX_WALLET_PER_IDENTITY: felt252 = 'max wallets per ID exceeded';
        pub const ADDRESS_ALREADY_LINKED_TOKEN: felt252 = 'address already linked token';
        pub const NOT_FACTORY_NOR_OWNER: felt252 = 'only factory or owner can call';
        pub const SALT_TAKEN: felt252 = 'salt already taken';
        pub const SALT_IS_ZERO: felt252 = 'salt cannot be zero';
        pub const MANAGEMENT_KEYS_EMPTY: felt252 = 'empty list of managent keys';
        pub const CANNOT_REMOVE_CALLER: felt252 = 'cant remove caller address';
        pub const ONLY_LINKED_WALLET_CAN_UNLINK: felt252 = 'only linked wallet can unlink';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, implementation_authority: ContractAddress, owner: ContractAddress,
    ) {
        assert(implementation_authority.is_non_zero(), Errors::IMPLEMENTATION_AUTH_ZERO_ADDRESS);
        assert(owner.is_non_zero(), Errors::OWNER_IS_ZERO_ADDRESS);
        self.implementation_authority.write(implementation_authority);
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl IdFactoryImpl of IIdFactory<ContractState> {
        /// This function registers an address as a token factory.
        ///
        /// # Arguments
        ///
        /// * `factory` - A 'ContractAddress' representing the address to be registered as token
        /// factory.
        ///
        /// # Requirements
        ///
        /// Caller must be the factory owner.
        /// `factory` must not be already registered as token factory.
        fn add_token_factory(ref self: ContractState, factory: ContractAddress) {
            self.ownable.assert_only_owner();
            assert(factory.is_non_zero(), Errors::TOKEN_FACTORY_IS_ZERO_ADDRESS);
            let token_factory_storage_path = self.token_factories.entry(factory);
            assert(!token_factory_storage_path.read(), Errors::ALREADY_FACTORY);
            token_factory_storage_path.write(true);
            self.emit(TokenFactoryAdded { factory });
        }

        /// This function unregisters an address previously registered as token factory.
        ///
        /// # Arguments
        ///
        /// * `factory` - A 'ContractAddress' representing the address of token factory to be
        /// unregistered.
        ///
        /// # Requirements
        ///
        /// Caller must be the factory owner.
        /// `factory` must be already registered as token factory.
        fn remove_token_factory(ref self: ContractState, factory: ContractAddress) {
            self.ownable.assert_only_owner();
            assert(factory.is_non_zero(), Errors::TOKEN_FACTORY_IS_ZERO_ADDRESS);
            let token_factory_storage_path = self.token_factories.entry(factory);
            assert(token_factory_storage_path.read(), Errors::NOT_FACTORY);
            token_factory_storage_path.write(false);
            self.emit(TokenFactoryRemoved { factory });
        }

        /// This function deploys a new identity from the factory
        ///
        /// # Arguments
        ///
        /// * `wallet` - A `ContractAddress` representing the address to be added as MANAGEMENT
        /// key.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        ///
        /// # Requirements
        ///
        /// - `wallet` must not linked to another identity.
        /// - `wallet` must not be zero address.
        /// - `salt` must be non-zero and not taken.
        /// Caller must be the factory owner.
        fn create_identity(
            ref self: ContractState, wallet: ContractAddress, salt: felt252,
        ) -> ContractAddress {
            self.ownable.assert_only_owner();
            assert(wallet.is_non_zero(), Errors::WALLET_IS_ZERO_ADDRESS);
            assert(salt.is_non_zero(), Errors::SALT_IS_ZERO);
            let oid_salt = poseidon_hash_span(array!['OID', salt].span());
            let salt_taken_storage_path = self.salt_taken.entry(oid_salt);
            assert(!salt_taken_storage_path.read(), Errors::SALT_TAKEN);
            let user_identity_storage_path = self.user_identity.entry(wallet);
            assert(user_identity_storage_path.read().is_zero(), Errors::WALLET_ALREADY_LINKED);
            assert(
                self.token_identity.entry(wallet).read().is_zero(),
                Errors::ADDRESS_ALREADY_LINKED_TOKEN,
            ); // solidity does not have this check ensure required
            let identity = self
                .deploy_identity(oid_salt, self.implementation_authority.read(), wallet);
            salt_taken_storage_path.write(true);
            user_identity_storage_path.write(identity);
            self.wallets.entry(identity).push(wallet);
            self.emit(WalletLinked { wallet, identity });
            identity
        }

        /// This function deploys a new identity from the factory, setting the wallet and listed
        /// keys as MANAGEMENT keys.
        ///
        /// # Arguments
        ///
        /// * `wallet` - A `ContractAddress` representing the primary owner of deployed identity
        /// contract.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        /// * `management_keys` - A `Array<felt252>` representing the array of keys hash(poseidon
        /// hash) to add as MANAGEMENT keys.
        ///
        /// # Requirements
        ///
        /// - `wallet` must not linked to another identity.
        /// - `wallet` must not be in `management_keys`
        /// - `salt` must be non-zero and not taken.
        /// Caller must be the factory owner.
        /// - `management_keys` length should be greater than 0.
        fn create_identity_with_management_keys(
            ref self: ContractState,
            wallet: ContractAddress,
            salt: felt252,
            management_keys: Array<felt252>,
        ) -> ContractAddress {
            self.ownable.assert_only_owner();
            assert(wallet.is_non_zero(), Errors::WALLET_IS_ZERO_ADDRESS);
            assert(salt.is_non_zero(), Errors::SALT_IS_ZERO);
            let oid_salt = poseidon_hash_span(array!['OID', salt].span());
            let salt_taken_storage_path = self.salt_taken.entry(oid_salt);
            assert(!salt_taken_storage_path.read(), Errors::SALT_TAKEN);
            let user_identity_storage_path = self.user_identity.entry(wallet);
            assert(user_identity_storage_path.read().is_zero(), Errors::WALLET_ALREADY_LINKED);
            assert(
                self.token_identity.entry(wallet).read().is_zero(),
                Errors::ADDRESS_ALREADY_LINKED_TOKEN,
            ); // solidity does not have this check ensure required
            assert(management_keys.len() > 0, Errors::MANAGEMENT_KEYS_EMPTY);

            let identity = self
                .deploy_identity(
                    oid_salt,
                    self.implementation_authority.read(),
                    starknet::get_contract_address(),
                );
            let mut identity_dispatcher = IERC734Dispatcher { contract_address: identity };
            // NOTE: Maybe add batch {add/remove}_key
            for key in management_keys {
                // NOTE: Why not let wallet to be registered as management key, is this a flaw?
                // wallet will not be initial key but will be linked wallet?
                assert!(
                    key != poseidon_hash_span(array![wallet.into()].span()),
                    "wallet is also listed in management keys",
                );
                identity_dispatcher.add_key(key, 1, 1);
            }
            identity_dispatcher
                .remove_key(
                    poseidon_hash_span(array![starknet::get_contract_address().into()].span()), 1,
                );
            salt_taken_storage_path.write(true);
            user_identity_storage_path.write(identity);
            self.wallets.entry(identity).push(wallet);
            self.emit(WalletLinked { wallet, identity });
            identity
        }

        /// This function deploys a new token identity from the factory
        ///
        /// # Arguments
        ///
        /// * `token` - A `ContractAddress` representing the address of the token contract.
        /// * `token_owner` - A `ContractAddress` representing the address of the owner of token.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        ///
        /// # Requirements
        ///
        /// - `token_owner` must not be zero address.
        /// - `token` must not linked to another identity.
        /// - `token` must not be zero address.
        /// - `salt` must be non-zero and not taken.
        /// Caller must be factory owner or registered as token_factory.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the address of deployed identity.
        fn create_token_identity(
            ref self: ContractState,
            token: ContractAddress,
            token_owner: ContractAddress,
            salt: felt252,
        ) -> ContractAddress {
            assert(
                self.is_token_factory(starknet::get_caller_address())
                    || self.ownable.owner() == starknet::get_caller_address(),
                Errors::NOT_FACTORY_NOR_OWNER,
            );

            assert(token.is_non_zero(), Errors::TOKEN_IS_ZERO_ADDRESS);
            assert(token_owner.is_non_zero(), Errors::TOKEN_OWNER_IS_ZERO_ADDRESS);
            assert(salt.is_non_zero(), Errors::SALT_IS_ZERO);
            let token_salt = poseidon_hash_span(array!['Token', salt].span());
            let salt_taken_storage_path = self.salt_taken.entry(token_salt);
            assert(!salt_taken_storage_path.read(), Errors::SALT_TAKEN);
            let token_identity_storage_path = self.token_identity.entry(token);
            assert(
                token_identity_storage_path.read().is_zero(), Errors::ADDRESS_ALREADY_LINKED_TOKEN,
            ); // solidity does not have this check ensure required
            assert(self.user_identity.entry(token).read().is_zero(), Errors::WALLET_ALREADY_LINKED);
            let identity = self
                .deploy_identity(token_salt, self.implementation_authority.read(), token_owner);
            salt_taken_storage_path.write(true);
            token_identity_storage_path.write(identity);
            self.token_address.entry(identity).write(token);
            self.wallets.entry(identity).push(token);
            self.emit(TokenLinked { token, identity });
            identity
        }

        /// This function links a new wallet to existing identity of the caller.
        ///
        /// # Arguments
        ///
        /// * `new_wallet` - A 'ContractAddress' representing the address of wallet to link.
        ///
        /// # Requirements
        ///
        /// Caller address must be linked to an existing identity.
        /// Cannot link more than 100 wallet per identity.
        /// - `new_wallet` must not be already linked to an identity.
        /// - `new_wallet` must not be zero address.
        fn link_wallet(ref self: ContractState, new_wallet: ContractAddress) {
            assert(new_wallet.is_non_zero(), Errors::WALLET_IS_ZERO_ADDRESS);
            let caller_user_identity = self
                .user_identity
                .entry(starknet::get_caller_address())
                .read();
            assert(caller_user_identity.is_non_zero(), Errors::WALLET_NOT_LINKED);
            let new_wallet_user_identity_storage_path = self.user_identity.entry(new_wallet);
            assert(
                new_wallet_user_identity_storage_path.read().is_zero(),
                Errors::WALLET_ALREADY_LINKED,
            );
            assert(
                self.token_identity.entry(new_wallet).read().is_zero(),
                Errors::ADDRESS_ALREADY_LINKED_TOKEN,
            );
            let caller_user_identity_wallets_storage_path = self
                .wallets
                .entry(caller_user_identity);
            assert(
                caller_user_identity_wallets_storage_path.len() < 101,
                Errors::MAX_WALLET_PER_IDENTITY,
            );
            new_wallet_user_identity_storage_path.write(caller_user_identity);
            caller_user_identity_wallets_storage_path.push(new_wallet);
            self.emit(WalletLinked { wallet: new_wallet, identity: caller_user_identity });
        }

        /// This function unlinks given wallet from an existing identity.
        ///
        /// # Arguments
        ///
        /// * `old_wallet` - A 'ContractAddress' representing the address of wallet to unlink.
        ///
        /// # Requirements
        ///
        /// Caller address to be linked to the same identity as `old_wallet`.
        /// Caller address cannot be `old_wallet` to keep at least 1 wallet linked to any identity.
        /// `old_wallet` cannot be zero address.
        fn unlink_wallet(ref self: ContractState, old_wallet: ContractAddress) {
            assert(old_wallet.is_non_zero(), Errors::WALLET_IS_ZERO_ADDRESS);
            let caller = starknet::get_caller_address();
            assert(old_wallet != caller, Errors::CANNOT_REMOVE_CALLER);
            let old_wallet_user_identity_storage_path = self.user_identity.entry(old_wallet);
            let old_wallet_user_identity = old_wallet_user_identity_storage_path.read();
            assert(
                self.user_identity.entry(caller).read() == old_wallet_user_identity,
                Errors::ONLY_LINKED_WALLET_CAN_UNLINK,
            );

            old_wallet_user_identity_storage_path.write(Zero::zero());
            let wallets_storage_path = self.wallets.entry(old_wallet_user_identity);
            let mut iterator = wallets_storage_path.into_iter_full_range().enumerate();
            let (index, _) = iterator
                .find(|iter| {
                    let (_, storage) = iter;
                    storage.read() == old_wallet
                })
                .expect(Errors::WALLET_NOT_LINKED);

            wallets_storage_path.pop_swap(index.into());

            self.emit(WalletUnlinked { wallet: old_wallet, identity: old_wallet_user_identity });
        }


        /// Returns identity for corresponding wallet/token
        ///
        /// # Arguments
        ///
        /// * `wallet` - A 'ContractAddress' representing the address of wallet/token to query for.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the address of identity corresponding wallet/token.
        fn get_identity(self: @ContractState, wallet: ContractAddress) -> ContractAddress {
            let token_identity = self.token_identity.entry(wallet).read();
            if token_identity.is_non_zero() {
                token_identity
            } else {
                self.user_identity.entry(wallet).read()
            }
        }

        /// Returns array of wallets linked to given identity
        ///
        /// # Arguments
        ///
        /// * `identity` - A 'ContractAddress' representing the address of identity.
        ///
        /// # Returns
        ///
        /// A `Array<ContractAddress>` - representing the addresses linked to given identity.
        fn get_wallets(self: @ContractState, identity: ContractAddress) -> Span<ContractAddress> {
            self.wallets.entry(identity).to_array().span()
        }

        /// Returns token address linked to given identity
        ///
        /// # Arguments
        ///
        /// * `identity` - A 'ContractAddress' representing the address of identity.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the address of token linked to given identity.
        fn get_token(self: @ContractState, identity: ContractAddress) -> ContractAddress {
            self.token_address.entry(identity).read()
        }

        /// Determines if given address is token factory.
        ///
        /// # Arguments
        ///
        /// * `factory` - A 'ContractAddress' representing the address to check.
        ///
        /// # Returns
        ///
        /// A `bool` - representing whether given address is registered as token factory. True if
        /// registered as token factory.
        fn is_token_factory(self: @ContractState, factory: ContractAddress) -> bool {
            self.token_factories.entry(factory).read()
        }

        /// Determines if given 'salt' has been taken.
        ///
        /// # Arguments
        ///
        /// * `salt` - A 'felt252' representing the salt to check.
        ///
        /// # Returns
        ///
        /// A `bool` - representing whether salt is taken. True for taken.
        fn is_salt_taken(self: @ContractState, salt: felt252) -> bool {
            self.salt_taken.entry(salt).read()
        }

        /// Returns the implementation authority used by this factory.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the implementation authority.
        fn implementation_authority(self: @ContractState) -> ContractAddress {
            self.implementation_authority.read()
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        /// This function deploys the identity contract referenced by the implementation authority
        /// using custom salt.
        ///
        /// # Arguments
        ///
        /// * `salt` - A `felt252` representing the salt used while deployment.
        /// * `implementation_authority` - A `ContractAddress` representing the address of
        /// implementation authority to query the implementation to deploy and set as implementation
        /// authority of identity contract.
        /// * `wallet`- A `ContractAddress` representing the initial management key for the identity
        /// to be deployed.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` - representing the deployed identity.
        fn deploy_identity(
            ref self: ContractState,
            salt: felt252,
            implementation_authority: ContractAddress,
            wallet: ContractAddress,
        ) -> ContractAddress {
            let implementation_class_hash = IIdentityImplementationAuthorityDispatcher {
                contract_address: implementation_authority,
            }
                .get_implementation();

            let mut ctor_data: Array<felt252> = array![
                implementation_authority.into(), wallet.into(),
            ];
            let (deployed_address, _) = starknet::syscalls::deploy_syscall(
                implementation_class_hash, salt, ctor_data.span(), false,
            )
                .unwrap();
            self.emit(Deployed { deployed_address });
            deployed_address
        }
    }
}

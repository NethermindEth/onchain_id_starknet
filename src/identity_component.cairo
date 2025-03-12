#[starknet::component]
pub mod IdentityComponent {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::interface::ierc734::{ERC734Event, IERC734};
    use onchain_id_starknet::interface::ierc735::{ERC735Event, IERC735};
    use onchain_id_starknet::interface::iidentity::{
        IIdentity, IIdentityDispatcher, IIdentityDispatcherTrait, IdentityABI,
    };
    use onchain_id_starknet::interface::{ierc734, ierc735};
    use onchain_id_starknet::proxy::version_manager::VersionManagerComponent;
    use onchain_id_starknet::proxy::version_manager::VersionManagerComponent::InternalTrait as VersionManagerInternalTrait;
    use onchain_id_starknet::storage::signature::{get_public_key_hash, is_valid_signature};
    use onchain_id_starknet::storage::storage::{
        Felt252VecToFelt252Array, MutableFelt252VecToFelt252Array,
        MutableStorageArrayFelt252IndexView, MutableStorageArrayTrait, StorageArrayFelt252,
        StorageArrayFelt252IndexView, StorageArrayTrait,
    };
    use onchain_id_starknet::storage::structs::{Claim, Execution, Key, delete_claim, delete_key};
    use onchain_id_starknet::version::version::VersionComponent;
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, Mutable, StoragePath, StoragePathEntry, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    #[storage]
    pub struct Storage {
        Identity_execution_nonce: felt252,
        Identity_keys: Map<felt252, Key>,
        Identity_keys_by_purpose: Map<felt252, StorageArrayFelt252>,
        Identity_executions: Map<felt252, Execution>,
        Identity_claims: Map<felt252, Claim>,
        Identity_claims_by_topic: Map<felt252, StorageArrayFelt252>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        ERC734Event: ERC734Event,
        #[flat]
        ERC735Event: ERC735Event,
    }

    pub mod Errors {
        pub const KEY_ALREADY_HAS_PURPOSE: felt252 = 'Key already has given purpose';
        pub const KEY_DOES_NOT_HAVE_PURPOSE: felt252 = 'Key doesnt have such purpose';
        pub const CLAIM_DOES_NOT_EXIST: felt252 = 'There is no claim with this ID';
        pub const INVALID_CLAIM: felt252 = 'Invalid claim';
        pub const KEY_NOT_REGISTERED: felt252 = 'Key is not registered';
        pub const NOT_HAVE_ACTION_KEY: felt252 = 'Sender not have action key';
        pub const NOT_HAVE_MANAGEMENT_KEY: felt252 = 'Sender not have management key';
        pub const ALREADY_EXECUTED: felt252 = 'Request already executed';
        pub const NON_EXISTING_EXECUTION: felt252 = 'Non-existing execution';
        pub const ZERO_ADDRESS: felt252 = 'Zero address';
        pub const NOT_HAVE_CLAIM_KEY: felt252 = 'Sender not have claim key';
    }

    #[embeddable_as(IdentityImpl)]
    pub impl Identity<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>,
    > of IIdentity<ComponentState<TContractState>> {
        fn is_claim_valid(
            self: @ComponentState<TContractState>,
            identity: ContractAddress,
            claim_topic: felt252,
            signature: Span<felt252>,
            data: ByteArray,
        ) -> bool {
            let pub_key_hash = get_public_key_hash(signature);
            if !self.key_has_purpose(pub_key_hash, 3) {
                return false;
            }

            // NOTE: How about comply with SNIP12
            let mut serialized_claim: Array<felt252> = array![];
            identity.serialize(ref serialized_claim);
            serialized_claim.append(claim_topic);
            data.serialize(ref serialized_claim);
            // TODO: Add prefix
            let data_hash = poseidon_hash_span(
                array!['Starknet Message', poseidon_hash_span(serialized_claim.span())].span(),
            );

            is_valid_signature(data_hash, signature)
        }
    }

    #[embeddable_as(ERC734Impl)]
    pub impl ERC734<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>,
    > of IERC734<ComponentState<TContractState>> {
        /// This function adds a key to the identity with given purpose, creates the key if not
        /// present else adds purpose
        ///
        /// # Arguments
        ///
        /// * `key` - A `felt252` representing hash of the key(public key, ContractAddress).
        /// TODO: deciding using `MANAGEMENT` etc... as purpose since it is felt252
        /// * `purpose` A `felt252` representing the purpose of key. For example 1 : MANAGEMENT, 2 :
        /// ACTION, 3: CLAIM.
        /// * `key_type` TODO: To Be Defined!
        ///
        /// # Requirements
        ///
        /// Must called by this contract or caller has MANAGEMENT key.
        /// - `key` must not already have given purpose.
        ///
        /// # Returns
        ///
        /// A `bool` indicating whether key is added successfully or not
        fn add_key(
            ref self: ComponentState<TContractState>,
            key: felt252,
            purpose: felt252,
            key_type: felt252,
        ) -> bool {
            self.only_manager();
            let mut key_storage_path = self.Identity_keys.entry(key);
            if key_storage_path.key.read() == key {
                let purposes_storage_path = key_storage_path.purposes.deref();
                for i in 0..purposes_storage_path.len() {
                    assert(
                        purpose != purposes_storage_path[i].read(), Errors::KEY_ALREADY_HAS_PURPOSE,
                    );
                }
                purposes_storage_path.append().write(purpose);
            } else {
                key_storage_path.key.write(key);
                key_storage_path.key_type.write(key_type);
                key_storage_path.purposes.deref().append().write(purpose);
            }
            self.Identity_keys_by_purpose.entry(purpose).append().write(key);
            self.emit(ERC734Event::KeyAdded(ierc734::KeyAdded { key, purpose, key_type }));
            true
        }

        /// This function removes given purpose from given key of given identity.
        ///
        /// # Arguments
        ///
        /// * `key` - A `felt252` representing hash of the key(public key, ContractAddress).
        /// TODO: deciding using `MANAGEMENT` etc... as purpose since it is felt252
        /// * `purpose` A `felt252` representing the purpose of key. For example 1 : MANAGEMENT, 2 :
        /// ACTION, 3: CLAIM.
        ///
        /// # Requirements
        ///
        /// Must called by this contract or caller has MANAGEMENT key.
        /// - `key` should be registered and has the given purpose.
        ///
        /// # Returns
        ///
        /// A `bool` indicating whether key is removed successfully or not
        fn remove_key(
            ref self: ComponentState<TContractState>, key: felt252, purpose: felt252,
        ) -> bool {
            self.only_manager();
            let key_storage_path = self.Identity_keys.entry(key);
            assert(key_storage_path.key.read() == key, Errors::KEY_NOT_REGISTERED);

            let purposes_storage_path = key_storage_path.purposes.deref();
            let purpose_size = purposes_storage_path.len();
            let mut purpose_index = Option::None;
            for i in 0..purpose_size {
                if purpose == purposes_storage_path[i].read() {
                    purpose_index = Option::Some(i);
                    break;
                }
            }
            assert(purpose_index != Option::None, Errors::KEY_DOES_NOT_HAVE_PURPOSE);
            purposes_storage_path.delete(purpose_index.unwrap());

            let keys_by_purpose_key_storage_path = self.Identity_keys_by_purpose.entry(purpose);
            let mut keys_len = keys_by_purpose_key_storage_path.len();
            // MOTE: this loops assumes that whenever key is added to keys mapping it
            // keys_by_purpose mapping is also updated thus no need to check for
            // purpose exist for key or not if this invariant holds check for
            // removal above should guarantee purpose exist for key
            let mut key_index = 0;
            for i in 0..keys_len {
                if keys_by_purpose_key_storage_path[i].read() == key {
                    key_index = i;
                    break;
                }
            }
            keys_by_purpose_key_storage_path.delete(key_index);
            let key_type = key_storage_path.key_type.read();

            /// if (_purposes.length - 1 == 0) {
            ///     delete _keys[_key];
            ///}
            if purposes_storage_path.len().is_zero() {
                delete_key(key_storage_path);
            }

            self.emit(ERC734Event::KeyRemoved(ierc734::KeyRemoved { key, purpose, key_type }));
            true
        }

        /// This function approves or reject the execution with given execution_id.
        ///
        /// # Arguments
        ///
        /// * `execution_id` A `felt252` representing the identifier of execution to approve/reject.
        /// * `approve` A `bool` representing the status of approval. (true for approve, false
        /// for reject).
        ///
        /// # Returns
        ///
        /// A `bool` indicating success of approve operation.
        fn approve(
            ref self: ComponentState<TContractState>, execution_id: felt252, approve: bool,
        ) -> bool {
            assert(
                Into::<felt252, u256>::into(execution_id) < self
                    .Identity_execution_nonce
                    .read()
                    .into(),
                Errors::NON_EXISTING_EXECUTION,
            );
            let execution_storage_path = self.Identity_executions.entry(execution_id);
            assert(!execution_storage_path.executed.read(), Errors::ALREADY_EXECUTED);
            let caller_hash = poseidon_hash_span(
                array![starknet::get_caller_address().into()].span(),
            );
            let to_address = execution_storage_path.to.read();
            if to_address == starknet::get_contract_address() {
                assert(self.key_has_purpose(caller_hash, 1), Errors::NOT_HAVE_MANAGEMENT_KEY);
            } else {
                assert(self.key_has_purpose(caller_hash, 2), Errors::NOT_HAVE_ACTION_KEY);
            }
            self.emit(ERC734Event::Approved(ierc734::Approved { execution_id, approved: approve }));
            if !approve {
                return false;
            }
            execution_storage_path.approved.write(true);
            let selector = execution_storage_path.selector.read();
            let calldata: Span<felt252> = Into::<
                StoragePath<Mutable<StorageArrayFelt252>>, Array<felt252>,
            >::into(execution_storage_path.calldata.deref())
                .span();

            match starknet::syscalls::call_contract_syscall(to_address, selector, calldata) {
                Result::Ok => {
                    execution_storage_path.executed.write(true);
                    self
                        .emit(
                            ERC734Event::Executed(
                                ierc734::Executed {
                                    execution_id, to: to_address, selector, data: calldata,
                                },
                            ),
                        );
                    true
                },
                Result::Err => {
                    self
                        .emit(
                            ERC734Event::ExecutionFailed(
                                ierc734::ExecutionFailed {
                                    execution_id, to: to_address, selector, data: calldata,
                                },
                            ),
                        );
                    false
                },
            }
        }

        fn execute(
            ref self: ComponentState<TContractState>,
            to: ContractAddress,
            selector: felt252,
            calldata: Span<felt252>,
        ) -> felt252 {
            let execution_nonce = self.Identity_execution_nonce.read();
            let execution_storage_path = self.Identity_executions.entry(execution_nonce);
            execution_storage_path.to.write(to);
            execution_storage_path.selector.write(selector);
            let calldata_storage_path = execution_storage_path.calldata.deref();
            for chunk in calldata.clone() {
                calldata_storage_path.append().write(*chunk);
            }

            self.Identity_execution_nonce.write(execution_nonce + 1);

            self
                .emit(
                    ERC734Event::ExecutionRequested(
                        ierc734::ExecutionRequested {
                            execution_id: execution_nonce, to, selector, data: calldata,
                        },
                    ),
                );

            let caller_hash = poseidon_hash_span(
                array![starknet::get_caller_address().into()].span(),
            );

            if to != starknet::get_contract_address() && self.key_has_purpose(caller_hash, 2) {
                self._approve(execution_nonce, to, selector, calldata);
            } else if self.key_has_purpose(caller_hash, 1) {
                self._approve(execution_nonce, to, selector, calldata);
            }

            execution_nonce
        }

        /// Returns the full key data
        ///
        /// # Arguments
        ///
        /// * `key` A `felt252` representing key identifier (hash of public key, ContractAddress).
        ///
        /// # Returns
        ///
        /// A `Span<felt252>` representing purposes this key has.
        /// A `felt252` representing key_type of the key.
        /// A `felt252` representing the hashed key.
        fn get_key(
            self: @ComponentState<TContractState>, key: felt252,
        ) -> (Span<felt252>, felt252, felt252) {
            let key_storage_path = self.Identity_keys.entry(key);
            let purposes: Array<felt252> = key_storage_path.purposes.deref().into();
            (purposes.span(), key_storage_path.key_type.read(), key_storage_path.key.read())
        }

        /// Returns the purposes given key has.
        ///
        /// # Arguments
        ///
        /// * `key` A `felt252` representing the key to get purposes for.
        ///
        /// # Returns
        ///
        /// A `Span<felt252>` representing the array of purposes given key has.
        fn get_key_purposes(self: @ComponentState<TContractState>, key: felt252) -> Span<felt252> {
            Into::<
                StoragePath<StorageArrayFelt252>, Array<felt252>,
            >::into(self.Identity_keys.entry(key).purposes.deref())
                .span()
        }

        /// Returns the keys which has given purpose.
        ///
        /// # Arguments
        ///
        /// * `purpose` A `felt252` representing the purpose to get keys for.
        ///
        /// # Returns
        ///
        /// A `Span<felt252>` representing the array of keys which has given purpose.
        fn get_keys_by_purpose(
            self: @ComponentState<TContractState>, purpose: felt252,
        ) -> Span<felt252> {
            Into::<
                StoragePath<StorageArrayFelt252>, Array<felt252>,
            >::into(self.Identity_keys_by_purpose.entry(purpose))
                .span()
        }

        /// Determines if key has given purpose.
        ///
        /// # Arguments
        ///
        /// * `key` A `felt252` representing the key to query for.
        /// * `purpose` A `felt252` representing the purpose to query for.
        ///
        /// # Returns
        ///
        /// A `bool` representing the key has given purpose or not.
        fn key_has_purpose(
            self: @ComponentState<TContractState>, key: felt252, purpose: felt252,
        ) -> bool {
            let key_storage_path = self.Identity_keys.entry(key);
            if key_storage_path.key.read().is_zero() {
                return false;
            }
            let purposes_storage_path = key_storage_path.purposes.deref();
            let mut has_purpose = false;
            for i in 0..purposes_storage_path.len() {
                let _purpose = purposes_storage_path[i].read();
                if _purpose == 1 || purpose == _purpose {
                    has_purpose = true;
                    break;
                }
            }
            has_purpose
        }
    }

    #[embeddable_as(ERC735Impl)]
    pub impl ERC735<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>,
    > of IERC735<ComponentState<TContractState>> {
        fn add_claim(
            ref self: ComponentState<TContractState>,
            topic: felt252,
            scheme: felt252,
            issuer: ContractAddress,
            signature: Span<felt252>,
            data: ByteArray,
            uri: ByteArray,
        ) -> felt252 {
            self.only_claim_key();
            let this_address = starknet::get_contract_address();

            if issuer != this_address {
                let is_valid_claim = IIdentityDispatcher { contract_address: issuer }
                    .is_claim_valid(this_address, topic, signature, data.clone());
                assert(is_valid_claim, Errors::INVALID_CLAIM);
            }

            let mut claim_data_serialized: Array<felt252> = array![];
            issuer.serialize(ref claim_data_serialized);
            topic.serialize(ref claim_data_serialized);
            let claim_id = poseidon_hash_span(claim_data_serialized.span());

            let claim_storage_path = self.Identity_claims.entry(claim_id);
            claim_storage_path.topic.write(topic);
            claim_storage_path.scheme.write(scheme);

            let signature_storage = claim_storage_path.signature.deref();
            for chunk in signature {
                signature_storage.append().write(*chunk);
            }

            claim_storage_path.data.write(data.clone());
            claim_storage_path.uri.write(uri.clone());

            if claim_storage_path.issuer.read() != issuer {
                self.Identity_claims_by_topic.entry(topic).append().write(claim_id);
                claim_storage_path.issuer.write(issuer);
                self
                    .emit(
                        ERC735Event::ClaimAdded(
                            ierc735::ClaimAdded {
                                claim_id, topic, scheme, issuer, signature, data, uri,
                            },
                        ),
                    );
            } else {
                self
                    .emit(
                        ERC735Event::ClaimChanged(
                            ierc735::ClaimChanged {
                                claim_id, topic, scheme, issuer, signature, data, uri,
                            },
                        ),
                    );
            }

            claim_id
        }

        fn remove_claim(ref self: ComponentState<TContractState>, claim_id: felt252) -> bool {
            self.only_claim_key();
            let claim_storage_path = self.Identity_claims.entry(claim_id);
            let topic = claim_storage_path.topic.read();
            assert(topic.is_non_zero(), Errors::CLAIM_DOES_NOT_EXIST);
            let claims_by_topic_storage_path = self.Identity_claims_by_topic.entry(topic);
            let mut claim_index = Option::None; // TODO: Might turn into Option<index>
            let claims_len = claims_by_topic_storage_path.len();
            for i in 0..claims_len {
                if claims_by_topic_storage_path[i].read() == claim_id {
                    claim_index = Option::Some(i);
                    break;
                }
            }
            assert(
                claim_index != Option::None, Errors::CLAIM_DOES_NOT_EXIST,
            ); // NOTE: this check might not be necessary due to above assertion we might assume claim_id will always be there

            claims_by_topic_storage_path.delete(claim_index.unwrap());

            self
                .emit(
                    ERC735Event::ClaimRemoved(
                        ierc735::ClaimRemoved {
                            claim_id,
                            topic,
                            scheme: claim_storage_path.scheme.read(),
                            issuer: claim_storage_path.issuer.read(),
                            signature: MutableFelt252VecToFelt252Array::into(
                                claim_storage_path.signature.deref(),
                            )
                                .span(),
                            data: claim_storage_path.data.read(),
                            uri: claim_storage_path.uri.read(),
                        },
                    ),
                );
            delete_claim(claim_storage_path);
            true
        }

        fn get_claim(
            self: @ComponentState<TContractState>, claim_id: felt252,
        ) -> (felt252, felt252, ContractAddress, Span<felt252>, ByteArray, ByteArray) {
            let claim_storage_path = self.Identity_claims.entry(claim_id);
            (
                claim_storage_path.topic.read(),
                claim_storage_path.scheme.read(),
                claim_storage_path.issuer.read(),
                Felt252VecToFelt252Array::into(claim_storage_path.signature.deref()).span(),
                claim_storage_path.data.read(),
                claim_storage_path.uri.read(),
            )
        }

        fn get_claim_ids_by_topics(
            self: @ComponentState<TContractState>, topic: felt252,
        ) -> Span<felt252> {
            Felt252VecToFelt252Array::into(self.Identity_claims_by_topic.entry(topic)).span()
        }
    }

    #[embeddable_as(IdentityABICentralyUpgradeableImpl)]
    impl IdentityABICentralyUpgradeable<
        TContractState,
        +Drop<TContractState>,
        +HasComponent<TContractState>,
        +VersionComponent::HasComponent<TContractState>,
        impl VersionManagerImpl: VersionManagerComponent::HasComponent<TContractState>,
        +UpgradeableComponent::HasComponent<TContractState>,
    > of IdentityABI<ComponentState<TContractState>> {
        fn is_claim_valid(
            ref self: ComponentState<TContractState>,
            identity: ContractAddress,
            claim_topic: felt252,
            signature: Span<felt252>,
            data: ByteArray,
        ) -> bool {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            Identity::is_claim_valid(@self, identity, claim_topic, signature, data)
        }
        // IERC734
        fn add_key(
            ref self: ComponentState<TContractState>,
            key: felt252,
            purpose: felt252,
            key_type: felt252,
        ) -> bool {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::add_key(ref self, key, purpose, key_type)
        }

        fn remove_key(
            ref self: ComponentState<TContractState>, key: felt252, purpose: felt252,
        ) -> bool {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::remove_key(ref self, key, purpose)
        }

        fn approve(
            ref self: ComponentState<TContractState>, execution_id: felt252, approve: bool,
        ) -> bool {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::approve(ref self, execution_id, approve)
        }

        fn execute(
            ref self: ComponentState<TContractState>,
            to: ContractAddress,
            selector: felt252,
            calldata: Span<felt252>,
        ) -> felt252 {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::execute(ref self, to, selector, calldata)
        }

        fn get_key(
            ref self: ComponentState<TContractState>, key: felt252,
        ) -> (Span<felt252>, felt252, felt252) {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::get_key(@self, key)
        }

        fn get_key_purposes(
            ref self: ComponentState<TContractState>, key: felt252,
        ) -> Span<felt252> {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::get_key_purposes(@self, key)
        }

        fn get_keys_by_purpose(
            ref self: ComponentState<TContractState>, purpose: felt252,
        ) -> Span<felt252> {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::get_keys_by_purpose(@self, purpose)
        }

        fn key_has_purpose(
            ref self: ComponentState<TContractState>, key: felt252, purpose: felt252,
        ) -> bool {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC734::key_has_purpose(@self, key, purpose)
        }
        // IERC735
        fn add_claim(
            ref self: ComponentState<TContractState>,
            topic: felt252,
            scheme: felt252,
            issuer: ContractAddress,
            signature: Span<felt252>,
            data: ByteArray,
            uri: ByteArray,
        ) -> felt252 {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC735::add_claim(ref self, topic, scheme, issuer, signature, data, uri)
        }

        fn remove_claim(ref self: ComponentState<TContractState>, claim_id: felt252) -> bool {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC735::remove_claim(ref self, claim_id)
        }

        fn get_claim(
            ref self: ComponentState<TContractState>, claim_id: felt252,
        ) -> (felt252, felt252, ContractAddress, Span<felt252>, ByteArray, ByteArray) {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC735::get_claim(@self, claim_id)
        }

        fn get_claim_ids_by_topics(
            ref self: ComponentState<TContractState>, topic: felt252,
        ) -> Span<felt252> {
            let mut version_manager_comp = get_dep_component_mut!(ref self, VersionManagerImpl);
            version_manager_comp.assert_up_to_date_implementation();
            ERC735::get_claim_ids_by_topics(@self, topic)
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +Drop<TContractState>, +HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        fn initialize(
            ref self: ComponentState<TContractState>, initial_management_key: ContractAddress,
        ) {
            assert(initial_management_key.is_non_zero(), Errors::ZERO_ADDRESS);
            let initial_management_key_hash = poseidon_hash_span(
                array![initial_management_key.into()].span(),
            );
            let key_storage_path = self.Identity_keys.entry(initial_management_key_hash);
            key_storage_path.key.write(initial_management_key_hash);
            key_storage_path.key_type.write(1);
            key_storage_path.purposes.deref().append().write(1);

            self.Identity_keys_by_purpose.entry(1).append().write(initial_management_key_hash);
            self
                .emit(
                    ERC734Event::KeyAdded(
                        ierc734::KeyAdded {
                            key: initial_management_key_hash, key_type: 1, purpose: 1,
                        },
                    ),
                );
        }

        fn only_manager(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            assert(
                caller == starknet::get_contract_address()
                    || self.key_has_purpose(poseidon_hash_span(array![caller.into()].span()), 1),
                Errors::NOT_HAVE_MANAGEMENT_KEY,
            );
        }

        fn only_claim_key(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            assert(
                caller == starknet::get_contract_address()
                    || self.key_has_purpose(poseidon_hash_span(array![caller.into()].span()), 3),
                Errors::NOT_HAVE_CLAIM_KEY,
            );
        }

        fn _approve(
            ref self: ComponentState<TContractState>,
            execution_id: felt252,
            to: ContractAddress,
            selector: felt252,
            data: Span<felt252>,
        ) -> bool {
            self.emit(ERC734Event::Approved(ierc734::Approved { execution_id, approved: true }));
            let execution_storage_path = self.Identity_executions.entry(execution_id);
            execution_storage_path.approved.write(true);
            // see
            // {https://book.cairo-lang.org/appendix-08-system-calls.html?highlight=call_con#call_contract}
            // TODO: remove failing path since we caannot handle gracefully
            match starknet::syscalls::call_contract_syscall(to, selector, data) {
                Result::Ok => {
                    execution_storage_path.executed.write(true);
                    self
                        .emit(
                            ERC734Event::Executed(
                                ierc734::Executed { execution_id, to, selector, data },
                            ),
                        );
                    true
                },
                Result::Err => {
                    self
                        .emit(
                            ERC734Event::ExecutionFailed(
                                ierc734::ExecutionFailed { execution_id, to, selector, data },
                            ),
                        );
                    false
                },
            }
        }
    }
}

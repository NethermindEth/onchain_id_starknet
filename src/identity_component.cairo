#[starknet::component]
pub mod IdentityComponent {
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::interface::ierc734::{ERC734Event, IERC734};
    use onchain_id_starknet::interface::ierc735::{ERC735Event, IERC735};
    use onchain_id_starknet::interface::iidentity::{
        IIdentity, IIdentityDispatcher, IIdentityDispatcherTrait,
    };
    use onchain_id_starknet::interface::{ierc734, ierc735};
    use onchain_id_starknet::storage::signature::{get_public_key_hash, is_valid_signature};
    use onchain_id_starknet::storage::structs::{
        Claim, Execution, ExecutionRequestStatus, KeyDetails, KeyDetailsTrait,
    };
    use openzeppelin_upgrades::upgradeable::UpgradeableComponent;
    use starknet::ContractAddress;
    use starknet::storage::{
        Map, MutableVecTrait, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
        Vec, VecTrait,
    };

    #[storage]
    pub struct Storage {
        Identity_execution_nonce: felt252,
        Identity_keys: Map<felt252, KeyDetails>,
        Identity_keys_by_purpose: Map<felt252, Vec<felt252>>,
        Identity_executions: Map<felt252, Execution>,
        Identity_claims: Map<felt252, Claim>,
        Identity_claims_by_topic: Map<felt252, Vec<felt252>>,
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
        pub const EXECUTION_REJECTED: felt252 = 'Request has been rejected';
    }

    pub mod Purpose {
        pub const MANAGEMENT: felt252 = 1;
        pub const ACTION: felt252 = 2;
        pub const CLAIM: felt252 = 3;
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
            if !self.key_has_purpose(pub_key_hash, Purpose::CLAIM) {
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
            let key_storage_path = self.Identity_keys.entry(key);
            let mut key_details = key_storage_path.read();
            let purpose_bit_index = purpose.try_into().expect('Invalid Purpose');
            assert(!key_details.has_purpose(purpose_bit_index), Errors::KEY_ALREADY_HAS_PURPOSE);
            key_details.grant_purpose(purpose_bit_index);
            key_details.key_type = key_type.try_into().expect('Invalid Key Type');
            key_storage_path.write(key_details);

            self.Identity_keys_by_purpose.entry(purpose).push(key);
            self.emit(ERC734Event::KeyAdded(ierc734::KeyAdded { key, purpose, key_type }));
            true
        }

        /// This function removes given purpose from given key of given identity.
        ///
        /// # Arguments
        ///
        /// * `key` - A `felt252` representing hash of the key(public key, ContractAddress).
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
            let mut key_details = key_storage_path.read();
            assert(key_details.purposes.is_non_zero(), Errors::KEY_NOT_REGISTERED);
            assert(key_details.has_purpose(purpose), Errors::KEY_DOES_NOT_HAVE_PURPOSE);

            key_details.revoke_purpose(purpose);

            let key_type: felt252 = key_details.key_type.into();
            if key_details.purposes.is_zero() {
                key_details.key_type = Zero::zero();
            }

            key_storage_path.write(key_details);

            let keys_by_purpose_key_storage_path = self.Identity_keys_by_purpose.entry(purpose);

            let keys_by_purpose_len = keys_by_purpose_key_storage_path.len();
            for i in 0..keys_by_purpose_len {
                if keys_by_purpose_key_storage_path[i].read() == key {
                    if i != keys_by_purpose_len - 1 {
                        let last_element = keys_by_purpose_key_storage_path.pop().unwrap();
                        keys_by_purpose_key_storage_path[i].write(last_element);
                    } else {
                        keys_by_purpose_key_storage_path.pop().unwrap();
                    }
                    break;
                }
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
            let mut execution_request_status = execution_storage_path
                .execution_request_status
                .read();

            assert(
                execution_request_status != ExecutionRequestStatus::Executed,
                Errors::ALREADY_EXECUTED,
            );
            assert(
                execution_request_status != ExecutionRequestStatus::Rejected,
                Errors::EXECUTION_REJECTED,
            );
            let caller_hash = poseidon_hash_span(
                array![starknet::get_caller_address().into()].span(),
            );
            let to_address = execution_storage_path.to.read();
            if to_address == starknet::get_contract_address() {
                assert(
                    self.key_has_purpose(caller_hash, Purpose::MANAGEMENT),
                    Errors::NOT_HAVE_MANAGEMENT_KEY,
                );
            } else {
                assert(
                    self.key_has_purpose(caller_hash, Purpose::ACTION), Errors::NOT_HAVE_ACTION_KEY,
                );
            }
            self.emit(ERC734Event::Approved(ierc734::Approved { execution_id, approved: approve }));
            if !approve {
                execution_storage_path
                    .execution_request_status
                    .write(ExecutionRequestStatus::Rejected);
                return false;
            }

            execution_request_status = ExecutionRequestStatus::Approved;
            let selector = execution_storage_path.selector.read();

            let mut calldata = array![];
            let calldata_storage = execution_storage_path.calldata.deref();
            for i in 0..calldata_storage.len() {
                calldata.append(calldata_storage.at(i).read())
            }

            let execution_result =
                match starknet::syscalls::call_contract_syscall(
                    to_address, selector, calldata.span(),
                ) {
                Result::Ok => {
                    self
                        .emit(
                            ERC734Event::Executed(
                                ierc734::Executed {
                                    execution_id, to: to_address, selector, data: calldata.span(),
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
                                    execution_id, to: to_address, selector, data: calldata.span(),
                                },
                            ),
                        );
                    false
                },
            };

            if execution_result {
                execution_request_status = ExecutionRequestStatus::Executed;
            }
            execution_storage_path.execution_request_status.write(execution_request_status);

            execution_result
        }

        fn execute(
            ref self: ComponentState<TContractState>,
            to: ContractAddress,
            selector: felt252,
            calldata: Span<felt252>,
        ) -> felt252 {
            let execution_nonce = self.Identity_execution_nonce.read();
            self.Identity_execution_nonce.write(execution_nonce + 1);

            let execution_storage_path = self.Identity_executions.entry(execution_nonce);
            execution_storage_path.to.write(to);
            execution_storage_path.selector.write(selector);
            let calldata_storage_path = execution_storage_path.calldata.deref();
            for chunk in calldata.clone() {
                calldata_storage_path.push(*chunk);
            }

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

            if to != starknet::get_contract_address()
                && self.key_has_purpose(caller_hash, Purpose::ACTION) {
                self._approve(execution_nonce, to, selector, calldata);
            } else if self.key_has_purpose(caller_hash, Purpose::MANAGEMENT) {
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
            let key_details = self.Identity_keys.entry(key).read();
            if key_details.purposes.is_zero() {
                return ([].span(), Zero::zero(), Zero::zero());
            }
            (key_details.get_all_purposes().span(), key_details.key_type.into(), key)
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
            self.Identity_keys.entry(key).read().get_all_purposes().span()
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
            let mut keys = array![];
            let keys_storage_path = self.Identity_keys_by_purpose.entry(purpose);
            for i in 0..keys_storage_path.len() {
                keys.append(keys_storage_path[i].read());
            }
            keys.span()
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
            let key_details = self.Identity_keys.entry(key).read();
            key_details.has_purpose(Purpose::MANAGEMENT) || key_details.has_purpose(purpose)
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

            claim_storage_path.scheme.write(scheme);

            let signature_storage = claim_storage_path.signature.deref();
            for chunk in signature {
                signature_storage.append().write(*chunk);
            }

            claim_storage_path.data.write(data.clone());
            claim_storage_path.uri.write(uri.clone());

            if claim_storage_path.issuer.read() != issuer {
                let signature_storage = claim_storage_path.signature.deref();
                for chunk in signature {
                    signature_storage.push(*chunk);
                }
                self.Identity_claims_by_topic.entry(topic).push(claim_id);
                claim_storage_path.issuer.write(issuer);
                claim_storage_path.topic.write(topic);
                self
                    .emit(
                        ERC735Event::ClaimAdded(
                            ierc735::ClaimAdded {
                                claim_id, topic, scheme, issuer, signature, data, uri,
                            },
                        ),
                    );
            } else {
                let signature_storage = claim_storage_path.signature.deref();
                // Clear previous signature
                while signature_storage.pop().is_some() {}
                // Store new signature
                for chunk in signature {
                    signature_storage.push(*chunk);
                }
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
            let mut claim_index = Option::None;
            let claims_by_topic_len = claims_by_topic_storage_path.len();
            for i in 0..claims_by_topic_len {
                if claims_by_topic_storage_path[i].read() == claim_id {
                    claim_index = Option::Some(i);
                    break;
                }
            }
            assert(
                claim_index != Option::None, Errors::CLAIM_DOES_NOT_EXIST,
            ); // NOTE: this check might not be necessary due to above assertion we might assume claim_id will always be there

            if claim_index.unwrap() != claims_by_topic_len - 1 {
                let last_element = claims_by_topic_storage_path.pop().unwrap();
                claims_by_topic_storage_path[claim_index.unwrap()].write(last_element);
            } else {
                claims_by_topic_storage_path.pop().unwrap();
            }

            let mut signature = array![];
            let signature_storage = claim_storage_path.signature.deref();
            for i in 0..signature_storage.len() {
                signature.append(signature_storage.at(i).read());
            }

            self
                .emit(
                    ERC735Event::ClaimRemoved(
                        ierc735::ClaimRemoved {
                            claim_id,
                            topic,
                            scheme: claim_storage_path.scheme.read(),
                            issuer: claim_storage_path.issuer.read(),
                            signature: signature.span(),
                            data: claim_storage_path.data.read(),
                            uri: claim_storage_path.uri.read(),
                        },
                    ),
                );

            // Delete claim data
            claim_storage_path.topic.write(Default::default());
            claim_storage_path.scheme.write(Default::default());
            claim_storage_path.issuer.write(Zero::zero());
            let signature_storage = claim_storage_path.signature.deref();
            // Clear signature
            while signature_storage.pop().is_some() {}
            claim_storage_path.data.write(Default::default());
            claim_storage_path.uri.write(Default::default());
            true
        }

        fn get_claim(
            self: @ComponentState<TContractState>, claim_id: felt252,
        ) -> (felt252, felt252, ContractAddress, Span<felt252>, ByteArray, ByteArray) {
            let claim_storage_path = self.Identity_claims.entry(claim_id);
            let mut signature = array![];
            let signature_storage = claim_storage_path.signature.deref();
            for i in 0..signature_storage.len() {
                signature.append(signature_storage.at(i).read());
            }

            (
                claim_storage_path.topic.read(),
                claim_storage_path.scheme.read(),
                claim_storage_path.issuer.read(),
                signature.span(),
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
            self
                .Identity_keys
                .entry(initial_management_key_hash)
                .write(KeyDetails { purposes: 2, key_type: 1 });

            self.Identity_keys_by_purpose.entry(1).push(initial_management_key_hash);
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
                    || self
                        .key_has_purpose(
                            poseidon_hash_span(array![caller.into()].span()), Purpose::MANAGEMENT,
                        ),
                Errors::NOT_HAVE_MANAGEMENT_KEY,
            );
        }

        fn only_claim_key(self: @ComponentState<TContractState>) {
            let caller = starknet::get_caller_address();
            assert(
                caller == starknet::get_contract_address()
                    || self
                        .key_has_purpose(
                            poseidon_hash_span(array![caller.into()].span()), Purpose::CLAIM,
                        ),
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

            let execution_result =
                match starknet::syscalls::call_contract_syscall(to, selector, data) {
                Result::Ok => {
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
            };

            let status = if execution_result {
                ExecutionRequestStatus::Executed
            } else {
                ExecutionRequestStatus::Approved
            };

            self.Identity_executions.entry(execution_id).execution_request_status.write(status);
            execution_result
        }
    }
}

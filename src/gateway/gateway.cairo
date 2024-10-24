use onchain_id_starknet::storage::structs::Signature;
use starknet::ContractAddress;

#[starknet::interface]
trait IGateway<TContractState> {
    fn approve_signer(ref self: TContractState, signer: felt252);
    fn revoke_signer(ref self: TContractState, signer: felt252);
    fn deploy_identity_with_salt(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: felt252,
        signature_expiry: u64,
        signature: Signature
    ) -> ContractAddress;
    fn deploy_identity_with_salt_and_management_keys(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: felt252,
        management_keys: Array<felt252>,
        signature_expiry: u64,
        signature: Signature
    ) -> ContractAddress;
    fn deploy_identity_for_wallet(
        ref self: TContractState, identity_owner: ContractAddress
    ) -> ContractAddress;
    fn revoke_signature(ref self: TContractState, signature: Signature);
    fn approve_signature(ref self: TContractState, signature: Signature);
    fn transfer_factory_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn call_factory(ref self: TContractState, selector: felt252, calldata: Span<felt252>);
}

#[starknet::contract]
mod Gateway {
    use core::ecdsa::recover_public_key;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use onchain_id_starknet::factory::iid_factory::{
        IIdFactoryDispatcher, IIdFactoryDispatcherTrait
    };
    use onchain_id_starknet::storage::structs::Signature;
    use openzeppelin_access::ownable::{
        ownable::OwnableComponent, interface::{IOwnableDispatcher, IOwnableDispatcherTrait},
    };
    use starknet::ContractAddress;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, Map, StoragePathEntry
    };

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl =
        OwnableComponent::OwnableImpl<ContractState>; // NOTE: consider making it 2 step
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        id_factory: ContractAddress,
        approved_signers: Map<felt252, bool>,
        revoked_signatures: Map<Signature, bool>, //Map<ByteArray, bool> in sol
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        SignerApproved: SignerApproved,
        SignerRevoked: SignerRevoked,
        SignatureApproved: SignatureApproved,
        SignatureRevoked: SignatureRevoked,
        #[flat]
        OwnableEvent: OwnableComponent::Event
    }

    #[derive(Drop, starknet::Event)]
    struct SignerApproved {
        #[key]
        signer: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct SignerRevoked {
        #[key]
        signer: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct SignatureApproved {
        #[key]
        signature: Signature,
    }

    #[derive(Drop, starknet::Event)]
    struct SignatureRevoked {
        #[key]
        signature: Signature,
    }

    pub mod Errors {
        use super::Signature;
        pub fn ZeroAddress() {
            panic!("A required parameter was set to the Zero address.");
        }
        pub fn TooManySigners() {
            panic!("The maximum number of signers was reached at deployment.");
        }
        pub fn SignerAlreadyApproved(signer: felt252) {
            panic!("The signed attempted to add was already approved. Signer: {:?}", signer);
        }
        pub fn SignerAlreadyNotApproved(signer: felt252) {
            panic!("The signed attempted to remove was not approved. Signer {:?}", signer);
        }
        pub fn UnsignedDeployment() {
            panic!(
                "A requested ONCHAINID deployment was requested without a valid signature while the Gateway requires one."
            );
        }
        pub fn UnapprovedSigner(signer: felt252) {
            panic!(
                "A requested ONCHAINID deployment was requested and signer by a non approved signer."
            );
        }
        pub fn RevokedSignature(signature: Signature) {
            panic!(
                "A requested ONCHAINID deployment was requested with a signature revoked. Signature: {:?}",
                signature
            );
        }
        pub fn ExpiredSignature(signature: Signature) {
            panic!(
                "A requested ONCHAINID deployment was requested with a signature that expired. Signature: {:?}",
                signature
            );
        }
        pub fn SignatureAlreadyRevoked(signature: Signature) {
            panic!(
                "Attempted to revoke a signature that was already revoked. Signature: {:?}",
                signature
            );
        }
        pub fn SignatureNotRevoked(signature: Signature) {
            panic!(
                "Attempted to approve a signature that was not revoked. Signature: {:?}", signature
            );
        }
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        id_factory_address: ContractAddress,
        signers_to_approve: Array<felt252>
    ) {
        if owner.is_zero() {
            Errors::ZeroAddress();
        }
        self.ownable.initializer(owner);

        if id_factory_address.is_zero() {
            Errors::ZeroAddress();
        }

        if signers_to_approve.len() > 10 {
            Errors::TooManySigners();
        }

        for signer in signers_to_approve {
            self.approved_signers.entry(signer).write(true);
        };

        self.id_factory.write(id_factory_address);
    }

    #[abi(embed_v0)]
    impl GatewayImpl of super::IGateway<ContractState> {
        /// This function approves a signer to sign identity deployments.
        ///
        /// # Arguments
        /// * `signer` - A `felt252` representing the public key of signer to approve.
        ///
        /// # Requirements
        ///
        /// Must be called by gateway owner.
        /// `signer` must not be zero.
        /// `signer` must not be already approved.
        fn approve_signer(ref self: ContractState, signer: felt252) {
            self.ownable.assert_only_owner();
            if signer.is_zero() {
                Errors::ZeroAddress();
            };
            let approved_signer_storage_path = self.approved_signers.entry(signer);
            if approved_signer_storage_path.read() {
                Errors::SignerAlreadyApproved(signer);
            }
            approved_signer_storage_path.write(true);
            self.emit(SignerApproved { signer });
        }

        /// This function revokes a signer to sign identity deployments.
        ///
        /// # Arguments
        ///
        /// * `signer` - A `felt252` representing the public key of signer to revoke.
        ///
        /// # Requirements
        ///
        /// Must be called by gateway owner.
        /// `signer` must not be zero.
        /// `signer` must be already approved.
        fn revoke_signer(ref self: ContractState, signer: felt252) {
            self.ownable.assert_only_owner();
            if signer.is_zero() {
                Errors::ZeroAddress();
            }
            let approved_signer_storage_path = self.approved_signers.entry(signer);
            if !approved_signer_storage_path.read() {
                Errors::SignerAlreadyNotApproved(signer);
            }
            approved_signer_storage_path.write(false);
            self.emit(SignerApproved { signer });
        }

        /// This function deploys an identity using a factory using custom salt and registers
        /// `identity_owner` as initial MANAGEMENT key.
        ///
        /// The operation must be signed by an approved public key. This method allows to deploy an
        /// identity using a custom salt.
        ///
        /// # Arguments
        ///
        /// * `identity_owner` - A `ContractAddress` respresenting the address to be added as
        /// MANAGEMENT key.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        /// * `signature_expiry`- A `u64` representing the block timestamp where the signature will
        /// expire.
        /// * `signature` - A `Signature` representing the signature of the deployment message.
        ///
        /// # Requirements
        ///
        /// - `identity_owner` must be non-zero.
        /// - `signature` must be signed by approved signer.
        /// - `signature`  must not expired already.
        /// - `signature`  must not revoked.
        /// - `salt` must be non-zero and not taken.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the deployed identity.
        fn deploy_identity_with_salt(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: felt252,
            signature_expiry: u64,
            signature: Signature
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            if signature_expiry != 0 && signature_expiry < starknet::get_block_timestamp() {
                Errors::ExpiredSignature(signature);
            }

            /// TODO: comply with  SNIP12
            let mut serialized_message: Array<felt252> = array![];
            let seperator: ByteArray = "Authorize ONCHAINID deployment";
            seperator.serialize(ref serialized_message);
            identity_owner.serialize(ref serialized_message);
            salt.serialize(ref serialized_message);
            signature_expiry.serialize(ref serialized_message);

            let message_hash: felt252 = poseidon_hash_span(serialized_message.span());
            let signer: felt252 = recover_public_key(
                message_hash, signature.r, signature.s, signature.y_parity
            )
                .unwrap();

            if self.approved_signers.entry(signer).read() {
                Errors::UnapprovedSigner(signer);
            }

            if self.revoked_signatures.entry(signature).read() {
                Errors::SignatureAlreadyRevoked(signature);
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, salt)
        }

        /// This function deploys an identity using a factory using custom salt and registers
        /// `management_keys` as initial MANAGEMENT keys.
        ///
        /// The operation must be signed by an approved public key. This method allows to deploy an
        /// identity using a custom salt. `identity_owner` wont be added as MANAGEMENT key, if this
        /// is desired add poseidon of `identity_owner` in `management_keys`.
        ///
        /// # Arguments
        ///
        /// * `identity_owner` - A `ContractAddress` respresenting the address to be added as
        /// MANAGEMENT key.
        /// * `salt` - A `felt252` representing the salt used while deployment.
        /// * `signature_expiry`- A `u64` representing the block timestamp where the signature will
        /// expire.
        /// * `signature` - A `Signature` representing the signature of the deployment message.
        /// * `management_keys` - A `Array<felt252>` representing the array of keys hash(poseidon
        /// hash) to add as MANAGEMENT keys.
        ///
        /// # Requirements
        ///
        /// - `identity_owner` must be non-zero.
        /// - `signature` must be signed by approved signer.
        /// - `signature` must not expired already.
        /// - `signature` must not revoked.
        /// - `management_keys` length should be greater than 0.
        /// - `salt` must be non-zero and not taken.
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the deployed identity.
        fn deploy_identity_with_salt_and_management_keys(
            ref self: ContractState,
            identity_owner: ContractAddress,
            salt: felt252,
            management_keys: Array<felt252>,
            signature_expiry: u64,
            signature: Signature
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            if signature_expiry != 0 && signature_expiry < starknet::get_block_timestamp() {
                Errors::ExpiredSignature(signature);
            }
            /// TODO: comply with  SNIP12
            let mut serialized_message: Array<felt252> = array![];
            let seperator: ByteArray = "Authorize ONCHAINID deployment";
            seperator.serialize(ref serialized_message);
            identity_owner.serialize(ref serialized_message);
            salt.serialize(ref serialized_message);
            management_keys.serialize(ref serialized_message);
            signature_expiry.serialize(ref serialized_message);

            /// TODO: comply with  SNIP12
            let message_hash: felt252 = poseidon_hash_span(serialized_message.span());
            let signer: felt252 = recover_public_key(
                message_hash, signature.r, signature.s, signature.y_parity
            )
                .unwrap();

            if self.approved_signers.entry(signer).read() {
                Errors::UnapprovedSigner(signer);
            }

            if self.revoked_signatures.entry(signature).read() {
                Errors::SignatureAlreadyRevoked(signature);
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity_with_management_keys(identity_owner, salt, management_keys)
        }

        /// This function deploys an identity using a factory using the identity_owner as salt.
        ///
        /// # Arguments
        ///
        /// * `identity_owner` - A `ContractAddress` respresenting the address to be added as
        /// MANAGEMENT key and will be used as salt value.
        ///
        /// # Requirements
        ///
        /// - `identity_owner` must be non-zero.
        /// - `identity_owner must not already deployed identity via this function`
        ///
        /// # Returns
        ///
        /// A `ContractAddress` representing the deployed identity.
        fn deploy_identity_for_wallet(
            ref self: ContractState, identity_owner: ContractAddress
        ) -> ContractAddress {
            if identity_owner.is_zero() {
                Errors::ZeroAddress();
            }

            IIdFactoryDispatcher { contract_address: self.id_factory.read() }
                .create_identity(identity_owner, identity_owner.into())
        }

        /// This function revokes the given signature
        ///
        /// If the signature is used to sign deployment, revoking the signature will invalidate the
        /// deployment, thus deployment will be rejected.
        ///
        /// # Arguments
        ///
        /// * `signature` - A `Signature` representing the signature to revoke.
        ///
        /// # Requirements
        ///
        /// Must be called by gateway owner.
        /// - `signature` must not be already revoked.
        fn revoke_signature(ref self: ContractState, signature: Signature) {
            self.ownable.assert_only_owner();
            let revoked_signature_storage_path = self.revoked_signatures.entry(signature);
            if revoked_signature_storage_path.read() {
                Errors::SignatureAlreadyRevoked(signature);
            }
            revoked_signature_storage_path.write(true);
            self.emit(SignatureRevoked { signature });
        }

        /// This function removes the given signature from revokes list
        ///
        /// # Arguments
        ///
        /// * `signature` - A `Signature` representing the signature to remove from revoke list.
        ///
        /// # Requirements
        ///
        /// Must be called by gateway owner.
        /// - `signature` must already revoked.
        fn approve_signature(ref self: ContractState, signature: Signature) {
            self.ownable.assert_only_owner();
            let revoked_signature_storage_path = self.revoked_signatures.entry(signature);
            if !revoked_signature_storage_path.read() {
                Errors::SignatureNotRevoked(signature);
            }
            revoked_signature_storage_path.write(false);
            self.emit(SignatureApproved { signature });
        }

        /// This functions transfers the ownership of the IdFactory contract.
        ///
        /// # Arguments
        ///
        /// * `new_owner` - A `ContractAddress` represent the new owner of the IdFactory.
        ///
        /// # Requirements
        ///
        /// Must called by gateway owner.
        fn transfer_factory_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self.ownable.assert_only_owner();
            IOwnableDispatcher { contract_address: self.id_factory.read() }
                .transfer_ownership(new_owner);
        }

        /// This function calls the IdFactory contract with the given arbitrary call params.
        ///
        /// # Arguments
        ///
        /// * `selector` - A `felt252` representing the entry point selector to call
        /// * `calldata` - A `Span<felt252>` representing the serialized calldata to be passed to
        /// factory.
        ///
        /// # Requirements
        ///
        /// Must be called by gateway owner.
        fn call_factory(ref self: ContractState, selector: felt252, calldata: Span<felt252>) {
            self.ownable.assert_only_owner();
            starknet::syscalls::call_contract_syscall(self.id_factory.read(), selector, calldata)
                .unwrap();
        }
    }
}

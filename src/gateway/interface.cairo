use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::PoseidonTrait;
use openzeppelin_utils::cryptography::snip12::{SNIP12HashSpanImpl, StructHash};
use starknet::ContractAddress;

#[derive(Copy, Debug, Drop, Serde, Hash)]
pub struct Signature {
    pub r: felt252,
    pub s: felt252,
    pub y_parity: bool,
}

#[derive(Copy, Drop, Serde)]
pub struct Deployment {
    pub identity_owner: ContractAddress,
    pub salt: felt252,
    pub expiration: u64,
}

pub const DEPLOYMENT_TYPEHASH: felt252 = selector!(
    "\"Deployment\"(
        \"identity_owner\":\"ContractAddress\",
        \"salt\":\"felt\",
        \"expiration\":\"u128\",
    )",
);

pub impl DeploymentStructHash of StructHash<Deployment> {
    fn hash_struct(self: @Deployment) -> felt252 {
        PoseidonTrait::new()
            .update_with(DEPLOYMENT_TYPEHASH)
            .update_with(*self.identity_owner)
            .update_with(*self.salt)
            .update_with(*self.expiration)
            .finalize()
    }
}

#[derive(Copy, Drop, Serde)]
pub struct DeploymentWithManagementKeys {
    pub identity_owner: ContractAddress,
    pub salt: felt252,
    pub management_keys: Span<felt252>,
    pub expiration: u64,
}

pub const DEPLOYMENT_WITH_MANAGEMENT_KEYS_TYPEHASH: felt252 = selector!(
    "\"DeploymentWithManagementKeys\"(
        \"identity_owner\":\"ContractAddress\",
        \"salt\":\"felt\",
        \"management_keys\":\"felt*\",
        \"expiration\":\"u128\",
    )",
);

pub impl DeploymentWithManagementKeysStructHash of StructHash<DeploymentWithManagementKeys> {
    fn hash_struct(self: @DeploymentWithManagementKeys) -> felt252 {
        PoseidonTrait::new()
            .update_with(DEPLOYMENT_WITH_MANAGEMENT_KEYS_TYPEHASH)
            .update_with(*self.identity_owner)
            .update_with(*self.salt)
            .update_with(*self.management_keys)
            .update_with(*self.expiration)
            .finalize()
    }
}

#[starknet::interface]
pub trait IGateway<TContractState> {
    fn approve_signer(ref self: TContractState, signer: felt252);
    fn revoke_signer(ref self: TContractState, signer: felt252);
    fn deploy_identity_with_salt(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: felt252,
        signature_expiry: u64,
        signature: Signature,
    ) -> ContractAddress;
    fn deploy_identity_with_salt_and_management_keys(
        ref self: TContractState,
        identity_owner: ContractAddress,
        salt: felt252,
        management_keys: Span<felt252>,
        signature_expiry: u64,
        signature: Signature,
    ) -> ContractAddress;
    fn deploy_identity_for_wallet(
        ref self: TContractState, identity_owner: ContractAddress,
    ) -> ContractAddress;
    fn revoke_signature(ref self: TContractState, signature: Signature);
    fn approve_signature(ref self: TContractState, signature: Signature);
    fn transfer_factory_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn call_factory(ref self: TContractState, selector: felt252, calldata: Span<felt252>);
    // Getters
    fn is_approved_signer(self: @TContractState, signer: felt252) -> bool;
    fn is_revoked_signature(self: @TContractState, signature: Signature) -> bool;
    fn get_id_factory(self: @TContractState) -> ContractAddress;
}

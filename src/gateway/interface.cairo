use starknet::ContractAddress;

#[derive(Copy, Debug, Drop, Serde, Hash)]
pub struct Signature {
    pub r: felt252,
    pub s: felt252,
    pub y_parity: bool,
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
        management_keys: Array<felt252>,
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

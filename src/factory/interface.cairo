use starknet::ContractAddress;

#[starknet::interface]
pub trait IIdFactory<TContractState> {
    fn create_identity(
        ref self: TContractState, wallet: ContractAddress, salt: felt252,
    ) -> ContractAddress;
    fn create_identity_with_management_keys(
        ref self: TContractState,
        wallet: ContractAddress,
        salt: felt252,
        management_keys: Array<felt252>,
    ) -> ContractAddress;
    fn create_token_identity(
        ref self: TContractState,
        token: ContractAddress,
        token_owner: ContractAddress,
        salt: felt252,
    ) -> ContractAddress;
    fn link_wallet(ref self: TContractState, new_wallet: ContractAddress);
    fn unlink_wallet(ref self: TContractState, old_wallet: ContractAddress);
    fn add_token_factory(ref self: TContractState, factory: ContractAddress);
    fn remove_token_factory(ref self: TContractState, factory: ContractAddress);
    fn get_identity(self: @TContractState, wallet: ContractAddress) -> ContractAddress;
    fn get_wallets(self: @TContractState, identity: ContractAddress) -> Span<ContractAddress>;
    fn get_token(self: @TContractState, identity: ContractAddress) -> ContractAddress;
    fn is_token_factory(self: @TContractState, factory: ContractAddress) -> bool;
    fn is_salt_taken(self: @TContractState, salt: felt252) -> bool;
    fn implementation_authority(self: @TContractState) -> ContractAddress;
}

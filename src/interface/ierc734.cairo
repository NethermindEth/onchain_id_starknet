use starknet::ContractAddress;

#[event]
#[derive(Drop, starknet::Event)]
pub enum ERC734Event {
    Approved: Approved,
    Executed: Executed,
    ExecutionRequested: ExecutionRequested,
    ExecutionFailed: ExecutionFailed,
    KeyAdded: KeyAdded,
    KeyRemoved: KeyRemoved,
}

#[derive(Drop, starknet::Event)]
pub struct Approved {
    #[key]
    pub execution_id: felt252,
    pub approved: bool,
}

#[derive(Drop, starknet::Event)]
pub struct Executed {
    #[key]
    pub execution_id: felt252,
    #[key]
    pub to: ContractAddress,
    #[key]
    pub selector: felt252,
    pub data: Span<felt252>,
}

#[derive(Drop, starknet::Event)]
pub struct ExecutionRequested {
    #[key]
    pub execution_id: felt252,
    #[key]
    pub to: ContractAddress,
    #[key]
    pub selector: felt252,
    pub data: Span<felt252>,
}

#[derive(Drop, starknet::Event)]
pub struct ExecutionFailed {
    #[key]
    pub execution_id: felt252,
    #[key]
    pub to: ContractAddress,
    #[key]
    pub selector: felt252,
    pub data: Span<felt252>,
}

#[derive(Drop, starknet::Event)]
pub struct KeyAdded {
    #[key]
    pub key: felt252,
    #[key]
    pub purpose: felt252,
    #[key]
    pub key_type: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct KeyRemoved {
    #[key]
    pub key: felt252,
    #[key]
    pub purpose: felt252,
    #[key]
    pub key_type: felt252,
}

#[starknet::interface]
pub trait IERC734<TContractState> {
    fn add_key(ref self: TContractState, key: felt252, purpose: felt252, key_type: felt252) -> bool;
    fn remove_key(ref self: TContractState, key: felt252, purpose: felt252) -> bool;
    fn approve(ref self: TContractState, execution_id: felt252, approve: bool) -> bool;
    fn execute(
        ref self: TContractState, to: ContractAddress, selector: felt252, calldata: Span<felt252>,
    ) -> felt252;
    fn key_has_purpose(self: @TContractState, key: felt252, purpose: felt252) -> bool;
    fn get_key(self: @TContractState, key: felt252) -> (Span<felt252>, felt252, felt252);
    fn get_key_purposes(self: @TContractState, key: felt252) -> Span<felt252>;
    fn get_keys_by_purpose(self: @TContractState, purpose: felt252) -> Span<felt252>;
}

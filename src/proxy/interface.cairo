use starknet::ClassHash;

#[starknet::interface]
pub trait IImplementationAuthority<TContractState> {
    fn update_implementation(ref self: TContractState, new_class_hash: ClassHash);
    fn get_implementation(self: @TContractState) -> ClassHash;
}

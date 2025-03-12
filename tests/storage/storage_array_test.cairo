use starknet::ContractAddress;

/// Mock Storage Array Holder
#[starknet::contract]
mod StorageArrayHolder {
    use onchain_id_starknet::storage::storage::{
        MutableContractAddressVecToContractAddressArray, MutableFelt252VecToFelt252Array,
        MutableStorageArrayTrait, StorageArrayContractAddress, StorageArrayFelt252,
    };
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        vec_felt252: StorageArrayFelt252,
        vec_contract_address: StorageArrayContractAddress,
    }

    #[external(v0)]
    pub fn append_vec_felt252(ref self: ContractState, value: felt252) {
        self.vec_felt252.deref().append().write(value);
    }

    #[external(v0)]
    pub fn append_vec_contract_address(ref self: ContractState, value: ContractAddress) {
        self.vec_contract_address.deref().append().write(value);
    }

    #[external(v0)]
    pub fn len_vec_felt252(ref self: ContractState) -> u64 {
        self.vec_felt252.deref().len()
    }

    #[external(v0)]
    pub fn len_vec_contract_address(ref self: ContractState) -> u64 {
        self.vec_contract_address.deref().len()
    }

    #[external(v0)]
    pub fn at_vec_felt252(ref self: ContractState, index: u64) -> felt252 {
        self.vec_felt252.deref().at(index).read()
    }

    #[external(v0)]
    pub fn at_vec_contract_address(ref self: ContractState, index: u64) -> ContractAddress {
        self.vec_contract_address.deref().at(index).read()
    }

    #[external(v0)]
    pub fn delete_from_vec_felt252(ref self: ContractState, index: u64) {
        self.vec_felt252.deref().delete(index);
    }

    #[external(v0)]
    pub fn delete_from_vec_contract_address(ref self: ContractState, index: u64) {
        self.vec_contract_address.deref().delete(index);
    }

    #[external(v0)]
    pub fn vec_felt252_into_array_felt252(ref self: ContractState) -> Array<felt252> {
        self.vec_felt252.deref().into()
    }

    #[external(v0)]
    pub fn vec_contract_address_into_array_contract_address(
        ref self: ContractState,
    ) -> Array<ContractAddress> {
        self.vec_contract_address.deref().into()
    }

    #[external(v0)]
    pub fn clear_vec_felt252(ref self: ContractState) {
        self.vec_felt252.deref().clear();
    }

    #[external(v0)]
    pub fn clear_vec_contract_address(ref self: ContractState) {
        self.vec_contract_address.deref().clear();
    }
}

/// Utils
pub fn serialized<T, +Serde<T>, +Destruct<T>>(value: T) -> Span<felt252> {
    let mut arr = Default::default();
    value.serialize(ref arr);
    arr.span()
}

pub fn deserialized<T, +Serde<T>, +Destruct<T>>(mut value: Span<felt252>) -> T {
    Serde::deserialize(ref value).unwrap()
}

/// Tests
#[test]
fn test_append_and_at_vec_felt252() {
    StorageArrayHolder::__external::append_vec_felt252(serialized(1));
    assert!(1 == deserialized(StorageArrayHolder::__external::at_vec_felt252(serialized(0))));
    assert!(1 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
    StorageArrayHolder::__external::append_vec_felt252(serialized(2));
    assert!(2 == deserialized(StorageArrayHolder::__external::at_vec_felt252(serialized(1))));
    assert!(2 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
    StorageArrayHolder::__external::append_vec_felt252(serialized(3));
    assert!(3 == deserialized(StorageArrayHolder::__external::at_vec_felt252(serialized(2))));
    assert!(3 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
}

#[test]
fn test_append_and_at_vec_contract_address() {
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap()),
    );
    assert!(
        TryInto::<felt252, ContractAddress>::try_into('first_address')
            .unwrap() == deserialized(
                StorageArrayHolder::__external::at_vec_contract_address(serialized(0)),
            ),
    );
    assert!(
        1 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap()),
    );
    assert!(
        TryInto::<felt252, ContractAddress>::try_into('second_address')
            .unwrap() == deserialized(
                StorageArrayHolder::__external::at_vec_contract_address(serialized(1)),
            ),
    );
    assert!(
        2 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap()),
    );
    assert!(
        TryInto::<felt252, ContractAddress>::try_into('third_address')
            .unwrap() == deserialized(
                StorageArrayHolder::__external::at_vec_contract_address(serialized(2)),
            ),
    );
    assert!(
        3 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
}

#[test]
fn test_vec_felt252_into_array() {
    StorageArrayHolder::__external::append_vec_felt252(serialized(1));
    StorageArrayHolder::__external::append_vec_felt252(serialized(2));
    StorageArrayHolder::__external::append_vec_felt252(serialized(3));
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_felt252_into_array_felt252(serialized(())),
        ) == array![1, 2, 3],
    );
}

#[test]
fn test_vec_contract_address_into_array() {
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap()),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap()),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap()),
    );
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_contract_address_into_array_contract_address(
                serialized(()),
            ),
        ) == array![
            TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap(),
            TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap(),
            TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap(),
        ],
    );
}


#[test]
fn test_delete_from_vec_felt252() {
    StorageArrayHolder::__external::append_vec_felt252(serialized(1));
    StorageArrayHolder::__external::append_vec_felt252(serialized(2));
    StorageArrayHolder::__external::append_vec_felt252(serialized(3));
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_felt252_into_array_felt252(serialized(())),
        ) == array![1, 2, 3],
    );
    assert!(3 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
    StorageArrayHolder::__external::delete_from_vec_felt252(serialized(0));
    assert!(2 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_felt252_into_array_felt252(serialized(())),
        ) == array![3, 2],
    );
    StorageArrayHolder::__external::delete_from_vec_felt252(serialized(1));
    assert!(1 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_felt252_into_array_felt252(serialized(())),
        ) == array![3],
    );
}

#[test]
fn test_delete_from_vec_contract_address() {
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap()),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap()),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap()),
    );
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_contract_address_into_array_contract_address(
                serialized(()),
            ),
        ) == array![
            TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap(),
            TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap(),
            TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap(),
        ],
    );
    assert!(
        3 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
    StorageArrayHolder::__external::delete_from_vec_contract_address(serialized(0));
    assert!(
        2 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_contract_address_into_array_contract_address(
                serialized(()),
            ),
        ) == array![
            TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap(),
            TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap(),
        ],
    );
    StorageArrayHolder::__external::delete_from_vec_contract_address(serialized(1));
    assert!(
        1 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_contract_address_into_array_contract_address(
                serialized(()),
            ),
        ) == array![TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap()],
    );
}

#[test]
fn test_clear_vec_felt252() {
    StorageArrayHolder::__external::append_vec_felt252(serialized(1));
    StorageArrayHolder::__external::append_vec_felt252(serialized(2));
    StorageArrayHolder::__external::append_vec_felt252(serialized(3));
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_felt252_into_array_felt252(serialized(())),
        ) == array![1, 2, 3],
    );
    assert!(3 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
    StorageArrayHolder::__external::clear_vec_felt252(serialized(()));
    assert!(0 == deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(()))));
}

#[test]
fn test_clear_vec_contract_address() {
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap()),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap()),
    );
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap()),
    );
    assert!(
        deserialized(
            StorageArrayHolder::__external::vec_contract_address_into_array_contract_address(
                serialized(()),
            ),
        ) == array![
            TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap(),
            TryInto::<felt252, ContractAddress>::try_into('second_address').unwrap(),
            TryInto::<felt252, ContractAddress>::try_into('third_address').unwrap(),
        ],
    );
    assert!(
        3 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
    StorageArrayHolder::__external::clear_vec_contract_address(serialized(()));
    assert!(
        0 == deserialized(StorageArrayHolder::__external::len_vec_contract_address(serialized(()))),
    );
}

#[test]
#[should_panic(expected: "Index out of bounds")]
fn test_should_panic_when_vec_felt252_when_access_out_of_bounds_index() {
    StorageArrayHolder::__external::append_vec_felt252(serialized(1));
    let len = deserialized(StorageArrayHolder::__external::len_vec_felt252(serialized(())));
    StorageArrayHolder::__external::at_vec_felt252(serialized(len + 1));
}

#[test]
#[should_panic(expected: "Index out of bounds")]
fn test_should_panic_when_vec_contract_address_when_access_out_of_bounds_index() {
    StorageArrayHolder::__external::append_vec_contract_address(
        serialized(TryInto::<felt252, ContractAddress>::try_into('first_address').unwrap()),
    );
    let len = deserialized(
        StorageArrayHolder::__external::len_vec_contract_address(serialized(())),
    );
    StorageArrayHolder::__external::at_vec_contract_address(serialized(len + 1));
}

use starknet::storage::{
    IntoIterRange, Mutable, MutableVecTrait, PendingStoragePath, StorageAsPath, StoragePath,
    StoragePointerReadAccess, StoragePointerWriteAccess, Vec,
};

pub trait VecDeleteTrait<T> {
    fn pop_swap(self: T, index: u64);
}

pub impl VecDeleteImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecDeleteTrait<StoragePath<Mutable<Vec<T>>>> {
    fn pop_swap(self: StoragePath<Mutable<Vec<T>>>, index: u64) {
        let len = self.len();
        assert!(index < len, "Index out of bounds");
        if index != len - 1 {
            let last_element = self.pop().unwrap();
            self.at(index).write(last_element);
        } else {
            self.pop().unwrap();
        }
    }
}

pub trait VecClearTrait<T> {
    fn clear(self: T);
}

impl VecClearImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecClearTrait<StoragePath<Mutable<Vec<T>>>> {
    fn clear(self: StoragePath<Mutable<Vec<T>>>) {
        while self.pop().is_some() {}
    }
}

pub trait VecToArrayTrait<T> {
    type ElementType;

    fn to_array(self: T) -> Array<Self::ElementType>;
}

impl VecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<StoragePath<Vec<T>>> {
    type ElementType = T;
    fn to_array(self: StoragePath<Vec<T>>) -> Array<Self::ElementType> {
        self.into_iter_full_range().map(|x| x.read()).collect::<Array<_>>()
    }
}

pub impl MutableVecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<StoragePath<Mutable<Vec<T>>>> {
    type ElementType = T;
    fn to_array(self: StoragePath<Mutable<Vec<T>>>) -> Array<Self::ElementType> {
        self.into_iter_full_range().map(|x| x.read()).collect::<Array<_>>()
    }
}

impl PathableVecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<PendingStoragePath<Vec<T>>> {
    type ElementType = T;
    fn to_array(self: PendingStoragePath<Vec<T>>) -> Array<Self::ElementType> {
        self.as_path().into_iter_full_range().map(|x| x.read()).collect::<Array<_>>()
    }
}

impl PathableMutableVecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<PendingStoragePath<Mutable<Vec<T>>>> {
    type ElementType = T;
    fn to_array(self: PendingStoragePath<Mutable<Vec<T>>>) -> Array<Self::ElementType> {
        self.as_path().into_iter_full_range().map(|x| x.read()).collect::<Array<_>>()
    }
}

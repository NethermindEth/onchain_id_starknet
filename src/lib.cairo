pub mod factory {
    pub mod factory;
    pub mod interface;
}

pub mod gateway {
    pub mod gateway;
    pub mod interface;
}

pub mod proxy {
    pub mod implementation_authority;
    pub mod interface;
}

pub mod storage {
    pub mod signature;
    pub mod structs;
}

pub mod verifiers {
    pub mod interface;
    pub mod verifier;
}

pub mod version {
    pub mod version;
}

pub mod mocks {
    pub mod mock_account;
    pub mod mock_simple_storage;
    pub mod mock_verifier;
}

pub mod claim_issuer {
    pub mod claim_issuer;
    pub mod interface;
}

pub mod identity {
    pub mod component;
    pub mod identity;
    pub mod interface;
}

pub mod common;
pub mod claim_issuers {
    pub mod claim_issuer_test;
}

pub mod factory {
    pub mod factory_test;
    pub mod token_identity_test;
}

pub mod gateway {
    pub mod gateway_test;
}

pub mod identities {
    pub mod claims_test;
    pub mod executions_test;
    pub mod initialization_test;
    pub mod keys_test;
}

pub mod verifiers {
    pub mod verifier_test;
    pub mod verifier_user_test;
}

pub mod proxy {
    pub mod implementation_authority_test;
}

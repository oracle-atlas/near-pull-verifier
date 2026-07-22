use near_sdk::{AccountId, near};

#[near(event_json(standard = "pull_verifier"))]
pub enum ContractEvent {
    #[event_version("1.0.0")]
    SignerStatusChanged { signer: String, added: bool },

    #[event_version("1.0.0")]
    OwnershipTransferred {
        old_owner: Option<AccountId>,
        new_owner: AccountId,
    },
}

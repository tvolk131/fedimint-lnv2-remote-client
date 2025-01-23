use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::ContractId;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct ClaimerRequest {
    pub claimed_contract_ids: Vec<ContractId>,
}

#[derive(Deserialize, Serialize)]
pub struct RemoteReceiverResponse {
    pub claimable_contracts: Vec<IncomingContract>,
}

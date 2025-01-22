use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::ContractId;
use tracing::instrument;

use crate::api::LightningFederationApi;
use crate::db::{ClaimerKey, RemoteReceivedContractsKey};
use crate::LightningClientContext;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RemoteReceiveStateMachine {
    pub common: RemoteReceiveSMCommon,
    pub state: RemoteReceiveSMState,
}

impl RemoteReceiveStateMachine {
    pub fn update(&self, state: RemoteReceiveSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct RemoteReceiveSMCommon {
    pub operation_id: OperationId,
    pub claimer_pubkey: PublicKey,
    pub contract: IncomingContract,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum RemoteReceiveSMState {
    Pending,
    Funded,
    Expired,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that waits on the receipt of a lightning payment which can
/// then be claimed by a remote user.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Pending -- incoming contract is confirmed --> Funded
///     Pending -- decryption contract expires --> Expired
/// ```
impl State for RemoteReceiveStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();

        let contract_id = self.common.contract.contract_id();
        let claimer_pubkey = self.common.claimer_pubkey;

        match &self.state {
            RemoteReceiveSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_incoming_contract(self.common.contract.clone(), gc.clone()),
                    move |dbtx, contract_confirmed, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
                            claimer_pubkey,
                            contract_id,
                            old_state,
                            contract_confirmed,
                        ))
                    },
                )]
            }
            RemoteReceiveSMState::Funded | RemoteReceiveSMState::Expired => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl RemoteReceiveStateMachine {
    #[instrument(skip(global_context))]
    async fn await_incoming_contract(
        contract: IncomingContract,
        global_context: DynGlobalClientContext,
    ) -> bool {
        global_context
            .module_api()
            .await_incoming_contract(&contract.contract_id(), contract.commitment.expiration)
            .await
    }

    async fn transition_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        claimer_pubkey: PublicKey,
        contract_id: ContractId,
        old_state: RemoteReceiveStateMachine,
        contract_confirmed: bool,
    ) -> RemoteReceiveStateMachine {
        let final_state = if !contract_confirmed {
            RemoteReceiveSMState::Expired
        } else {
            RemoteReceiveSMState::Funded
        };

        let iroh_pubkey_or = dbtx
            .module_tx()
            .get_value(&ClaimerKey(claimer_pubkey))
            .await;

        // If the contract is stored, update it.
        if let Some(iroh_pubkey) = iroh_pubkey_or {
            let mut unnotified_contracts = dbtx
                .module_tx()
                .get_value(&RemoteReceivedContractsKey(iroh_pubkey))
                .await
                .expect("Always contains value if claimer key is registered");

            if final_state == RemoteReceiveSMState::Funded {
                // Mark the contract as funded.
                for unnotified_contract in &mut unnotified_contracts {
                    if unnotified_contract.contract.contract_id() == contract_id {
                        unnotified_contract.is_funded = true;
                    }
                }
            } else {
                // Remove the contract if it expired.
                unnotified_contracts.retain(|c| c.contract.contract_id() != contract_id);
            }

            dbtx.module_tx()
                .insert_entry(
                    &RemoteReceivedContractsKey(iroh_pubkey),
                    &unnotified_contracts,
                )
                .await;
        };

        old_state.update(final_state)
    }
}

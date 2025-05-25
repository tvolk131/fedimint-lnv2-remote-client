use fedimint_client::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::OutPoint;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_common::contracts::IncomingContract;
use tracing::instrument;

use crate::LightningClientContext;
use crate::api::LightningFederationApi;
use crate::db::{FundedContractInfo, FundedContractKey, UnfundedContractKey};

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

        match &self.state {
            RemoteReceiveSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_incoming_contract(self.common.contract.clone(), gc.clone()),
                    move |dbtx, contract_outpoint, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
                            contract_id,
                            old_state,
                            contract_outpoint,
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
    ) -> Option<OutPoint> {
        global_context
            .module_api()
            .await_incoming_contract(&contract.contract_id(), contract.commitment.expiration)
            .await
    }

    async fn transition_incoming_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        contract_id: ContractId,
        old_state: RemoteReceiveStateMachine,
        contract_outpoint: Option<OutPoint>,
    ) -> RemoteReceiveStateMachine {
        let final_state = if contract_outpoint.is_none() {
            RemoteReceiveSMState::Expired
        } else {
            RemoteReceiveSMState::Funded
        };

        let contract_and_claimer_pubkey_or = dbtx
            .module_tx()
            .remove_entry(&UnfundedContractKey(contract_id))
            .await;

        // It's possible for `contract_and_claimer_pubkey_or` to be `None` if there was
        // a failure between starting the state machine and saving the contract,
        // since the two operations happen back-to-back but in separate
        // transactions.
        if let Some(contract_and_claimer_pubkey) = contract_and_claimer_pubkey_or {
            // If the contract is funded, move it to the funded state.
            // Otherwise, the contract is expired and we can remove it from the database.
            if final_state == RemoteReceiveSMState::Funded {
                dbtx.module_tx()
                    .insert_entry(
                        &FundedContractKey(contract_id),
                        &FundedContractInfo {
                            contract: contract_and_claimer_pubkey.contract,
                            claimer_pk: contract_and_claimer_pubkey.claimer_pk,
                            // TODO: This is always safe since `final_state` is `Funded` only if
                            // `contract_outpoint` is `Some`.
                            // But the code guaranteeing this is a bit roundabout. Maybe add the
                            // `Outpoint` as data to the `Funded` enum
                            // variant of `RemoteReceiveSMState`?
                            outpoint: contract_outpoint.unwrap(),
                        },
                    )
                    .await;
            }
        }

        old_state.update(final_state)
    }
}

use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::ContractId;
use tracing::instrument;

use crate::api::LightningFederationApi;
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
                    move |dbtx, contract_confirmed, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
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
        contract_id: ContractId,
        old_state: RemoteReceiveStateMachine,
        contract_confirmed: bool,
    ) -> RemoteReceiveStateMachine {
        if !contract_confirmed {
            return old_state.update(RemoteReceiveSMState::Expired);
        }

        // TODO: Save `contract_id` to the database so we
        // can send it to the remote user at a later point.

        old_state.update(RemoteReceiveSMState::Funded)
    }
}

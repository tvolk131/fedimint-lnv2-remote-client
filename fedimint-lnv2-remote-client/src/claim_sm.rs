use fedimint_client::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client::DynGlobalClientContext;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::OutPoint;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_common::{LightningInput, LightningInputV0};
use tpe::AggregateDecryptionKey;
use tracing::instrument;

use crate::api::LightningFederationApi;
use crate::LightningClientContext;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ClaimStateMachine {
    pub common: ClaimSMCommon,
    pub state: ClaimSMState,
}

impl ClaimStateMachine {
    pub fn update(&self, state: ClaimSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct ClaimSMCommon {
    pub operation_id: OperationId,
    pub contract: IncomingContract,
    pub claim_keypair: Keypair,
    pub agg_decryption_key: AggregateDecryptionKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum ClaimSMState {
    /// Starting state.
    Pending,

    /// The contract has been successfully claimed.
    Claiming(Vec<OutPoint>),

    /// The contract is expired and cannot be claimed.
    /// This will only happen if the remote receiver is buggy or malicious.
    Expired,

    /// The remote receiver provided a contract that we don't have a key for.
    /// This will only happen if the remote receiver is buggy or malicious.
    UnknownKey,
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that claims an incoming lightning contract which was funded by
/// a remote user.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///     Pending -- contract is claimed --> Claimed
///     Pending -- contract is expired --> Expired
///     Pending -- remote receiver provided contract we don't have a key for --> UnknownKey
/// ```
impl State for ClaimStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();

        match &self.state {
            ClaimSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_incoming_contract(self.common.contract.clone(), gc.clone()),
                    move |dbtx, contract_confirmed, old_state| {
                        Box::pin(Self::transition_incoming_contract(
                            dbtx,
                            old_state,
                            gc.clone(),
                            contract_confirmed,
                        ))
                    },
                )]
            }
            ClaimSMState::Claiming(..) | ClaimSMState::Expired | ClaimSMState::UnknownKey => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl ClaimStateMachine {
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
        old_state: ClaimStateMachine,
        global_context: DynGlobalClientContext,
        contract_confirmed: bool,
    ) -> ClaimStateMachine {
        if !contract_confirmed {
            return old_state.update(ClaimSMState::Expired);
        }

        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Incoming(
                old_state.common.contract.contract_id(),
                old_state.common.agg_decryption_key,
            )),
            amount: old_state.common.contract.commitment.amount,
            keys: vec![old_state.common.claim_keypair],
        };

        let (_txid, change_range) = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
            .expect("Cannot claim input, additional funding needed");

        old_state.update(ClaimSMState::Claiming(change_range))
    }
}

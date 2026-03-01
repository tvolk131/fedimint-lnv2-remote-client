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

        // Fatal invariant: the pending receive record must exist for every
        // remote receive transition.
        let contract_and_claimer_pubkey = dbtx
            .module_tx()
            .remove_entry(&UnfundedContractKey(contract_id))
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Invariant violation: missing unfunded contract record for contract id {contract_id:?}"
                )
            });

        // If the contract is funded, move it to the funded state. Otherwise,
        // it is expired and we only remove it from unfunded storage.
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
                        outpoint: contract_outpoint.expect("Funded state requires outpoint"),
                    },
                )
                .await;
        }

        old_state.update(final_state)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash, sha256};
    use fedimint_client_module::sm::ClientSMDatabaseTransaction;
    use fedimint_core::Amount;
    use fedimint_core::core::{ModuleInstanceId, OperationId};
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{AutocommitError, Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1;
    use fedimint_core::{OutPoint, TransactionId};
    use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
    use tpe::{AggregatePublicKey, G1Affine};

    use super::{RemoteReceiveSMCommon, RemoteReceiveSMState, RemoteReceiveStateMachine};
    use crate::db::{FundedContractKey, UnfundedContractInfo, UnfundedContractKey};

    const MODULE_INSTANCE_ID: ModuleInstanceId = 0;

    fn make_contract() -> IncomingContract {
        let mut rng = secp256k1::rand::thread_rng();

        let (_, claim_pk) = secp256k1::generate_keypair(&mut rng);
        let (_, refund_pk) = secp256k1::generate_keypair(&mut rng);
        let (_, ephemeral_pk) = secp256k1::generate_keypair(&mut rng);

        let preimage = [42; 32];

        IncomingContract::new(
            AggregatePublicKey(G1Affine::generator()),
            [7; 32],
            preimage,
            PaymentImage::Hash(sha256::Hash::hash(&preimage)),
            Amount::from_msats(1000),
            u64::MAX,
            claim_pk,
            refund_pk,
            ephemeral_pk,
        )
    }

    fn make_state_machine(
        contract: IncomingContract,
        claimer_pubkey: secp256k1::PublicKey,
    ) -> RemoteReceiveStateMachine {
        RemoteReceiveStateMachine {
            common: RemoteReceiveSMCommon {
                operation_id: OperationId::from_encodable(&contract),
                claimer_pubkey,
                contract,
            },
            state: RemoteReceiveSMState::Pending,
        }
    }

    fn make_database() -> Database {
        Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
    }

    fn make_outpoint() -> OutPoint {
        OutPoint {
            txid: TransactionId::from_byte_array([1; 32]),
            out_idx: 0,
        }
    }

    #[tokio::test]
    async fn funded_transition_moves_unfunded_to_funded() {
        let db = make_database();
        let contract = make_contract();
        let contract_id = contract.contract_id();
        let mut rng = secp256k1::rand::thread_rng();
        let (_, claimer_pubkey) = secp256k1::generate_keypair(&mut rng);
        let outpoint = make_outpoint();

        let mut dbtx = db.begin_transaction().await;
        {
            let mut dbtx_ref = dbtx.to_ref_nc();
            let mut sm_dbtx = ClientSMDatabaseTransaction::new(&mut dbtx_ref, MODULE_INSTANCE_ID);

            let mut module_tx = sm_dbtx.module_tx();
            module_tx
                .insert_new_entry(
                    &UnfundedContractKey(contract_id),
                    &UnfundedContractInfo {
                        contract: contract.clone(),
                        claimer_pk: claimer_pubkey,
                    },
                )
                .await;
            drop(module_tx);

            let final_state = RemoteReceiveStateMachine::transition_incoming_contract(
                &mut sm_dbtx,
                contract_id,
                make_state_machine(contract.clone(), claimer_pubkey),
                Some(outpoint),
            )
            .await;

            assert_eq!(final_state.state, RemoteReceiveSMState::Funded);
        }
        dbtx.commit_tx().await;

        let mut read_tx = db.begin_transaction_nc().await;
        let mut module_read_tx = read_tx
            .to_ref_with_prefix_module_id(MODULE_INSTANCE_ID)
            .0
            .into_nc();
        assert!(
            module_read_tx
                .get_value(&UnfundedContractKey(contract_id))
                .await
                .is_none()
        );
        let funded = module_read_tx
            .get_value(&FundedContractKey(contract_id))
            .await
            .expect("Funded contract record should exist");
        assert_eq!(funded.contract, contract);
        assert_eq!(funded.claimer_pk, claimer_pubkey);
        assert_eq!(funded.outpoint, outpoint);
    }

    #[tokio::test]
    async fn expired_transition_removes_unfunded_without_funded() {
        let db = make_database();
        let contract = make_contract();
        let contract_id = contract.contract_id();
        let mut rng = secp256k1::rand::thread_rng();
        let (_, claimer_pubkey) = secp256k1::generate_keypair(&mut rng);

        let mut dbtx = db.begin_transaction().await;
        {
            let mut dbtx_ref = dbtx.to_ref_nc();
            let mut sm_dbtx = ClientSMDatabaseTransaction::new(&mut dbtx_ref, MODULE_INSTANCE_ID);

            let mut module_tx = sm_dbtx.module_tx();
            module_tx
                .insert_new_entry(
                    &UnfundedContractKey(contract_id),
                    &UnfundedContractInfo {
                        contract: contract.clone(),
                        claimer_pk: claimer_pubkey,
                    },
                )
                .await;
            drop(module_tx);

            let final_state = RemoteReceiveStateMachine::transition_incoming_contract(
                &mut sm_dbtx,
                contract_id,
                make_state_machine(contract, claimer_pubkey),
                None,
            )
            .await;

            assert_eq!(final_state.state, RemoteReceiveSMState::Expired);
        }
        dbtx.commit_tx().await;

        let mut read_tx = db.begin_transaction_nc().await;
        let mut module_read_tx = read_tx
            .to_ref_with_prefix_module_id(MODULE_INSTANCE_ID)
            .0
            .into_nc();
        assert!(
            module_read_tx
                .get_value(&UnfundedContractKey(contract_id))
                .await
                .is_none()
        );
        assert!(
            module_read_tx
                .get_value(&FundedContractKey(contract_id))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    #[should_panic(expected = "Invariant violation: missing unfunded contract record")]
    async fn funded_transition_panics_when_unfunded_missing() {
        let db = make_database();
        let contract = make_contract();
        let contract_id = contract.contract_id();
        let mut rng = secp256k1::rand::thread_rng();
        let (_, claimer_pubkey) = secp256k1::generate_keypair(&mut rng);

        let mut dbtx = db.begin_transaction().await;
        {
            let mut dbtx_ref = dbtx.to_ref_nc();
            let mut sm_dbtx = ClientSMDatabaseTransaction::new(&mut dbtx_ref, MODULE_INSTANCE_ID);

            let _ = RemoteReceiveStateMachine::transition_incoming_contract(
                &mut sm_dbtx,
                contract_id,
                make_state_machine(contract, claimer_pubkey),
                Some(make_outpoint()),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn unfunded_insert_is_rolled_back_when_start_step_fails() {
        let db = make_database();
        let contract = make_contract();
        let contract_id = contract.contract_id();
        let mut rng = secp256k1::rand::thread_rng();
        let (_, claimer_pubkey) = secp256k1::generate_keypair(&mut rng);

        let err = db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        let mut module_tx = dbtx
                            .to_ref_with_prefix_module_id(MODULE_INSTANCE_ID)
                            .0
                            .into_nc();

                        module_tx
                            .insert_new_entry(
                                &UnfundedContractKey(contract_id),
                                &UnfundedContractInfo {
                                    contract: contract.clone(),
                                    claimer_pk: claimer_pubkey,
                                },
                            )
                            .await;

                        Err::<(), &'static str>("forced start failure")
                    })
                },
                None,
            )
            .await
            .expect_err("autocommit should fail when start step fails");

        match err {
            AutocommitError::ClosureError { error, .. } => {
                assert_eq!(error, "forced start failure");
            }
            AutocommitError::CommitFailed { .. } => {
                panic!("Expected closure failure, got commit failure");
            }
        }

        let mut read_tx = db.begin_transaction_nc().await;
        let mut module_read_tx = read_tx
            .to_ref_with_prefix_module_id(MODULE_INSTANCE_ID)
            .0
            .into_nc();
        assert!(
            module_read_tx
                .get_value(&UnfundedContractKey(contract_id))
                .await
                .is_none(),
            "Unfunded contract entry should not be committed on start failure",
        );
    }
}

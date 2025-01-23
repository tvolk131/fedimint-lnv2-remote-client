#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

mod api;
mod claim_sm;
#[cfg(feature = "cli")]
mod cli;
mod db;
mod iroh_msgs;
mod remote_receive_sm;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_stream::stream;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1;
use db::{ClaimerKey, RemoteReceiveContractNotification, RemoteReceivedContractsKey};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule};
use fedimint_client::sm::util::MapStateTransitions;
use fedimint_client::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client::{sm_enum_variant_translation, DynGlobalClientContext};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiAuth, ApiVersion, CommonModuleInit, ModuleCommon, ModuleConsensusVersion, ModuleInit,
    MultiApiVersion,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, Amount};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::{
    GatewayConnection, GatewayConnectionError, PaymentFee, RealGatewayConnection, RoutingInfo,
};
use fedimint_lnv2_common::{
    Bolt11InvoiceDescription, ContractId, LightningModuleTypes, MODULE_CONSENSUS_VERSION,
};
use futures::StreamExt;
use iroh_msgs::{ClaimerRequest, RemoteReceiverResponse};
use lightning_invoice::Bolt11Invoice;
use rand::seq::SliceRandom;
use rand::thread_rng;
use secp256k1::{ecdh, Keypair, PublicKey, Scalar};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpe::{derive_agg_decryption_key, AggregateDecryptionKey};

use crate::api::LightningFederationApi;
use crate::claim_sm::{ClaimSMCommon, ClaimSMState, ClaimStateMachine};
use crate::remote_receive_sm::{
    RemoteReceiveSMCommon, RemoteReceiveSMState, RemoteReceiveStateMachine,
};

const KIND: ModuleKind = ModuleKind::from_static_str("lnv2");

/// The maximum size of an Iroh request in bytes. Set to 1MB.
const IROH_REQUEST_SIZE_LIMIT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMeta {
    pub contract: IncomingContract,
}

/// The final state of an operation receiving a payment over lightning.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinalRemoteReceiveOperationState {
    /// The payment has been confirmed.
    Funded,
    /// The payment request has expired.
    Expired,
}

/// The final state of an operation receiving a payment over lightning.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum FinalClaimOperationState {
    /// The payment has been successfully claimed.
    Claimed,
    /// The payment request expired before it was funded.
    Expired,
    /// Either a programming error has occurred or the federation is malicious.
    Failure,
}

#[derive(Debug)]
pub struct LightningRemoteCommonInit;

impl CommonModuleInit for LightningRemoteCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = LightningClientConfig;

    fn decoder() -> Decoder {
        LightningModuleTypes::decoder()
    }
}

pub type RemoteReceiveResult = Result<(Bolt11Invoice, OperationId), RemoteReceiveError>;

#[derive(Debug, Clone)]
pub struct LightningRemoteClientInit {
    pub gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
}

impl Default for LightningRemoteClientInit {
    fn default() -> Self {
        LightningRemoteClientInit {
            gateway_conn: Arc::new(RealGatewayConnection),
        }
    }
}

impl ModuleInit for LightningRemoteClientInit {
    type Common = LightningRemoteCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(BTreeMap::new().into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for LightningRemoteClientInit {
    type Module = LightningClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(LightningClientModule::new(
            *args.federation_id(),
            args.cfg().clone(),
            args.notifier().clone(),
            args.context(),
            args.module_api().clone(),
            args.module_root_secret()
                .clone()
                .to_secp_key(fedimint_core::secp256k1::SECP256K1),
            self.gateway_conn.clone(),
            args.admin_auth().cloned(),
            args.task_group(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct LightningClientContext {
    iroh_secret_key: iroh::SecretKey,
    iroh_remote_receive_endpoint: Option<iroh::Endpoint>,
}

impl Context for LightningClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

#[derive(Debug)]
pub struct LightningClientModule {
    federation_id: FederationId,
    cfg: LightningClientConfig,
    notifier: ModuleNotifier<LightningClientStateMachines>,
    client_ctx: ClientContext<Self>,
    module_api: DynModuleApi,
    keypair: Keypair,
    gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
    #[allow(unused)] // The field is only used by the cli feature
    admin_auth: Option<ApiAuth>,
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for LightningClientModule {
    type Init = LightningRemoteClientInit;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = LightningClientContext;
    type States = LightningClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        LightningClientContext {
            iroh_secret_key: iroh::SecretKey::from_bytes(&self.keypair.secret_bytes()),
            iroh_remote_receive_endpoint: None,
        }
    }

    fn input_fee(
        &self,
        amount: Amount,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    fn output_fee(
        &self,
        amount: Amount,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amount> {
        Some(self.cfg.fee_consensus.fee(amount))
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

fn generate_ephemeral_tweak(static_pk: PublicKey) -> ([u8; 32], PublicKey) {
    let keypair = Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());

    let tweak = ecdh::SharedSecret::new(&static_pk, &keypair.secret_key());

    (tweak.secret_bytes(), keypair.public_key())
}

impl LightningClientModule {
    #[allow(clippy::too_many_arguments)]
    fn new(
        federation_id: FederationId,
        cfg: LightningClientConfig,
        notifier: ModuleNotifier<LightningClientStateMachines>,
        client_ctx: ClientContext<Self>,
        module_api: DynModuleApi,
        keypair: Keypair,
        gateway_conn: Arc<dyn GatewayConnection + Send + Sync>,
        admin_auth: Option<ApiAuth>,
        task_group: &TaskGroup,
    ) -> Self {
        Self::spawn_iroh_request_handler_task(client_ctx.clone(), keypair.clone(), task_group);

        Self {
            federation_id,
            cfg,
            notifier,
            client_ctx,
            module_api,
            keypair,
            gateway_conn,
            admin_auth,
        }
    }

    fn spawn_iroh_request_handler_task(
        client_ctx: ClientContext<Self>,
        keypair: Keypair,
        task_group: &TaskGroup,
    ) {
        task_group.spawn("iroh_request_handler_task", move |handle| async move {
            let mut shutdown_rx = handle.make_shutdown_rx();

            // TODO: Retry rather than unwrapping.
            let endpoint = iroh::Endpoint::builder()
                .secret_key(iroh::SecretKey::from_bytes(&keypair.secret_bytes()))
                .bind()
                .await
                .unwrap();

            loop {
                tokio::select! {
                    incoming_connection_or = endpoint.accept() => {
                        // If `accept()` yields `None`, the endpoint has been closed.
                        let Some(incoming_connection) = incoming_connection_or else { break };

                        // TODO: Log error.
                        let Ok(connecting) = incoming_connection.accept() else { continue };

                        // TODO: Log error.
                        let Ok(connection) = connecting.await else { continue };

                        let Ok(claimer_iroh_pubkey) = iroh::endpoint::get_remote_node_id(&connection) else { continue };

                        // TODO: Log error.
                        let Ok((send_stream, recv_stream)) = connection.accept_bi().await else { continue };

                        let _ = Self::handle_iroh_connection_from_claimer(
                            send_stream,
                            recv_stream,
                            claimer_iroh_pubkey,
                            client_ctx.clone(),
                        ).await;
                    },
                    () = &mut shutdown_rx => {
                        endpoint.close().await;
                        break;
                    },
                };
            }
        });
    }

    async fn handle_iroh_connection_from_claimer(
        mut send_stream: iroh::endpoint::SendStream,
        mut recv_stream: iroh::endpoint::RecvStream,
        claimer_iroh_pubkey: iroh::PublicKey,
        client_ctx: ClientContext<Self>,
    ) -> anyhow::Result<()> {
        let request_bytes = recv_stream
            .read_to_end(IROH_REQUEST_SIZE_LIMIT_BYTES)
            .await?;

        let request: ClaimerRequest = bincode::deserialize(&request_bytes)?;

        let mut dbtx = client_ctx.module_db().begin_transaction().await;

        Self::remove_claimed_contracts(
            &mut dbtx.to_ref_nc(),
            claimer_iroh_pubkey,
            request.claimed_contract_ids,
        )
        .await;

        let claimable_contracts =
            Self::get_claimable_contracts(&mut dbtx.to_ref_nc(), claimer_iroh_pubkey).await;

        let response = RemoteReceiverResponse {
            claimable_contracts,
        };

        // TODO: `write_all()` is *NOT* cancel-safe.
        send_stream
            .write_all(&bincode::serialize(&response).unwrap())
            .await?;

        Ok(())
    }

    async fn get_random_gateway(&self) -> Result<(SafeUrl, RoutingInfo), SelectGatewayError> {
        let mut gateways = self
            .module_api
            .gateways()
            .await
            .map_err(|e| SelectGatewayError::FederationError(e.to_string()))?;

        if gateways.is_empty() {
            return Err(SelectGatewayError::NoVettedGateways);
        }

        gateways.shuffle(&mut thread_rng());

        for gateway in gateways {
            if let Ok(Some(routing_info)) = self.routing_info(&gateway).await {
                return Ok((gateway, routing_info));
            }
        }

        Err(SelectGatewayError::FailedToFetchRoutingInfo)
    }

    async fn routing_info(
        &self,
        gateway: &SafeUrl,
    ) -> Result<Option<RoutingInfo>, GatewayConnectionError> {
        self.gateway_conn
            .routing_info(gateway.clone(), &self.federation_id)
            .await
    }

    pub fn get_public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    pub async fn register_claimer(
        &self,
        claimer_static_pk: PublicKey,
        claimer_iroh_pubkey: iroh::PublicKey,
    ) -> anyhow::Result<()> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        if dbtx
            .get_value(&ClaimerKey(claimer_static_pk))
            .await
            .is_some()
        {
            return Err(anyhow::anyhow!("Claimer is already registered"));
        }

        dbtx.insert_entry(
            &ClaimerKey(claimer_static_pk),
            claimer_iroh_pubkey.as_bytes(),
        )
        .await;

        dbtx.insert_entry(
            &RemoteReceivedContractsKey(*claimer_iroh_pubkey.as_bytes()),
            &Vec::new(),
        )
        .await;

        dbtx.commit_tx_result().await
    }

    pub async fn unregister_claimer(
        &self,
        claimer_static_pk: PublicKey,
        force: bool,
    ) -> anyhow::Result<()> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let Some(iroh_pubkey) = dbtx.remove_entry(&ClaimerKey(claimer_static_pk)).await else {
            return Err(anyhow::anyhow!("Claimer is not registered"));
        };

        let contracts = dbtx
            .remove_entry(&RemoteReceivedContractsKey(iroh_pubkey))
            .await
            .expect("Always contains value if claimer key is registered");

        // If the claimer has unclaimed contracts, the operation will fail unless
        // forced.
        if !force && !contracts.is_empty() {
            return Err(anyhow::anyhow!("Claimer has unclaimed contracts"));
        }

        dbtx.commit_tx_result().await
    }

    pub async fn get_claimable_contracts(
        dbtx: &mut DatabaseTransaction<'_>,
        claimer_iroh_pubkey: iroh::PublicKey,
    ) -> Vec<IncomingContract> {
        dbtx.get_value(&RemoteReceivedContractsKey(*claimer_iroh_pubkey.as_bytes()))
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| if c.is_funded { Some(c.contract) } else { None })
            .collect()
    }

    pub async fn remove_claimed_contracts(
        dbtx: &mut DatabaseTransaction<'_>,
        claimer_iroh_pubkey: iroh::PublicKey,
        contract_ids: Vec<ContractId>,
    ) {
        let key = RemoteReceivedContractsKey(*claimer_iroh_pubkey.as_bytes());

        if let Some(mut contract_notifications) = dbtx.get_value(&key).await {
            contract_notifications.retain(|c| !contract_ids.contains(&c.contract.contract_id()));
            dbtx.insert_entry(&key, &contract_notifications).await;
        }
    }

    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a random online gateway will be selected
    /// automatically.
    ///
    /// The total fee for this payment may depend on the chosen gateway but
    /// will be limited to half of one percent plus fifty satoshis. Since the
    /// selected gateway has been vetted by at least one guardian we trust it to
    /// set a reasonable fee and only enforce a rather high limit.
    ///
    /// The absolute fee for a payment can be calculated from the operation meta
    /// to be shown to the user in the transaction history.
    pub async fn remote_receive(
        &self,
        claimer_static_pk: PublicKey,
        amount: Amount,
        expiry_secs: u32,
        description: Bolt11InvoiceDescription,
        gateway: Option<SafeUrl>,
    ) -> Result<(Bolt11Invoice, IncomingContract, OperationId), RemoteReceiveError> {
        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;

        let Some(iroh_pubkey) = dbtx.get_value(&ClaimerKey(claimer_static_pk)).await else {
            return Err(RemoteReceiveError::UnregisteredClaimer);
        };

        let (invoice, contract) = self
            .create_contract_and_fetch_invoice(
                claimer_static_pk,
                amount,
                expiry_secs,
                description,
                gateway,
            )
            .await?;

        let mut contract_notifications = dbtx
            .get_value(&RemoteReceivedContractsKey(iroh_pubkey))
            .await
            .expect("Always contains value if claimer key is registered");

        contract_notifications.push(RemoteReceiveContractNotification {
            contract: contract.clone(),
            is_funded: false,
        });

        dbtx.insert_entry(
            &RemoteReceivedContractsKey(iroh_pubkey),
            &contract_notifications,
        )
        .await;

        let operation_id = self
            .start_remote_receive_state_machine(contract.clone(), claimer_static_pk)
            .await;

        dbtx.commit_tx_result().await.unwrap(); // TODO: Return an error here.

        Ok((invoice, contract, operation_id))
    }

    /// Create an incoming contract locked to a specified public key and fetch
    /// the corresponding invoice.
    async fn create_contract_and_fetch_invoice(
        &self,
        claimer_static_pk: PublicKey,
        amount: Amount,
        expiry_secs: u32,
        description: Bolt11InvoiceDescription,
        gateway: Option<SafeUrl>,
    ) -> Result<(Bolt11Invoice, IncomingContract), RemoteReceiveError> {
        let (ephemeral_tweak, ephemeral_pk) = generate_ephemeral_tweak(claimer_static_pk);

        let encryption_seed = ephemeral_tweak
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let preimage = encryption_seed
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let (gateway, routing_info) = match gateway {
            Some(gateway) => (
                gateway.clone(),
                self.routing_info(&gateway)
                    .await
                    .map_err(RemoteReceiveError::GatewayConnectionError)?
                    .ok_or(RemoteReceiveError::UnknownFederation)?,
            ),
            None => self
                .get_random_gateway()
                .await
                .map_err(RemoteReceiveError::FailedToSelectGateway)?,
        };

        if !routing_info.receive_fee.le(&PaymentFee::RECEIVE_FEE_LIMIT) {
            return Err(RemoteReceiveError::PaymentFeeExceedsLimit);
        }

        let contract_amount = routing_info.receive_fee.subtract_from(amount.msats);

        // The dust limit ensures that the incoming contract can be claimed without
        // additional funds as the contracts amount is sufficient to cover the fees
        if contract_amount < Amount::from_sats(50) {
            return Err(RemoteReceiveError::DustAmount);
        }

        let expiration = duration_since_epoch()
            .as_secs()
            .saturating_add(u64::from(expiry_secs));

        let claim_pk = claimer_static_pk
            .mul_tweak(
                secp256k1::SECP256K1,
                &Scalar::from_be_bytes(ephemeral_tweak).expect("Within curve order"),
            )
            .expect("Tweak is valid");

        let contract = IncomingContract::new(
            self.cfg.tpe_agg_pk,
            encryption_seed,
            preimage,
            PaymentImage::Hash(preimage.consensus_hash()),
            contract_amount,
            expiration,
            claim_pk,
            routing_info.module_public_key,
            ephemeral_pk,
        );

        let invoice = self
            .gateway_conn
            .bolt11_invoice(
                gateway,
                self.federation_id,
                contract.clone(),
                amount,
                description,
                expiry_secs,
            )
            .await
            .map_err(RemoteReceiveError::GatewayConnectionError)?;

        if invoice.payment_hash() != &preimage.consensus_hash() {
            return Err(RemoteReceiveError::InvalidInvoicePaymentHash);
        }

        if invoice.amount_milli_satoshis() != Some(amount.msats) {
            return Err(RemoteReceiveError::InvalidInvoiceAmount);
        }

        Ok((invoice, contract))
    }

    /// Start a remote receive state machine that
    /// waits for an incoming contract to be funded.
    async fn start_remote_receive_state_machine(
        &self,
        contract: IncomingContract,
        claimer_pubkey: PublicKey,
    ) -> OperationId {
        let operation_id = OperationId::from_encodable(&contract.clone());

        let receive_sm = LightningClientStateMachines::RemoteReceive(RemoteReceiveStateMachine {
            common: RemoteReceiveSMCommon {
                operation_id,
                claimer_pubkey,
                contract: contract.clone(),
            },
            state: RemoteReceiveSMState::Pending,
        });

        // this may only fail if the operation id is already in use, in which case we
        // ignore the error such that the method is idempotent
        self.client_ctx
            .manual_operation_start(
                operation_id,
                LightningRemoteCommonInit::KIND.as_str(),
                OperationMeta { contract },
                vec![self.client_ctx.make_dyn_state(receive_sm)],
            )
            .await
            .ok();

        operation_id
    }

    pub async fn claim_contract(&self, contract: IncomingContract) -> Option<OperationId> {
        let operation_id = OperationId::from_encodable(&contract.clone());

        let (claim_keypair, agg_decryption_key) = self.recover_contract_keys(&contract)?;

        let claim_sm = LightningClientStateMachines::Claim(ClaimStateMachine {
            common: ClaimSMCommon {
                operation_id,
                contract: contract.clone(),
                claim_keypair,
                agg_decryption_key,
            },
            state: ClaimSMState::Pending,
        });

        // this may only fail if the operation id is already in use, in which case we
        // ignore the error such that the method is idempotent
        self.client_ctx
            .manual_operation_start(
                operation_id,
                LightningRemoteCommonInit::KIND.as_str(),
                OperationMeta { contract },
                vec![self.client_ctx.make_dyn_state(claim_sm)],
            )
            .await
            .ok();

        Some(operation_id)
    }

    fn recover_contract_keys(
        &self,
        contract: &IncomingContract,
    ) -> Option<(Keypair, AggregateDecryptionKey)> {
        let ephemeral_tweak = ecdh::SharedSecret::new(
            &contract.commitment.ephemeral_pk,
            &self.keypair.secret_key(),
        )
        .secret_bytes();

        let encryption_seed = ephemeral_tweak
            .consensus_hash::<sha256::Hash>()
            .to_byte_array();

        let claim_keypair = self
            .keypair
            .secret_key()
            .mul_tweak(&Scalar::from_be_bytes(ephemeral_tweak).expect("Within curve order"))
            .expect("Tweak is valid")
            .keypair(secp256k1::SECP256K1);

        if claim_keypair.public_key() != contract.commitment.claim_pk {
            return None; // The claim key is not derived from our pk
        }

        let agg_decryption_key = derive_agg_decryption_key(&self.cfg.tpe_agg_pk, &encryption_seed);

        if !contract.verify_agg_decryption_key(&self.cfg.tpe_agg_pk, &agg_decryption_key) {
            return None; // The decryption key is not derived from our pk
        }

        contract.decrypt_preimage(&agg_decryption_key)?;

        Some((claim_keypair, agg_decryption_key))
    }

    /// Await the final state of the remote receive operation.
    pub async fn await_final_remote_receive_operation_state(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<FinalRemoteReceiveOperationState> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;

        // TODO: Do we need to use `outcome_or_updates` here?
        // I'm using it here because the LNv2 client does.
        Ok(self.client_ctx.outcome_or_updates(&operation, operation_id, || {
            stream! {
                loop {
                    if let Some(LightningClientStateMachines::RemoteReceive(state)) = stream.next().await {
                        match state.state {
                            RemoteReceiveSMState::Pending => continue,
                            RemoteReceiveSMState::Funded => {
                                yield FinalRemoteReceiveOperationState::Funded;
                                return;
                            },
                            RemoteReceiveSMState::Expired => {
                                yield FinalRemoteReceiveOperationState::Expired;
                                return;
                            },
                        }
                    }
                }
            }
        }).into_stream().next().await.expect("Stream contains one final state"))
    }

    /// Await the final state of the claim operation.
    pub async fn await_final_claim_operation_state(
        &self,
        operation_id: OperationId,
    ) -> anyhow::Result<FinalClaimOperationState> {
        let operation = self.client_ctx.get_operation(operation_id).await?;
        let mut stream = self.notifier.subscribe(operation_id).await;
        let client_ctx = self.client_ctx.clone();

        // TODO: Do we need to use `outcome_or_updates` here?
        // I'm using it here because the LNv2 client does.
        Ok(self.client_ctx.outcome_or_updates(&operation, operation_id, || {
            stream! {
                loop {
                    if let Some(LightningClientStateMachines::Claim(state)) = stream.next().await {
                        match state.state {
                            ClaimSMState::Pending => continue,
                            ClaimSMState::Claiming(out_points) => {
                                if client_ctx.await_primary_module_outputs(operation_id, out_points).await.is_ok() {
                                    yield FinalClaimOperationState::Claimed;
                                } else {
                                    yield FinalClaimOperationState::Failure;
                                }
                                return;
                            },
                            ClaimSMState::Expired => {
                                yield FinalClaimOperationState::Expired;
                                return;
                            },
                        }
                    }
                }
            }
        }).into_stream().next().await.expect("Stream contains one final state"))
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum SelectGatewayError {
    #[error("Federation returned an error: {0}")]
    FederationError(String),
    #[error("The federation has no vetted gateways")]
    NoVettedGateways,
    #[error("All vetted gateways failed to respond on request of the routing info")]
    FailedToFetchRoutingInfo,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum RemoteReceiveError {
    #[error("Failed to select gateway: {0}")]
    FailedToSelectGateway(SelectGatewayError),
    #[error("Gateway connection error: {0}")]
    GatewayConnectionError(GatewayConnectionError),
    #[error("The gateway does not support our federation")]
    UnknownFederation,
    #[error("The gateways fee exceeds the limit")]
    PaymentFeeExceedsLimit,
    #[error("The total fees required to complete this payment exceed its amount")]
    DustAmount,
    #[error("The invoice's payment hash is incorrect")]
    InvalidInvoicePaymentHash,
    #[error("The invoice's amount is incorrect")]
    InvalidInvoiceAmount,
    #[error("The pubkey of the claimer is not registered")]
    UnregisteredClaimer,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum LightningClientStateMachines {
    Claim(ClaimStateMachine),
    RemoteReceive(RemoteReceiveStateMachine),
}

impl IntoDynInstance for LightningClientStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for LightningClientStateMachines {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            LightningClientStateMachines::Claim(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    LightningClientStateMachines::Claim
                )
            }
            LightningClientStateMachines::RemoteReceive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    LightningClientStateMachines::RemoteReceive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            LightningClientStateMachines::Claim(state) => state.operation_id(),
            LightningClientStateMachines::RemoteReceive(state) => state.operation_id(),
        }
    }
}

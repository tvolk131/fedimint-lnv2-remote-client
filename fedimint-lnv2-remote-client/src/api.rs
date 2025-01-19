use std::collections::{BTreeMap, BTreeSet};

use fedimint_api_client::api::{
    FederationApiExt, FederationResult, IModuleFederationApi, PeerError, PeerResult,
};
use fedimint_api_client::query::{FilterMapThreshold, ThresholdConsensus};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, NumPeersExt, PeerId};
use fedimint_lnv2_common::endpoint_constants::{
    AWAIT_INCOMING_CONTRACT_ENDPOINT, AWAIT_PREIMAGE_ENDPOINT, CONSENSUS_BLOCK_COUNT_ENDPOINT,
    GATEWAYS_ENDPOINT,
};
use fedimint_lnv2_common::ContractId;
use rand::seq::SliceRandom;

#[apply(async_trait_maybe_send!)]
pub trait LightningFederationApi {
    async fn consensus_block_count(&self) -> FederationResult<u64>;

    async fn await_incoming_contract(&self, contract_id: &ContractId, expiration: u64) -> bool;

    async fn await_preimage(&self, contract_id: &ContractId, expiration: u64) -> Option<[u8; 32]>;

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>>;

    async fn gateways_from_peer(&self, peer: PeerId) -> PeerResult<Vec<SafeUrl>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LightningFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn consensus_block_count(&self) -> FederationResult<u64> {
        self.request_current_consensus(
            CONSENSUS_BLOCK_COUNT_ENDPOINT.to_string(),
            ApiRequestErased::new(()),
        )
        .await
    }

    // TODO: Use `request_current_consensus_retry` like `fedimint-lnv2-client` does
    // once v0.6.0 is released.
    async fn await_incoming_contract(&self, contract_id: &ContractId, expiration: u64) -> bool {
        let contract_id: Option<ContractId> = self
            .request_with_strategy(
                ThresholdConsensus::new(self.all_peers().to_num_peers()),
                AWAIT_INCOMING_CONTRACT_ENDPOINT.to_string(),
                ApiRequestErased::new((contract_id, expiration)),
            )
            .await
            .unwrap();

        contract_id.is_some()
    }

    // TODO: Use `request_current_consensus_retry` like `fedimint-lnv2-client` does
    // once v0.6.0 is released.
    async fn await_preimage(&self, contract_id: &ContractId, expiration: u64) -> Option<[u8; 32]> {
        self.request_with_strategy(
            ThresholdConsensus::new(self.all_peers().to_num_peers()),
            AWAIT_PREIMAGE_ENDPOINT.to_string(),
            ApiRequestErased::new((contract_id, expiration)),
        )
        .await
        .unwrap()
    }

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>> {
        let gateways: BTreeMap<PeerId, Vec<SafeUrl>> = self
            .request_with_strategy(
                FilterMapThreshold::new(
                    |_, gateways| Ok(gateways),
                    self.all_peers().to_num_peers(),
                ),
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
            )
            .await?;

        let mut union = gateways
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<SafeUrl>>()
            .into_iter()
            .collect::<Vec<SafeUrl>>();

        // Shuffling the gateways ensures that payments are distributed over the
        // gateways evenly.
        union.shuffle(&mut rand::thread_rng());

        union.sort_by_cached_key(|r| {
            gateways
                .values()
                .filter(|response| !response.contains(r))
                .count()
        });

        Ok(union)
    }

    async fn gateways_from_peer(&self, peer: PeerId) -> PeerResult<Vec<SafeUrl>> {
        let value = self
            .request_single_peer(
                None,
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
                peer,
            )
            .await?;

        serde_json::from_value(value).map_err(|e| PeerError::ResponseDeserialization(e.into()))
    }
}

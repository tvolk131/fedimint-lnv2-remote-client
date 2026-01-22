use std::collections::{BTreeMap, BTreeSet};

use fedimint_api_client::api::{
    FederationApiExt, FederationResult, IModuleFederationApi,
};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_connectors::error::ServerError;
use fedimint_connectors::ServerResult;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::util::SafeUrl;
use fedimint_core::{NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send};
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_common::endpoint_constants::{
    AWAIT_INCOMING_CONTRACT_ENDPOINT, GATEWAYS_ENDPOINT,
};
use rand::{rng, seq::SliceRandom};

#[apply(async_trait_maybe_send!)]
pub trait LightningFederationApi {
    async fn await_incoming_contract(
        &self,
        contract_id: &ContractId,
        expiration: u64,
    ) -> Option<OutPoint>;

    async fn gateways(&self) -> FederationResult<Vec<SafeUrl>>;

    async fn gateways_from_peer(&self, peer: PeerId) -> ServerResult<Vec<SafeUrl>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> LightningFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn await_incoming_contract(
        &self,
        contract_id: &ContractId,
        expiration: u64,
    ) -> Option<OutPoint> {
        self.request_current_consensus_retry::<Option<OutPoint>>(
            AWAIT_INCOMING_CONTRACT_ENDPOINT.to_string(),
            ApiRequestErased::new((contract_id, expiration)),
        )
        .await
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
        union.shuffle(&mut rng());

        union.sort_by_cached_key(|r| {
            gateways
                .values()
                .filter(|response| !response.contains(r))
                .count()
        });

        Ok(union)
    }

    async fn gateways_from_peer(&self, peer: PeerId) -> ServerResult<Vec<SafeUrl>> {
        let value = self
            .request_single_peer(
                GATEWAYS_ENDPOINT.to_string(),
                ApiRequestErased::default(),
                peer,
            )
            .await?;

        serde_json::from_value(value).map_err(|e| ServerError::ResponseDeserialization(e.into()))
    }
}

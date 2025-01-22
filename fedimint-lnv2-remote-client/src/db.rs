use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::contracts::IncomingContract;

use crate::remote_receive_sm::RemoteReceiveSMState;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    Claimer = 0xb1,
    RemoteReceivedContracts = 0xb2,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ClaimerKey(pub PublicKey); // The pubkey to use to lock contracts to a claimer.

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ClaimerKeyPrefix;

impl_db_record!(
    key = ClaimerKey,
    value = [u8; 32], // Represents the `iroh::PublicKey` of the claimer.
    db_prefix = DbKeyPrefix::Claimer,
);
impl_db_lookup!(key = ClaimerKey, query_prefix = ClaimerKeyPrefix);

// Represents the `iroh::PublicKey` of the claimer whose claimable contracts
// we're storing. We should send them the contracts when they request them.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RemoteReceivedContractsKey(pub [u8; 32]);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RemoteReceivedContractsKeyPrefix;

impl_db_record!(
    key = RemoteReceivedContractsKey,
    value = Vec<RemoteReceiveContractNotification>,
    db_prefix = DbKeyPrefix::RemoteReceivedContracts,
);
impl_db_lookup!(
    key = RemoteReceivedContractsKey,
    query_prefix = RemoteReceivedContractsKeyPrefix
);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RemoteReceiveContractNotification {
    pub contract: IncomingContract,
    pub is_funded: bool,
}

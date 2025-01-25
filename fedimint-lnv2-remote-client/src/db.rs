use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::contracts::IncomingContract;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    RemoteReceivedContracts = 0xb1,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RemoteReceivedContractsKey(pub PublicKey);

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

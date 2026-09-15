//! Durable request identity for invoice creation. These receipts commit in the
//! same transaction as the receive operation, not in an application-side journal.
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::PublicKey;
use fedimint_core::{
    Amount,
    core::OperationId,
    encoding::{Decodable, Encodable},
    util::SafeUrl,
};
use fedimint_lnv2_common::Bolt11InvoiceDescription;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

/// Retrying this identity returns the original invoice, even after expiration.
/// Use a fresh identity only for an intentionally new payment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteReceiveRequest {
    pub id: [u8; 32],
    pub claimer_pk: PublicKey,
    pub amount: Amount,
    pub expiry_secs: u32,
    pub description: Bolt11InvoiceDescription,
    pub gateway: Option<SafeUrl>,
}

impl RemoteReceiveRequest {
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        // The struct's field order is fixed. Include all parameters, not just the
        // amount, so a reused identity cannot redirect a payment or change terms.
        sha256::Hash::hash(&serde_json::to_vec(self).expect("request is serializable"))
            .to_byte_array()
    }
}

/// A receipt proves creation, not funding. Keep it while callers may retry or
/// recover this request; deleting it would permit a second invoice for the ID.
#[derive(Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct RemoteReceiveReceipt {
    pub request_id: [u8; 32],
    pub operation_id: OperationId,
    pub claimer_pk: PublicKey,
    pub invoice: Bolt11Invoice,
    pub(crate) request_fingerprint: [u8; 32],
}

impl std::fmt::Debug for RemoteReceiveReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteReceiveReceipt")
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

impl RemoteReceiveReceipt {
    pub fn matches_request(&self, request: &RemoteReceiveRequest) -> bool {
        self.request_id == request.id && self.request_fingerprint == request.fingerprint()
    }
}

pub(crate) async fn existing_receipt(
    dbtx: &mut fedimint_core::db::DatabaseTransaction<'_>,
    id: [u8; 32],
    fingerprint: [u8; 32],
) -> Result<Option<RemoteReceiveReceipt>, crate::RemoteReceiveError> {
    use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
    let receipt = dbtx.get_value(&crate::db::ReceiveRequestKey(id)).await;
    if receipt.as_ref().is_some_and(|receipt| {
        receipt.request_id != id || receipt.request_fingerprint != fingerprint
    }) {
        return Err(crate::RemoteReceiveError::RequestConflict);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ReceiveRequestKey;
    use bitcoin::secp256k1;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped, mem_impl::MemDatabase};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    fn fixture() -> (RemoteReceiveRequest, RemoteReceiveReceipt) {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
        let request = RemoteReceiveRequest {
            id: [2; 32],
            claimer_pk: PublicKey::from_secret_key(&secp, &secret),
            amount: Amount::from_sats(100),
            expiry_secs: 40,
            description: Bolt11InvoiceDescription::Direct("recovery test".to_owned()),
            gateway: None,
        };
        let invoice = lightning_invoice::InvoiceBuilder::new(lightning_invoice::Currency::Regtest)
            .description("recovery test".to_owned())
            .payment_hash(sha256::Hash::hash(&[3; 32]))
            .payment_secret(lightning_invoice::PaymentSecret([4; 32]))
            .duration_since_epoch(std::time::Duration::from_secs(1))
            .min_final_cltv_expiry_delta(18)
            .amount_milli_satoshis(request.amount.msats)
            .build_signed(|message| secp.sign_ecdsa_recoverable(message, &secret))
            .unwrap();
        let receipt = RemoteReceiveReceipt {
            request_id: request.id,
            request_fingerprint: request.fingerprint(),
            operation_id: OperationId([5; 32]),
            claimer_pk: request.claimer_pk,
            invoice,
        };
        (request, receipt)
    }

    #[test]
    fn request_identity_binds_every_parameter_and_receipt_round_trips() {
        let (request, receipt) = fixture();
        let encoded = receipt.consensus_encode_to_vec();
        let decoded = RemoteReceiveReceipt::consensus_decode_whole(
            &encoded,
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();
        assert!(decoded.matches_request(&request));
        assert_eq!(decoded.invoice, receipt.invoice);
        assert_eq!(decoded.operation_id, receipt.operation_id);
        let mut variants = Vec::new();
        let mut changed = request.clone();
        changed.amount += Amount::from_msats(1);
        variants.push(changed);
        let mut changed = request.clone();
        changed.expiry_secs += 1;
        variants.push(changed);
        let mut changed = request.clone();
        changed.description = Bolt11InvoiceDescription::Direct("different".to_owned());
        variants.push(changed);
        let mut changed = request.clone();
        changed.id[0] ^= 1;
        variants.push(changed);
        let mut changed = request.clone();
        changed.gateway = Some("http://localhost:1234".parse().unwrap());
        variants.push(changed);
        let mut changed = request.clone();
        changed.claimer_pk = PublicKey::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[2; 32]).unwrap(),
        );
        variants.push(changed);
        for changed in variants {
            assert!(!receipt.matches_request(&changed));
        }
    }

    #[tokio::test]
    async fn aborted_receipt_is_invisible_and_committed_receipt_is_recoverable() {
        let database = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let (request, receipt) = fixture();
        let mut tx = database.begin_transaction().await;
        tx.insert_new_entry(&ReceiveRequestKey(request.id), &receipt)
            .await;
        drop(tx); // Process loss before commit: no receipt can authorize display.
        assert!(
            existing_receipt(
                &mut database.begin_transaction_nc().await,
                request.id,
                request.fingerprint()
            )
            .await
            .unwrap()
            .is_none()
        );
        let mut tx = database.begin_transaction().await;
        tx.insert_new_entry(&ReceiveRequestKey(request.id), &receipt)
            .await;
        tx.commit_tx().await;
        let recovered = existing_receipt(
            &mut database.begin_transaction_nc().await,
            request.id,
            request.fingerprint(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recovered.invoice, receipt.invoice);
        assert_eq!(recovered.operation_id, receipt.operation_id);
        assert!(
            existing_receipt(
                &mut database.begin_transaction_nc().await,
                request.id,
                [0; 32]
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn competing_commits_choose_one_receipt_without_overwriting_it() {
        async fn commit(
            database: &Database,
            candidate: &RemoteReceiveReceipt,
        ) -> RemoteReceiveReceipt {
            database
                .autocommit(
                    |tx, _| {
                        Box::pin(async {
                            if let Some(existing) = existing_receipt(
                                tx,
                                candidate.request_id,
                                candidate.request_fingerprint,
                            )
                            .await?
                            {
                                return Ok(existing);
                            }
                            tokio::task::yield_now().await;
                            tx.insert_new_entry(
                                &ReceiveRequestKey(candidate.request_id),
                                candidate,
                            )
                            .await;
                            Ok::<_, crate::RemoteReceiveError>(candidate.clone())
                        })
                    },
                    None,
                )
                .await
                .unwrap()
        }
        let database = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let (_, first) = fixture();
        let mut second = first.clone();
        second.operation_id = OperationId([9; 32]);
        let (a, b) = tokio::join!(commit(&database, &first), commit(&database, &second));
        assert_eq!(a.operation_id, b.operation_id);
        assert_eq!(a.invoice, b.invoice);
    }
}

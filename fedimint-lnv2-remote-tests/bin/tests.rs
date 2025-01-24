use std::time::Duration;

use devimint::cmd;
use devimint::federation::Client;
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::Amount;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_remote_client::{FinalRemoteReceiveOperationState, PublicKeys};
use lightning_invoice::Bolt11Invoice;
use substring::Substring;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fed = dev_fed.fed().await?;

        fed.pegin_gateways(
            1_000_000,
            vec![
                dev_fed.gw_cln().await.unwrap(),
                dev_fed.gw_lnd().await.unwrap(),
                dev_fed.gw_ldk().await.unwrap().as_ref().unwrap(),
            ],
        )
        .await?;

        let receiver_client = fed.new_joined_client("client0").await?;
        let claimer_client = fed.new_joined_client("client1").await?;

        let receiver_pubkeys = get_public_keys(&receiver_client).await.unwrap();
        let claimer_pubkeys = get_public_keys(&claimer_client).await.unwrap();

        let ldk_gw_addr = dev_fed.gw_cln().await.as_ref().unwrap().addr.clone();

        register_claimer(&receiver_client, &claimer_pubkeys)
            .await
            .unwrap();

        let (invoice, incoming_contract, operation_id) = remote_receive(
            &receiver_client,
            &claimer_client,
            Amount::from_sats(1_000),
            &ldk_gw_addr,
        )
        .await
        .unwrap();

        dev_fed
            .lnd()
            .await
            .unwrap()
            .pay_bolt11_invoice(invoice.to_string())
            .await
            .unwrap();

        tokio::task::spawn(async move {
            run_remote_receiver_server(&receiver_client).await.unwrap();
        });

        info!(
            "Claimer client balance is {}",
            claimer_client.balance().await.unwrap()
        );

        info!("Syncing with remote receiver...");
        let sync_res = sync_with_remote_receiver(&claimer_client, receiver_pubkeys.iroh_pk).await;

        if sync_res.is_ok() {
            info!("Claimer synced with remote receiver!");
        } else {
            error!("Failed to sync with remote receiver. {sync_res:?}");
        }

        std::thread::sleep(Duration::from_secs(5));

        info!(
            "Claimer client balance is now {}",
            claimer_client.balance().await.unwrap()
        );

        info!("Successfully completed fedimint-lnv2-remote test");

        Ok(())
    })
    .await
}

async fn get_public_keys(client: &Client) -> anyhow::Result<PublicKeys> {
    Ok(serde_json::from_value(
        cmd!(client, "module", "lnv2", "get-public-keys")
            .out_json()
            .await?,
    )?)
}

async fn run_remote_receiver_server(client: &Client) -> anyhow::Result<()> {
    Ok(serde_json::from_value(
        cmd!(client, "module", "lnv2", "run-remote-receiver-server")
            .out_json()
            .await?,
    )?)
}

async fn sync_with_remote_receiver(
    client: &Client,
    remote_receiver_iroh_pubkey: iroh::PublicKey,
) -> anyhow::Result<()> {
    Ok(cmd!(
        client,
        "module",
        "lnv2",
        "sync-with-remote-receiver",
        remote_receiver_iroh_pubkey
    )
    .run()
    .await?)
}

async fn register_claimer(client: &Client, claimer_pks: &PublicKeys) -> anyhow::Result<()> {
    Ok(cmd!(
        client,
        "module",
        "lnv2",
        "register-claimer",
        claimer_pks.claimer_static_pk,
        claimer_pks.iroh_pk
    )
    .run()
    .await?)
}

async fn unregister_claimer(
    client: &Client,
    claimer_static_pk: PublicKey,
    force: bool,
) -> anyhow::Result<()> {
    Ok(cmd!(
        client,
        "module",
        "lnv2",
        "unregister-claimer",
        claimer_static_pk,
        force
    )
    .run()
    .await?)
}

async fn remote_receive(
    receiver_client: &Client,
    claimer_client: &Client,
    amount: Amount,
    gateway: &str,
) -> anyhow::Result<(Bolt11Invoice, IncomingContract, OperationId)> {
    let claimer_pks = get_public_keys(claimer_client).await?;

    let mut json_result = cmd!(
        receiver_client,
        "module",
        "lnv2",
        "remote-receive",
        claimer_pks.claimer_static_pk,
        amount.to_string(),
        "--gateway",
        gateway
    )
    .out_json()
    .await?;

    let json_array = json_result.as_array_mut().unwrap();

    assert_eq!(json_array.len(), 3);

    let operation_id: OperationId = json_array.pop().unwrap().as_str().unwrap().parse().unwrap();
    let incoming_contract: IncomingContract =
        serde_json::from_value(json_array.pop().unwrap()).unwrap();
    let invoice: Bolt11Invoice = json_array.pop().unwrap().as_str().unwrap().parse().unwrap();

    Ok((invoice, incoming_contract, operation_id))
}

async fn await_remote_receive_funded(
    client: &Client,
    operation_id: OperationId,
) -> anyhow::Result<()> {
    assert_eq!(
        cmd!(
            client,
            "module",
            "lnv2",
            "await-remote-receive-funded",
            serde_json::to_string(&operation_id)?.substring(1, 65)
        )
        .out_json()
        .await?,
        serde_json::to_value(FinalRemoteReceiveOperationState::Funded)
            .expect("JSON serialization failed"),
    );

    Ok(())
}

use std::time::Duration;

use devimint::cmd;
use devimint::federation::Client;
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::Amount;
use fedimint_lnv2_common::contracts::IncomingContract;
use fedimint_lnv2_remote_client::FinalRemoteReceiveOperationState;
use lightning_invoice::Bolt11Invoice;
use serde_json::json;
use substring::Substring;
use tracing::info;

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

        let ldk_gw_addr = dev_fed
            .gw_cln()
            .await
            // .unwrap()
            .as_ref()
            .unwrap()
            .addr
            .clone();

        let (invoice, incoming_contract, operation_id) = remote_receive(
            &receiver_client,
            &claimer_client,
            Amount::from_sats(10_000),
            &ldk_gw_addr,
        )
        .await
        .unwrap();

        // dev_fed
        //     .lnd()
        //     .await
        //     .unwrap()
        //     .pay_bolt11_invoice(invoice.to_string())
        //     .await
        //     .unwrap();

        await_receive_funded(&receiver_client, operation_id)
            .await
            .unwrap();

        std::thread::sleep(Duration::from_secs(5));

        println!(
            "{:?}",
            claim(&claimer_client, &incoming_contract).await.unwrap()
        );

        std::thread::sleep(Duration::from_secs(5));

        println!("{}", claimer_client.balance().await.unwrap());

        info!("Successfully completed fedimint-lnv2-remote test");

        Ok(())
    })
    .await
}

async fn get_public_key(client: &Client) -> anyhow::Result<PublicKey> {
    Ok(cmd!(client, "module", "lnv2", "get-public-key")
        .out_json()
        .await?
        .as_str()
        .unwrap()
        .to_string()
        .parse()
        .unwrap())
}

async fn remote_receive(
    receiver_client: &Client,
    claimer_client: &Client,
    amount: Amount,
    gateway: &str,
) -> anyhow::Result<(Bolt11Invoice, IncomingContract, OperationId)> {
    let claimer_pubkey = get_public_key(claimer_client).await?;

    let mut json_result = cmd!(
        receiver_client,
        "module",
        "lnv2",
        "remote-receive",
        claimer_pubkey,
        amount,
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

async fn await_receive_funded(client: &Client, operation_id: OperationId) -> anyhow::Result<()> {
    assert_eq!(
        cmd!(
            client,
            "module",
            "lnv2",
            "await-remote-receive",
            serde_json::to_string(&operation_id)?.substring(1, 65)
        )
        .out_json()
        .await?,
        serde_json::to_value(FinalRemoteReceiveOperationState::Funded)
            .expect("JSON serialization failed"),
    );

    Ok(())
}

async fn claim(
    claimer_client: &Client,
    incoming_contract: &IncomingContract,
) -> anyhow::Result<OperationId> {
    cmd!(
        claimer_client,
        "module",
        "lnv2",
        "claim",
        json!(incoming_contract)
    )
    .out_json()
    .await
    .map(|value| value.as_str().unwrap().parse().unwrap())
}

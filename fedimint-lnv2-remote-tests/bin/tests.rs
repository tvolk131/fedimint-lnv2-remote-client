use devimint::cmd;
use devimint::federation::Client;
use fedimint_core::secp256k1::PublicKey;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fed = dev_fed.fed().await?;
        let client0 = fed.new_joined_client("client0").await?;
        let client1 = fed.new_joined_client("client1").await?;

        println!("{}", get_public_key(&client0).await.unwrap());
        println!("{}", get_public_key(&client1).await.unwrap());

        info!("Successfully completed fedimint-lnv2-remote test");
        Ok(())
    })
    .await
}

async fn get_public_key(client: &Client) -> anyhow::Result<String> {
    Ok(cmd!(client, "module", "lnv2", "get-public-key")
        .out_string()
        .await?)
}

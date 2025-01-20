use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, _process_mgr| async move {
        let fed = dev_fed.fed().await?;
        let client0 = fed.new_joined_client("guardian0").await?;
        let client1 = fed.new_joined_client("guardian1").await?;
        let client2 = fed.new_joined_client("guardian2").await?;
        let client3 = fed.new_joined_client("guardian3").await?;

        // TODO: Actually test stuff here.

        info!("Successfully completed fedimint-lnv2-remote test");
        Ok(())
    })
    .await
}

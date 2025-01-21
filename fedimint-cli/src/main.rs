use fedimint_cli::FedimintCli;
use fedimint_core::fedimint_build_code_version_env;
use fedimint_meta_client::MetaClientInit;
use fedimint_mint_client::MintClientInit;
use fedimint_wallet_client::WalletClientInit;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new(fedimint_build_code_version_env!())?
        .with_module(MintClientInit)
        .with_module(WalletClientInit::default())
        .with_module(MetaClientInit)
        .with_module(fedimint_lnv2_remote_client::LightningRemoteClientInit::default())
        .run()
        .await;
    Ok(())
}

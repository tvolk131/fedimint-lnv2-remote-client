use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_core::core::OperationId;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use secp256k1::PublicKey;
use serde::Serialize;
use serde_json::Value;

use crate::api::LightningFederationApi;
use crate::{Bolt11InvoiceDescription, LightningClientModule};

#[derive(Parser, Serialize)]
enum Opts {
    GetPublicKey,
    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a gateway will be selected
    /// automatically.
    RemoteReceive {
        recipient_static_pk: PublicKey,
        amount: Amount,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the receive operation.
    AwaitRemoteReceive {
        operation_id: OperationId,
    },
    /// Claim a payment.
    Claim {},
    /// Gateway subcommands
    #[command(subcommand)]
    Gateways(GatewaysOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewaysOpts {
    /// Update the mapping from lightning node public keys to gateway api
    /// endpoints maintained in the module database to optimise gateway
    /// selection for a given invoice; this command is intended for testing.
    Map,
    /// List all vetted gateways.
    List {
        #[arg(long)]
        peer: Option<PeerId>,
    },
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2-remote")).chain(args.iter()));

    let value = match opts {
        Opts::GetPublicKey => json(lightning.get_public_key()),
        Opts::RemoteReceive {
            recipient_static_pk,
            amount,
            gateway,
        } => json(
            lightning
                .remote_receive(
                    recipient_static_pk,
                    amount,
                    3600,
                    Bolt11InvoiceDescription::Direct(String::new()),
                    gateway,
                    Value::Null,
                )
                .await?,
        ),
        Opts::AwaitRemoteReceive { operation_id } => json(
            lightning
                .await_final_remote_receive_operation_state(operation_id)
                .await?,
        ),
        Opts::Claim {} => unimplemented!(),
        Opts::Gateways(gateway_opts) => match gateway_opts {
            #[allow(clippy::unit_arg)]
            GatewaysOpts::Map => json(
                LightningClientModule::update_gateway_map(
                    &lightning.federation_id,
                    &lightning.client_ctx,
                    &lightning.module_api,
                    &lightning.gateway_conn,
                )
                .await,
            ),
            GatewaysOpts::List { peer } => match peer {
                Some(peer) => json(lightning.module_api.gateways_from_peer(peer).await?),
                None => json(lightning.module_api.gateways().await?),
            },
        },
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

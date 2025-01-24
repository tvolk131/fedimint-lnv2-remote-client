use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use serde::Serialize;
use serde_json::Value;

use crate::api::LightningFederationApi;
use crate::{Bolt11InvoiceDescription, LightningClientModule};

#[derive(Parser, Serialize)]
enum Opts {
    GetPublicKeys,
    RunRemoteReceiverServer,
    SyncWithRemoteReceiver {
        remote_receiver_iroh_pubkey: iroh::PublicKey,
    },
    RegisterClaimer {
        claimer_static_pk: PublicKey,
        claimer_iroh_pk: iroh::PublicKey,
    },
    UnRegisterClaimer {
        claimer_static_pk: PublicKey,
        force: bool,
    },
    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a gateway will be selected
    /// automatically.
    RemoteReceive {
        claimer_static_pk: PublicKey,
        amount: Amount,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the remote receive operation.
    AwaitRemoteReceiveFunded {
        operation_id: OperationId,
    },
    /// Gateway subcommands
    #[command(subcommand)]
    Gateways(GatewaysOpts),
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewaysOpts {
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
        Opts::GetPublicKeys => json(lightning.get_public_keys()),
        Opts::RunRemoteReceiverServer => json(lightning.run_remote_receiver_server().await),
        Opts::SyncWithRemoteReceiver {
            remote_receiver_iroh_pubkey,
        } => json(
            lightning
                .sync_with_remote_receiver(remote_receiver_iroh_pubkey)
                .await
                .unwrap(),
        ),
        Opts::RegisterClaimer {
            claimer_static_pk,
            claimer_iroh_pk,
        } => json(
            lightning
                .register_claimer(claimer_static_pk, claimer_iroh_pk)
                .await
                .unwrap(),
        ),
        Opts::UnRegisterClaimer {
            claimer_static_pk,
            force,
        } => json(
            lightning
                .unregister_claimer(claimer_static_pk, force)
                .await
                .unwrap(),
        ),
        Opts::RemoteReceive {
            claimer_static_pk,
            amount,
            gateway,
        } => json(
            lightning
                .remote_receive(
                    claimer_static_pk,
                    amount,
                    3600,
                    Bolt11InvoiceDescription::Direct(String::new()),
                    gateway,
                )
                .await?,
        ),
        Opts::AwaitRemoteReceiveFunded { operation_id } => json(
            lightning
                .await_final_remote_receive_operation_state(operation_id)
                .await?,
        ),
        Opts::Gateways(gateway_opts) => match gateway_opts {
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

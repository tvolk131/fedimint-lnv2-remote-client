# Fedimint lnv2 remote client

Receive Lightning payments into contracts claimable by another device.

## Recoverable invoice creation

`LightningClientModule::remote_receive_idempotent(RemoteReceiveRequest)` accepts
a caller-generated 32-byte request ID. Persist that ID before requesting an
invoice. Its creation receipt, unfunded contract, operation log, and receive
state machine commit in a single database transaction before the invoice is
returned to the caller.

Retries with the same ID and parameters return the original invoice and
operation ID, even if that invoice has expired. Reusing the ID with different
parameters is an error. IDs are scoped to a client module / federation;
applications spanning federations must coordinate their own request namespace.
Concurrent requests may fetch extra gateway invoices, but only one receive
operation commits and only the winning invoice is returned to callers.

After a crash, `recover_remote_receive(id)` reads the committed receipt locally
without contacting a gateway or creating an invoice. `None` means nothing has
committed for that ID, not that an in-flight concurrent request cannot still
commit. Serialize recovery with creation when this distinction matters.

A receipt proves creation, **not payment**. Use `await_remote_receive` to observe
the final funded/expired state. Keep receipts as long as callers can retry;
deleting them would allow a second invoice for the same ID. The existing
`remote_receive` API remains available for callers that do not need recovery.

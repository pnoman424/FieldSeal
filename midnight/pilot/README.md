# esense Midnight receipt pilot

This package compiles, deploys, and exercises the esense receipt registry without
giving the Flask web process access to a Midnight wallet or issuer secret.

Only the salted 32-byte document commitment may cross the Midnight boundary.
Customer details, job references, report text, measurements, photographs, access
grants, and esense identifiers remain in the encrypted esense database.

## Version baseline

- Official example: `midnightntwrk/example-hello-world` commit `96f323bc14174e6a3159606424ab43c9343ff868`
- Compact installer `0.5.1`, compiler `0.31.1`, language `0.23`
- Midnight.js `4.1.1`, wallet SDK `1.2.0`, proof server `8.1.0`
- Node.js `22.23.1`, Yarn `1.22.22`

Provider and wallet structure is derived from the Apache-2.0 licensed official
example. The esense contract, privacy boundary, tests, and integration are local.

## Local validation

```bash
PATH="$HOME/.local/node22/bin:$HOME/.local/bin:$PATH" corepack yarn install --frozen-lockfile
PATH="$HOME/.local/node22/bin:$HOME/.local/bin:$PATH" corepack yarn compile
PATH="$HOME/.local/node22/bin:$HOME/.local/bin:$PATH" corepack yarn env:up
PATH="$HOME/.local/node22/bin:$HOME/.local/bin:$PATH" corepack yarn test:local
PATH="$HOME/.local/node22/bin:$HOME/.local/bin:$PATH" corepack yarn env:down
```

Preprod secrets belong in a root-readable environment file on the Cardano server.
Never commit or paste wallet or issuer secrets into chat.

## Preprod operations

Each command writes one redacted JSON result. It never serializes the Midnight
SDK transaction object, wallet seed, issuer secret, proof transcript, or private
contract state.

```bash
MIDNIGHT_NETWORK=preprod yarn wallet:preprod
MIDNIGHT_NETWORK=preprod yarn pilot funds
MIDNIGHT_NETWORK=preprod yarn pilot deploy
MIDNIGHT_NETWORK=preprod yarn pilot register <64-hex-document-commitment>
MIDNIGHT_NETWORK=preprod yarn pilot verify <64-hex-document-commitment>
MIDNIGHT_NETWORK=preprod yarn pilot revoke <64-hex-document-commitment>
```

The public wallet address must first receive Preprod test NIGHT from the official
faucet. The `funds` command waits for that balance and performs the SDK's
NIGHT-to-DUST registration needed to pay transaction fees.

On the server, the root-only launcher reads the private environment and then
drops privileges to the dedicated `esense-midnight` account before running a
command:

```bash
sudo esense-midnight-pilot /opt/esense-midnight/app/src/pilot-cli.ts wallet-info
```

## Production activation

Production remains disabled until the Preprod wallet is funded and a contract
deployment has returned a confirmed 64-hex contract address. Activation is a
root-only operation so the web application never receives the wallet seed or
issuer secret: <REDACTED>
sudo configure-esense-midnight-preprod <64-hex-contract-address>
```

That command creates a private worker token, configures the same public network
and contract address for the web application and worker, restarts esense, and
enables the worker. The worker keeps one synchronized wallet open, claims only
commitment-only jobs from the local authenticated queue, and writes confirmed
transaction details back to esense.

The dedicated service account also maintains a mode-`0600` serialized wallet
state cache under `/var/lib/esense-midnight/state`. It contains no master seed
and is accepted only when its network and derived public address match the
root-owned service identity. The cache avoids rebuilding wallet state from
genesis after routine restarts; the signing seed remains only in the root-owned
environment file.

The first Preprod synchronization can take substantially longer on modest
hardware. Preprod therefore allows six hours by default
(`MIDNIGHT_SYNC_TIMEOUT_MS=21600000`) and the persistent worker checkpoints its
private wallet state every five minutes while catching up. Once ready, the same
worker remains alive and processes all anchor jobs without rebuilding the wallet.

The synthetic demonstration package can then be queued without exposing report
content:

```bash
/opt/esense/.venv/bin/python /opt/esense/queue_midnight_demo.py
```

Operational invariants:

- Only `commitment`, `operation`, `network`, and `contract_address` cross the
  internal worker boundary.
- A report is described as anchored only after a confirmed transaction can be
  checked against public contract state.
- Retries are idempotent: the worker checks public state before submitting a
  duplicate register or revoke transaction.
- Revocation is a separate public state transition; it does not erase the
  original receipt or reveal the report.
- If the worker is unavailable, report creation still succeeds and the anchor
  remains queued or failed with a retryable status.

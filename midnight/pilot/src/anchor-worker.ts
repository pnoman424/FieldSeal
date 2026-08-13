import { WebSocket } from 'ws';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import {
  findDeployedContract,
  submitCallTx,
} from '@midnight-ntwrk/midnight-js-contracts';
import type { ContractAddress } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import {
  waitForFunds,
  type EnvironmentConfiguration,
} from '@midnight-ntwrk/testkit-js';
import pino from 'pino';

import { getConfig } from './config.ts';
import { buildProviders, type ReceiptProviders } from './providers.ts';
import { hexToBytes } from './private-state.ts';
import {
  MidnightWalletProvider,
  resolveWalletSecret,
  resolveSyncTimeout,
  syncWallet,
  waitForSpendableDust,
} from './wallet.ts';
import {
  CompiledReceiptContract,
  type Contract,
  ledger,
  zkConfigPath,
} from '../contracts/index.ts';

// @ts-expect-error The generated indexer client expects a browser WebSocket global.
globalThis.WebSocket = WebSocket;

type AnchorJob = {
  id: string;
  commitment: string;
  operation: 'register' | 'revoke';
  network: string;
  contract_address: string;
};

type PublicTransactionResult = {
  transactionId?: string;
  blockHash?: string;
  blockHeight?: number;
};

const privateStateId = 'esenseIssuerState';
const baseUrl = (process.env['ESENSE_INTERNAL_URL'] ?? 'http://127.0.0.1:5000/api/internal/midnight')
  .replace(/\/$/, '');
const token: <REDACTED>
const pollMilliseconds = Math.max(5_000, Number(process.env['ESENSE_MIDNIGHT_POLL_MS'] ?? 15_000));
const syncCheckpointMilliseconds = Math.max(
  60_000,
  Number(process.env['MIDNIGHT_SYNC_CHECKPOINT_MS'] ?? 5 * 60_000),
);
const logger = pino({ level: process.env['LOG_LEVEL'] ?? 'info' }, pino.destination(2));

if (!token) throw new Error('ESENSE_MIDNIGHT_WORKER_TOKEN is required.');

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function persistWalletState(wallet: MidnightWalletProvider): Promise<void> {
  try {
    await wallet.saveState();
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Wallet state cache update failed';
    logger.warn({ error: message }, 'Midnight wallet state was not cached');
  }
}

async function internalRequest(path: string, body: Record<string, unknown>): Promise<any> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      Authorization: <REDACTED>
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`esense internal API returned ${response.status}`);
  return payload;
}

async function reportConfirmed(
  job: AnchorJob,
  result: PublicTransactionResult,
  method: 'finalized_transaction' | 'contract_state',
): Promise<void> {
  await internalRequest(`/anchors/${encodeURIComponent(job.id)}/result`, {
    status: 'confirmed',
    transaction_id: result.transactionId ?? null,
    block_hash: result.blockHash ?? null,
    block_height: result.blockHeight ?? null,
    verification_method: method,
  });
}

async function receiptState(
  providers: ReceiptProviders,
  contractAddress: ContractAddress,
  commitment: Uint8Array,
): Promise<{ registered: boolean; revoked: boolean }> {
  const result = await providers.publicDataProvider.queryContractState(contractAddress);
  if (!result) throw new Error('The receipt registry contract was not found.');
  const state = ledger(result.data);
  return {
    registered: state.activeReceipts.member(commitment),
    revoked: state.revokedReceipts.member(commitment),
  };
}

async function processJob(
  providers: ReceiptProviders,
  configuredNetwork: string,
  configuredAddress: ContractAddress,
  job: AnchorJob,
): Promise<void> {
  if (job.network !== configuredNetwork || job.contract_address !== configuredAddress) {
    throw new Error('The queued anchor does not match the configured Midnight deployment.');
  }
  const commitment = hexToBytes(job.commitment);
  const existing = await receiptState(providers, configuredAddress, commitment);
  if ((job.operation === 'register' && existing.registered && !existing.revoked)
    || (job.operation === 'revoke' && existing.revoked)) {
    await reportConfirmed(job, {}, 'contract_state');
    logger.info({ anchorId: job.id, operation: job.operation }, 'Recovered confirmed Midnight state');
    return;
  }

  const circuitId = job.operation === 'register' ? 'registerReceipt' : 'revokeReceipt';
  const transaction = await submitCallTx<Contract, typeof circuitId>(providers, {
    compiledContract: CompiledReceiptContract,
    contractAddress: configuredAddress,
    privateStateId,
    circuitId,
    args: [commitment],
  });
  const publicData = transaction.public;
  await reportConfirmed(
    job,
    {
      transactionId: String(publicData.txId),
      blockHash: String(publicData.blockHash),
      blockHeight: publicData.blockHeight,
    },
    'finalized_transaction',
  );
  logger.info(
    { anchorId: job.id, operation: job.operation, transactionId: String(publicData.txId) },
    'Midnight anchor confirmed',
  );
}

let stopping = false;
process.on('SIGTERM', () => { stopping = true; });
process.on('SIGINT', () => { stopping = true; });

async function main(): Promise<void> {
  const config = getConfig();
  const configuredAddress = process.env['MIDNIGHT_CONTRACT_ADDRESS']?.trim() as ContractAddress | undefined;
  if (!configuredAddress) throw new Error('MIDNIGHT_CONTRACT_ADDRESS is required.');
  setNetworkId(config.networkId);
  const environment: EnvironmentConfiguration = {
    walletNetworkId: config.networkId,
    networkId: config.networkId,
    indexer: config.indexer,
    indexerWS: config.indexerWS,
    node: config.node,
    nodeWS: config.nodeWS,
    faucet: config.faucet,
    proofServer: config.proofServer,
  };
  const wallet = await MidnightWalletProvider.build(
    logger,
    environment,
    resolveWalletSecret(process.env['MIDNIGHT_NETWORK'] ?? 'preprod'),
  );
  try {
    await wallet.start();
    const syncCheckpoint = setInterval(() => {
      void persistWalletState(wallet);
    }, syncCheckpointMilliseconds);
    try {
      await syncWallet(logger, wallet.wallet, resolveSyncTimeout(config.networkId));
    } finally {
      clearInterval(syncCheckpoint);
      await persistWalletState(wallet);
    }
    await waitForFunds(wallet.wallet, environment, false, wallet.unshieldedKeystore);
    await waitForSpendableDust(logger, wallet.wallet);
    await persistWalletState(wallet);
    const providers = buildProviders(wallet, zkConfigPath, config);
    await findDeployedContract<Contract>(providers, {
      compiledContract: CompiledReceiptContract,
      contractAddress: configuredAddress,
      privateStateId,
    });

    logger.info({ network: config.networkId, contractAddress: configuredAddress }, 'esense Midnight worker ready');
    while (!stopping) {
      try {
        const response = await internalRequest('/anchors/claim', {});
        const job = response.job as AnchorJob | null;
        if (!job) {
          await sleep(pollMilliseconds);
          continue;
        }
        try {
          await processJob(providers, config.networkId, configuredAddress, job);
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Midnight worker operation failed';
          await internalRequest(`/anchors/${encodeURIComponent(job.id)}/result`, {
            status: 'failed',
            error: message.slice(0, 500),
          });
          logger.error({ anchorId: job.id, operation: job.operation, error: message }, 'Midnight anchor failed');
        } finally {
          await persistWalletState(wallet);
        }
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : 'Worker polling failed';
        logger.warn({ error: message }, 'Midnight worker could not poll esense');
        await sleep(pollMilliseconds);
      }
    }
  } finally {
    await persistWalletState(wallet);
    await wallet.stop();
  }
  logger.info('esense Midnight worker stopped');
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Midnight worker failed';
  logger.fatal({ error: message }, 'esense Midnight worker terminated');
  process.exitCode = 1;
});

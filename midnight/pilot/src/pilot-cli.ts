import { WebSocket } from 'ws';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import {
  deployContract,
  findDeployedContract,
  submitCallTx,
} from '@midnight-ntwrk/midnight-js-contracts';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import type { ContractAddress } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import {
  waitForFunds,
  type EnvironmentConfiguration,
} from '@midnight-ntwrk/testkit-js';
import pino from 'pino';

import { getConfig, type NetworkConfig } from './config.ts';
import { buildProviders } from './providers.ts';
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

const privateStateId = 'esenseIssuerState';
const logger = pino(
  { level: process.env['LOG_LEVEL'] ?? 'warn' },
  pino.destination(2),
);

type PublicResult = Record<string, boolean | number | string | null>;

function environmentFor(config: NetworkConfig): EnvironmentConfiguration {
  return {
    walletNetworkId: config.networkId,
    networkId: config.networkId,
    indexer: config.indexer,
    indexerWS: config.indexerWS,
    node: config.node,
    nodeWS: config.nodeWS,
    faucet: config.faucet,
    proofServer: config.proofServer,
  };
}

function output(result: PublicResult): void {
  process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
}

function contractAddressFromEnvironment(): ContractAddress {
  const value = process.env['MIDNIGHT_CONTRACT_ADDRESS']?.trim();
  if (!value) throw new Error('MIDNIGHT_CONTRACT_ADDRESS is required.');
  return value as ContractAddress;
}

function commitmentFromArgument(value: string | undefined): Uint8Array {
  if (!value) throw new Error('A 64-character hexadecimal commitment is required.');
  return hexToBytes(value);
}

async function publicReceiptStatus(
  config: NetworkConfig,
  contractAddress: ContractAddress,
  commitment: Uint8Array,
): Promise<PublicResult> {
  const provider = indexerPublicDataProvider(config.indexer, config.indexerWS);
  const result = await provider.queryContractState(contractAddress);
  if (!result) throw new Error('The receipt registry contract was not found.');
  const state = ledger(result.data);
  const registered = state.activeReceipts.member(commitment);
  const revoked = state.revokedReceipts.member(commitment);
  return {
    network: config.networkId,
    contractAddress,
    registered,
    revoked,
    valid: registered && !revoked,
  };
}

async function withFundedWallet<T>(
  config: NetworkConfig,
  operation: (wallet: MidnightWalletProvider) => Promise<T>,
): Promise<T> {
  const environment = environmentFor(config);
  const wallet = await MidnightWalletProvider.build(
    logger,
    environment,
    resolveWalletSecret(process.env['MIDNIGHT_NETWORK'] ?? 'local'),
  );
  try {
    await wallet.start();
    const checkpointMilliseconds = Math.max(
      60_000,
      Number(process.env['MIDNIGHT_SYNC_CHECKPOINT_MS'] ?? 5 * 60_000),
    );
    const syncCheckpoint = setInterval(() => {
      void wallet.saveState().catch((error: unknown) => {
        const message = error instanceof Error ? error.message : 'Wallet state cache update failed';
        logger.warn({ error: message }, 'Midnight wallet sync checkpoint failed');
      });
    }, checkpointMilliseconds);
    try {
      await syncWallet(logger, wallet.wallet, resolveSyncTimeout(config.networkId));
    } finally {
      clearInterval(syncCheckpoint);
      await wallet.saveState();
    }
    if (config.networkId !== 'undeployed') {
      await waitForFunds(wallet.wallet, environment, false, wallet.unshieldedKeystore);
      await waitForSpendableDust(logger, wallet.wallet);
    }
    return await operation(wallet);
  } finally {
    try {
      await wallet.saveState();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Wallet state cache update failed';
      logger.warn({ error: message }, 'Midnight wallet state was not cached');
    }
    await wallet.stop();
  }
}

async function main(): Promise<void> {
  const [command, argument] = process.argv.slice(2);
  const config = getConfig();
  const secretProfile = process.env['MIDNIGHT_NETWORK'] ?? 'local';
  setNetworkId(config.networkId);

  if (command === 'wallet-info') {
    const wallet = await MidnightWalletProvider.build(
      logger,
      environmentFor(config),
      resolveWalletSecret(secretProfile),
    );
    output({
      network: config.networkId,
      unshieldedAddress: wallet.unshieldedKeystore.getBech32Address().toString(),
    });
    return;
  }

  if (command === 'verify') {
    output(await publicReceiptStatus(
      config,
      contractAddressFromEnvironment(),
      commitmentFromArgument(argument),
    ));
    return;
  }

  if (command === 'funds') {
    await withFundedWallet(config, async (wallet) => {
      output({
        network: config.networkId,
        funded: true,
        unshieldedAddress: wallet.unshieldedKeystore.getBech32Address().toString(),
      });
    });
    return;
  }

  if (command === 'deploy') {
    const issuerSecret: <REDACTED>
    if (!issuerSecret) throw new Error('MIDNIGHT_ISSUER_SECRET is required.');
    await withFundedWallet(config, async (wallet) => {
      const providers = buildProviders(wallet, zkConfigPath, config);
      const deployed = await deployContract<Contract>(providers, {
        compiledContract: CompiledReceiptContract,
        privateStateId,
        initialPrivateState: { issuerSecret: <REDACTED>
      });
      const transaction = deployed.deployTxData.public;
      output({
        network: config.networkId,
        contractAddress: transaction.contractAddress,
        transactionId: String(transaction.txId),
        blockHash: String(transaction.blockHash),
        blockHeight: transaction.blockHeight,
      });
    });
    return;
  }

  if (command === 'register' || command === 'revoke') {
    const commitment = commitmentFromArgument(argument);
    const contractAddress = contractAddressFromEnvironment();
    await withFundedWallet(config, async (wallet) => {
      const providers = buildProviders(wallet, zkConfigPath, config);
      await findDeployedContract<Contract>(providers, {
        compiledContract: CompiledReceiptContract,
        contractAddress,
        privateStateId,
      });
      const circuitId = command === 'register' ? 'registerReceipt' : 'revokeReceipt';
      const transaction = await submitCallTx<Contract, typeof circuitId>(providers, {
        compiledContract: CompiledReceiptContract,
        contractAddress,
        privateStateId,
        circuitId,
        args: [commitment],
      });
      output({
        network: config.networkId,
        contractAddress,
        operation: command,
        transactionId: String(transaction.public.txId),
        blockHash: String(transaction.public.blockHash),
        blockHeight: transaction.public.blockHeight,
      });
    });
    return;
  }

  throw new Error('Use wallet-info, funds, deploy, register <commitment>, verify <commitment>, or revoke <commitment>.');
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'The Midnight operation failed.';
  process.stderr.write(`${JSON.stringify({ ok: false, error: message.slice(0, 500) })}\n`);
  process.exitCode = 1;
});

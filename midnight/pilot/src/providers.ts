import { type MidnightProviders } from '@midnight-ntwrk/midnight-js-types';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import type { MidnightWalletProvider } from './wallet.ts';
import type { NetworkConfig } from './config.ts';
import type { ReceiptPrivateState } from './private-state.ts';

export type ReceiptCircuits = 'registerReceipt' | 'revokeReceipt' | 'assertValidReceipt';
export type ReceiptProviders = MidnightProviders<any>;

export function buildProviders(
  wallet: MidnightWalletProvider,
  zkConfigPath: string,
  config: NetworkConfig,
): ReceiptProviders {
  const zkConfigProvider = new NodeZkConfigProvider<ReceiptCircuits>(zkConfigPath);
  const password: <REDACTED>
  if (!password) {
    throw new Error('MIDNIGHT_PRIVATE_STATE_PASSWORD is required');
  }
  return {
    privateStateProvider: levelPrivateStateProvider<string, ReceiptPrivateState>({
      privateStateStoreName: `esense-receipt-${config.networkId}`,
      signingKeyStoreName: `esense-receipt-signing-${config.networkId}`,
      privateStoragePasswordProvider: () => password,
      accountId: wallet.getCoinPublicKey(),
    }),
    publicDataProvider: indexerPublicDataProvider(config.indexer, config.indexerWS),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(config.proofServer, zkConfigProvider),
    walletProvider: wallet,
    midnightProvider: wallet,
  };
}

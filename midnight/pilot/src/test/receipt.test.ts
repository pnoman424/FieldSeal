import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import {
  deployContract,
  submitCallTx,
  type DeployedContract,
} from '@midnight-ntwrk/midnight-js-contracts';
import type { ContractAddress } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import type { EnvironmentConfiguration } from '@midnight-ntwrk/testkit-js';
import pino from 'pino';

import { getConfig } from '../config.ts';
import { MidnightWalletProvider, resolveWalletSecret, syncWallet } from '../wallet.ts';
import { buildProviders, type ReceiptProviders } from '../providers.ts';
import { hexToBytes } from '../private-state.ts';
import {
  CompiledReceiptContract,
  type Contract,
  ledger,
  zkConfigPath,
} from '../../contracts/index.ts';

// @ts-expect-error The indexer client requires a WebSocket global in Node.
globalThis.WebSocket = WebSocket;

const network = process.env['MIDNIGHT_NETWORK'] ?? 'local';
const logger = pino({ level: process.env['LOG_LEVEL'] ?? 'info' });
const privateStateId = 'esenseIssuerState';
const issuerSecret: <REDACTED>
  process.env['MIDNIGHT_ISSUER_SECRET'] ??
    '4c7f06f9508f58f7e68f849f219dc375b76f4d573d2cb68d063a843a840a6c42',
);
const commitment = hexToBytes('e64bbb986ecc4d5eabe4f0640913fdb6a80d3f34a527895fcdad2752f01cdc7d');

describe(`esense receipt registry (${network})`, () => {
  let wallet: MidnightWalletProvider;
  let providers: ReceiptProviders;
  let contractAddress: ContractAddress;

  beforeAll(async () => {
    const config = getConfig();
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
    wallet = await MidnightWalletProvider.build(logger, environment, resolveWalletSecret(network));
    await wallet.start();
    await syncWallet(logger, wallet.wallet, network === 'local' ? 10 * 60_000 : 60 * 60_000);
    providers = buildProviders(wallet, zkConfigPath, config);
  });

  afterAll(async () => {
    if (wallet) await wallet.stop();
  });

  async function state() {
    const result = await providers.publicDataProvider.queryContractState(contractAddress);
    expect(result).not.toBeNull();
    return ledger(result!.data);
  }

  it('deploys with a private issuer secret', async () => {
    const deployed: DeployedContract<Contract> = await deployContract<Contract>(providers, {
      compiledContract: CompiledReceiptContract,
      privateStateId,
      initialPrivateState: { issuerSecret },
    });
    contractAddress = deployed.deployTxData.public.contractAddress;
    const registry = await state();
    expect(registry.activeReceipts.size()).toBe(0n);
    expect(registry.revokedReceipts.size()).toBe(0n);
  });

  it('registers the synthetic document commitment once', async () => {
    await submitCallTx<Contract, 'registerReceipt'>(providers, {
      compiledContract: CompiledReceiptContract,
      contractAddress,
      privateStateId,
      circuitId: 'registerReceipt',
      args: [commitment],
    });
    expect((await state()).activeReceipts.member(commitment)).toBe(true);
  });

  it('revokes the synthetic document commitment', async () => {
    await submitCallTx<Contract, 'revokeReceipt'>(providers, {
      compiledContract: CompiledReceiptContract,
      contractAddress,
      privateStateId,
      circuitId: 'revokeReceipt',
      args: [commitment],
    });
    expect((await state()).revokedReceipts.member(commitment)).toBe(true);
  });
});

import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  type CoinPublicKey,
  DustSecretKey,
  type EncPublicKey,
  type FinalizedTransaction,
  LedgerParameters,
  ZswapSecretKeys,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import type {
  MidnightProvider,
  UnboundTransaction,
  WalletProvider,
} from '@midnight-ntwrk/midnight-js-types';
import { ttlOneHour } from '@midnight-ntwrk/midnight-js-utils';
import {
  DustWallet,
  InMemoryTransactionHistoryStorage,
  UnshieldedWallet,
  WalletEntrySchema,
  createKeystore,
  mergeWalletEntries,
  type DefaultConfiguration,
  type WalletFacade,
  type FacadeState,
  type UnshieldedKeystore,
} from '@midnight-ntwrk/wallet-sdk';
import {
  type DustWalletOptions,
  type EnvironmentConfiguration,
  FluentWalletBuilder,
  WalletFactory,
  WalletSeeds,
} from '@midnight-ntwrk/testkit-js';
import * as Rx from 'rxjs';
import type { Logger } from 'pino';

export type WalletSecret: <REDACTED>
  | { kind: 'mnemonic'; value: string };

type SerializedWalletCache = {
  version: 1;
  network: string;
  unshieldedAddress: string;
  shielded: string;
  unshielded: string;
  dust: string;
};

const cacheFilename = 'wallet-state.json';
const defaultPreprodSyncTimeout = 6 * 60 * 60_000;

function walletConfiguration(env: EnvironmentConfiguration): DefaultConfiguration {
  return {
    indexerClientConnection: {
      indexerHttpUrl: env.indexer,
      indexerWsUrl: env.indexerWS,
    },
    provingServerUrl: new URL(env.proofServer),
    networkId: env.walletNetworkId,
    relayURL: new URL(env.nodeWS),
    txHistoryStorage: new InMemoryTransactionHistoryStorage(WalletEntrySchema, mergeWalletEntries),
    costParameters: { feeBlocksMargin: 5 },
  };
}

function resolveWalletSeeds(secret: <REDACTED>
  return secret.kind === 'mnemonic'
    ? WalletSeeds.fromMnemonic(secret.value)
    : WalletSeeds.fromMasterSeed(secret.value);
}

function cachePath(): string | undefined {
  const directory = process.env['MIDNIGHT_WALLET_STATE_DIR']?.trim();
  return directory ? path.join(directory, cacheFilename) : undefined;
}

export function resolveSyncTimeout(network: string): number {
  const configured = Number(process.env['MIDNIGHT_SYNC_TIMEOUT_MS']);
  if (Number.isFinite(configured) && configured >= 60_000) return configured;
  return network === 'local' ? 10 * 60_000 : defaultPreprodSyncTimeout;
}

export class MidnightWalletProvider implements MidnightProvider, WalletProvider {
  readonly wallet: WalletFacade;
  readonly unshieldedKeystore: UnshieldedKeystore;

  private constructor(
    private readonly logger: Logger,
    wallet: WalletFacade,
    private readonly zswapSecretKeys: ZswapSecretKeys,
    private readonly dustSecretKey: DustSecretKey,
    unshieldedKeystore: UnshieldedKeystore,
    private readonly network: string,
    private readonly stateCachePath?: string,
  ) {
    this.wallet = wallet;
    this.unshieldedKeystore = unshieldedKeystore;
  }

  getCoinPublicKey(): CoinPublicKey {
    return this.zswapSecretKeys.coinPublicKey;
  }

  getEncryptionPublicKey(): EncPublicKey {
    return this.zswapSecretKeys.encryptionPublicKey;
  }

  async balanceTx(
    tx: UnboundTransaction,
    ttl: Date = ttlOneHour(),
  ): Promise<FinalizedTransaction> {
    const recipe = await this.wallet.balanceUnboundTransaction(
      tx,
      { shieldedSecretKeys: this.zswapSecretKeys, dustSecretKey: this.dustSecretKey },
      { ttl },
    );
    return await this.wallet.finalizeRecipe(recipe);
  }

  submitTx(tx: FinalizedTransaction): Promise<string> {
    return this.wallet.submitTransaction(tx);
  }

  async start(): Promise<void> {
    this.logger.info('Starting Midnight wallet');
    await this.wallet.start(this.zswapSecretKeys, this.dustSecretKey);
  }

  async stop(): Promise<void> {
    return this.wallet.stop();
  }

  async saveState(): Promise<void> {
    if (!this.stateCachePath) return;
    const [shielded, unshielded, dust] = await Promise.all([
      this.wallet.shielded.serializeState(),
      this.wallet.unshielded.serializeState(),
      this.wallet.dust.serializeState(),
    ]);
    const payload: SerializedWalletCache = {
      version: 1,
      network: this.network,
      unshieldedAddress: this.unshieldedKeystore.getBech32Address().toString(),
      shielded,
      unshielded,
      dust,
    };
    const directory = path.dirname(this.stateCachePath);
    const temporary = `${this.stateCachePath}.${process.pid}.tmp`;
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(temporary, JSON.stringify(payload), { encoding: 'utf8', mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, this.stateCachePath);
    this.logger.info('Midnight wallet state cache updated');
  }

  static async build(
    logger: Logger,
    env: EnvironmentConfiguration,
    secret: <REDACTED>
  ): Promise<MidnightWalletProvider> {
    const derivedSeeds = resolveWalletSeeds(secret);
    const unshieldedKeystore = createKeystore(derivedSeeds.unshielded, env.walletNetworkId);
    const stateCachePath = cachePath();
    if (stateCachePath) {
      try {
        const cached = JSON.parse(await readFile(stateCachePath, 'utf8')) as SerializedWalletCache;
        const expectedAddress = unshieldedKeystore.getBech32Address().toString();
        if (
          cached.version !== 1
          || cached.network !== env.walletNetworkId
          || cached.unshieldedAddress !== expectedAddress
          || !cached.shielded
          || !cached.unshielded
          || !cached.dust
        ) {
          throw new Error('Wallet state cache identity does not match this service');
        }
        const configuration = walletConfiguration(env);
        const shieldedWallet = await WalletFactory.restoreShieldedWallet(configuration, cached.shielded);
        const restoredUnshielded = UnshieldedWallet(configuration).restore(cached.unshielded);
        const restoredDust = DustWallet({
          ...configuration,
          costParameters: {
            additionalFeeOverhead: 1_000n,
            feeBlocksMargin: 5,
          },
        }).restore(cached.dust);
        const wallet = await WalletFactory.createWalletFacade(
          configuration,
          shieldedWallet,
          restoredUnshielded,
          restoredDust,
        );
        logger.info('Restored Midnight wallet from the private state cache');
        return new MidnightWalletProvider(
          logger,
          wallet,
          ZswapSecretKeys.fromSeed(derivedSeeds.shielded),
          DustSecretKey.fromSeed(derivedSeeds.dust),
          unshieldedKeystore,
          env.walletNetworkId,
          stateCachePath,
        );
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : 'Wallet state cache could not be restored';
        logger.warn({ error: message }, 'Using a fresh Midnight wallet state');
      }
    }

    const dustOptions: DustWalletOptions = {
      ledgerParams: LedgerParameters.initialParameters(),
      additionalFeeOverhead: 1_000n,
      feeBlocksMargin: 5,
    };
    const base = FluentWalletBuilder.forEnvironment(env).withDustOptions(dustOptions);
    const builder = secret.kind === 'mnemonic'
      ? base.withMnemonic(secret.value)
      : base.withSeed(secret.value);
    const result = await builder.buildWithoutStarting();
    const { wallet, seeds, keystore } = result as {
      wallet: WalletFacade;
      seeds: { shielded: Uint8Array; dust: Uint8Array };
      keystore: UnshieldedKeystore;
    };
    return new MidnightWalletProvider(
      logger,
      wallet,
      ZswapSecretKeys.fromSeed(seeds.shielded),
      DustSecretKey.fromSeed(seeds.dust),
      keystore,
      env.walletNetworkId,
      stateCachePath,
    );
  }
}

function isSyncComplete(progress: unknown): boolean {
  if (!progress || typeof progress !== 'object') return false;
  const check = (progress as { isStrictlyComplete?: unknown }).isStrictlyComplete;
  return typeof check === 'function' && (check as () => boolean).call(progress);
}

function syncProgressSnapshot(progress: unknown): Record<string, boolean | number | string> {
  if (!progress || typeof progress !== 'object') return {};
  const source = progress as Record<string, unknown>;
  const snapshot: Record<string, boolean | number | string> = {
    complete: isSyncComplete(progress),
  };
  for (const key of [
    'appliedIndex',
    'highestRelevantWalletIndex',
    'highestIndex',
    'highestRelevantIndex',
    'isConnected',
  ]) {
    const value = source[key];
    if (typeof value === 'bigint') snapshot[key] = value.toString();
    else if (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
      snapshot[key] = value;
    }
  }
  return snapshot;
}

export async function syncWallet(
  logger: Logger,
  wallet: WalletFacade,
  timeout = 300_000,
): Promise<FacadeState> {
  let emissions = 0;
  return Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.tap((state: FacadeState) => {
        emissions += 1;
        if (emissions === 1 || emissions % 500 === 0) {
          logger.info({
            emissions,
            shielded: syncProgressSnapshot(state.shielded.state.progress),
            dust: syncProgressSnapshot(state.dust.state.progress),
            unshielded: syncProgressSnapshot(state.unshielded.progress),
          }, 'Wallet syncing');
        }
      }),
      Rx.filter(
        (state: FacadeState) =>
          isSyncComplete(state.shielded.state.progress) &&
          isSyncComplete(state.dust.state.progress) &&
          isSyncComplete(state.unshielded.progress),
      ),
      Rx.timeout({
        each: timeout,
        with: () => Rx.throwError(() => new Error(`Wallet sync timed out after ${timeout} ms`)),
      }),
    ),
  );
}

export async function waitForSpendableDust(
  logger: Logger,
  wallet: WalletFacade,
  timeout = 15 * 60_000,
): Promise<FacadeState> {
  logger.info('Waiting for spendable DUST');
  return Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.filter((state: FacadeState) => state.dust.balance(new Date()) > 0n),
      Rx.timeout({
        first: timeout,
        with: () => Rx.throwError(() => new Error(`Spendable DUST was not available after ${timeout} ms`)),
      }),
    ),
  );
}

export function resolveWalletSecret(network: string): WalletSecret {
  if (network === 'local') {
    return { kind: 'seed', value: '0000000000000000000000000000000000000000000000000000000000000001' };
  }
  const prefix = `MIDNIGHT_${network.toUpperCase()}`;
  const mnemonic = process.env[`${prefix}_MNEMONIC`]?.trim().replace(/\s+/g, ' ');
  const seed = process.env[`${prefix}_SEED`]?.trim();
  if (mnemonic && seed) throw new Error(`Set only one of ${prefix}_MNEMONIC or ${prefix}_SEED.`);
  if (mnemonic) return { kind: 'mnemonic', value: mnemonic };
  if (seed && /^[0-9a-fA-F]{64}$/.test(seed)) return { kind: 'seed', value: seed };
  throw new Error(`A valid ${prefix}_MNEMONIC or ${prefix}_SEED is required.`);
}

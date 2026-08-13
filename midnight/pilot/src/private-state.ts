export type ReceiptPrivateState = {
  issuerSecret: <REDACTED>
};

export function hexToBytes(value: string, expectedBytes = 32): Uint8Array {
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length !== expectedBytes * 2) {
    throw new Error(`Expected exactly ${expectedBytes * 2} hexadecimal characters.`);
  }
  return Uint8Array.from(normalized.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)));
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

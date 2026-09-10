/** Preserve the key already enrolled with the temporary create/show button. */
export const BROWSER_KEY_SCOPE = 'development-diagnostic-v1';
export const MAX_AGENT_PACKET = 65536;
export const SIGN_TIMEOUT = 10000;

export function bytes(
  value: unknown,
  maximum = MAX_AGENT_PACKET,
): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) && !(value instanceof ArrayBuffer)) {
    throw new Error('Expected binary SSH data');
  }
  if (value.byteLength > maximum) throw new Error('SSH data exceeds limit');
  return new Uint8Array(value instanceof ArrayBuffer ? value : value.slice());
}

export function fields(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Invalid browser key message');
  }
  return value as Record<string, unknown>;
}

export function sshString(value: Uint8Array | string): Uint8Array<ArrayBuffer> {
  const data =
    typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const result = new Uint8Array(data.length + 4);
  new DataView(result.buffer).setUint32(0, data.length);
  result.set(data, 4);
  return result;
}

export class Reader {
  private offset = 0;
  constructor(private readonly data: Uint8Array) {}
  byte(): number {
    if (this.offset >= this.data.length) {
      throw new Error('Truncated SSH message');
    }
    const value = this.data[this.offset];
    this.offset += 1;
    return value;
  }
  uint32(): number {
    if (this.offset + 4 > this.data.length) {
      throw new Error('Truncated SSH length');
    }
    const value = new DataView(
      this.data.buffer,
      this.data.byteOffset + this.offset,
      4,
    ).getUint32(0);
    this.offset += 4;
    return value;
  }
  string(): Uint8Array<ArrayBuffer> {
    const size = this.uint32();
    if (size > this.data.length - this.offset) {
      throw new Error('Truncated SSH string');
    }
    const value = new Uint8Array(
      this.data.subarray(this.offset, this.offset + size),
    );
    this.offset += size;
    return value;
  }
  text(): string {
    return new TextDecoder('utf-8', { fatal: true }).decode(this.string());
  }
  end(): void {
    if (this.offset !== this.data.length) {
      throw new Error('Unexpected SSH trailing data');
    }
  }
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

export function publicBlob(line: unknown): Uint8Array<ArrayBuffer> {
  if (
    typeof line !== 'string' ||
    line.length > 2048 ||
    !/^ssh-rsa [A-Za-z0-9+/]+={0,2}$/.test(line)
  ) {
    throw new Error('Expected an OpenSSH RSA public key');
  }
  const blob = Uint8Array.from(atob(line.slice(8)), (char) =>
    char.charCodeAt(0),
  );
  const reader = new Reader(blob);
  if (reader.text() !== 'ssh-rsa') throw new Error('Expected RSA key');
  const e = reader.string();
  const n = reader.string();
  reader.end();
  if (
    !equalBytes(e, new Uint8Array([1, 0, 1])) ||
    n.length !== 385 ||
    n[0] !== 0 ||
    n[1] < 128
  ) {
    throw new Error('Expected canonical RSA-3072 key with exponent 65537');
  }
  return blob;
}

/** Permit only an ordinary SSH public-key login for this user and key. */
export function checkUserAuth(
  data: Uint8Array,
  user: string,
  key: Uint8Array,
): void {
  if (data.length > 32768) throw new Error('SSH signing payload exceeds limit');
  const reader = new Reader(data);
  const exchange = reader.string();
  if (
    exchange.length < 16 ||
    exchange.length > 128 ||
    reader.byte() !== 50 ||
    reader.text() !== user ||
    reader.text() !== 'ssh-connection' ||
    reader.text() !== 'publickey' ||
    reader.byte() !== 1 ||
    reader.text() !== 'rsa-sha2-256' ||
    !equalBytes(reader.string(), key)
  ) {
    throw new Error('Refusing unrelated SSH signing request');
  }
  reader.end();
}

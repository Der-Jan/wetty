import { Reader, equalBytes, sshString } from './browserAgent.js';

export const MAX_IMPORTED_KEYS = 8;
export type SigningAlgorithm = 'rsa-sha2-256' | 'rsa-sha2-512' | 'ssh-ed25519';
export function base64url(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function integer(reader: Reader): Uint8Array {
  const value = reader.string();
  if (
    !value.length ||
    value.length > 1025 ||
    value[0] >= 128 ||
    (value[0] === 0 && (value.length === 1 || value[1] < 128))
  ) {
    throw new Error('Invalid positive SSH integer');
  }
  return value[0] === 0 ? value.slice(1) : value;
}
function mpint(value: Uint8Array): Uint8Array {
  return sshString(value[0] >= 128 ? new Uint8Array([0, ...value]) : value);
}
function number(value: Uint8Array): bigint {
  return BigInt(
    `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('')}`,
  );
}
function encoded(value: bigint): string {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return base64url(
    Uint8Array.from(hex.match(/../g) ?? [], (pair) => parseInt(pair, 16)),
  );
}
export function publicIdentity(blob: Uint8Array): {
  jwk: JsonWebKey;
  rsa: boolean;
} {
  const reader = new Reader(blob);
  const type = reader.text();
  if (type === 'ssh-ed25519') {
    const key = reader.string();
    reader.end();
    if (key.length !== 32) throw new Error('Invalid Ed25519 key');
    return {
      rsa: false,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: base64url(key) },
    };
  }
  if (type !== 'ssh-rsa') throw new Error('Unsupported key type');
  const e = integer(reader);
  const n = integer(reader);
  reader.end();
  if (
    n.length < 256 ||
    n.length > 1024 ||
    (n.length === 256 && n[0] < 128) ||
    e.length > 4 ||
    number(e) < 3n ||
    number(e) % 2n === 0n
  ) {
    throw new Error('RSA keys must be 2048–8192 bits');
  }
  return { rsa: true, jwk: { kty: 'RSA', n: base64url(n), e: base64url(e) } };
}
export function signatureAlgorithm(
  blob: Uint8Array,
  flags: number,
): SigningAlgorithm {
  const { rsa } = publicIdentity(blob);
  if (rsa && flags === 2) return 'rsa-sha2-256';
  if (rsa && flags === 4) return 'rsa-sha2-512';
  if (!rsa && flags === 0) return 'ssh-ed25519';
  throw new Error('Unsupported signature flags');
}
export function webAlgorithm(
  algorithm: SigningAlgorithm,
): AlgorithmIdentifier | RsaHashedImportParams {
  return algorithm === 'ssh-ed25519'
    ? 'Ed25519'
    : {
        name: 'RSASSA-PKCS1-v1_5',
        hash: algorithm === 'rsa-sha2-256' ? 'SHA-256' : 'SHA-512',
      };
}
/** Parse only un-constrained ADD_IDENTITY. Never silently discard constraints. */
export function importedIdentity(packet: Uint8Array): {
  blob: Uint8Array;
  comment: string;
  jwk: JsonWebKey;
} {
  if (packet.length > 16384) throw new Error('Import exceeds limit');
  const reader = new Reader(packet);
  if (reader.byte() !== 17) throw new Error('Unsupported key import operation');
  const type = reader.text();
  let blob: Uint8Array;
  let jwk: JsonWebKey;
  if (type === 'ssh-rsa') {
    const n = integer(reader);
    const e = integer(reader);
    const d = integer(reader);
    const qi = integer(reader);
    const p = integer(reader);
    const q = integer(reader);
    blob = new Uint8Array([...sshString(type), ...mpint(e), ...mpint(n)]);
    const pub = publicIdentity(blob);
    const pp = number(p);
    const qq = number(q);
    const dd = number(d);
    if (
      pp < 3n ||
      qq < 3n ||
      pp * qq !== number(n) ||
      (number(qi) * qq) % pp !== 1n
    ) {
      throw new Error('Invalid RSA parameters');
    }
    jwk = {
      ...pub.jwk,
      d: base64url(d),
      p: base64url(p),
      q: base64url(q),
      qi: base64url(qi),
      dp: encoded(dd % (pp - 1n)),
      dq: encoded(dd % (qq - 1n)),
    };
  } else if (type === 'ssh-ed25519') {
    const pub = reader.string();
    const secret = reader.string();
    if (
      pub.length !== 32 ||
      secret.length !== 64 ||
      !equalBytes(pub, secret.slice(32))
    ) {
      throw new Error('Invalid Ed25519 parameters');
    }
    blob = new Uint8Array([...sshString(type), ...sshString(pub)]);
    jwk = { ...publicIdentity(blob).jwk, d: base64url(secret.slice(0, 32)) };
    secret.fill(0);
  } else throw new Error('Unsupported key type');
  const comment = reader.text();
  reader.end();
  if (
    comment.length > 256 ||
    Array.from(comment).some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
    )
  ) {
    throw new Error('Invalid key comment');
  }
  return { blob, comment, jwk };
}
export async function keyFingerprint(blob: Uint8Array): Promise<string> {
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new Uint8Array(blob)),
  );
  return `SHA256:${btoa(String.fromCharCode(...hash)).replace(/=+$/, '')}`;
}

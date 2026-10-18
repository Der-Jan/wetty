import { generateKeyPairSync, sign } from 'node:crypto';
import { sshString } from './browserAgent';

export const bindingSession = new Uint8Array(32).fill(7);
function mpint(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  const value = bytes.slice(start);
  return sshString(value[0] >= 128 ? new Uint8Array([0, ...value]) : value);
}

/** Disposable public proof fixtures; no private key data is written to disk. */
export function bindingHost(kind = 'ed25519') {
  const curves: Record<string, [string, string, number] | undefined> = {
    nistp256: ['prime256v1', 'sha256', 32],
    nistp384: ['secp384r1', 'sha384', 48],
    nistp521: ['secp521r1', 'sha512', 66],
  };
  const curve = curves[kind];
  let pair;
  if (kind === 'rsa') {
    pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  } else if (kind === 'ed25519') pair = generateKeyPairSync('ed25519');
  else {
    if (!curve) throw new Error('Unknown test curve');
    pair = generateKeyPairSync('ec', { namedCurve: curve[0] });
  }
  const jwk = pair.publicKey.export({ format: 'jwk' });
  let host: Uint8Array;
  if (kind === 'rsa') {
    host = new Uint8Array([
      ...sshString('ssh-rsa'),
      ...mpint(Buffer.from(String(jwk.e), 'base64url')),
      ...mpint(Buffer.from(String(jwk.n), 'base64url')),
    ]);
  } else if (kind === 'ed25519') {
    host = new Uint8Array([
      ...sshString('ssh-ed25519'),
      ...sshString(Buffer.from(String(jwk.x), 'base64url')),
    ]);
  } else {
    const point = new Uint8Array([
      4,
      ...Buffer.from(String(jwk.x), 'base64url'),
      ...Buffer.from(String(jwk.y), 'base64url'),
    ]);
    host = new Uint8Array([
      ...sshString(`ecdsa-sha2-${kind}`),
      ...sshString(kind),
      ...sshString(point),
    ]);
  }
  return {
    host,
    packet(
      session: Uint8Array = bindingSession,
      forwarded = false,
      rsaHash = 'sha256',
    ): Uint8Array {
      const hash = kind === 'ed25519' ? null : rsaHash;
      let signature = sign(curve?.[1] ?? hash, session, {
        key: pair.privateKey,
        dsaEncoding: 'ieee-p1363',
      });
      let algorithm = 'ssh-ed25519';
      if (kind === 'rsa') {
        algorithm = rsaHash === 'sha256' ? 'rsa-sha2-256' : 'rsa-sha2-512';
      } else if (curve) {
        algorithm = `ecdsa-sha2-${kind}`;
        const width = curve[2];
        signature = Buffer.from([
          ...mpint(signature.subarray(0, width)),
          ...mpint(signature.subarray(width)),
        ]);
      }
      const encoded = new Uint8Array([
        ...sshString(algorithm),
        ...sshString(signature),
      ]);
      return new Uint8Array([
        27,
        ...sshString('session-bind@openssh.com'),
        ...sshString(host),
        ...sshString(session),
        ...sshString(encoded),
        forwarded ? 1 : 0,
      ]);
    },
  };
}

export function boundAuth(
  key: Uint8Array,
  host?: Uint8Array,
  session = bindingSession,
  user = 'git',
  algorithm = 'rsa-sha2-256',
): Uint8Array {
  return new Uint8Array([
    ...sshString(session),
    50,
    ...sshString(user),
    ...sshString('ssh-connection'),
    ...sshString(host ? 'publickey-hostbound-v00@openssh.com' : 'publickey'),
    1,
    ...sshString(algorithm),
    ...sshString(key),
    ...(host ? sshString(host) : []),
  ]);
}

import { fields, Reader } from './browserAgent.js';

export interface HostTarget {
  host: string;
  port: number;
}

export function hostTarget(value: unknown): HostTarget {
  const target = fields(value);
  if (
    typeof target.host !== 'string' ||
    target.host.length > 253 ||
    !/^[A-Za-z0-9:][A-Za-z0-9.:%_-]*$/.test(target.host) ||
    typeof target.port !== 'number' ||
    !Number.isInteger(target.port) ||
    target.port < 1 ||
    target.port > 65535
  ) {
    throw new Error('Invalid SSH host target');
  }
  return { host: target.host, port: target.port };
}

/** Only raw host keys, never known_hosts patterns, options or certificates. */
export function hostKey(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length > 8192 ||
    !/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,2}$/.test(
      value,
    )
  ) {
    throw new Error('Unsupported SSH host key');
  }
  const [type, encoded] = value.split(' ');
  const blob = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
  if (btoa(String.fromCharCode(...blob)) !== encoded) {
    throw new Error('Noncanonical host key');
  }
  const reader = new Reader(blob);
  if (reader.text() !== type) throw new Error('Host key type mismatch');
  if (type === 'ssh-ed25519') {
    if (reader.string().length !== 32) {
      throw new Error('Invalid Ed25519 host key');
    }
  } else if (type === 'ssh-rsa') {
    const exponent = reader.string();
    const modulus = reader.string();
    if (
      exponent.length < 1 ||
      exponent.length > 8 ||
      modulus.length < 129 ||
      modulus.length > 1025
    ) {
      throw new Error('Invalid RSA host key');
    }
  } else {
    const curve = reader.text();
    const sizes: Record<string, number> = {
      nistp256: 65,
      nistp384: 97,
      nistp521: 133,
    };
    const point = reader.string();
    if (
      type !== `ecdsa-sha2-${curve}` ||
      point.length !== sizes[curve] ||
      point[0] !== 4
    ) {
      throw new Error('Invalid ECDSA host key');
    }
  }
  reader.end();
  return value;
}

export async function hostFingerprint(key: string): Promise<string> {
  const encoded = hostKey(key).split(' ')[1];
  const digest = await crypto.subtle.digest(
    'SHA-256',
    Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0)),
  );
  return `SHA256:${btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/=+$/, '')}`;
}

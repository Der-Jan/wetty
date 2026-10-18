import { Reader, checkUserAuth, sshString } from './browserAgent.js';
import { hostKey } from './hostKey.js';

/** Validate OpenSSH's host-bound format without changing the bytes to sign.
 * The included host key is syntactically checked, not independently trusted.
 */
export function checkForwardedAuth(
  data: Uint8Array,
  key: Uint8Array,
  algorithm = 'rsa-sha2-256',
): string {
  return forwardedAuth(data, key, algorithm).user;
}

export function forwardedAuth(
  data: Uint8Array,
  key: Uint8Array,
  algorithm = 'rsa-sha2-256',
): { user: string; session: Uint8Array; host?: Uint8Array } {
  if (data.length > 32768) throw new Error('SSH signing payload exceeds limit');
  const reader = new Reader(data);
  const exchange = reader.string();
  const message = reader.byte();
  const user = reader.text();
  const service = reader.text();
  const method = reader.text();
  if (method !== 'publickey-hostbound-v00@openssh.com') {
    return {
      user: checkUserAuth(data, undefined, key, algorithm),
      session: exchange,
    };
  }
  const hasSignature = reader.byte();
  const requestedAlgorithm = reader.text();
  const requestedKey = reader.string();
  const host = reader.string();
  reader.end();
  if (host.length > 4096) throw new Error('Host key exceeds limit');
  const type = new Reader(host).text();
  hostKey(`${type} ${btoa(String.fromCharCode(...host))}`);
  // Reuse strict checks of every ordinary authentication field. The caller
  // signs data, never this normalized validation-only representation.
  const validatedUser = checkUserAuth(
    new Uint8Array([
      ...sshString(exchange),
      message,
      ...sshString(user),
      ...sshString(service),
      ...sshString('publickey'),
      hasSignature,
      ...sshString(requestedAlgorithm),
      ...sshString(requestedKey),
    ]),
    undefined,
    key,
    algorithm,
  );
  return { user: validatedUser, session: exchange, host };
}

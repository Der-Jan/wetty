import { createPublicKey, verify } from 'node:crypto';
import {
  Reader,
  bytes,
  equalBytes,
  fields,
  sshString,
} from '../../shared/browserAgent.js';
import { checkForwardedAuth } from '../../shared/forwardedAuth.js';
import {
  MAX_IMPORTED_KEYS,
  publicIdentity,
  signatureAlgorithm,
} from '../../shared/importedKeys.js';

export type KeyRequest = (
  operation: string,
  payload: Record<string, unknown>,
  connectionId?: string,
) => Promise<Record<string, unknown>>;
/** Only public metadata and transient protocol buffers live in the backend. */
export function forwardedKeys(
  primary: Uint8Array,
  signPrimary: (data: Uint8Array, connectionId?: string) => Promise<Uint8Array>,
  requestBrowser: KeyRequest,
): (packet: Uint8Array, connectionId?: string) => Promise<Uint8Array> {
  return async (packet, connectionId) => {
    const reader = new Reader(packet);
    const type = reader.byte();
    if (type === 17) {
      if (packet.length > 16384) throw new Error('Import exceeds limit');
      const result = await requestBrowser('add', { packet }, connectionId);
      if (result.ok !== true) throw new Error('Import refused');
      return new Uint8Array([6]);
    }
    if (type === 11) {
      reader.end();
      const result = await requestBrowser('list', {}, connectionId);
      if (
        !Array.isArray(result.identities) ||
        result.identities.length > MAX_IMPORTED_KEYS
      ) {
        throw new Error('Invalid identity list');
      }
      const identities = [
        { blob: primary, comment: 'WeTTY browser key' },
        ...result.identities.map((value: unknown) => {
          const entry = fields(value);
          const blob = bytes(entry.blob, 2048);
          publicIdentity(blob);
          if (typeof entry.comment !== 'string' || entry.comment.length > 256) {
            throw new Error('Invalid identity comment');
          }
          return { blob, comment: entry.comment };
        }),
      ];
      return new Uint8Array([
        12,
        0,
        0,
        0,
        identities.length,
        ...identities.flatMap(({ blob, comment }) => [
          ...sshString(blob),
          ...sshString(comment),
        ]),
      ]);
    }
    if (type !== 13) return new Uint8Array([5]);
    const blob = reader.string();
    const data = reader.string();
    const flags = reader.uint32();
    reader.end();
    const algorithm = signatureAlgorithm(blob, flags);
    checkForwardedAuth(data, blob, algorithm);
    let signature: Uint8Array;
    if (equalBytes(blob, primary)) {
      if (algorithm !== 'rsa-sha2-256') {
        throw new Error('Browser-generated key requires SHA-256');
      }
      signature = await signPrimary(data, connectionId);
    } else {
      const result = await requestBrowser(
        'sign',
        { blob, data, flags },
        connectionId,
      );
      signature = bytes(result.signature, 1024);
    }
    const { jwk } = publicIdentity(blob);
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    const hash = algorithm === 'rsa-sha2-256' ? 'RSA-SHA256' : 'RSA-SHA512';
    if (
      !verify(algorithm === 'ssh-ed25519' ? null : hash, data, key, signature)
    ) {
      throw new Error('Invalid browser signature');
    }
    return new Uint8Array([
      14,
      ...sshString(
        new Uint8Array([...sshString(algorithm), ...sshString(signature)]),
      ),
    ]);
  };
}

import { fields } from '../../../shared/browserAgent';
import {
  MAX_IMPORTED_KEYS,
  base64url,
  importedIdentity,
  publicIdentity,
  webAlgorithm,
} from '../../../shared/importedKeys';
import type { SigningAlgorithm } from '../../../shared/importedKeys';

export interface ImportedKey {
  blob: Uint8Array;
  comment: string;
  keys: Partial<Record<SigningAlgorithm, CryptoKey>>;
}
const DATABASE = 'wetty-imported-ssh-keys';
const STORE = 'keys';
async function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    let blocked = false;
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onerror = () => {
      reject(new Error('Imported key storage unavailable'));
    };
    request.onblocked = () => {
      blocked = true;
      reject(new Error('Imported key storage blocked'));
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        db.close();
      };
      if (blocked) db.close();
      else resolve(db);
    };
  });
}
function validate(value: unknown): ImportedKey {
  const record = fields(value);
  if (
    !(record.blob instanceof Uint8Array) ||
    typeof record.comment !== 'string' ||
    record.comment.length > 256
  ) {
    throw new Error('Invalid imported key record');
  }
  const { rsa } = publicIdentity(record.blob);
  const keys = fields(record.keys);
  const algorithms: SigningAlgorithm[] = rsa
    ? ['rsa-sha2-256', 'rsa-sha2-512']
    : ['ssh-ed25519'];
  for (const algorithm of algorithms) {
    const key = keys[algorithm];
    if (
      !(key instanceof CryptoKey) ||
      key.type !== 'private' ||
      key.extractable ||
      key.usages.join(',') !== 'sign'
    ) {
      throw new Error('Invalid imported private key');
    }
    const expected = webAlgorithm(algorithm);
    if (
      key.algorithm.name !==
      (typeof expected === 'string' ? expected : expected.name)
    ) {
      throw new Error('Invalid key algorithm');
    }
    if (
      rsa &&
      (key.algorithm as RsaHashedKeyAlgorithm).hash.name !==
        (algorithm === 'rsa-sha2-256' ? 'SHA-256' : 'SHA-512')
    ) {
      throw new Error('Invalid key hash');
    }
  }
  return {
    blob: record.blob,
    comment: record.comment,
    keys,
  };
}
export async function listImportedKeys(): Promise<ImportedKey[]> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE);
      const request = tx.objectStore(STORE).getAll();
      tx.onabort = () => {
        reject(new Error('Imported key read failed'));
      };
      tx.oncomplete = () => {
        try {
          const values = request.result as unknown[];
          if (values.length > MAX_IMPORTED_KEYS) {
            throw new Error('Imported key limit exceeded');
          }
          resolve(values.map(validate));
        } catch (error) {
          reject(
            error instanceof Error ? error : new Error('Invalid imported key'),
          );
        }
      };
    });
  } finally {
    db.close();
  }
}
export async function prepareImportedKey(
  packet: Uint8Array,
): Promise<ImportedKey> {
  const { blob, comment, jwk } = importedIdentity(packet);
  const algorithms: SigningAlgorithm[] =
    jwk.kty === 'RSA' ? ['rsa-sha2-256', 'rsa-sha2-512'] : ['ssh-ed25519'];
  const keys: ImportedKey['keys'] = {};
  await Promise.all(
    algorithms.map(async (algorithm) => {
      const params = webAlgorithm(algorithm);
      // Import independent non-extractable handles for each RSA hash.
      const key = await crypto.subtle.importKey('jwk', jwk, params, false, [
        'sign',
      ]);
      const pub = await crypto.subtle.importKey(
        'jwk',
        publicIdentity(blob).jwk,
        params,
        true,
        ['verify'],
      );
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const signature = await crypto.subtle.sign(params, key, challenge);
      if (!(await crypto.subtle.verify(params, pub, signature, challenge))) {
        throw new Error('Imported key failed local verification');
      }
      keys[algorithm] = key;
    }),
  );
  return { blob, comment, keys };
}
export async function saveImportedKey(
  key: ImportedKey,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();
  const db = await database();
  try {
    signal.throwIfAborted();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const aborted = (): void => {
        tx.abort();
      };
      signal.addEventListener('abort', aborted, { once: true });
      const store = tx.objectStore(STORE);
      const request = store.getAllKeys();
      request.onsuccess = () => {
        const id = base64url(key.blob);
        if (
          request.result.length >= MAX_IMPORTED_KEYS &&
          !request.result.includes(id)
        ) {
          tx.abort();
        } else store.put(key, id);
      };
      tx.oncomplete = () => {
        signal.removeEventListener('abort', aborted);
        resolve();
      };
      tx.onabort = () => {
        signal.removeEventListener('abort', aborted);
        reject(new Error('Import storage failed, cancelled, or full'));
      };
    });
  } finally {
    db.close();
  }
}
export async function signImportedKey(
  key: ImportedKey,
  algorithm: SigningAlgorithm,
  data: Uint8Array,
): Promise<Uint8Array> {
  const privateKey = key.keys[algorithm];
  if (!privateKey) throw new Error('Unsupported signature algorithm');
  return new Uint8Array(
    await crypto.subtle.sign(
      webAlgorithm(algorithm),
      privateKey,
      new Uint8Array(data),
    ),
  );
}

const DATABASE = 'wetty-ssh-keys';
const STORE = 'keys';
const ALGORITHM = 'RSASSA-PKCS1-v1_5';
const MODULUS_LENGTH = 3072;

interface StoredKey {
  version: 1;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export interface BrowserSshKey {
  readonly privateKeyExtractable: boolean;
  /** Export only the public key as an OpenSSH authorized_keys line. */
  publicKey(): Promise<string>;
  /** Sign the original bytes (not a precomputed digest), returning raw RSA bytes. */
  sign(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

function openDatabase(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(DATABASE, 1);
    let blocked = false;
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE);
    };
    request.onblocked = () => {
      blocked = true;
      reject(new Error('SSH key database is blocked; close other WeTTY tabs'));
    };
    request.onerror = () => {
      reject(
        new Error(request.error?.message ?? 'Unable to open SSH key database'),
      );
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

/** Resolve only after commit. A read/write transaction serializes racing tabs. */
function record(
  db: IDBDatabase,
  scope: string,
  candidate?: StoredKey,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(
      STORE,
      candidate === undefined ? 'readonly' : 'readwrite',
    );
    const store = transaction.objectStore(STORE);
    const request = store.get(scope);
    let result: unknown;
    let writeError: Error | undefined;
    transaction.oncomplete = () => {
      resolve(result);
    };
    transaction.onabort = () => {
      reject(
        writeError ??
          new Error(
            transaction.error?.message ?? 'SSH key storage transaction aborted',
          ),
      );
    };
    request.onsuccess = () => {
      result = request.result as unknown;
      if (result === undefined && candidate !== undefined) {
        // No crypto awaits inside this transaction: it must stay active.
        try {
          store.add(candidate, scope);
        } catch (error) {
          writeError =
            error instanceof Error
              ? error
              : new Error('Unable to persist SSH key');
          transaction.abort();
        }
      }
    };
  });
}

function validKey(
  value: unknown,
  type: 'private' | 'public',
): value is CryptoKey {
  if (!(value instanceof CryptoKey)) return false;
  const algorithm = value.algorithm as Partial<RsaHashedKeyAlgorithm>;
  return (
    value.type === type &&
    value.extractable === (type === 'public') &&
    value.usages.length === 1 &&
    value.usages[0] === (type === 'private' ? 'sign' : 'verify') &&
    algorithm.name === ALGORITHM &&
    algorithm.hash?.name === 'SHA-256' &&
    algorithm.modulusLength === MODULUS_LENGTH &&
    algorithm.publicExponent?.join(',') === '1,0,1'
  );
}

function validateRecord(value: unknown): StoredKey {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('version' in value) ||
    value.version !== 1 ||
    !('privateKey' in value) ||
    !validKey(value.privateKey, 'private') ||
    !('publicKey' in value) ||
    !validKey(value.publicKey, 'public')
  ) {
    throw new Error('Stored SSH key is invalid; refusing to replace it');
  }
  return {
    version: 1,
    privateKey: value.privateKey,
    publicKey: value.publicKey,
  };
}

function sshString(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const encoded = new Uint8Array(4 + bytes.length);
  new DataView(encoded.buffer).setUint32(0, bytes.length, false);
  encoded.set(bytes, 4);
  return encoded;
}

function publicInteger(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  let offset = 0;
  while (offset < bytes.length && bytes[offset] === 0) offset += 1;
  const unsigned = bytes.subarray(offset);
  // SSH mpints are signed: prepend zero for a positive high-bit integer.
  return sshString(
    unsigned.length > 0 && unsigned[0] >= 0x80
      ? new Uint8Array([0, ...unsigned])
      : unsigned,
  );
}

async function exportPublicKey(key: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (jwk.kty !== 'RSA' || !jwk.e || !jwk.n) {
    throw new Error('Unable to export RSA public key');
  }
  const blob = new Uint8Array([
    ...sshString(new TextEncoder().encode('ssh-rsa')),
    ...publicInteger(jwk.e),
    ...publicInteger(jwk.n),
  ]);
  return `ssh-rsa ${btoa(String.fromCharCode(...blob))}`;
}

/**
 * Load or create a persisted RSA SHA-256 key. Scope is supplied by the caller;
 * it is a storage namespace, not an authentication or authorization mechanism.
 * No key handle is returned until persistence and local verification succeed.
 */
export async function loadSshKey(
  scope: string,
  factory: IDBFactory = globalThis.indexedDB,
): Promise<BrowserSshKey> {
  if (scope.trim() === '' || scope.length > 1024) {
    throw new Error('An explicit SSH key storage scope is required');
  }
  if (
    typeof crypto === 'undefined' ||
    typeof crypto.subtle === 'undefined' ||
    typeof factory === 'undefined'
  ) {
    throw new Error(
      'SSH keys require WebCrypto and IndexedDB in a secure context',
    );
  }
  const db = await openDatabase(factory);
  let stored: StoredKey;
  try {
    const existing = await record(db, scope);
    if (existing === undefined) {
      const pair = await crypto.subtle.generateKey(
        {
          name: ALGORITHM,
          modulusLength: MODULUS_LENGTH,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        false,
        ['sign', 'verify'],
      );
      await record(db, scope, { version: 1, ...pair });
      // Read the committed structured clone, including the winner of any race.
      stored = validateRecord(await record(db, scope));
    } else {
      stored = validateRecord(existing);
    }
  } finally {
    db.close();
  }

  const key: BrowserSshKey = {
    privateKeyExtractable: stored.privateKey.extractable,
    publicKey: () => exportPublicKey(stored.publicKey),
    sign: async (data) =>
      new Uint8Array(
        await crypto.subtle.sign(
          ALGORITHM,
          stored.privateKey,
          new Uint8Array(data),
        ),
      ),
    verify: (data, signature) =>
      crypto.subtle.verify(
        ALGORITHM,
        stored.publicKey,
        new Uint8Array(signature),
        new Uint8Array(data),
      ),
  };
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  if (!(await key.verify(challenge, await key.sign(challenge)))) {
    throw new Error('Stored SSH key pair failed local verification');
  }
  return Object.freeze(key);
}

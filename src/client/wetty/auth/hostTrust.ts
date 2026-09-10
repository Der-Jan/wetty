import { hostKey, hostTarget } from '../../../shared/hostKey';
import type { HostTarget } from '../../../shared/hostKey';

const DATABASE = 'wetty-known-hosts';
const STORE = 'hosts';
export type HostApproval = (
  target: HostTarget,
  offered: string,
  previous: string | undefined,
  signal: AbortSignal,
) => boolean | Promise<boolean>;

function open(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(DATABASE, 1);
    let blocked = false;
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE);
    };
    request.onblocked = () => {
      blocked = true;
      reject(
        new Error('Host trust storage is blocked; close other WeTTY tabs'),
      );
    };
    request.onerror = () => {
      reject(new Error('Host trust storage is unavailable'));
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

function record(
  db: IDBDatabase,
  target: HostTarget,
  signal: AbortSignal,
  update?: { previous: string | undefined; key: string },
): Promise<string | undefined> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(
      STORE,
      update ? 'readwrite' : 'readonly',
    );
    const store = transaction.objectStore(STORE);
    const index = JSON.stringify([target.host.toLowerCase(), target.port]);
    const request = store.get(index);
    let result: string | undefined;
    let error: unknown;
    const abort = (): void => {
      transaction.abort();
    };
    signal.addEventListener('abort', abort, { once: true });
    transaction.oncomplete = () => {
      signal.removeEventListener('abort', abort);
      resolve(result);
    };
    transaction.onabort = () => {
      signal.removeEventListener('abort', abort);
      reject(
        error instanceof Error
          ? error
          : new Error('Host trust storage transaction failed'),
      );
    };
    request.onsuccess = () => {
      try {
        result =
          request.result === undefined ? undefined : hostKey(request.result);
        if (update) {
          if (result !== update.previous && result !== update.key) {
            throw new Error(
              'Host trust changed in another tab; reconnect to review it',
            );
          }
          store.put(update.key, index);
          result = update.key;
        }
      } catch (cause) {
        error = cause;
        transaction.abort();
      }
    };
  });
}

/** Read before prompting, then compare-and-swap after approval to avoid tab races. */
export async function browserHostTrust(
  targetValue: unknown,
  offeredValue: unknown,
  approve: HostApproval,
  signal: AbortSignal,
  factory: IDBFactory = globalThis.indexedDB,
): Promise<string | null> {
  const target = hostTarget(targetValue);
  const offered =
    offeredValue === undefined ? undefined : hostKey(offeredValue);
  signal.throwIfAborted();
  if (typeof factory === 'undefined') {
    throw new Error('Host trust requires IndexedDB');
  }
  const db = await open(factory);
  try {
    const previous = await record(db, target, signal);
    if (offered === undefined) return previous ?? null;
    if (previous === offered) return offered;
    if (!(await approve(target, offered, previous, signal))) {
      throw new Error('SSH host key was not trusted');
    }
    signal.throwIfAborted();
    await record(db, target, signal, { previous, key: offered });
    return offered;
  } finally {
    db.close();
  }
}

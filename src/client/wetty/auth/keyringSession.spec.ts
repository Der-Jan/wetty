import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { IDBFactory } from 'fake-indexeddb';
import 'mocha';
import { fields, sshString } from '../../../shared/browserAgent';
import { listImportedKeys } from './importedKeys';
import { setupKeyringSession } from './keyringSession';
import type { ImportApproval, KeyringContext } from './keyringSession';
import type { Socket } from 'socket.io-client';

function packet(): Uint8Array {
  const jwk = generateKeyPairSync('ed25519').privateKey.export({
    format: 'jwk',
  });
  const pub = Buffer.from(String(jwk.x), 'base64url');
  const seed = Buffer.from(String(jwk.d), 'base64url');
  return new Uint8Array([
    17,
    ...sshString('ssh-ed25519'),
    ...sshString(pub),
    ...sshString(new Uint8Array([...seed, ...pub])),
    ...sshString('cancellation test'),
  ]);
}
describe('Imported-key session authorization', () => {
  let original: IDBFactory;
  let client: EventEmitter & { connected: boolean; id: string };
  let active: KeyringContext | undefined;
  let approval: ImportApproval;
  beforeEach(() => {
    original = globalThis.indexedDB;
    globalThis.indexedDB = new IDBFactory();
    client = Object.assign(new EventEmitter(), {
      connected: true,
      id: 'connection',
    });
    active = {
      sessionId: 'session',
      forwarding: true,
      controller: new AbortController(),
      prompting: false,
      blob: new Uint8Array(),
      managedRequests: new Set(),
    };
    approval = () => true;
    setupKeyringSession(
      client as unknown as Socket,
      () => active,
      () => true,
      (...args) => approval(...args),
    );
  });
  afterEach(() => {
    active?.controller.abort();
    globalThis.indexedDB = original;
  });
  async function request(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return new Promise((resolve) => {
      client.once('browser-key:result', (result) => {
        resolve(fields(result));
      });
      client.emit('browser-key:manage', {
        v: 1,
        sessionId: 'session',
        requestId: 'request',
        ...payload,
      });
    });
  }
  it('should reject unprepared forwarding and mismatched session IDs', async () => {
    assert(active);
    active.forwarding = false;
    assert.equal(
      (await request({ operation: 'add', packet: packet() })).error,
      'KEY_OPERATION_FAILED',
    );
    active.forwarding = true;
    assert.equal(
      (
        await request({
          operation: 'add',
          packet: packet(),
          sessionId: 'other',
        })
      ).error,
      'KEY_OPERATION_FAILED',
    );
    assert.equal((await listImportedKeys()).length, 0);
  });
  it('should reject replay after an approved import', async () => {
    const payload = { operation: 'add', packet: packet() };
    assert.equal((await request(payload)).ok, true);
    assert.equal((await request(payload)).error, 'KEY_OPERATION_FAILED');
    assert.equal((await listImportedKeys()).length, 1);
  });
  it('should not persist after disconnect during approval, even if accepted later', async () => {
    let finish: (value: boolean) => void = () => {
      throw new Error('Not prompting');
    };
    let notify: () => void = () => {
      throw new Error('Not waiting');
    };
    const prompted = new Promise<void>((resolve) => {
      notify = resolve;
    });
    approval = () =>
      new Promise<boolean>((resolve) => {
        finish = resolve;
        notify();
      });
    const replies: unknown[] = [];
    client.on('browser-key:result', (value) => {
      replies.push(value);
    });
    client.emit('browser-key:manage', {
      v: 1,
      sessionId: 'session',
      requestId: 'request',
      operation: 'add',
      packet: packet(),
    });
    await prompted;
    active?.controller.abort();
    client.connected = false;
    active = undefined;
    finish(true);
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
    assert.equal((await listImportedKeys()).length, 0);
    assert.deepEqual(replies, []);
  });
  it('should fail an approved import if IndexedDB is unavailable', async () => {
    approval = () => {
      globalThis.indexedDB = {
        open: () => {
          throw new Error('No storage');
        },
      } as unknown as IDBFactory;
      return true;
    };
    assert.equal(
      (await request({ operation: 'add', packet: packet() })).error,
      'KEY_OPERATION_FAILED',
    );
  });
});

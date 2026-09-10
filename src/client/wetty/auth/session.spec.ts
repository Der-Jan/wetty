import { EventEmitter } from 'node:events';
import { expect } from 'chai';
import { IDBFactory } from 'fake-indexeddb';
import 'mocha';
import { fields, publicBlob, sshString } from '../../../shared/browserAgent';
import { setupBrowserSigner } from './session';
import type { Socket } from 'socket.io-client';

function data(blob: Uint8Array, user = 'fixed'): Uint8Array {
  return new Uint8Array([
    ...sshString(new Uint8Array(32)),
    50,
    ...sshString(user),
    ...sshString('ssh-connection'),
    ...sshString('publickey'),
    1,
    ...sshString('rsa-sha2-256'),
    ...sshString(blob),
  ]);
}

describe('Browser signing session', function signerSuite() {
  this.timeout(10000);
  let socket: EventEmitter & { connected: boolean };
  let original: IDBFactory;
  beforeEach(() => {
    original = globalThis.indexedDB;
    globalThis.indexedDB = new IDBFactory();
    socket = Object.assign(new EventEmitter(), { connected: true });
    setupBrowserSigner(socket as unknown as Socket);
  });
  afterEach(() => {
    socket.emit('disconnect');
    globalThis.indexedDB = original;
  });
  async function message(
    event: string,
    payload: unknown,
  ): Promise<Record<string, unknown>> {
    return fields(
      await new Promise<unknown>((resolve) => {
        socket.once('browser-key:result', resolve);
        socket.emit(event, payload);
      }),
    );
  }
  async function prepare(): Promise<Uint8Array> {
    return publicBlob(
      (
        await message('browser-key:prepare', {
          v: 1,
          sessionId: 'current',
          target: { user: 'fixed', host: 'server', port: 22 },
        })
      ).publicKey,
    );
  }
  it('should reject signing before preparation', async () => {
    expect(await message('browser-key:sign', {})).to.have.property('error');
  });
  it('should bind signatures to the prepared session and reject replay', async () => {
    const blob = await prepare();
    const request = {
      v: 1,
      sessionId: 'current',
      requestId: 'first',
      algorithm: 'rsa-sha2-256',
      data: data(blob),
    };
    expect(
      await message('browser-key:sign', { ...request, sessionId: 'other' }),
    ).to.have.property('error');
    expect(await message('browser-key:sign', request))
      .to.have.property('signature')
      .with.length(384);
    expect(await message('browser-key:sign', request)).to.have.property(
      'error',
    );
  });
  it('should refuse different usernames, algorithms and arbitrary data', async () => {
    const blob = await prepare();
    const base = {
      v: 1,
      sessionId: 'current',
      requestId: 'first',
      algorithm: 'rsa-sha2-256',
      data: data(blob, 'other'),
    };
    expect(await message('browser-key:sign', base)).to.have.property('error');
    expect(
      await message('browser-key:sign', {
        ...base,
        requestId: 'second',
        data: new Uint8Array([1]),
      }),
    ).to.have.property('error');
    expect(
      await message('browser-key:sign', {
        ...base,
        requestId: 'third',
        algorithm: 'rsa-sha2-512',
      }),
    ).to.have.property('error');
  });
  it('should discard the previous context after disconnect', async () => {
    const blob = await prepare();
    socket.emit('disconnect');
    expect(
      await message('browser-key:sign', {
        v: 1,
        sessionId: 'current',
        requestId: 'first',
        algorithm: 'rsa-sha2-256',
        data: data(blob),
      }),
    ).to.have.property('error');
  });
});

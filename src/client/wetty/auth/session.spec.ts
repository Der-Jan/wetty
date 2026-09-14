import { EventEmitter } from 'node:events';
import { expect } from 'chai';
import { IDBFactory } from 'fake-indexeddb';
import 'mocha';
import { fields, publicBlob, sshString } from '../../../shared/browserAgent';
import { setupBrowserSigner } from './session';
import type { ForwardApproval } from './forwardPrompt';
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
  let approvals: string[];
  let approve: ForwardApproval;
  beforeEach(() => {
    original = globalThis.indexedDB;
    globalThis.indexedDB = new IDBFactory();
    socket = Object.assign(new EventEmitter(), { connected: true });
    approvals = [];
    approve = (user) => {
      approvals.push(user);
      return true;
    };
    setupBrowserSigner(socket as unknown as Socket, (...args) =>
      approve(...args),
    );
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
  async function prepare(forwarding = false): Promise<Uint8Array> {
    return publicBlob(
      (
        await message('browser-key:prepare', {
          v: 1,
          sessionId: 'current',
          forwarding,
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
  it('should require forwarding opt-in before prompting', async () => {
    const blob = await prepare();
    expect(
      await message('browser-key:sign', {
        v: 1,
        sessionId: 'current',
        requestId: 'forward',
        forwarded: true,
        algorithm: 'rsa-sha2-256',
        data: data(blob, 'git'),
      }),
    ).to.have.property('error');
    expect(approvals).to.deep.equal([]);
  });
  it('should approve other usernames only through the forwarded path and reject replay', async () => {
    const blob = await prepare(true);
    const request = {
      v: 1,
      sessionId: 'current',
      requestId: 'forward',
      forwarded: true,
      algorithm: 'rsa-sha2-256',
      data: data(blob, 'git'),
    };
    expect(await message('browser-key:sign', request)).to.have.property(
      'signature',
    );
    expect(approvals).to.deep.equal(['git']);
    expect(await message('browser-key:sign', request)).to.have.property(
      'error',
    );
    expect(
      await message('browser-key:sign', {
        ...request,
        requestId: 'primary',
        forwarded: false,
      }),
    ).to.have.property('error');
    expect(approvals).to.deep.equal(['git']);
  });
  it('should not sign if consent is denied', async () => {
    approve = () => false;
    const blob = await prepare(true);
    expect(
      await message('browser-key:sign', {
        v: 1,
        sessionId: 'current',
        requestId: 'denied',
        forwarded: true,
        algorithm: 'rsa-sha2-256',
        data: data(blob),
      }),
    ).to.have.property('error');
  });
  it('should abort approval on disconnect and discard a late acceptance', async () => {
    const blob = await prepare(true);
    let accept: (value: boolean) => void = () => {
      throw new Error('No pending approval');
    };
    let pendingSignal: AbortSignal | undefined;
    approve = (_user, signal) => {
      pendingSignal = signal;
      return new Promise<boolean>((resolve) => {
        accept = resolve;
      });
    };
    const replies: unknown[] = [];
    socket.on('browser-key:result', (reply: unknown) => replies.push(reply));
    socket.emit('browser-key:sign', {
      v: 1,
      sessionId: 'current',
      requestId: 'pending',
      forwarded: true,
      algorithm: 'rsa-sha2-256',
      data: data(blob),
    });
    socket.emit('disconnect');
    expect(pendingSignal?.aborted).to.equal(true);
    accept(true);
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
    expect(replies).to.deep.equal([]);
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

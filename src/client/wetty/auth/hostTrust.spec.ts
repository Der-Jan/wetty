import { expect } from 'chai';
import { IDBFactory } from 'fake-indexeddb';
import 'mocha';
import { sshString } from '../../../shared/browserAgent';
import { hostFingerprint, hostKey } from '../../../shared/hostKey';
import { browserHostTrust } from './hostTrust';
import type { HostApproval } from './hostTrust';

const key = (byte: number): string =>
  `ssh-ed25519 ${btoa(String.fromCharCode(...new Uint8Array([...sshString('ssh-ed25519'), ...sshString(new Uint8Array(32).fill(byte))])))}`;
const target = { host: 'server.example', port: 22 };
const accept: HostApproval = () => true;

describe('Browser host trust', () => {
  let factory: IDBFactory;
  let controller: AbortController;
  beforeEach(() => {
    factory = new IDBFactory();
    controller = new AbortController();
  });
  const lookup = (
    offered: string | undefined,
    approve = accept,
  ): Promise<string | null> =>
    browserHostTrust(target, offered, approve, controller.signal, factory);

  it('should persist an approved public host key and silently match it on reconnect', async () => {
    expect(await lookup(undefined)).to.equal(null);
    let prompts = 0;
    const approve: HostApproval = (_target, offered, previous) => {
      prompts += 1;
      expect(offered).to.equal(key(1));
      expect(previous).to.equal(undefined);
      return true;
    };
    expect(await lookup(key(1), approve)).to.equal(key(1));
    expect(await lookup(undefined)).to.equal(key(1));
    expect(await lookup(key(1), approve)).to.equal(key(1));
    expect(prompts).to.equal(1);
  });
  it('should refuse cancellation without saving the offered key', async () => {
    const result = await Promise.allSettled([lookup(key(1), () => false)]);
    expect(result[0].status).to.equal('rejected');
    expect(await lookup(undefined)).to.equal(null);
  });
  it('should keep a changed key blocked unless replacement is explicitly approved', async () => {
    await lookup(key(1));
    const result = await Promise.allSettled([
      lookup(key(2), (_target, _key, previous) => {
        expect(previous).to.equal(key(1));
        return false;
      }),
    ]);
    expect(result[0].status).to.equal('rejected');
    expect(await lookup(undefined)).to.equal(key(1));
    await lookup(key(2));
    expect(await lookup(undefined)).to.equal(key(2));
  });
  it('should isolate hostnames, ports and browser profiles', async () => {
    await lookup(key(1));
    const values = await Promise.all([
      browserHostTrust(
        { ...target, port: 2222 },
        undefined,
        accept,
        controller.signal,
        factory,
      ),
      browserHostTrust(
        { ...target, host: 'other.example' },
        undefined,
        accept,
        controller.signal,
        factory,
      ),
      browserHostTrust(
        target,
        undefined,
        accept,
        controller.signal,
        new IDBFactory(),
      ),
    ]);
    expect(values).to.deep.equal([null, null, null]);
  });
  it('should abort a pending approval without saving trust', async () => {
    const result = await Promise.allSettled([
      lookup(key(1), () => {
        controller.abort();
        return true;
      }),
    ]);
    expect(result[0].status).to.equal('rejected');
    controller = new AbortController();
    expect(await lookup(undefined)).to.equal(null);
  });
  it('should not overwrite a conflicting approval made in another tab', async () => {
    const result = await Promise.allSettled([
      lookup(key(1), async () => {
        await lookup(key(2));
        return true;
      }),
    ]);
    expect(result[0].status).to.equal('rejected');
    expect(await lookup(undefined)).to.equal(key(2));
  });
  it('should refuse malformed host keys before prompting', async () => {
    let prompts = 0;
    const results = await Promise.allSettled(
      [
        `@cert-authority * ${key(1)}`,
        `${key(1)}\nother`,
        `ssh-rsa ${key(1).split(' ')[1]}`,
      ].map((offered) =>
        lookup(offered, () => {
          prompts += 1;
          return true;
        }),
      ),
    );
    expect(results.map((result) => result.status)).to.deep.equal([
      'rejected',
      'rejected',
      'rejected',
    ]);
    expect(prompts).to.equal(0);
  });
  it('should fail closed when IndexedDB is unavailable', async () => {
    const results = await Promise.allSettled([
      browserHostTrust(target, key(1), accept, controller.signal, {
        open: () => {
          throw new Error('Unavailable');
        },
      } as unknown as IDBFactory),
    ]);
    expect(results[0].status).to.equal('rejected');
  });
  it('should calculate the standard SHA-256 host fingerprint', async () => {
    expect(hostKey(key(1))).to.equal(key(1));
    expect(await hostFingerprint(key(1))).to.match(
      /^SHA256:[A-Za-z0-9+/]{43}$/,
    );
  });
});

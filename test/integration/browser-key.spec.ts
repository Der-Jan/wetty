import assert from 'node:assert/strict';
import { execFileSync, spawn as childSpawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { IDBFactory } from 'fake-indexeddb';
import { Server } from 'socket.io';
import { io as connect } from 'socket.io-client';
import { setupBrowserHostTrust } from '../../src/client/wetty/auth/hostSession';
import { browserHostTrust } from '../../src/client/wetty/auth/hostTrust';
import { loadSshKey } from '../../src/client/wetty/auth/keys';
import { setupBrowserSigner } from '../../src/client/wetty/auth/session';
import { validateBrowserSsh } from '../../src/server/browserAgent/command';
import { browserKeySession } from '../../src/server/browserAgent/session';
import { BROWSER_KEY_SCOPE } from '../../src/shared/browserAgent';
import { sshDefault } from '../../src/shared/defaults';
import type { HostApproval } from '../../src/client/wetty/auth/hostTrust';
import type { SSH } from '../../src/shared/interfaces';
import type { ChildProcess } from 'node:child_process';
import type { AddressInfo } from 'node:net';

/** Opt-in: uses an isolated sshd on loopback and the current Unix account. */
describe('browser-key real OpenSSH login', function integrationSuite() {
  this.timeout(30000);
  let directory: string;
  let daemon: ChildProcess | undefined;
  let ssh: SSH;
  let logs = '';
  let publicKey: string;
  let originalFactory: IDBFactory;
  before(async () => {
    originalFactory = globalThis.indexedDB;
    globalThis.indexedDB = new IDBFactory();
    directory = await mkdtemp(join(tmpdir(), 'wetty-login-test-'));
    const key = await loadSshKey(BROWSER_KEY_SCOPE);
    publicKey = await key.publicKey();
    await writeFile(join(directory, 'authorized_keys'), `${publicKey}\n`, {
      mode: 0o600,
    });
    execFileSync('/usr/bin/ssh-keygen', [
      '-q',
      '-t',
      'ed25519',
      '-N',
      '',
      '-f',
      join(directory, 'host'),
    ]);
    const reserve = tcpServer();
    reserve.listen(0, '127.0.0.1');
    await once(reserve, 'listening');
    const { port } = reserve.address() as AddressInfo;
    await new Promise<void>((resolve) => {
      reserve.close(() => {
        resolve();
      });
    });
    const hostKey = (
      await readFile(join(directory, 'host.pub'), 'utf8')
    ).trim();
    await writeFile(
      join(directory, 'known_hosts'),
      `[127.0.0.1]:${String(port)} ${hostKey}\n`,
    );
    await writeFile(
      join(directory, 'sshd_config'),
      [
        `Port ${String(port)}`,
        'ListenAddress 127.0.0.1',
        `HostKey ${join(directory, 'host')}`,
        `PidFile ${join(directory, 'sshd.pid')}`,
        `AuthorizedKeysFile ${join(directory, 'authorized_keys')}`,
        'StrictModes no',
        'UsePAM no',
        'PasswordAuthentication yes',
        'KbdInteractiveAuthentication no',
        'PubkeyAuthentication yes',
        'AuthenticationMethods any',
        'LogLevel VERBOSE',
        `AllowUsers ${userInfo().username}`,
        'PermitRootLogin prohibit-password',
      ].join('\n'),
    );
    daemon = childSpawn('/usr/sbin/sshd', [
      '-D',
      '-e',
      '-f',
      join(directory, 'sshd_config'),
    ]);
    await new Promise<void>((resolve, reject) => {
      daemon.stderr?.on('data', (data: Buffer) => {
        logs += data.toString();
        if (logs.includes('Server listening')) resolve();
      });
      daemon.once('error', reject);
      daemon.once('exit', () => {
        reject(new Error(logs));
      });
    });
    ssh = {
      ...sshDefault,
      user: userInfo().username,
      host: '127.0.0.1',
      port,
      auth: 'browser-key',
      pass: undefined,
      key: undefined,
      config: undefined,
      knownHosts: join(directory, 'known_hosts'),
      browserOrigin: 'http://localhost:3000',
    };
    await validateBrowserSsh(ssh);
  });
  after(async () => {
    if (daemon?.exitCode === null) {
      daemon.kill();
      await once(daemon, 'exit');
    }
    if (directory) await rm(directory, { recursive: true, force: true });
    globalThis.indexedDB = originalFactory;
  });

  async function login(
    command: string,
    settings = ssh,
    dropOnSign = false,
    stopAtPassword = false,
    approve: HostApproval = () => true,
    dropOnHost = false,
  ): Promise<{ output: string; signs: number }> {
    const http = createServer();
    const server = new Server(http);
    let closeSession: (() => Promise<void>) | undefined;
    let closeCount = 0;
    server.on('connection', (socket) => {
      closeSession = browserKeySession(socket, settings, command, () => {
        closeCount += 1;
      });
    });
    http.listen(0, '127.0.0.1');
    await once(http, 'listening');
    const client = connect(
      `http://127.0.0.1:${String((http.address() as AddressInfo).port)}`,
      { autoConnect: false },
    );
    let output = '';
    let signs = 0;
    client.on('data', (data: string) => {
      output += data;
      if (stopAtPassword && /password:/i.test(output)) client.disconnect();
    });
    client.on('browser-key:sign', () => {
      signs += 1;
      if (dropOnSign) client.disconnect();
    });
    setupBrowserSigner(client);
    setupBrowserHostTrust(client, (...args) => {
      const result = approve(...args);
      if (dropOnHost) client.disconnect();
      return result;
    });
    client.on('connect', () => client.emit('browser-key:hello'));
    try {
      const done = new Promise<void>((resolve, reject) => {
        client.once('disconnect', () => {
          resolve();
        });
        client.once('connect_error', reject);
        client.once('error', (message: string) => {
          reject(new Error(message));
        });
      });
      client.connect();
      await done;
      await closeSession?.();
      assert.equal(closeCount, 1);
      return { output, signs };
    } finally {
      client.disconnect();
      await closeSession?.();
      await server.close();
    }
  }

  it('logs in through node-pty, system SSH, the Unix agent and browser signing handlers', async () => {
    const result = await login('printf BROWSER_KEY_OK');
    assert.match(result.output, /BROWSER_KEY_OK/);
    assert.ok(result.signs >= 1, logs);
  });

  it('offers a password prompt when the browser key is not enrolled', async () => {
    await writeFile(join(directory, 'authorized_keys'), '');
    try {
      const result = await login('printf MUST_NOT_RUN', ssh, false, true);
      assert.doesNotMatch(result.output, /MUST_NOT_RUN/);
      assert.match(result.output, /password:/i);
    } finally {
      await writeFile(join(directory, 'authorized_keys'), `${publicKey}\n`);
    }
  });

  it('offers a password prompt when browser key storage is unavailable', async () => {
    const factory = globalThis.indexedDB;
    globalThis.indexedDB = {
      open() {
        throw new Error('Storage unavailable');
      },
    } as unknown as IDBFactory;
    try {
      const result = await login('printf MUST_NOT_RUN', ssh, false, true);
      assert.equal(result.signs, 0);
      assert.match(result.output, /Browser key unavailable/);
      assert.match(result.output, /password:/i);
    } finally {
      globalThis.indexedDB = factory;
    }
  });

  it('rejects an unknown host before asking the browser to sign', async () => {
    await writeFile(join(directory, 'empty_hosts'), '');
    const result = await login('printf MUST_NOT_RUN', {
      ...ssh,
      knownHosts: join(directory, 'empty_hosts'),
    });
    assert.equal(result.signs, 0);
    assert.match(result.output, /Host key verification failed/);
    assert.doesNotMatch(result.output, /password:/i);
  });

  it('closes a session disconnected while signing', async () => {
    const result = await login('printf MUST_NOT_RUN', ssh, true);
    assert.equal(result.signs, 1);
    assert.doesNotMatch(result.output, /MUST_NOT_RUN/);
  });
  describe('browser-managed known hosts', () => {
    beforeEach(async () => {
      await new Promise<void>((resolve, reject) => {
        const request =
          globalThis.indexedDB.deleteDatabase('wetty-known-hosts');
        request.onsuccess = () => {
          resolve();
        };
        request.onerror = () => {
          reject(
            new Error(
              request.error?.message ?? 'Unable to clear test host trust',
            ),
          );
        };
      });
    });
    it('approves the actual host key and reconnects without prompting', async () => {
      const settings = { ...ssh, knownHosts: 'browser' };
      let prompts = 0;
      const approve: HostApproval = async (target, offered, previous) => {
        prompts += 1;
        assert.equal(target.port, ssh.port);
        assert.equal(previous, undefined);
        assert.equal(
          offered,
          (await readFile(join(directory, 'host.pub'), 'utf8'))
            .trim()
            .split(' ')
            .slice(0, 2)
            .join(' '),
        );
        return true;
      };
      const first = await login(
        'printf TRUSTED_HOST_OK',
        settings,
        false,
        false,
        approve,
      );
      assert.match(first.output, /TRUSTED_HOST_OK/);
      assert.ok(first.signs > 0);
      const second = await login(
        'printf TRUSTED_AGAIN_OK',
        settings,
        false,
        false,
        approve,
      );
      assert.match(second.output, /TRUSTED_AGAIN_OK/);
      assert.equal(prompts, 1);
    });
    it('rejects a first-use denial before signing or password authentication', async () => {
      const result = await login(
        'printf MUST_NOT_RUN',
        { ...ssh, knownHosts: 'browser' },
        false,
        false,
        () => false,
      );
      assert.equal(result.signs, 0);
      assert.doesNotMatch(result.output, /MUST_NOT_RUN|password:/i);
      assert.match(result.output, /Host verification cancelled/);
    });
    it('blocks a changed key and requires explicit replacement', async () => {
      const previous = publicKey;
      await browserHostTrust(
        ssh,
        previous,
        () => true,
        new AbortController().signal,
      );
      const settings = { ...ssh, knownHosts: 'browser' };
      const denied = await login(
        'printf MUST_NOT_RUN',
        settings,
        false,
        false,
        (_target, _key, saved) => {
          assert.equal(saved, previous);
          return false;
        },
      );
      assert.equal(denied.signs, 0);
      assert.doesNotMatch(denied.output, /MUST_NOT_RUN|password:/i);
      const accepted = await login(
        'printf REPLACED_OK',
        settings,
        false,
        false,
        (_target, _key, saved) => {
          assert.equal(saved, previous);
          return true;
        },
      );
      assert.match(accepted.output, /REPLACED_OK/);
    });
    it('retains password fallback after browser host approval', async () => {
      await writeFile(join(directory, 'authorized_keys'), '');
      try {
        const result = await login(
          'printf MUST_NOT_RUN',
          { ...ssh, knownHosts: 'browser' },
          false,
          true,
        );
        assert.match(result.output, /password:/i);
        assert.doesNotMatch(result.output, /MUST_NOT_RUN/);
      } finally {
        await writeFile(join(directory, 'authorized_keys'), `${publicKey}\n`);
      }
    });
    it('waits for a human approval beyond the SSH connection timeout', async () => {
      const result = await login(
        'printf DELAYED_OK',
        { ...ssh, knownHosts: 'browser' },
        false,
        false,
        async () => {
          await new Promise<void>((resolve) => {
            setTimeout(resolve, 16000);
          });
          return true;
        },
      );
      assert.match(result.output, /DELAYED_OK/);
    });
    it('aborts pending host approval on disconnect before authentication', async () => {
      let aborted = false;
      const result = await login(
        'printf MUST_NOT_RUN',
        { ...ssh, knownHosts: 'browser' },
        false,
        false,
        (_target, _key, _previous, signal) =>
          new Promise<boolean>((resolve) => {
            signal.addEventListener(
              'abort',
              () => {
                aborted = true;
                resolve(false);
              },
              { once: true },
            );
          }),
        true,
      );
      assert.equal(aborted, true);
      assert.equal(result.signs, 0);
      assert.doesNotMatch(result.output, /password:|MUST_NOT_RUN/i);
      assert.equal(
        await browserHostTrust(
          ssh,
          undefined,
          () => false,
          new AbortController().signal,
        ),
        null,
      );
    });
    it('fails closed with unavailable browser host storage, even when password fallback is enabled', async () => {
      const factory = globalThis.indexedDB;
      globalThis.indexedDB = {
        open() {
          throw new Error('Unavailable');
        },
      } as unknown as IDBFactory;
      try {
        const result = await login('printf MUST_NOT_RUN', {
          ...ssh,
          knownHosts: 'browser',
        });
        assert.equal(result.signs, 0);
        assert.doesNotMatch(result.output, /password:|MUST_NOT_RUN/i);
        assert.match(result.output, /Host verification cancelled/);
      } finally {
        globalThis.indexedDB = factory;
      }
    });
  });
});

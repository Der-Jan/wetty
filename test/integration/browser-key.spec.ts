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
import { browserSshIntegration } from '../../src/server/browserAgent/integration';
import { BROWSER_KEY_SCOPE, fields } from '../../src/shared/browserAgent';
import { sshDefault } from '../../src/shared/defaults';
import type { ForwardApproval } from '../../src/client/wetty/auth/forwardPrompt';
import type { HostApproval } from '../../src/client/wetty/auth/hostTrust';
import type { ImportApproval } from '../../src/client/wetty/auth/keyringSession';
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
    approveSign: ForwardApproval = () => false,
    legacyBrowser = false,
    approveImport?: ImportApproval,
    pollingOnly = false,
  ): Promise<{ output: string; signs: number }> {
    const http = createServer();
    const server = new Server(http);
    let closeCount = 0;
    const browserSsh = await browserSshIntegration(settings);
    const sessions = browserSsh.attach(server, command, () => {
      closeCount += 1;
    });
    const closeSession = (): Promise<void> => sessions.close();
    server.on('connection', (socket) => {
      assert.equal(sessions.handle(socket), true);
    });
    http.listen(0, '127.0.0.1');
    await once(http, 'listening');
    const client = connect(
      `http://127.0.0.1:${String((http.address() as AddressInfo).port)}`,
      {
        autoConnect: false,
        transports: approveImport
          ? [pollingOnly ? 'polling' : 'websocket']
          : undefined,
      },
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
    setupBrowserSigner(client, approveSign, approveImport);
    if (legacyBrowser) {
      client.onAnyOutgoing((event: string, payload: unknown) => {
        if (event === 'browser-key:result') {
          delete fields(payload).forwarding;
          delete fields(payload).loginKeys;
        }
      });
    }
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
      await closeSession();
      assert.equal(closeCount, 1);
      return { output, signs };
    } finally {
      client.disconnect();
      await closeSession();
      await server.close();
    }
  }

  it('logs in through node-pty, system SSH, the Unix agent and browser signing handlers', async () => {
    const result = await login('printf BROWSER_KEY_OK');
    assert.match(result.output, /BROWSER_KEY_OK/);
    assert.ok(result.signs >= 1, logs);
  });

  it('does not forward an agent by default', async () => {
    const result = await login(
      'test -z "$SSH_AUTH_SOCK" && printf NO_FORWARDED_AGENT',
    );
    assert.match(result.output, /NO_FORWARDED_AGENT/);
  });

  it('does not forward to an older browser without explicit approval capability', async () => {
    const result = await login(
      'test -z "$SSH_AUTH_SOCK" && printf NO_FORWARDED_AGENT',
      { ...ssh, browserAgentForwarding: true },
      false,
      false,
      () => true,
      false,
      () => {
        throw new Error('Must not request approval');
      },
      true,
    );
    assert.match(result.output, /NO_FORWARDED_AGENT/);
  });

  it('lists the browser identity through the forwarded agent', async () => {
    const result = await login('ssh-add -L', {
      ...ssh,
      browserAgentForwarding: true,
    });
    assert.ok(result.output.includes(publicKey));
  });

  function onwardCommand(): string {
    return `/usr/bin/ssh -F /dev/null -o BatchMode=yes -o PubkeyAuthentication=unbound -o PubkeyAcceptedAlgorithms=rsa-sha2-256 -o IdentityFile=none -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${join(directory, 'known_hosts')} -o GlobalKnownHostsFile=/dev/null -p ${String(ssh.port)} -l ${ssh.user} 127.0.0.1 printf FORWARDED_LOGIN_OK`;
  }

  it('requires approval even for an onward login using the initial username', async () => {
    let approvals = 0;
    const result = await login(
      onwardCommand(),
      { ...ssh, browserAgentForwarding: true },
      false,
      false,
      () => true,
      false,
      (user) => {
        assert.equal(user, ssh.user);
        approvals += 1;
        return true;
      },
    );
    assert.match(result.output, /FORWARDED_LOGIN_OK/);
    assert.equal(approvals, 1);
    assert.equal(result.signs, 2);
  });

  it('denies onward login when browser approval is refused', async () => {
    let approvals = 0;
    const result = await login(
      onwardCommand(),
      { ...ssh, browserAgentForwarding: true },
      false,
      false,
      () => true,
      false,
      () => {
        approvals += 1;
        return false;
      },
    );
    assert.doesNotMatch(result.output, /FORWARDED_LOGIN_OK/);
    assert.equal(approvals, 1);
    assert.match(result.output, /Permission denied|signing failed/);
  });

  it('reuses a host-bound grant across fresh real SSH connections until the browser disconnects', async () => {
    const onward = onwardCommand().replace(
      'PubkeyAuthentication=unbound',
      'PubkeyAuthentication=host-bound',
    );
    let approvals = 0;
    const approve: ForwardApproval = (
      _user,
      _signal,
      _initial,
      destination,
    ) => {
      assert.equal(destination?.canRemember, true);
      assert.equal(destination.forwardingHostFingerprints.length, 1);
      approvals += 1;
      return 'session';
    };
    const first = await login(
      `${onward} && ${onward}`,
      { ...ssh, browserAgentForwarding: true },
      false,
      false,
      () => true,
      false,
      approve,
    );
    assert.equal(
      first.output.split('FORWARDED_LOGIN_OK').length - 1,
      2,
      first.output,
    );
    assert.equal(approvals, 1);
    const second = await login(
      onward,
      { ...ssh, browserAgentForwarding: true },
      false,
      false,
      () => true,
      false,
      approve,
    );
    assert.match(second.output, /FORWARDED_LOGIN_OK/);
    assert.equal(approvals, 2);
  });

  it('verifies multiple forwarding hops and scopes the grant to the full path', async () => {
    const onward = onwardCommand().replace(
      'PubkeyAuthentication=unbound',
      'PubkeyAuthentication=host-bound',
    );
    const nested = onward
      .replace('/usr/bin/ssh ', '/usr/bin/ssh -A ')
      .replace(
        'printf FORWARDED_LOGIN_OK',
        `'${onward.replaceAll("'", "'\\''")}'`,
      );
    const paths: number[] = [];
    const result = await login(
      `${onward} && ${nested} && ${nested}`,
      { ...ssh, browserAgentForwarding: true },
      false,
      false,
      () => true,
      false,
      (_user, _signal, _initial, destination) => {
        assert.equal(destination?.canRemember, true);
        paths.push(destination.forwardingHostFingerprints.length);
        return 'session';
      },
    );
    assert.equal(
      result.output.split('FORWARDED_LOGIN_OK').length - 1,
      3,
      result.output,
    );
    assert.deepEqual(paths, [1, 2]);
  });

  describe('ssh-add imported identities', () => {
    beforeEach(async () => {
      await new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase('wetty-imported-ssh-keys');
        request.onsuccess = () => {
          resolve();
        };
        request.onerror = () => {
          reject(new Error('Cannot reset imported keys'));
        };
      });
    });
    function importFile(type: 'rsa' | 'ed25519'): string {
      const path = join(directory, `import-${type}`);
      return path;
    }
    before(() => {
      for (const type of ['rsa', 'ed25519'] as const) {
        execFileSync('/usr/bin/ssh-keygen', [
          '-q',
          '-t',
          type,
          ...(type === 'rsa' ? ['-b', '2048'] : []),
          '-N',
          '',
          '-f',
          importFile(type),
        ]);
      }
    });
    (['rsa', 'ed25519'] as const).forEach((type) => {
      it(`imports ${type} with real ssh-add, persists it and uses it for onward login`, async () => {
        let imports = 0;
        const path = importFile(type);
        const importedPublic = (await readFile(`${path}.pub`, 'utf8')).trim();
        const result = await login(
          `/usr/bin/ssh-add ${path} && /usr/bin/ssh-add -L`,
          { ...ssh, browserAgentForwarding: true },
          false,
          false,
          () => true,
          false,
          () => true,
          false,
          () => {
            imports += 1;
            return true;
          },
        );
        assert.equal(imports, 1);
        assert.ok(
          result.output.includes(
            importedPublic.split(' ').slice(0, 2).join(' '),
          ),
        );
        const reconnect = await login('/usr/bin/ssh-add -L', {
          ...ssh,
          browserAgentForwarding: true,
        });
        assert.ok(
          reconnect.output.includes(
            importedPublic.split(' ').slice(0, 2).join(' '),
          ),
        );
        await writeFile(
          join(directory, 'authorized_keys'),
          `${publicKey}\n${importedPublic}\n`,
        );
        try {
          let signs = 0;
          const onward = `/usr/bin/ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityFile=${path}.pub -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${join(directory, 'known_hosts')} -p ${String(ssh.port)} -l ${ssh.user} 127.0.0.1 printf IMPORTED_LOGIN_OK`;
          const signed = await login(
            onward,
            { ...ssh, browserAgentForwarding: true },
            false,
            false,
            () => true,
            false,
            () => {
              signs += 1;
              return true;
            },
          );
          assert.match(signed.output, /IMPORTED_LOGIN_OK/);
          assert.equal(signs, 1);
          let remembered = 0;
          const reusable = await login(
            `${onward} && ${onward}`,
            { ...ssh, browserAgentForwarding: true },
            false,
            false,
            () => true,
            false,
            (_user, _signal, _initial, destination) => {
              assert.equal(destination?.canRemember, true);
              remembered += 1;
              return 'session';
            },
          );
          assert.equal(
            reusable.output.split('IMPORTED_LOGIN_OK').length - 1,
            2,
            reusable.output,
          );
          assert.equal(remembered, 1);
          const denied = await login(onward, {
            ...ssh,
            browserAgentForwarding: true,
          });
          assert.doesNotMatch(denied.output, /IMPORTED_LOGIN_OK/);
          // Only the imported key is authorized: prove the initial login uses it,
          // even when forwarding is off, and still asks permission to sign.
          await writeFile(
            join(directory, 'authorized_keys'),
            `${importedPublic}\n`,
          );
          let initialApprovals = 0;
          const initial = await login(
            'printf IMPORTED_INITIAL_OK',
            { ...ssh, browserAgentForwarding: false },
            false,
            true,
            () => true,
            false,
            () => {
              initialApprovals += 1;
              return true;
            },
          );
          assert.match(initial.output, /IMPORTED_INITIAL_OK/);
          assert.equal(initialApprovals, 1);
          assert.equal(initial.signs, 0);
          const refused = await login('printf MUST_NOT_RUN', ssh, false, true);
          assert.match(refused.output, /password:/i);
          assert.doesNotMatch(refused.output, /MUST_NOT_RUN/);
          const legacy = await login(
            'printf MUST_NOT_RUN',
            ssh,
            false,
            true,
            () => true,
            false,
            () => true,
            true,
          );
          assert.match(legacy.output, /password:/i);
        } finally {
          await writeFile(join(directory, 'authorized_keys'), `${publicKey}\n`);
        }
      });
    });
    it('rejects a declined import and leaves the identity list unchanged', async () => {
      let imports = 0;
      const result = await login(
        `/usr/bin/ssh-add ${importFile('ed25519')}; /usr/bin/ssh-add -L`,
        { ...ssh, browserAgentForwarding: true },
        false,
        false,
        () => true,
        false,
        () => true,
        false,
        () => {
          imports += 1;
          return false;
        },
      );
      assert.equal(imports, 1);
      assert.match(result.output, /agent refused operation/);
      assert.equal(result.output.split('ssh-ed25519 ').length, 1);
    });
    it('rejects constrained imports without prompting', async () => {
      const result = await login(
        `/usr/bin/ssh-add -t 60 ${importFile('ed25519')}`,
        { ...ssh, browserAgentForwarding: true },
        false,
        false,
        () => true,
        false,
        () => true,
        false,
        () => {
          throw new Error('Must not prompt');
        },
      );
      assert.match(result.output, /agent refused operation/);
    });
    it('refuses private-key transport over HTTP polling', async () => {
      const result = await login(
        `/usr/bin/ssh-add ${importFile('ed25519')}`,
        { ...ssh, browserAgentForwarding: true },
        false,
        false,
        () => true,
        false,
        () => true,
        false,
        () => {
          throw new Error('Must not receive private import');
        },
        true,
      );
      assert.match(result.output, /agent refused operation/);
    });
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

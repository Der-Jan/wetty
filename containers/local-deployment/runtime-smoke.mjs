import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { access, readFile, stat, writeFile } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { promisify } from 'node:util';
import pty from '/usr/src/app/node_modules/node-pty/lib/index.js';
import { createBrowserAgent } from '/usr/src/app/build/server/browserAgent/agent.js';
import { createBrowserKnownHosts } from '/usr/src/app/build/server/browserAgent/knownHosts.js';
import { browserSshCommand } from '/usr/src/app/build/server/browserAgent/command.js';
import { sshString } from '/usr/src/app/build/shared/browserAgent.js';
import { sshDefault } from '/usr/src/app/build/shared/defaults.js';
import { browserKeySession } from '/usr/src/app/build/server/browserAgent/session.js';
assert.equal(typeof browserKeySession, 'function');

const run = promisify(execFile);
const timeout = setTimeout(() => { console.error('Smoke test timed out'); process.exit(1); }, 20000);
try {
  assert.equal(process.getuid(), 1000);
  const status = await readFile('/proc/self/status', 'utf8');
  assert.match(status, /^CapEff:\s+0+$/m);
  assert.match(status, /^NoNewPrivs:\s+1$/m);
  await assert.rejects(writeFile('/home/node/hardening-write-probe', 'test'), { code: 'EROFS' });
  for (const path of ['/usr/bin/gcc', '/usr/bin/make', '/usr/bin/git', '/usr/bin/python3', '/usr/src/app/src']) {
    await assert.rejects(access(path), { code: 'ENOENT' });
  }
  const mounts = await readFile('/proc/mounts', 'utf8');
  const tmpMount = mounts.split('\n').find(line => line.split(' ')[1] === '/tmp');
  assert(tmpMount);
  for (const option of ['noexec', 'nosuid', 'nodev']) assert(tmpMount.includes(option));
  console.log('Non-root, read-only, no capabilities, no-new-privileges and tmpfs checks passed');

  await new Promise((resolve, reject) => {
    const terminal = pty.spawn('/bin/sh', ['-c', 'test -t 0 && printf "PTY_READY"'], { name: 'xterm-256color', cols: 80, rows: 24, cwd: '/usr/src/app', env: { PATH: '/usr/bin:/bin' } });
    let output = '';
    terminal.onData(data => { output += data; });
    terminal.onExit(({ exitCode }) => {
      try { assert.equal(exitCode, 0); assert.match(output, /PTY_READY/); resolve(); } catch (error) { reject(error); }
    });
  });
  console.log('Real node-pty child creation passed');

  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const jwk = publicKey.export({ format: 'jwk' });
  const mpint = value => {
    const bytes = Buffer.from(value, 'base64url');
    return bytes[0] & 128 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes;
  };
  const blob = Buffer.concat([sshString('ssh-rsa'), sshString(mpint(jwk.e)), sshString(mpint(jwk.n))]);
  const agent = await createBrowserAgent(blob, 'smoke-test', async () => { throw new Error('No signing expected'); });
  try {
    assert.equal((await stat(agent.path)).mode & 0o777, 0o600);
    await new Promise((resolve, reject) => {
      const client = createConnection(agent.path);
      const chunks = [];
      client.on('error', reject);
      client.on('connect', () => client.write(Buffer.from([0, 0, 0, 1, 11])));
      client.on('data', chunk => {
        chunks.push(chunk);
        const data = Buffer.concat(chunks);
        if (data.length < 4 || data.length < data.readUInt32BE(0) + 4) return;
        client.destroy();
        try { assert.equal(data[4], 12); assert.equal(data.readUInt32BE(5), 1); resolve(); } catch (error) { reject(error); }
      });
    });
  } finally { await agent.close(); }
  await assert.rejects(access(agent.path), { code: 'ENOENT' });
  console.log('Agent Unix socket, identity request and cleanup passed');

  const hosts = await createBrowserKnownHosts({ host: 'smoke.example', port: 22 }, async () => null);
  try {
    assert.equal((await stat(hosts.path)).mode & 0o777, 0o600);
    const result = await run(process.execPath, ['/usr/src/app/build/server/browserAgent/knownHostsHelper.js', hosts.path, 'ORDER', 'NONE', 'NONE']);
    assert.equal(result.stdout, '');
    const command = browserSshCommand({ ...sshDefault, user: 'smoke-test', host: 'smoke.example', auth: 'browser-key', knownHosts: 'browser' }, 'login', hosts.command);
    const config = await run(command[0], ['-G', ...command.slice(1)]);
    assert.match(config.stdout, /^passwordauthentication yes$/m);
    assert.match(config.stdout, /^kbdinteractiveauthentication yes$/m);
    assert.match(config.stdout, /^preferredauthentications publickey,password,keyboard-interactive$/m);
  } finally { await hosts.close(); }
  await assert.rejects(access(hosts.path), { code: 'ENOENT' });
  console.log('Known-host helper execution/cleanup and OpenSSH password fallback configuration passed');
} finally { clearTimeout(timeout); }

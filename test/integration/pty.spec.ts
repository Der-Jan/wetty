import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from '../../src/server/spawn';
import type { SpawnOptions } from '../../src/server/spawn';
import type { Socket } from 'socket.io';

/** Real node-pty coverage without SSH authentication or browser dependencies. */
describe('Generic PTY integration', function ptySuite() {
  this.timeout(10000);
  let directory: string;
  before(async () => {
    directory = await mkdtemp(join(tmpdir(), 'wetty-pty-test-'));
  });
  after(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  async function run(
    args: string[],
    options: SpawnOptions = {},
    stop?: 'disconnect' | 'abort',
  ) {
    const socket = Object.assign(new EventEmitter(), { connected: true });
    const controller = new AbortController();
    let output = '';
    let exits = 0;
    let externalInputs = 0;
    const externalInput = (): void => {
      externalInputs += 1;
    };
    socket.on('input', externalInput);
    socket.on('data', (data: string) => {
      output += data;
      if (output.includes('READY')) {
        if (stop === 'abort') controller.abort();
        if (stop === 'disconnect') {
          socket.connected = false;
          socket.emit('disconnect');
        }
      }
    });
    const done = new Promise<void>((resolve) => {
      socket.once('logout', resolve);
    });
    try {
      await spawn(socket as unknown as Socket, args, {
        ...options,
        signal: controller.signal,
        onExit: () => {
          exits += 1;
        },
      });
      await done;
      socket.emit('input', 'after exit');
      assert.equal(exits, 1);
      assert.equal(externalInputs, 1);
      assert.equal(socket.listenerCount('resize'), 0);
      assert.equal(socket.listenerCount('commit'), 0);
      assert.equal(socket.listenerCount('disconnect'), 0);
      return output;
    } finally {
      controller.abort();
    }
  }

  it('keeps the legacy env-wrapper path and delivers final terminal output', async () => {
    const script = join(directory, 'legacy.sh');
    await writeFile(script, 'printf LEGACY_FINAL_OUTPUT\n');
    assert.equal(await run(['/bin/sh', script]), 'LEGACY_FINAL_OUTPUT');
  });
  it('preserves literal argv and isolates concurrent per-session environments', async () => {
    const script = join(directory, 'environment.sh');
    await writeFile(script, 'printf "%s|%s" "$SSH_AUTH_SOCK" "$1"\n');
    const literal = 'spaces ; $(not-a-command) and "quotes"';
    const inherited = process.env.SSH_AUTH_SOCK;
    const outputs = await Promise.all([
      run(['/bin/sh', script, literal], {
        env: { PATH: '/usr/bin:/bin', SSH_AUTH_SOCK: '/tmp/agent-one' },
      }),
      run(['/bin/sh', script, literal], {
        env: { PATH: '/usr/bin:/bin', SSH_AUTH_SOCK: '/tmp/agent-two' },
      }),
    ]);
    assert.deepEqual(outputs, [
      `/tmp/agent-one|${literal}`,
      `/tmp/agent-two|${literal}`,
    ]);
    assert.equal(process.env.SSH_AUTH_SOCK, inherited);
  });
  (['disconnect', 'abort'] as const).forEach((stop) => {
    it(`terminates a child ignoring hangup on ${stop}`, async () => {
      const script = join(directory, `${stop}.sh`);
      await writeFile(script, 'trap "" HUP\nprintf READY\nexec sleep 30\n');
      assert.match(await run(['/bin/sh', script], {}, stop), /READY/);
    });
  });
  it('rejects disconnected or aborted sessions before creating a PTY', async () => {
    const socket = Object.assign(new EventEmitter(), { connected: false });
    await assert.rejects(
      spawn(socket as unknown as Socket, ['/bin/true']),
      /disconnected/,
    );
    const controller = new AbortController();
    controller.abort();
    socket.connected = true;
    await assert.rejects(
      spawn(socket as unknown as Socket, ['/bin/true'], {
        signal: controller.signal,
      }),
      /abort/i,
    );
  });
});

import * as pty from 'node-pty';
import { logger as getLogger } from '../shared/logger.js';
import { tinybuffer, FlowControlServer } from './flowcontrol.js';
import { xterm } from './shared/xterm.js';
import { envVersionOr } from './spawn/env.js';
import { parseDimensions } from './spawn/resize.js';
import type SocketIO from 'socket.io';

interface SpawnOptions {
  env?: Record<string, string>;
  signal?: AbortSignal;
  onExit?: () => void;
}

export async function spawn(
  socket: SocketIO.Socket,
  args: string[],
  options: SpawnOptions = {},
): Promise<void> {
  const logger = getLogger();
  // Browser agents use direct exec and an isolated environment; retain legacy argv.
  const version = options.env ? 0 : await envVersionOr(0);
  options.signal?.throwIfAborted();
  if (!socket.connected) {
    throw new Error('Client disconnected before PTY creation');
  }
  const cmd = version >= 9 ? ['-S', ...args] : args;
  const term = options.env
    ? pty.spawn(args[0], args.slice(1), { ...xterm, env: options.env })
    : pty.spawn('/usr/bin/env', cmd, xterm);
  const { pid } = term;
  logger.info('Process Started on behalf of user', { pid });
  const send = tinybuffer(socket, 2, 524288);
  const fcServer = new FlowControlServer();
  let ended = false;
  let killed = false;
  let killTimer: NodeJS.Timeout | undefined;
  const kill = (): void => {
    if (ended || killed) return;
    killed = true;
    try {
      term.kill();
    } catch {
      /* Process may already have exited. */
    }
    killTimer = setTimeout(() => {
      if (!ended) {
        try {
          term.kill('SIGKILL');
        } catch {
          /* Already gone. */
        }
      }
    }, 2000);
    killTimer.unref();
  };
  const resize = (payload: unknown): void => {
    const dimensions = parseDimensions(payload);
    if (!dimensions || ended) return;
    try {
      term.resize(dimensions.cols, dimensions.rows);
    } catch (error) {
      logger.debug('Resize rejected by PTY', { pid, err: error });
    }
  };
  const input = (value: unknown): void => {
    if (!ended && typeof value === 'string') term.write(value);
  };
  const commit = (size: unknown): void => {
    if (
      !ended &&
      typeof size === 'number' &&
      Number.isSafeInteger(size) &&
      size > 0 &&
      size <= fcServer.counter &&
      fcServer.commit(size)
    ) {
      term.resume();
    }
  };
  const output = term.onData((data) => {
    send(data);
    if (fcServer.account(data.length)) term.pause();
  });
  term.onExit(({ exitCode }) => {
    ended = true;
    clearTimeout(killTimer);
    output.dispose();
    send.flush();
    send.dispose();
    socket
      .off('disconnect', kill)
      .off('resize', resize)
      .off('input', input)
      .off('commit', commit);
    options.signal?.removeEventListener('abort', kill);
    logger.info('Process exited', { exitCode, pid });
    socket.emit('logout');
    options.onExit?.();
  });
  socket
    .on('resize', resize)
    .on('input', input)
    .on('disconnect', kill)
    .on('commit', commit);
  options.signal?.addEventListener('abort', kill, { once: true });
  if (options.signal?.aborted) kill();
  socket.emit('login');
}

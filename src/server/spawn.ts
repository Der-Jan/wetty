import * as pty from 'node-pty';
import { logger as getLogger } from '../shared/logger.js';
import { tinybuffer, FlowControlServer } from './flowcontrol.js';
import { writePtyInput } from './shared/input.js';
import { logSafeArgs } from './shared/logsafe.js';
import { xterm } from './shared/xterm.js';
import { envVersionOr } from './spawn/env.js';
import { ptyLifecycle } from './spawn/lifecycle.js';
import { parseDimensions } from './spawn/resize.js';
import type SocketIO from 'socket.io';

export interface SpawnOptions {
  /** Execute argv directly with this environment, without changing global env. */
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
  const version = options.env ? 0 : await envVersionOr(0);
  options.signal?.throwIfAborted();
  if (!socket.connected) {
    throw new Error('Client disconnected before PTY creation');
  }
  const cmd = version >= 9 ? ['-S', ...args] : args;
  logger.debug('Spawning PTY', { cmd: logSafeArgs(cmd) });
  const term = options.env
    ? pty.spawn(args[0], args.slice(1), { ...xterm, env: options.env })
    : pty.spawn('/usr/bin/env', cmd, xterm);
  const { pid } = term;
  logger.info('Process Started on behalf of user', { pid });
  const send = tinybuffer(socket, 2, 524288);
  const fcServer = new FlowControlServer();
  const lifecycle = ptyLifecycle(socket, term, {
    signal: options.signal,
    onExit: ({ exitCode }) => {
      send.flush();
      send.dispose();
      logger.info('Process exited', { exitCode, pid });
      socket.emit('logout');
      options.onExit?.();
    },
  });
  lifecycle.own(
    term.onData((data: string) => {
      send(data);
      if (fcServer.account(data.length)) term.pause();
    }),
  );
  lifecycle
    .on('resize', (payload: unknown) => {
      // Socket.IO does not catch throws in listeners, so an invalid size would
      // otherwise take down the process and every other session with it.
      const dimensions = parseDimensions(payload);
      if (dimensions === undefined) {
        logger.debug('Ignoring invalid resize request', { pid });
        return;
      }
      try {
        term.resize(dimensions.cols, dimensions.rows);
      } catch (error) {
        logger.debug('Resize rejected by PTY', { pid, err: error });
      }
    })
    .on('input', (input: unknown, binary?: unknown) => {
      if (typeof input === 'string') {
        writePtyInput(term, input, binary === true);
      }
    })
    .on('commit', (size: unknown) => {
      if (
        typeof size === 'number' &&
        Number.isSafeInteger(size) &&
        size > 0 &&
        size <= fcServer.counter &&
        fcServer.commit(size)
      ) {
        term.resume();
      }
    });
  lifecycle.start();
  socket.emit('login');
}

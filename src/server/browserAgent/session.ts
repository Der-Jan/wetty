import { randomUUID } from 'node:crypto';
import {
  SIGN_TIMEOUT,
  bytes,
  fields,
  publicBlob,
} from '../../shared/browserAgent.js';
import { logger } from '../../shared/logger.js';
import { spawn } from '../spawn.js';
import { createBrowserAgent } from './agent.js';
import { browserSshCommand, browserSshEnv } from './command.js';
import { forwardedKeys } from './forwardedKeys.js';
import { createBrowserKnownHosts } from './knownHosts.js';
import type { BrowserAgent } from './agent.js';
import type { BrowserKnownHosts } from './knownHosts.js';
import type { SSH } from '../../shared/interfaces.js';
import type { Socket } from 'socket.io';

function requestBrowser(
  socket: Socket,
  event: string,
  payload: Record<string, unknown>,
  signal: AbortSignal,
  timeout: number,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted();
    const requestId =
      typeof payload.requestId === 'string' ? payload.requestId : randomUUID();
    const timer = setTimeout(() => {
      fail(new Error('Browser request timed out'));
    }, timeout);
    function cleanup(): void {
      clearTimeout(timer);
      signal.removeEventListener('abort', aborted);
      socket.off('browser-key:result', result);
    }
    function fail(error: Error): void {
      cleanup();
      reject(error);
    }
    function aborted(): void {
      fail(new Error('Browser key session closed'));
    }
    function result(value: unknown): void {
      let response: Record<string, unknown>;
      try {
        response = fields(value);
      } catch {
        return;
      }
      if (
        response.sessionId !== payload.sessionId ||
        response.requestId !== requestId
      ) {
        return;
      }
      cleanup();
      resolve(response);
    }
    signal.addEventListener('abort', aborted, { once: true });
    socket.on('browser-key:result', result);
    socket.emit(event, { ...payload, requestId });
  });
}

/** Setup is opt-in through the configured auth mode, never through URL input. */
export function browserKeySession(
  socket: Socket,
  ssh: SSH,
  command: string,
  onClose: () => void,
): () => Promise<void> {
  const controller = new AbortController();
  const { signal } = controller;
  const sessionId = randomUUID();
  let agent: BrowserAgent | undefined;
  let forwardingAgent: BrowserAgent | undefined;
  let knownHosts: BrowserKnownHosts | undefined;
  let closing: Promise<void> | undefined;
  let signingRequests = 0;
  let setupTimer: NodeJS.Timeout;
  const close = (): Promise<void> => {
    closing ??= (async () => {
      clearTimeout(setupTimer);
      controller.abort();
      socket.off('browser-key:hello', hello);
      socket.off('disconnect', disconnected);
      socket.disconnect(true);
      onClose();
      await Promise.all([
        agent?.close(),
        forwardingAgent?.close(),
        knownHosts?.close(),
      ]);
    })().catch((error: unknown) => {
      logger().error('Browser key cleanup failed', { err: error });
    });
    return closing;
  };
  const fail = (message: string): void => {
    socket.emit('error', message);
    void close();
  };
  setupTimer = setTimeout(() => {
    fail('Browser key preparation timed out');
  }, 60000);
  function disconnected(): void {
    void close();
  }
  async function prepare(): Promise<void> {
    if (ssh.knownHosts === 'browser') {
      const created = await createBrowserKnownHosts(ssh, async (key) => {
        const response = fields(
          await requestBrowser(
            socket,
            'browser-host:request',
            {
              v: 1,
              sessionId,
              phase: key === undefined ? 'lookup' : 'verify',
              target: { host: ssh.host, port: ssh.port },
              ...(key === undefined ? {} : { key }),
            },
            signal,
            120000,
          ),
        );
        signal.throwIfAborted();
        if (response.v !== 1 || response.error) {
          socket.emit(
            'data',
            '\r\nHost verification cancelled or unavailable. Authentication stopped.\r\n',
          );
          throw new Error('Browser did not approve the SSH host key');
        }
        return response.key;
      });
      if (signal.aborted) {
        await created.close();
        return;
      }
      knownHosts = created;
    }
    let blob: Uint8Array;
    let supportsForwarding = false;
    let supportsKeyManagement = false;
    let supportsLoginKeys = false;
    let supportsBindings = false;
    let bindingRequests = 0;
    let managedRequests = 0;
    try {
      const response = fields(
        await requestBrowser(
          socket,
          'browser-key:prepare',
          {
            v: 1,
            sessionId,
            target: { user: ssh.user, host: ssh.host, port: ssh.port },
            forwarding: ssh.browserAgentForwarding === true,
          },
          signal,
          60000,
        ),
      );
      signal.throwIfAborted();
      if (response.sessionId !== sessionId || response.v !== 1) {
        throw new Error('Invalid browser key preparation response');
      }
      blob = publicBlob(response.publicKey);
      supportsKeyManagement = response.keyManagement === 1;
      supportsLoginKeys = supportsKeyManagement && response.loginKeys === 1;
      supportsForwarding =
        ssh.browserAgentForwarding === true && response.forwarding === true;
      supportsBindings = supportsForwarding && response.sessionBinding === 1;
    } catch (error) {
      if (signal.aborted) return;
      logger().info(
        'Browser key unavailable; trying interactive authentication',
        {
          reason: error instanceof Error ? error.message : 'Unknown error',
        },
      );
      socket.emit(
        'data',
        '\r\nBrowser key unavailable; trying password authentication.\r\n',
      );
      await spawn(
        socket,
        browserSshCommand(ssh, command, knownHosts?.command),
        {
          env: browserSshEnv(),
          signal,
          onExit: disconnected,
        },
      );
      return;
    }
    const sign = async (
      data: Uint8Array,
      forwarded = false,
      agentConnectionId?: string,
    ): Promise<Uint8Array> => {
      signingRequests += 1;
      if (signingRequests > 32) throw new Error('Too many signing requests');
      const requestId = randomUUID();
      const result = fields(
        await requestBrowser(
          socket,
          'browser-key:sign',
          {
            v: 1,
            sessionId,
            requestId,
            algorithm: 'rsa-sha2-256',
            forwarded,
            ...(forwarded ? { agentConnectionId } : {}),
            data,
          },
          signal,
          forwarded ? 60000 : SIGN_TIMEOUT,
        ),
      );
      signal.throwIfAborted();
      if (
        result.v !== 1 ||
        result.sessionId !== sessionId ||
        result.requestId !== requestId
      ) {
        throw new Error('Invalid browser signing response');
      }
      return bytes(result.signature, 384);
    };
    const manage =
      (forwarded: boolean) =>
      async (
        operation: string,
        payload: Record<string, unknown>,
        agentConnectionId?: string,
      ): Promise<Record<string, unknown>> => {
        signal.throwIfAborted();
        managedRequests += 1;
        if (managedRequests > 128) {
          throw new Error('Too many key management requests');
        }
        // Private imports must never travel in cacheable HTTP polling responses.
        if (
          operation === 'add' &&
          (!socket.connected || socket.conn.transport.name !== 'websocket')
        ) {
          throw new Error('Key imports require an active WebSocket');
        }
        const result = fields(
          await requestBrowser(
            socket,
            'browser-key:manage',
            {
              v: 1,
              sessionId,
              operation,
              forwarded,
              ...payload,
              ...(forwarded ? { agentConnectionId } : {}),
            },
            signal,
            operation === 'list' ? SIGN_TIMEOUT : 60000,
          ),
        );
        signal.throwIfAborted();
        if (result.v !== 1 || result.error) {
          throw new Error('Browser key operation failed');
        }
        return result;
      };
    const created = await createBrowserAgent(
      blob,
      ssh.user,
      (data) => sign(data),
      supportsLoginKeys
        ? forwardedKeys(blob, (data) => sign(data), manage(false))
        : undefined,
    );
    if (signal.aborted) {
      await created.close();
      return;
    }
    agent = created;
    if (supportsForwarding) {
      const managed = supportsKeyManagement
        ? forwardedKeys(blob, (data, id) => sign(data, true, id), manage(true))
        : undefined;
      const forwarded = await createBrowserAgent(
        blob,
        undefined,
        (data, id) => sign(data, true, id),
        managed,
        supportsBindings
          ? {
              bind: async (agentConnectionId, packet) => {
                bindingRequests += 1;
                if (bindingRequests > 128) {
                  throw new Error('Too many binding requests');
                }
                const result = fields(
                  await requestBrowser(
                    socket,
                    'browser-key:bind',
                    {
                      v: 1,
                      sessionId,
                      agentConnectionId,
                      packet,
                    },
                    signal,
                    SIGN_TIMEOUT,
                  ),
                );
                signal.throwIfAborted();
                if (result.v !== 1 || result.ok !== true) {
                  throw new Error('Browser refused agent binding');
                }
              },
              close: (agentConnectionId) => {
                if (socket.connected && !signal.aborted) {
                  socket.emit('browser-key:agent-close', {
                    v: 1,
                    sessionId,
                    agentConnectionId,
                  });
                }
              },
            }
          : undefined,
      );
      try {
        signal.throwIfAborted();
      } catch {
        await forwarded.close();
        return;
      }
      forwardingAgent = forwarded;
    }
    await spawn(
      socket,
      browserSshCommand(
        ssh,
        command,
        knownHosts?.command,
        forwardingAgent?.path,
      ),
      {
        env: browserSshEnv(agent.path),
        signal,
        onExit: disconnected,
      },
    );
    signal.throwIfAborted();
    clearTimeout(setupTimer);
  }
  function hello(): void {
    clearTimeout(setupTimer);
    void prepare().catch((error: unknown) => {
      if (!signal.aborted) {
        logger().info('Browser key session failed', {
          reason: error instanceof Error ? error.message : 'Unknown error',
        });
        fail(
          'Browser key login could not start. Check key storage and server configuration.',
        );
      }
    });
  }
  socket.once('browser-key:hello', hello);
  socket.once('disconnect', disconnected);
  return close;
}

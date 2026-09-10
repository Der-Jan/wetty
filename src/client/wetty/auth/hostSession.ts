import { fields } from '../../../shared/browserAgent';
import { promptHostTrust } from './hostPrompt';
import { browserHostTrust } from './hostTrust';
import type { HostApproval } from './hostTrust';
import type { Socket } from 'socket.io-client';

export function setupBrowserHostTrust(
  socket: Socket,
  approve: HostApproval = promptHostTrust,
): void {
  let active: AbortController | undefined;
  let sessionId: string | undefined;
  const clear = (): void => {
    active?.abort();
    active = undefined;
    sessionId = undefined;
  };
  socket.on('disconnect', clear);
  socket.on('logout', clear);
  socket.on('browser-host:request', (payload: unknown) => {
    if (!socket.connected) return;
    const connectionId = socket.id;
    const controller = new AbortController();
    const reply = (value: Record<string, unknown>): void => {
      if (
        !socket.connected ||
        socket.id !== connectionId ||
        controller.signal.aborted
      ) {
        return;
      }
      const request = fields(payload);
      socket.emit('browser-key:result', {
        v: 1,
        sessionId: request.sessionId,
        requestId: request.requestId,
        ...value,
      });
    };
    void (async () => {
      const request = fields(payload);
      if (
        request.v !== 1 ||
        typeof request.sessionId !== 'string' ||
        request.sessionId.length > 64 ||
        typeof request.requestId !== 'string' ||
        request.requestId.length > 64 ||
        active ||
        (sessionId !== undefined && sessionId !== request.sessionId) ||
        (request.phase !== 'lookup' && request.phase !== 'verify') ||
        (request.phase === 'verify' && typeof request.key !== 'string')
      ) {
        throw new Error('Invalid host verification request');
      }
      active = controller;
      sessionId = request.sessionId;
      const key = await browserHostTrust(
        request.target,
        request.phase === 'verify' ? request.key : undefined,
        approve,
        controller.signal,
      );
      reply({ key });
    })()
      .catch((error: unknown) => {
        try {
          reply({
            error:
              error instanceof Error
                ? error.message
                : 'Host verification failed',
          });
        } catch {
          /* Malformed envelope: no reply. */
        }
      })
      .finally(() => {
        if (active === controller) active = undefined;
      });
  });
}

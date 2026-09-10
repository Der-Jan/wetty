import {
  BROWSER_KEY_SCOPE,
  bytes,
  checkUserAuth,
  fields,
  publicBlob,
} from '../../../shared/browserAgent';
import { loadSshKey } from './keys';
import type { BrowserSshKey } from './keys';
import type { Socket } from 'socket.io-client';

/** No reconnect replay: each Socket.IO connection gets a new signer context. */
export function setupBrowserSigner(socket: Socket): void {
  let context:
    | {
        sessionId: string;
        user: string;
        key: BrowserSshKey;
        blob: Uint8Array;
        seen: Set<string>;
      }
    | undefined;
  let preparing: string | undefined;
  socket.on('disconnect', () => {
    context = undefined;
    preparing = undefined;
  });
  socket.on('logout', () => {
    context = undefined;
    preparing = undefined;
  });
  socket.on('browser-key:prepare', (payload: unknown) => {
    if (!socket.connected) return;
    const connectionId = socket.id;
    const ack = (value: Record<string, unknown>): void => {
      if (!socket.connected || socket.id !== connectionId) return;
      if (
        typeof payload !== 'object' ||
        payload === null ||
        Array.isArray(payload)
      ) {
        return;
      }
      const request = fields(payload);
      socket.emit('browser-key:result', {
        sessionId: request.sessionId,
        requestId: request.requestId,
        ...value,
      });
    };
    void (async () => {
      const request = fields(payload);
      const target = fields(request.target);
      if (
        request.v !== 1 ||
        typeof request.sessionId !== 'string' ||
        request.sessionId.length > 64 ||
        typeof target.user !== 'string' ||
        target.user.length > 256 ||
        context ||
        preparing
      ) {
        throw new Error('Invalid browser key preparation');
      }
      const { sessionId } = request;
      preparing = sessionId;
      const key = await loadSshKey(BROWSER_KEY_SCOPE);
      const publicKey = await key.publicKey();
      if (!socket.connected || preparing !== sessionId) return;
      context = {
        sessionId,
        user: target.user,
        key,
        blob: publicBlob(publicKey),
        seen: new Set(),
      };
      ack({ v: 1, sessionId, publicKey });
    })().catch(() => {
      ack({ v: 1, error: 'KEY_UNAVAILABLE' });
    });
  });
  socket.on('browser-key:sign', (payload: unknown) => {
    if (!socket.connected) return;
    const connectionId = socket.id;
    const ack = (value: Record<string, unknown>): void => {
      if (!socket.connected || socket.id !== connectionId) return;
      if (
        typeof payload !== 'object' ||
        payload === null ||
        Array.isArray(payload)
      ) {
        return;
      }
      const request = fields(payload);
      socket.emit('browser-key:result', {
        sessionId: request.sessionId,
        requestId: request.requestId,
        ...value,
      });
    };
    const active = context;
    void (async () => {
      const request = fields(payload);
      if (
        !active ||
        request.v !== 1 ||
        request.sessionId !== active.sessionId ||
        request.algorithm !== 'rsa-sha2-256' ||
        typeof request.requestId !== 'string' ||
        request.requestId.length > 64 ||
        active.seen.has(request.requestId) ||
        active.seen.size >= 32
      ) {
        throw new Error('Invalid SSH signing request');
      }
      active.seen.add(request.requestId);
      const data = bytes(request.data, 32768);
      checkUserAuth(data, active.user, active.blob);
      const signature = await active.key.sign(data);
      if (socket.connected && context === active) {
        ack({
          v: 1,
          sessionId: active.sessionId,
          requestId: request.requestId,
          signature,
        });
      }
    })().catch(() => {
      if (socket.connected && context === active) {
        ack({ v: 1, error: 'SIGN_FAILED' });
      }
    });
  });
}

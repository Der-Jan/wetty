import {
  BROWSER_KEY_SCOPE,
  bytes,
  checkUserAuth,
  fields,
  publicBlob,
} from '../../../shared/browserAgent';
import { checkForwardedAuth } from '../../../shared/forwardedAuth';
import { promptForwardSign } from './forwardPrompt';
import { setupKeyringSession } from './keyringSession';
import { loadSshKey } from './keys';
import type { ForwardApproval } from './forwardPrompt';
import type { ImportApproval } from './keyringSession';
import type { BrowserSshKey } from './keys';
import type { Socket } from 'socket.io-client';

/** No reconnect replay: each Socket.IO connection gets a new signer context. */
export function setupBrowserSigner(
  socket: Socket,
  approve: ForwardApproval = promptForwardSign,
  approveImport?: ImportApproval,
): void {
  let context:
    | {
        sessionId: string;
        user: string;
        key: BrowserSshKey;
        blob: Uint8Array;
        seen: Set<string>;
        managedRequests: Set<string>;
        forwarding: boolean;
        controller: AbortController;
        prompting: boolean;
      }
    | undefined;
  let preparing: string | undefined;
  setupKeyringSession(socket, () => context, approve, approveImport);
  socket.on('disconnect', () => {
    context?.controller.abort();
    context = undefined;
    preparing = undefined;
  });
  socket.on('logout', () => {
    context?.controller.abort();
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
        managedRequests: new Set(),
        forwarding: request.forwarding === true,
        controller: new AbortController(),
        prompting: false,
      };
      ack({
        v: 1,
        sessionId,
        publicKey,
        forwarding: context.forwarding,
        keyManagement: 1,
      });
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
    const current = (): boolean =>
      socket.connected && context === active && socket.id === connectionId;
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
      const forwarded = request.forwarded === true;
      if (
        request.forwarded !== undefined &&
        typeof request.forwarded !== 'boolean'
      ) {
        throw new Error('Invalid forwarding flag');
      }
      if (forwarded && (!active.forwarding || active.prompting)) {
        throw new Error('Forwarding unavailable');
      }
      const user = forwarded
        ? checkForwardedAuth(data, active.blob)
        : checkUserAuth(data, active.user, active.blob);
      if (forwarded) {
        active.prompting = true;
        try {
          if (!(await approve(user, active.controller.signal))) {
            throw new Error('Signing declined');
          }
        } finally {
          active.prompting = false;
        }
      }
      active.controller.signal.throwIfAborted();
      if (!current()) return;
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

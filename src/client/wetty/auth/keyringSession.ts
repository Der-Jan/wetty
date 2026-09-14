import { bytes, equalBytes, fields } from '../../../shared/browserAgent';
import { checkForwardedAuth } from '../../../shared/forwardedAuth';
import {
  keyFingerprint,
  signatureAlgorithm,
} from '../../../shared/importedKeys';
import { promptAgentAction } from './approvalPrompt';
import {
  listImportedKeys,
  prepareImportedKey,
  saveImportedKey,
  signImportedKey,
} from './importedKeys';
import type { ForwardApproval } from './forwardPrompt';
import type { Socket } from 'socket.io-client';

export interface KeyringContext {
  sessionId: string;
  forwarding: boolean;
  controller: AbortController;
  prompting: boolean;
  blob: Uint8Array;
  managedRequests: Set<string>;
}
export type ImportApproval = (
  description: string,
  signal: AbortSignal,
) => boolean | Promise<boolean>;
export const promptKeyImport: ImportApproval = (description, signal) =>
  promptAgentAction(
    'Import SSH key into this browser?',
    `${description}\nThis private key came from the remote host through WeTTY. Store it as a non-extractable key in this browser for future forwarded SSH connections? Each use will still require approval. This request expires in 45 seconds.`,
    'Import key',
    signal,
  );
export function setupKeyringSession(
  socket: Socket,
  context: () => KeyringContext | undefined,
  approveSign: ForwardApproval,
  approveImport: ImportApproval = promptKeyImport,
): void {
  socket.on('browser-key:manage', (payload: unknown) => {
    const active = context();
    const connectionId = socket.id;
    const current = (): boolean =>
      !!active &&
      socket.connected &&
      socket.id === connectionId &&
      context() === active &&
      !active.controller.signal.aborted;
    let request: Record<string, unknown>;
    try {
      request = fields(payload);
    } catch {
      return;
    }
    const ack = (result: Record<string, unknown>): void => {
      if (current()) {
        socket.emit('browser-key:result', {
          v: 1,
          sessionId: request.sessionId,
          requestId: request.requestId,
          ...result,
        });
      }
    };
    void (async () => {
      if (
        !active ||
        !current() ||
        !active.forwarding ||
        request.v !== 1 ||
        request.sessionId !== active.sessionId ||
        typeof request.requestId !== 'string' ||
        request.requestId.length > 64 ||
        active.managedRequests.has(request.requestId) ||
        active.managedRequests.size >= 128
      ) {
        throw new Error('Invalid key management request');
      }
      active.managedRequests.add(request.requestId);
      if (request.operation === 'list') {
        const keys = await listImportedKeys();
        ack({
          identities: keys
            .filter((key) => !equalBytes(key.blob, active.blob))
            .map(({ blob, comment }) => ({ blob, comment })),
        });
        return;
      }
      if (active.prompting) throw new Error('Another approval is pending');
      active.prompting = true;
      try {
        if (request.operation === 'add') {
          const packet = bytes(request.packet, 16384);
          try {
            const key = await prepareImportedKey(packet);
            if (equalBytes(key.blob, active.blob)) {
              throw new Error('Cannot replace the browser-generated key');
            }
            if (!current()) return;
            const fingerprint = await keyFingerprint(key.blob);
            if (
              !(await approveImport(
                `${key.comment || 'Unnamed key'}\n${fingerprint}`,
                active.controller.signal,
              ))
            ) {
              throw new Error('Import declined');
            }
            active.controller.signal.throwIfAborted();
            if (!current()) return;
            await saveImportedKey(key, active.controller.signal);
            ack({ ok: true });
          } finally {
            packet.fill(0);
          }
        } else if (request.operation === 'sign') {
          const blob = bytes(request.blob, 2048);
          const algorithm = signatureAlgorithm(blob, Number(request.flags));
          const data = bytes(request.data, 32768);
          const user = checkForwardedAuth(data, blob, algorithm);
          const key = (await listImportedKeys()).find((candidate) =>
            equalBytes(candidate.blob, blob),
          );
          if (!key) throw new Error('Unknown imported key');
          const fingerprint = await keyFingerprint(blob);
          if (!current()) return;
          if (
            !(await approveSign(
              `${user} (key ${fingerprint})`,
              active.controller.signal,
            ))
          ) {
            throw new Error('Signing declined');
          }
          active.controller.signal.throwIfAborted();
          if (!current()) return;
          ack({ signature: await signImportedKey(key, algorithm, data) });
        } else throw new Error('Unsupported key management operation');
      } finally {
        active.prompting = false;
      }
    })().catch(() => {
      ack({ error: 'KEY_OPERATION_FAILED' });
    });
  });
}

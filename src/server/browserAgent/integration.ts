import { validateBrowserSsh } from './command.js';
import { browserKeySession } from './session.js';
import type { SSH } from '../../shared/interfaces.js';
import type { Server, Socket } from 'socket.io';

interface BrowserSessions {
  handle(socket: Socket): boolean;
  close(): Promise<void>;
}

/** Isolate opt-in dispatch and resource ownership from the upstream server. */
export async function browserSshIntegration(ssh: SSH): Promise<{
  origin: string | undefined;
  attach(io: Server, command: string, onClose: () => void): BrowserSessions;
}> {
  const enabled = ssh.auth === 'browser-key';
  if (enabled) await validateBrowserSsh(ssh);
  return {
    origin: enabled ? ssh.browserOrigin : undefined,
    attach(io, command, onClose) {
      const sessions = new Set<() => Promise<void>>();
      let closed = false;
      let closing: Promise<void> | undefined;
      const close = (): Promise<void> => {
        closed = true;
        closing ??= Promise.all([...sessions].map((end) => end())).then(() => {
          // Repeated shutdown callers wait for the same cleanup.
        });
        return closing;
      };
      if (enabled) {
        io.httpServer.once('close', () => {
          void close();
        });
      }
      return {
        close,
        handle(socket) {
          if (!enabled) return false;
          if (closed) {
            socket.disconnect(true);
            onClose();
            return true;
          }
          const end = browserKeySession(socket, ssh, command, () => {
            sessions.delete(end);
            onClose();
          });
          sessions.add(end);
          return true;
        },
      };
    },
  };
}

import type { IDisposable, IPty } from 'node-pty';
import type { Socket } from 'socket.io';

interface LifecycleOptions {
  signal?: AbortSignal;
  onExit(event: { exitCode: number; signal?: number }): void;
}

/** Own only this PTY's resources; other socket listeners belong to their callers. */
export function ptyLifecycle(
  socket: Socket,
  term: IPty,
  options: LifecycleOptions,
) {
  const resources: IDisposable[] = [];
  let ended = false;
  let stopping = false;
  let started = false;
  let killTimer: NodeJS.Timeout | undefined;
  const hasExited = (): boolean => ended;
  const kill = (): void => {
    if (ended || stopping) return;
    stopping = true;
    try {
      term.kill();
    } catch {
      /* The child may already have exited. */
    }
    if (hasExited()) return;
    killTimer = setTimeout(() => {
      if (!ended) {
        try {
          term.kill('SIGKILL');
        } catch {
          /* The child may already have exited. */
        }
      }
    }, 2000);
    killTimer.unref();
  };
  const own = (resource: IDisposable): void => {
    if (ended) resource.dispose();
    else resources.push(resource);
  };
  own(
    term.onExit((event) => {
      if (ended) return;
      ended = true;
      clearTimeout(killTimer);
      socket.off('disconnect', kill);
      options.signal?.removeEventListener('abort', kill);
      for (const resource of resources.splice(0)) resource.dispose();
      options.onExit(event);
    }),
  );
  const lifecycle = {
    own,
    on(
      event: 'resize' | 'input' | 'commit',
      listener: (value: unknown) => void,
    ) {
      const handler = (value: unknown): void => {
        if (!ended) listener(value);
      };
      if (!ended) {
        socket.on(event, handler);
        own({
          dispose: () => {
            socket.off(event, handler);
          },
        });
      }
      return lifecycle;
    },
    start(): void {
      if (started || ended) return;
      started = true;
      socket.on('disconnect', kill);
      options.signal?.addEventListener('abort', kill, { once: true });
      if (!socket.connected || options.signal?.aborted) kill();
    },
  };
  return lifecycle;
}

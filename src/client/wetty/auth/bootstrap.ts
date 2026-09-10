import { library } from '@fortawesome/fontawesome-svg-core';
import { faKey } from '@fortawesome/free-solid-svg-icons';
import { setupSshKeyButton } from './button';
import { setupBrowserHostTrust } from './hostSession';
import { setupBrowserSigner } from './session';
import type { Socket } from 'socket.io-client';

const initialized = new WeakSet<Socket>();

/** Call after terminal listeners are installed and before socket.connect(). */
export function setupBrowserSsh(socket: Socket): void {
  if (initialized.has(socket)) return;
  initialized.add(socket);
  library.add(faKey);
  setupSshKeyButton();
  setupBrowserSigner(socket);
  setupBrowserHostTrust(socket);
  socket.on('connect', () => {
    socket.emit('browser-key:hello');
  });
}

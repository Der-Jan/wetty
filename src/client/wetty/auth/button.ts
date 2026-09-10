import { createSshKeyControl } from './control';
import { diagnoseSshKey } from './diagnostics';

const boundButtons = new WeakSet<HTMLButtonElement>();

/** Bind once at page startup, independently of terminal connection/reconnection. */
export function setupSshKeyButton(): void {
  const { button, status } = createSshKeyControl();
  if (boundButtons.has(button)) return;
  boundButtons.add(button);

  let dismissNotice: (() => void) | undefined;

  button.addEventListener('click', () => {
    if (button.disabled) return;
    dismissNotice?.();
    const terminal = window.wetty_term;
    const connectionId = terminal?.socket.id;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    status.textContent = 'Creating or loading your browser key…';

    void diagnoseSshKey()
      .then((result) => {
        if (!result.signingAndVerificationSucceed) {
          throw new Error('SSH key verification failed');
        }
        if (
          terminal &&
          window.wetty_term === terminal &&
          terminal.socket.connected &&
          terminal.socket.id === connectionId
        ) {
          // xterm handles bracketed paste; never append Enter or a command.
          terminal.paste(result.publicKey);
          terminal.focus();
          status.textContent =
            'Public key pasted into the terminal without Enter. Add it as a line in ~/.ssh/authorized_keys.';
          let input: { dispose(): void } | undefined;
          let timer: number | undefined;
          const dismiss = (): void => {
            window.clearTimeout(timer);
            input?.dispose();
            terminal.socket.off('disconnect', dismiss);
            status.textContent = '';
            dismissNotice = undefined;
          };
          dismissNotice = dismiss;
          // Subscribe after paste so the inserted key does not dismiss its notice.
          input = terminal.onData(dismiss);
          terminal.socket.once('disconnect', dismiss);
          timer = window.setTimeout(dismiss, 5000);
        } else {
          status.textContent =
            'Public key printed to the browser console. Copy the ssh-rsa line into authorized_keys.';
        }
      })
      .catch((error: unknown) => {
        status.textContent =
          error instanceof Error ? error.message : 'Unable to prepare SSH key';
      })
      .finally(() => {
        button.disabled = false;
        button.removeAttribute('aria-busy');
      });
  });
}

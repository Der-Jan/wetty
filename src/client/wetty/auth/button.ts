import { diagnoseSshKey } from './diagnostics';

/** Bind once at page startup, independently of terminal connection/reconnection. */
export function setupSshKeyButton(): void {
  const button = document.querySelector<HTMLButtonElement>('#ssh-key-create');
  const status = document.getElementById('ssh-key-status');
  if (button === null || status === null) return;

  button.addEventListener('click', () => {
    if (button.disabled) return;
    button.disabled = true;
    button.textContent = 'Preparing SSH key…';
    status.textContent = 'Creating or loading your browser key…';

    void diagnoseSshKey()
      .then((result) => {
        if (!result.signingAndVerificationSucceed) {
          throw new Error('SSH key verification failed');
        }
        status.textContent =
          'Public key printed to the browser console. Copy the ssh-rsa line into authorized_keys.';
      })
      .catch((error: unknown) => {
        status.textContent =
          error instanceof Error ? error.message : 'Unable to prepare SSH key';
      })
      .finally(() => {
        button.disabled = false;
        button.textContent = 'Create / show SSH key';
      });
  });
}

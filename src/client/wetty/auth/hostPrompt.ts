import { hostFingerprint } from '../../../shared/hostKey';
import type { HostApproval } from './hostTrust';

export const promptHostTrust: HostApproval = async (
  target,
  offered,
  previous,
  signal,
) => {
  const fingerprint = await hostFingerprint(offered);
  const oldFingerprint = previous ? await hostFingerprint(previous) : undefined;
  signal.throwIfAborted();
  return new Promise<boolean>((resolve) => {
    const dialog = document.createElement('dialog');
    dialog.className = 'ssh-host-trust';
    const title = document.createElement('h2');
    title.id = 'ssh-host-trust-title';
    title.textContent = previous
      ? 'SSH host key changed'
      : 'Trust this SSH host?';
    dialog.setAttribute('aria-labelledby', title.id);
    const destination = document.createElement('p');
    destination.textContent = `Host: ${target.host} · Port: ${String(target.port)}`;
    const explanation = document.createElement('p');
    explanation.textContent = previous
      ? 'The host key differs from the one saved in this browser. This could be a server replacement or an intercepted connection. Verify the new fingerprint with the server administrator before replacing it.'
      : 'This browser has not trusted this host before. Compare this fingerprint with one obtained directly from the server or its administrator.';
    dialog.append(title, destination, explanation);
    const details = document.createElement('pre');
    details.textContent = `${oldFingerprint ? `Saved fingerprint:\n${oldFingerprint}\n\n` : ''}Offered key: ${offered.split(' ')[0]}\n${fingerprint}`;
    dialog.append(details);
    const trust = document.createElement('button');
    trust.type = 'button';
    trust.textContent = previous
      ? 'Replace trusted key and connect'
      : 'Trust and connect';
    if (previous) {
      const label = document.createElement('label');
      label.textContent =
        'Type the complete new SHA256 fingerprint to confirm replacement';
      const input = document.createElement('input');
      input.type = 'text';
      input.autocomplete = 'off';
      input.spellcheck = false;
      trust.disabled = true;
      input.addEventListener('input', () => {
        trust.disabled = input.value.trim() !== fingerprint;
      });
      label.append(input);
      dialog.append(label);
    }
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.textContent = 'Cancel';
    const actions = document.createElement('div');
    actions.className = 'ssh-host-actions';
    actions.append(cancel, trust);
    dialog.append(actions);
    const finish = (accepted: boolean): void => {
      signal.removeEventListener('abort', aborted);
      dialog.close();
      dialog.remove();
      resolve(accepted);
    };
    function aborted(): void {
      finish(false);
    }
    signal.addEventListener('abort', aborted, { once: true });
    cancel.addEventListener('click', () => {
      finish(false);
    });
    trust.addEventListener('click', () => {
      finish(true);
    });
    dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      finish(false);
    });
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
};

export function promptAgentAction(
  heading: string,
  message: string,
  action: string,
  signal: AbortSignal,
): Promise<boolean> {
  signal.throwIfAborted();
  return new Promise<boolean>((resolve) => {
    const dialog = document.createElement('dialog');
    dialog.className = 'ssh-host-trust';
    const title = document.createElement('h2');
    title.id = 'ssh-agent-approval-title';
    title.textContent = heading;
    dialog.setAttribute('aria-labelledby', title.id);
    const details = document.createElement('p');
    details.textContent = message;
    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.textContent = 'Deny';
    const allow = document.createElement('button');
    allow.type = 'button';
    allow.textContent = action;
    const actions = document.createElement('div');
    actions.className = 'ssh-host-actions';
    actions.append(cancel, allow);
    dialog.append(title, details, actions);
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (accepted: boolean): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', aborted);
      dialog.close();
      dialog.remove();
      resolve(accepted);
    };
    timer = setTimeout(() => {
      finish(false);
    }, 45000);
    function aborted(): void {
      finish(false);
    }
    signal.addEventListener('abort', aborted, { once: true });
    cancel.addEventListener('click', () => {
      finish(false);
    });
    allow.addEventListener('click', () => {
      finish(true);
    });
    dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      finish(false);
    });
    document.body.append(dialog);
    try {
      dialog.showModal();
      cancel.focus();
    } catch {
      finish(false);
    }
  });
}

/** Feature-owned markup: keep the upstream page template unchanged. */
export function createSshKeyControl(): {
  button: HTMLButtonElement;
  status: HTMLParagraphElement;
} {
  const existing = document.getElementById('ssh-key-tools');
  const existingButton =
    existing?.querySelector<HTMLButtonElement>('#ssh-key-create');
  const existingStatus =
    existing?.querySelector<HTMLParagraphElement>('#ssh-key-status');
  if (existingButton && existingStatus) {
    return { button: existingButton, status: existingStatus };
  }

  const root = document.createElement('div');
  root.id = 'ssh-key-tools';
  const button = document.createElement('button');
  button.id = 'ssh-key-create';
  button.type = 'button';
  button.title = 'Create / paste SSH public key';
  button.setAttribute('aria-label', button.title);
  button.setAttribute('aria-describedby', 'ssh-key-status');
  const icon = document.createElement('i');
  icon.className = 'fas fa-key';
  icon.setAttribute('aria-hidden', 'true');
  button.append(icon);
  const status = document.createElement('p');
  status.id = 'ssh-key-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  root.append(button, status);
  if (existing) existing.replaceWith(root);
  else document.body.append(root);
  return { button, status };
}

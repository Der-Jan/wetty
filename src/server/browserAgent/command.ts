import { stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import type { SSH } from '../../shared/interfaces.js';

export async function validateBrowserSsh(ssh: SSH): Promise<void> {
  if (
    !/^[A-Za-z0-9_][A-Za-z0-9_.-]*[$]?$/.test(ssh.user) ||
    !/^[A-Za-z0-9:][A-Za-z0-9.:%_-]*$/.test(ssh.host) ||
    !Number.isInteger(ssh.port) ||
    ssh.port < 1 ||
    ssh.port > 65535
  ) {
    throw new Error(
      'browser-key requires a fixed SSH user, host and valid port',
    );
  }
  if (
    ssh.pass ||
    ssh.key ||
    ssh.config ||
    ssh.allowRemoteHosts ||
    ssh.allowRemoteCommand
  ) {
    throw new Error(
      'browser-key cannot use configured passwords, key files, SSH config or URL overrides',
    );
  }
  if (
    ssh.knownHosts !== 'browser' &&
    (!isAbsolute(ssh.knownHosts) || !(await stat(ssh.knownHosts)).isFile())
  ) {
    throw new Error(
      'browser-key requires known-hosts=browser or an absolute trusted known-hosts file',
    );
  }
  const origin = new URL(ssh.browserOrigin ?? '');
  if (
    origin.origin !== ssh.browserOrigin ||
    (origin.protocol !== 'https:' &&
      !(
        origin.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)
      ))
  ) {
    throw new Error(
      'browser-origin must be an exact HTTPS origin (HTTP localhost is allowed)',
    );
  }
}

export function browserSshCommand(
  ssh: SSH,
  command: string,
  knownHostsCommand?: string,
): string[] {
  if (ssh.knownHosts === 'browser' && !knownHostsCommand) {
    throw new Error('Browser host verification helper required');
  }
  const options = [
    'BatchMode=no',
    'PreferredAuthentications=publickey,password,keyboard-interactive',
    'PubkeyAuthentication=unbound',
    'PasswordAuthentication=yes',
    'KbdInteractiveAuthentication=yes',
    'HostbasedAuthentication=no',
    'PubkeyAcceptedAlgorithms=rsa-sha2-256',
    'IdentityFile=none',
    'CertificateFile=none',
    'IdentitiesOnly=no',
    'ForwardAgent=no',
    'ForwardX11=no',
    'ClearAllForwardings=yes',
    'ControlMaster=no',
    'ControlPath=none',
    'ControlPersist=no',
    'StrictHostKeyChecking=yes',
    `UserKnownHostsFile=${ssh.knownHosts === 'browser' ? 'none' : ssh.knownHosts}`,
    ...(ssh.knownHosts === 'browser'
      ? [
          `KnownHostsCommand=${knownHostsCommand ?? ''}`,
          'CheckHostIP=no',
          'VerifyHostKeyDNS=no',
          'HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256',
        ]
      : []),
    'GlobalKnownHostsFile=/dev/null',
    'UpdateHostKeys=no',
    'EscapeChar=none',
    'ConnectTimeout=15',
    'ConnectionAttempts=1',
  ];
  return [
    '/usr/bin/ssh',
    '-F',
    '/dev/null',
    '-t',
    '-p',
    String(ssh.port),
    '-l',
    ssh.user,
    ...options.flatMap((option) => ['-o', option]),
    '--',
    ssh.host,
    ...(command === 'login' ? [] : [command]),
  ];
}

export function browserSshEnv(agentPath?: string): Record<string, string> {
  const env: Record<string, string> = {
    PATH: '/usr/bin:/bin',
    SSH_AUTH_SOCK: agentPath ?? '',
  };
  for (const name of ['HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ']) {
    const value = process.env[name];
    if (value !== undefined) env[name] = value;
  }
  return env;
}

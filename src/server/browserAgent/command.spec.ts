import { expect } from 'chai';
import 'mocha';
import { sshDefault } from '../../shared/defaults';
import {
  browserSshCommand,
  browserSshEnv,
  validateBrowserSsh,
} from './command';

describe('Browser key SSH command policy', () => {
  it('should prefer the browser key and allow interactive password fallback', () => {
    const args = browserSshCommand(
      { ...sshDefault, user: 'fixed', host: 'server.example', port: 2222 },
      'login',
    );
    expect(args[0]).to.equal('/usr/bin/ssh');
    expect(args).to.include('PubkeyAuthentication=unbound');
    expect(args).to.include('PubkeyAcceptedAlgorithms=rsa-sha2-256');
    expect(args).to.include('BatchMode=no');
    expect(args).to.include(
      'PreferredAuthentications=publickey,password,keyboard-interactive',
    );
    expect(args).to.include('PasswordAuthentication=yes');
    expect(args).to.include('KbdInteractiveAuthentication=yes');
    expect(args).to.include('IdentityFile=none');
    expect(args).to.include('ControlPath=none');
    expect(args).to.include('ForwardAgent=no');
    expect(args.slice(-2)).to.deep.equal(['--', 'server.example']);
    expect(args).to.include('fixed');
  });

  it('should forward only the separate socket when explicitly enabled', () => {
    expect(
      browserSshCommand(
        { ...sshDefault, browserAgentForwarding: true },
        'login',
        undefined,
        '/tmp/forward-agent',
      ),
    ).to.include('ForwardAgent=/tmp/forward-agent');
    expect(
      browserSshCommand(
        { ...sshDefault, browserAgentForwarding: false },
        'login',
        undefined,
        '/tmp/forward-agent',
      ),
    ).to.include('ForwardAgent=no');
    expect(
      browserSshCommand(
        { ...sshDefault, browserAgentForwarding: true },
        'login',
      ),
    ).to.include('ForwardAgent=no');
  });

  it('should require a fixed user and known-hosts file', async () => {
    const results = await Promise.allSettled([
      validateBrowserSsh(sshDefault),
      validateBrowserSsh({ ...sshDefault, user: 'fixed' }),
    ]);
    expect(results.map((result) => result.status)).to.deep.equal([
      'rejected',
      'rejected',
    ]);
  });

  it('should require a host helper and disable persistent trust sources in browser mode', () => {
    const ssh = { ...sshDefault, knownHosts: 'browser' };
    expect(() => browserSshCommand(ssh, 'login')).to.throw('helper required');
    const args = browserSshCommand(ssh, 'login', '/helper');
    expect(args).to.include('KnownHostsCommand=/helper');
    expect(args).to.include('UserKnownHostsFile=none');
    expect(args).to.include('GlobalKnownHostsFile=/dev/null');
    expect(args).to.include('StrictHostKeyChecking=yes');
    expect(args).to.include('VerifyHostKeyDNS=no');
  });

  it('should isolate the child environment without mutating process.env', () => {
    const inherited = process.env.SSH_AUTH_SOCK;
    const first = browserSshEnv('/tmp/agent-one');
    const second = browserSshEnv('/tmp/agent-two');
    expect(first.SSH_AUTH_SOCK).to.equal('/tmp/agent-one');
    expect(second.SSH_AUTH_SOCK).to.equal('/tmp/agent-two');
    expect(browserSshEnv().SSH_AUTH_SOCK).to.equal('');
    expect(first).not.to.have.property('VAULT_TOKEN');
    expect(first).not.to.have.property('SSH_ASKPASS');
    expect(process.env.SSH_AUTH_SOCK).to.equal(inherited);
  });
});

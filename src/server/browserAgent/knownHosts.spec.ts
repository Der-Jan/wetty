import { stat } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { expect } from 'chai';
import 'mocha';
import { sshString } from '../../shared/browserAgent';
import { createBrowserKnownHosts } from './knownHosts';
import type { BrowserKnownHosts } from './knownHosts';

const key = `ssh-ed25519 ${Buffer.concat([Buffer.from(sshString('ssh-ed25519')), Buffer.from(sshString(new Uint8Array(32)))]).toString('base64')}`;
function exchange(path: string, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = createConnection(path);
    let result = '';
    client.once('connect', () => client.write(payload));
    client.on('data', (data: Buffer) => {
      result += data.toString();
    });
    client.once('error', reject);
    client.once('close', () => {
      resolve(result);
    });
  });
}
const verify = `${JSON.stringify({ reason: 'HOSTNAME', type: 'ssh-ed25519', key: key.split(' ')[1] })}\n`;
describe('Browser KnownHostsCommand bridge', () => {
  let helper: BrowserKnownHosts | undefined;
  afterEach(async () => {
    await helper?.close();
  });
  it('should return only the browser-approved key for the fixed destination', async () => {
    helper = await createBrowserKnownHosts(
      { host: 'server', port: 2222 },
      (offered) => Promise.resolve(offered ?? null),
    );
    expect(
      JSON.parse(await exchange(helper.path, '{"reason":"ORDER"}\n')),
    ).to.deep.equal({ line: '' });
    expect(JSON.parse(await exchange(helper.path, verify))).to.deep.equal({
      line: `[server]:2222 ${key}`,
    });
  });
  it('should reject unapproved keys, malformed and oversized input', async () => {
    helper = await createBrowserKnownHosts({ host: 'server', port: 22 }, () =>
      Promise.resolve(null),
    );
    expect(await exchange(helper.path, verify)).to.equal('');
    expect(await exchange(helper.path, '{"reason":"ADDRESS"}\n')).to.equal('');
    expect(await exchange(helper.path, 'x'.repeat(10001))).to.equal('');
  });
  it('should isolate session approvals and remove private sockets on cleanup', async () => {
    helper = await createBrowserKnownHosts({ host: 'server', port: 22 }, () =>
      Promise.resolve(key),
    );
    const other = await createBrowserKnownHosts(
      { host: 'server', port: 22 },
      () => Promise.resolve(null),
    );
    try {
      expect((await stat(helper.path)).mode % 0o1000).to.equal(0o600);
      expect(
        (await stat(helper.path.slice(0, helper.path.lastIndexOf('/')))).mode %
          0o1000,
      ).to.equal(0o700);
      expect(await exchange(other.path, verify)).to.equal('');
      expect(await exchange(helper.path, verify)).to.contain(key);
    } finally {
      await other.close();
    }
    await helper.close();
    await helper.close();
    expect((await Promise.allSettled([stat(helper.path)]))[0].status).to.equal(
      'rejected',
    );
  });
});

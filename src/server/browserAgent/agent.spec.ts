import { once } from 'node:events';
import { stat } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { dirname } from 'node:path';
import { expect } from 'chai';
import { IDBFactory } from 'fake-indexeddb';
import 'mocha';
import { loadSshKey } from '../../client/wetty/auth/keys';
import { publicBlob, Reader, sshString } from '../../shared/browserAgent';
import { createBrowserAgent } from './agent';
import type { BrowserAgent } from './agent';
import type { BrowserSshKey } from '../../client/wetty/auth/keys';

function authData(blob: Uint8Array, user = 'test'): Uint8Array {
  return new Uint8Array([
    ...sshString(new Uint8Array(32)),
    50,
    ...sshString(user),
    ...sshString('ssh-connection'),
    ...sshString('publickey'),
    1,
    ...sshString('rsa-sha2-256'),
    ...sshString(blob),
  ]);
}

function signPacket(blob: Uint8Array, flags = 2, user = 'test'): Uint8Array {
  return new Uint8Array([
    13,
    ...sshString(blob),
    ...sshString(authData(blob, user)),
    0,
    0,
    0,
    flags,
  ]);
}

async function request(
  path: string,
  packet: Uint8Array,
  fragmented = false,
): Promise<Buffer> {
  const client = createConnection(path);
  try {
    await once(client, 'connect');
    return await new Promise<Buffer>((resolve, reject) => {
      let result = Buffer.alloc(0);
      client.setTimeout(2000, () => {
        reject(new Error('Agent reply timed out'));
      });
      client.on('error', reject);
      client.on('data', (data: Buffer) => {
        result = Buffer.concat([result, data]);
        if (
          result.length >= 4 &&
          result.length === result.readUInt32BE(0) + 4
        ) {
          resolve(result.subarray(4));
        }
      });
      const frame = sshString(packet);
      if (fragmented) {
        client.write(frame.subarray(0, 2));
        setImmediate(() => client.write(frame.subarray(2)));
      } else client.write(frame);
    });
  } finally {
    client.destroy();
  }
}

describe('Browser SSH agent', function agentSuite() {
  this.timeout(10000);
  let key: BrowserSshKey;
  let blob: Uint8Array;
  let agent: BrowserAgent;
  let signs = 0;
  before(async () => {
    key = await loadSshKey('agent-tests', new IDBFactory());
    blob = publicBlob(await key.publicKey());
  });
  beforeEach(async () => {
    signs = 0;
    agent = await createBrowserAgent(blob, 'test', (data) => {
      signs += 1;
      return key.sign(data);
    });
  });
  afterEach(async () => {
    await agent.close();
  });

  it('should advertise exactly the enrolled public key across fragmented frames', async () => {
    const reader = new Reader(
      await request(agent.path, new Uint8Array([11]), true),
    );
    expect(reader.byte()).to.equal(12);
    expect(reader.uint32()).to.equal(1);
    expect(reader.string()).to.deep.equal(blob);
    reader.text();
    reader.end();
  });

  it('should return a verified RSA SHA-256 signature with agent framing', async () => {
    const reader = new Reader(await request(agent.path, signPacket(blob)));
    expect(reader.byte()).to.equal(14);
    const signature = new Reader(reader.string());
    reader.end();
    expect(signature.text()).to.equal('rsa-sha2-256');
    expect(await key.verify(authData(blob), signature.string())).to.be.true;
    signature.end();
    expect(signs).to.equal(1);
  });

  it('should refuse SHA-1, SHA-512 and combined flags without signing', async () => {
    const replies = await Promise.all(
      [0, 4, 6].map((flags) => request(agent.path, signPacket(blob, flags))),
    );
    replies.forEach((reply) => expect([...reply]).to.deep.equal([5]));
    expect(signs).to.equal(0);
  });

  it('should refuse requests for a different SSH user', async () => {
    expect([
      ...(await request(agent.path, signPacket(blob, 2, 'other'))),
    ]).to.deep.equal([5]);
    expect(signs).to.equal(0);
  });

  it('should refuse extension and identity mutation operations', async () => {
    const replies = await Promise.all(
      [17, 19, 27].map((type) => request(agent.path, new Uint8Array([type]))),
    );
    replies.forEach((reply) => expect([...reply]).to.deep.equal([5]));
    expect(signs).to.equal(0);
  });

  it('should reject invalid signatures from a browser', async () => {
    const invalid = await createBrowserAgent(blob, 'test', () =>
      Promise.resolve(new Uint8Array(384)),
    );
    try {
      expect([
        ...(await request(invalid.path, signPacket(blob))),
      ]).to.deep.equal([5]);
    } finally {
      await invalid.close();
    }
  });

  it('should use private filesystem permissions and clean up idempotently', async () => {
    expect((await stat(agent.path)).mode % 512).to.equal(0o600);
    expect((await stat(dirname(agent.path))).mode % 512).to.equal(0o700);
    await Promise.all([agent.close(), agent.close()]);
    let exists = true;
    try {
      await stat(dirname(agent.path));
    } catch {
      exists = false;
    }
    expect(exists).to.be.false;
  });

  it('should close malformed oversized frames', async () => {
    const client = createConnection(agent.path);
    await once(client, 'connect');
    const closed = once(client, 'close');
    client.write(new Uint8Array([127, 255, 255, 255]));
    await closed;
    expect(signs).to.equal(0);
  });
});

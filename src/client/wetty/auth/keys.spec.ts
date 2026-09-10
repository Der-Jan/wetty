import { createPublicKey, verify } from 'node:crypto';
import { expect } from 'chai';
import { IDBFactory } from 'fake-indexeddb';
import 'mocha';
import * as sinon from 'sinon';
import { loadSshKey } from './keys';

function database(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open('wetty-ssh-keys', 1);
    request.onsuccess = () => {
      resolve(request.result);
    };
    request.onerror = () => {
      reject(new Error(request.error?.message ?? 'Database request failed'));
    };
  });
}

async function storedPair(
  factory: IDBFactory,
  scope: string,
): Promise<CryptoKeyPair> {
  const db = await database(factory);
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction('keys').objectStore('keys').get(scope);
      request.onsuccess = () => {
        resolve(request.result as CryptoKeyPair);
      };
      request.onerror = () => {
        reject(new Error(request.error?.message ?? 'Database request failed'));
      };
    });
  } finally {
    db.close();
  }
}

async function replaceRecord(
  factory: IDBFactory,
  scope: string,
  value: unknown,
): Promise<void> {
  const db = await database(factory);
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction('keys', 'readwrite');
      transaction.oncomplete = () => {
        resolve();
      };
      transaction.onabort = () => {
        reject(new Error(transaction.error?.message ?? 'Transaction failed'));
      };
      transaction.objectStore('keys').put(value, scope);
    });
  } finally {
    db.close();
  }
}

async function failure(operation: Promise<unknown>): Promise<Error> {
  try {
    await operation;
  } catch (error) {
    expect(error).to.be.instanceOf(Error);
    return error as Error;
  }
  throw new Error('Expected operation to reject');
}

// Decode independently using Node Buffers, not the production encoder.
function decodePublic(line: string): { n: string; e: string } {
  const [type, encoded] = line.split(' ');
  expect(type).to.equal('ssh-rsa');
  const blob = Buffer.from(encoded, 'base64');
  let offset = 0;
  const field = (): Buffer => {
    const length = blob.readUInt32BE(offset);
    offset += 4;
    const value = blob.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  expect(field().toString()).to.equal('ssh-rsa');
  const exponent = field();
  const modulus = field();
  expect(exponent).to.deep.equal(Buffer.from([1, 0, 1]));
  expect(modulus.length).to.equal(385);
  expect(modulus[0]).to.equal(0);
  expect(modulus[1]).to.be.at.least(0x80);
  expect(offset).to.equal(blob.length);
  return {
    e: exponent.toString('base64url'),
    n: modulus.subarray(1).toString('base64url'),
  };
}

describe('Browser SSH keys', function keysSuite() {
  this.timeout(30000);
  let factory: IDBFactory;

  beforeEach(() => {
    factory = new IDBFactory();
  });

  afterEach(() => {
    sinon.restore();
  });

  it('should persist non-extractable CryptoKeys and refuse private export', async () => {
    const key = await loadSshKey('alice', factory);
    const pair = await storedPair(factory, 'alice');
    expect(pair.privateKey).to.be.instanceOf(CryptoKey);
    expect(pair.privateKey.extractable).to.be.false;
    expect(pair.privateKey.usages).to.deep.equal(['sign']);
    expect(key.privateKeyExtractable).to.be.false;
    expect(pair.publicKey.extractable).to.be.true;
    expect(
      (await failure(crypto.subtle.exportKey('jwk', pair.privateKey))).name,
    ).to.equal('InvalidAccessError');
    expect(
      (await failure(crypto.subtle.exportKey('pkcs8', pair.privateKey))).name,
    ).to.equal('InvalidAccessError');
  });

  it('should export valid OpenSSH RSA and sign exact binary bytes with SHA-256', async () => {
    const key = await loadSshKey('alice', factory);
    const jwk = decodePublic(await key.publicKey());
    const publicKey = createPublicKey({
      key: { kty: 'RSA', ...jwk },
      format: 'jwk',
    });
    const data = new Uint8Array([99, 0, 128, 255, 10, 88]).subarray(1, 5);
    const signature = await key.sign(data);
    expect(signature.length).to.equal(384);
    expect(verify('RSA-SHA256', data, publicKey, signature)).to.be.true;
    expect(verify('RSA-SHA512', data, publicKey, signature)).to.be.false;
    expect(await key.verify(data, signature)).to.be.true;
    expect(await key.verify(new Uint8Array([0]), signature)).to.be.false;
  });

  it('should reload the same key without generating another pair', async () => {
    const first = await loadSshKey('alice', factory);
    const generate = sinon.spy(crypto.subtle, 'generateKey');
    const second = await loadSshKey('alice', factory);
    expect(await second.publicKey()).to.equal(await first.publicKey());
    expect(generate.called).to.be.false;
    const data = new Uint8Array([1, 2, 3]);
    expect(await first.verify(data, await second.sign(data))).to.be.true;
  });

  it('should converge on one persisted key during concurrent initialization', async () => {
    const keys = await Promise.all([
      loadSshKey('alice', factory),
      loadSshKey('alice', factory),
      loadSshKey('alice', factory),
    ]);
    const exported = await Promise.all(keys.map((key) => key.publicKey()));
    expect(new Set(exported).size).to.equal(1);
    expect(await (await loadSshKey('alice', factory)).publicKey()).to.equal(
      exported[0],
    );
  });

  it('should isolate storage scopes', async () => {
    const alice = await loadSshKey('alice', factory);
    const bob = await loadSshKey('bob', factory);
    expect(await alice.publicKey()).not.to.equal(await bob.publicKey());
  });

  it('should reject malformed records without replacing them', async () => {
    await loadSshKey('alice', factory);
    await replaceRecord(factory, 'alice', { version: 99 });
    const generate = sinon.spy(crypto.subtle, 'generateKey');
    expect((await failure(loadSshKey('alice', factory))).message).to.include(
      'invalid',
    );
    expect(generate.called).to.be.false;
  });

  it('should reject mismatched persisted key pairs', async () => {
    await loadSshKey('alice', factory);
    await loadSshKey('bob', factory);
    const alice = await storedPair(factory, 'alice');
    const bob = await storedPair(factory, 'bob');
    await replaceRecord(factory, 'alice', {
      version: 1,
      privateKey: alice.privateKey,
      publicKey: bob.publicKey,
    });
    expect((await failure(loadSshKey('alice', factory))).message).to.include(
      'verification',
    );
  });

  it('should reject an extractable stored private key', async () => {
    await loadSshKey('alice', factory);
    const pair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 3072,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    );
    await replaceRecord(factory, 'alice', { version: 1, ...pair });
    expect((await failure(loadSshKey('alice', factory))).message).to.include(
      'invalid',
    );
  });

  it('should reject unavailable storage without generating a key', async () => {
    sinon
      .stub(factory, 'open')
      .throws(new DOMException('Storage denied', 'SecurityError'));
    const generate = sinon.spy(crypto.subtle, 'generateKey');
    expect((await failure(loadSshKey('alice', factory))).name).to.equal(
      'SecurityError',
    );
    expect(generate.called).to.be.false;
  });

  it('should reject a failed storage commit without returning an ephemeral key', async () => {
    await loadSshKey('seed', factory);
    const db = await database(factory);
    const transaction = db.transaction('keys', 'readwrite');
    const store = transaction.objectStore('keys');
    // Abort after a successful add request but before the transaction commits.
    const prototype = Object.getPrototypeOf(store) as IDBObjectStore;
    // Preserve the method to invoke with the live transaction below.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const original = prototype.add;
    sinon.stub(prototype, 'add').callsFake(function abortWrite(
      this: IDBObjectStore,
      value: unknown,
      key?: IDBValidKey,
    ) {
      const request = original.call(this, value, key);
      request.onsuccess = () => {
        this.transaction.abort();
      };
      return request;
    });
    db.close();
    expect((await failure(loadSshKey('alice', factory))).message).to.include(
      'aborted',
    );
  });

  it('should require an explicit scope', async () => {
    expect((await failure(loadSshKey(' ', factory))).message).to.include(
      'scope',
    );
  });
});

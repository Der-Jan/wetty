import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import 'mocha';
import { fields, sshString } from '../../../shared/browserAgent';
import {
  listImportedKeys,
  prepareImportedKey,
  saveImportedKey,
  signImportedKey,
} from './importedKeys';

function fixture(rsa = false) {
  const pair = rsa
    ? generateKeyPairSync('rsa', { modulusLength: 2048 })
    : generateKeyPairSync('ed25519');
  const jwk = pair.privateKey.export({ format: 'jwk' });
  const decode = (name: string): Uint8Array =>
    Buffer.from(String(fields(jwk)[name]), 'base64url');
  const integer = (name: string): Uint8Array => {
    const value = decode(name);
    return sshString(value[0] >= 128 ? new Uint8Array([0, ...value]) : value);
  };
  const packet = new Uint8Array([
    17,
    ...sshString(rsa ? 'ssh-rsa' : 'ssh-ed25519'),
    ...(rsa
      ? ['n', 'e', 'd', 'qi', 'p', 'q'].flatMap((name) => [...integer(name)])
      : [
          ...sshString(decode('x')),
          ...sshString(new Uint8Array([...decode('d'), ...decode('x')])),
        ]),
    ...sshString('import test'),
  ]);
  return { ...pair, packet };
}
describe('Imported SSH key storage', function importedSuite() {
  this.timeout(10000);
  let original: IDBFactory;
  beforeEach(() => {
    original = globalThis.indexedDB;
    globalThis.indexedDB = new IDBFactory();
  });
  afterEach(() => {
    globalThis.indexedDB = original;
  });
  it('should persist a non-extractable Ed25519 key and verify signatures after reload', async () => {
    const source = fixture();
    const key = await prepareImportedKey(source.packet);
    await saveImportedKey(key, new AbortController().signal);
    const [loaded] = await listImportedKeys();
    const privateKey = loaded.keys['ssh-ed25519'];
    assert(privateKey);
    assert.equal(privateKey.extractable, false);
    await assert.rejects(crypto.subtle.exportKey('jwk', privateKey));
    const data = new Uint8Array([1, 2, 3]);
    assert(
      verify(
        null,
        data,
        source.publicKey,
        await signImportedKey(loaded, 'ssh-ed25519', data),
      ),
    );
  });
  it('should support both SHA-256 and SHA-512 for imported RSA keys', async () => {
    const source = fixture(true);
    const key = await prepareImportedKey(source.packet);
    await saveImportedKey(key, new AbortController().signal);
    const [loaded] = await listImportedKeys();
    await Promise.all(
      (['rsa-sha2-256', 'rsa-sha2-512'] as const).map(async (algorithm) => {
        const privateKey = loaded.keys[algorithm];
        assert(privateKey);
        assert.equal(privateKey.extractable, false);
        await assert.rejects(crypto.subtle.exportKey('jwk', privateKey));
        const data = new Uint8Array([4, 5, 6]);
        assert(
          verify(
            algorithm === 'rsa-sha2-256' ? 'RSA-SHA256' : 'RSA-SHA512',
            data,
            source.publicKey,
            await signImportedKey(loaded, algorithm, data),
          ),
        );
      }),
    );
  });
  it('should reject constraints, truncated packets and inconsistent private material', async () => {
    const source = fixture();
    const constrained = source.packet.slice();
    constrained[0] = 25;
    const inconsistent = source.packet.slice();
    inconsistent[60] = (inconsistent[60] + 1) % 256;
    await assert.rejects(prepareImportedKey(constrained));
    await assert.rejects(prepareImportedKey(source.packet.slice(0, 10)));
    await assert.rejects(prepareImportedKey(inconsistent));
    assert.equal((await listImportedKeys()).length, 0);
  });
  it('should refuse storage after cancellation and deduplicate repeated imports', async () => {
    const key = await prepareImportedKey(fixture().packet);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(saveImportedKey(key, controller.signal));
    await Promise.all([
      saveImportedKey(key, new AbortController().signal),
      saveImportedKey(key, new AbortController().signal),
    ]);
    assert.equal((await listImportedKeys()).length, 1);
  });
  it('should enforce the persistent key limit across concurrent transactions', async () => {
    const keys = await Promise.all(
      Array.from({ length: 9 }, () => prepareImportedKey(fixture().packet)),
    );
    const results = await Promise.allSettled(
      keys.map((key) => saveImportedKey(key, new AbortController().signal)),
    );
    assert.equal(
      results.filter((result) => result.status === 'fulfilled').length,
      8,
    );
    assert.equal((await listImportedKeys()).length, 8);
  });
});

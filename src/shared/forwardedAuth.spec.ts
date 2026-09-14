import assert from 'node:assert/strict';
import 'mocha';
import { checkUserAuth, sshString } from './browserAgent.js';
import { checkForwardedAuth } from './forwardedAuth.js';

const key = new Uint8Array([
  ...sshString('ssh-ed25519'),
  ...sshString(new Uint8Array(32).fill(1)),
]);
const host = new Uint8Array([
  ...sshString('ssh-ed25519'),
  ...sshString(new Uint8Array(32).fill(2)),
]);
function payload(
  method = 'publickey-hostbound-v00@openssh.com',
  extra = sshString(host),
): Uint8Array {
  return new Uint8Array([
    ...sshString(new Uint8Array(32)),
    50,
    ...sshString('git'),
    ...sshString('ssh-connection'),
    ...sshString(method),
    1,
    ...sshString('ssh-ed25519'),
    ...sshString(key),
    ...extra,
  ]);
}
describe('Forwarded host-bound SSH authentication', () => {
  it('should accept both ordinary and host-bound authentication without modifying the original bytes', () => {
    const data = payload();
    const original = data.slice();
    assert.equal(checkForwardedAuth(data, key, 'ssh-ed25519'), 'git');
    assert.deepEqual(data, original);
    assert.equal(
      checkForwardedAuth(
        payload('publickey', new Uint8Array()),
        key,
        'ssh-ed25519',
      ),
      'git',
    );
  });
  it('should keep the initial-login validator restricted to unbound authentication', () => {
    assert.throws(() => checkUserAuth(payload(), 'git', key, 'ssh-ed25519'));
  });
  it('should reject missing, malformed and trailing host-key fields', () => {
    assert.throws(() =>
      checkForwardedAuth(
        payload('publickey-hostbound-v00@openssh.com', new Uint8Array()),
        key,
        'ssh-ed25519',
      ),
    );
    assert.throws(() =>
      checkForwardedAuth(
        payload(
          'publickey-hostbound-v00@openssh.com',
          sshString(new Uint8Array([1])),
        ),
        key,
        'ssh-ed25519',
      ),
    );
    assert.throws(() =>
      checkForwardedAuth(new Uint8Array([...payload(), 0]), key, 'ssh-ed25519'),
    );
  });
  it('should reject other methods, keys, algorithms and oversized payloads', () => {
    assert.throws(() =>
      checkForwardedAuth(payload('hostbased'), key, 'ssh-ed25519'),
    );
    assert.throws(() => checkForwardedAuth(payload(), host, 'ssh-ed25519'));
    assert.throws(() => checkForwardedAuth(payload(), key, 'rsa-sha2-256'));
    assert.throws(() =>
      checkForwardedAuth(new Uint8Array(32769), key, 'ssh-ed25519'),
    );
  });
});

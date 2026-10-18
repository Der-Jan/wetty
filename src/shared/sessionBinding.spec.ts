import assert from 'node:assert/strict';
import 'mocha';
import { verifySessionBinding } from './sessionBinding';
import { bindingHost, bindingSession } from './sessionBinding.test-utils';

describe('OpenSSH session binding proof verification', () => {
  for (const kind of ['ed25519', 'rsa', 'nistp256', 'nistp384', 'nistp521']) {
    it(`verifies ${kind} proofs and rejects tampering`, async () => {
      const host = bindingHost(kind);
      const result = await verifySessionBinding(host.packet());
      assert.deepEqual(result, {
        host: host.host,
        session: bindingSession,
        forwarded: false,
      });
      const corrupt = host.packet();
      corrupt[corrupt.length - 2] = (corrupt[corrupt.length - 2] + 1) % 256;
      await assert.rejects(verifySessionBinding(corrupt));
    });
  }
  it('accepts RSA SHA-512 and rejects trailing data and invalid forwarding flags', async () => {
    const host = bindingHost('rsa');
    await verifySessionBinding(host.packet(bindingSession, true, 'sha512'));
    await assert.rejects(
      verifySessionBinding(new Uint8Array([...host.packet(), 0])),
    );
    const packet = host.packet();
    packet[packet.length - 1] = 2;
    await assert.rejects(verifySessionBinding(packet));
    await assert.rejects(verifySessionBinding(host.packet(new Uint8Array(15))));
  });
});

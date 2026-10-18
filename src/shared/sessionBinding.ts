import { bytes, Reader } from './browserAgent.js';
import { base64url, publicIdentity, webAlgorithm } from './importedKeys.js';

export interface SessionBinding {
  host: Uint8Array;
  session: Uint8Array;
  forwarded: boolean;
}

function positive(reader: Reader, width: number): Uint8Array<ArrayBuffer> {
  const value = reader.string();
  if (
    !value.length ||
    value[0] >= 128 ||
    (value[0] === 0 && (value.length === 1 || value[1] < 128))
  ) {
    throw new Error('Invalid SSH integer');
  }
  const magnitude = value[0] === 0 ? value.slice(1) : value;
  if (magnitude.length > width) throw new Error('SSH integer exceeds limit');
  return magnitude;
}

/** Verify OpenSSH PROTOCOL.agent's proof using browser WebCrypto, not a
 * backend assertion. This proves key possession, not hostname trust.
 * Certificates and security-key host formats are deliberately unsupported.
 */
export async function verifySessionBinding(
  packet: Uint8Array,
): Promise<SessionBinding> {
  const reader = new Reader(bytes(packet, 16384));
  if (reader.byte() !== 27 || reader.text() !== 'session-bind@openssh.com') {
    throw new Error('Unsupported agent extension');
  }
  const host = reader.string();
  const session = reader.string();
  const signature = new Reader(reader.string());
  const algorithm = signature.text();
  let rawSignature = signature.string();
  signature.end();
  const flag = reader.byte();
  reader.end();
  if (
    host.length > 4096 ||
    session.length < 16 ||
    session.length > 128 ||
    flag > 1
  ) {
    throw new Error('Invalid session binding');
  }
  const keyReader = new Reader(host);
  const type = keyReader.text();
  let jwk: JsonWebKey;
  let keyAlgorithm:
    AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  let verification: AlgorithmIdentifier | EcdsaParams;
  if (type.startsWith('ecdsa-sha2-')) {
    const curve = keyReader.text();
    const curves: Record<string, [string, string, number] | undefined> = {
      nistp256: ['P-256', 'SHA-256', 32],
      nistp384: ['P-384', 'SHA-384', 48],
      nistp521: ['P-521', 'SHA-512', 66],
    };
    const parameters = curves[curve];
    if (!parameters || type !== `ecdsa-sha2-${curve}` || algorithm !== type) {
      throw new Error('Unsupported ECDSA host key');
    }
    const [namedCurve, hash, width] = parameters;
    const point = keyReader.string();
    keyReader.end();
    if (point.length !== 1 + 2 * width || point[0] !== 4) {
      throw new Error('Invalid EC point');
    }
    jwk = {
      kty: 'EC',
      crv: namedCurve,
      x: base64url(point.slice(1, 1 + width)),
      y: base64url(point.slice(1 + width)),
    };
    keyAlgorithm = { name: 'ECDSA', namedCurve };
    verification = { name: 'ECDSA', hash };
    const integers = new Reader(rawSignature);
    const r = positive(integers, width);
    const s = positive(integers, width);
    integers.end();
    rawSignature = new Uint8Array(width * 2);
    rawSignature.set(r, width - r.length);
    rawSignature.set(s, width * 2 - s.length);
  } else {
    jwk = publicIdentity(host).jwk;
    if (
      type === 'ssh-ed25519' &&
      algorithm === type &&
      rawSignature.length === 64
    ) {
      keyAlgorithm = 'Ed25519';
    } else if (
      type === 'ssh-rsa' &&
      (algorithm === 'rsa-sha2-256' || algorithm === 'rsa-sha2-512')
    ) {
      keyAlgorithm = webAlgorithm(algorithm);
      const width = Uint8Array.from(
        atob(String(jwk.n).replace(/-/g, '+').replace(/_/g, '/')),
        (c) => c.charCodeAt(0),
      ).length;
      if (rawSignature.length > width) {
        throw new Error('Invalid RSA signature width');
      }
      const padded = new Uint8Array(width);
      padded.set(rawSignature, width - rawSignature.length);
      rawSignature = padded;
    } else throw new Error('Unsupported host signature');
    verification = keyAlgorithm;
  }
  const key = await crypto.subtle.importKey('jwk', jwk, keyAlgorithm, false, [
    'verify',
  ]);
  if (!(await crypto.subtle.verify(verification, key, rawSignature, session))) {
    throw new Error('Invalid host session signature');
  }
  return { host, session, forwarded: flag === 1 };
}

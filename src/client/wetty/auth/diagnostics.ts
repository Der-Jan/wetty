import { BROWSER_KEY_SCOPE } from '../../../shared/browserAgent';
import { loadSshKey } from './keys';

/** Temporary, opt-in key diagnostics shared by the button and dev console. */
export async function diagnoseSshKey() {
  const key = await loadSshKey(BROWSER_KEY_SCOPE);
  const publicKey = await key.publicKey();
  const data = crypto.getRandomValues(new Uint8Array(32));
  const signature = await key.sign(data);
  const result = {
    keyExists: true,
    privateKeyNonExtractable: !key.privateKeyExtractable,
    publicKeyExportSucceeds: publicKey.startsWith('ssh-rsa '),
    signingAndVerificationSucceed: await key.verify(data, signature),
    publicKey,
  };
  // Only status and public material: never log CryptoKey objects or signatures.
  // eslint-disable-next-line no-console
  console.table(result);
  // Print an unadorned line for copying into authorized_keys.
  // eslint-disable-next-line no-console
  console.log(publicKey);
  return result;
}

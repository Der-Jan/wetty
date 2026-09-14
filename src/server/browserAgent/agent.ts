import { createPublicKey, verify } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  MAX_AGENT_PACKET,
  Reader,
  checkUserAuth,
  equalBytes,
  sshString,
} from '../../shared/browserAgent.js';
import { checkForwardedAuth } from '../../shared/forwardedAuth.js';
import { logger } from '../../shared/logger.js';
import type { Socket } from 'node:net';

export interface BrowserAgent {
  path: string;
  close(): Promise<void>;
}

/** The only private operation is delegated to the session's browser signer. */
export async function createBrowserAgent(
  blob: Uint8Array,
  user: string | undefined,
  sign: (data: Uint8Array) => Promise<Uint8Array>,
  handleForwarded?: (packet: Uint8Array) => Promise<Uint8Array>,
): Promise<BrowserAgent> {
  if (handleForwarded && user !== undefined) {
    throw new Error('Key management is forwarding-only');
  }
  const reader = new Reader(blob);
  if (reader.text() !== 'ssh-rsa') throw new Error('Expected RSA public key');
  const e = reader.string();
  const n = reader.string();
  reader.end();
  const publicKey = createPublicKey({
    format: 'jwk',
    key: {
      kty: 'RSA',
      e: Buffer.from(e).toString('base64url'),
      n: Buffer.from(n.subarray(n[0] === 0 ? 1 : 0)).toString('base64url'),
    },
  });
  const directory = await mkdtemp(join(tmpdir(), 'wetty-agent-'));
  const path = join(directory, 'agent');
  const clients = new Set<Socket>();
  let closed = false;
  let pending = 0;
  let closing: Promise<void> | undefined;
  const server = createServer((client) => {
    if (closed || clients.size >= 4) {
      client.destroy();
      return;
    }
    clients.add(client);
    client.setTimeout(user === undefined ? 65000 : 15000, () =>
      client.destroy(),
    );
    client.on('error', () => client.destroy());
    client.once('close', () => clients.delete(client));
    let buffer = Buffer.alloc(0);
    let queue = Promise.resolve();
    const available = (): boolean => !closed && !client.destroyed;
    const processPacket = async (packet: Buffer): Promise<void> => {
      try {
        if (closed || client.destroyed) return;
        let reply: Uint8Array = new Uint8Array([5]);
        const request = new Reader(packet);
        const type = request.byte();
        if (handleForwarded) {
          reply = await handleForwarded(packet);
        } else if (type === 11) {
          request.end();
          reply = new Uint8Array([
            12,
            0,
            0,
            0,
            1,
            ...sshString(blob),
            ...sshString('WeTTY browser key'),
          ]);
        } else if (type === 13) {
          const requestedKey = request.string();
          const data = request.string();
          const flags = request.uint32();
          request.end();
          if (flags === 2 && equalBytes(requestedKey, blob)) {
            if (user === undefined) checkForwardedAuth(data, blob);
            else checkUserAuth(data, user, blob);
            const signature = await sign(data);
            if (
              signature.length !== 384 ||
              !verify('RSA-SHA256', data, publicKey, signature)
            ) {
              throw new Error('Invalid browser signature');
            }
            reply = new Uint8Array([
              14,
              ...sshString(
                new Uint8Array([
                  ...sshString('rsa-sha2-256'),
                  ...sshString(signature),
                ]),
              ),
            ]);
          }
        }
        if (available()) client.write(sshString(reply));
      } catch (error) {
        logger().debug('Agent request failed', {
          reason: error instanceof Error ? error.message : 'Unknown',
        });
        if (available()) {
          client.write(sshString(new Uint8Array([5])));
        }
      } finally {
        if (packet[0] === 17 || packet[0] === 25) packet.fill(0);
        pending -= 1;
      }
    };
    client.on('data', (chunk: Buffer) => {
      if (buffer.length + chunk.length > MAX_AGENT_PACKET * 2) {
        client.destroy();
        return;
      }
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (length < 1 || length > MAX_AGENT_PACKET) {
          client.destroy();
          return;
        }
        if (buffer.length < length + 4) return;
        if (pending >= 8) {
          client.destroy();
          return;
        }
        const packet = Buffer.from(buffer.subarray(4, length + 4));
        buffer = buffer.subarray(length + 4);
        pending += 1;
        queue = queue.then(() => processPacket(packet));
      }
    });
  });
  const close = (): Promise<void> => {
    closing ??= (async () => {
      closed = true;
      for (const client of clients) client.destroy();
      if (server.listening) {
        await new Promise<void>((resolve) => {
          server.close(() => {
            resolve();
          });
        });
      }
      await rm(directory, { recursive: true, force: true });
    })();
    return closing;
  };
  try {
    await chmod(directory, 0o700);
    if (Buffer.byteLength(path) > 100) {
      throw new Error('SSH agent runtime path is too long');
    }
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(path, () => {
        server.removeListener('error', reject);
        resolve();
      });
    });
    server.on('error', () => {
      void close().catch(() => {
        /* Cleanup errors surface again to the session owner. */
      });
    });
    await chmod(path, 0o600);
    return { path, close };
  } catch (error) {
    await close();
    throw error;
  }
}

import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fields } from '../../shared/browserAgent.js';
import { hostKey, hostTarget } from '../../shared/hostKey.js';
import type { HostTarget } from '../../shared/hostKey.js';
import type { Socket } from 'node:net';

export interface BrowserKnownHosts {
  command: string;
  path: string;
  close(): Promise<void>;
}

export async function createBrowserKnownHosts(
  target: HostTarget,
  request: (key?: string) => Promise<unknown>,
): Promise<BrowserKnownHosts> {
  hostTarget(target);
  const directory = await mkdtemp(join(tmpdir(), 'wetty-hosts-'));
  const path = join(directory, 'socket');
  const clients = new Set<Socket>();
  let closing: Promise<void> | undefined;
  let count = 0;
  const server = createServer((client) => {
    count += 1;
    if (closing || clients.size >= 2 || count > 8) {
      client.destroy();
      return;
    }
    clients.add(client);
    client.on('error', () => client.destroy());
    client.once('close', () => clients.delete(client));
    client.setTimeout(125000, () => client.destroy());
    let buffer = '';
    let received = false;
    client.on('data', (chunk: Buffer) => {
      if (received || buffer.length + chunk.length > 10000) {
        client.destroy();
        return;
      }
      buffer += chunk.toString('utf8');
      if (!buffer.endsWith('\n')) return;
      received = true;
      void (async () => {
        const value = fields(JSON.parse(buffer));
        if (value.reason !== 'ORDER' && value.reason !== 'HOSTNAME') {
          throw new Error('Invalid host lookup');
        }
        const offered =
          value.reason === 'HOSTNAME'
            ? hostKey(`${String(value.type)} ${String(value.key)}`)
            : undefined;
        const response = await request(offered);
        const trusted =
          response === null && offered === undefined ? null : hostKey(response);
        if (offered !== undefined && offered !== trusted) {
          throw new Error('Host key not approved');
        }
        const name =
          target.port === 22
            ? target.host
            : `[${target.host}]:${String(target.port)}`;
        if (!closing && !client.destroyed) {
          client.end(
            `${JSON.stringify({ line: trusted ? `${name} ${trusted}` : '' })}\n`,
          );
        }
      })().catch(() => client.destroy());
    });
  });
  const close = (): Promise<void> => {
    closing ??= (async () => {
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
      throw new Error('Known hosts socket path too long');
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
        /* Report on owner cleanup. */
      });
    });
    await chmod(path, 0o600);
    // tsx runs the source integration tests; production uses the compiled helper.
    const source = import.meta.url.endsWith('.ts');
    const helper = fileURLToPath(
      new URL(`./knownHostsHelper.${source ? 'ts' : 'js'}`, import.meta.url),
    );
    const args = [
      process.execPath,
      ...(source ? ['--import', 'tsx'] : []),
      helper,
      path,
    ];
    const quote = (value: string): string =>
      `"${value.replace(/%/g, '%%').replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
    return { path, command: `${args.map(quote).join(' ')} %I %t %K`, close };
  } catch (error) {
    await close();
    throw error;
  }
}

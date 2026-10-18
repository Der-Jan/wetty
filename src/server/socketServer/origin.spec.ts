import { once } from 'node:events';
import { expect } from 'chai';
import express from 'express';
import 'mocha';
import { io } from 'socket.io-client';
import { listen } from './socket';
import type { AddressInfo } from 'node:net';

describe('Browser key handshake origin', () => {
  it('should require the configured origin on both Socket.IO transports', async () => {
    const server = listen(express(), {
      host: '127.0.0.1',
      port: 0,
      path: '',
      ssl: {},
      socket: false,
      browserOrigin: 'https://terminal.example',
    });
    try {
      await once(server.httpServer, 'listening');
      const address = server.httpServer.address() as AddressInfo;
      const connected = async (
        transport: string,
        headers: Record<string, string>,
      ): Promise<boolean> => {
        const client = io(`http://127.0.0.1:${String(address.port)}`, {
          transports: [transport],
          extraHeaders: headers,
          reconnection: false,
          timeout: 2000,
        });
        try {
          return await new Promise<boolean>((resolve) => {
            client.once('connect', () => {
              resolve(true);
            });
            client.once('connect_error', () => {
              resolve(false);
            });
          });
        } finally {
          client.disconnect();
        }
      };
      const sameOrigin = {
        'Sec-Fetch-Site': 'same-origin',
        Referer: 'https://terminal.example/',
      };
      await Promise.all(
        ['polling', 'websocket'].map(async (transport) => {
          const cases: [Record<string, string>, boolean][] = [
            [{ Origin: 'https://terminal.example' }, true],
            [{ Origin: 'https://attacker.example' }, false],
            // The client connects to loopback, so its Host is not pinned.
            // Fetch Metadata and Referer alone must not bypass Host validation.
            [sameOrigin, false],
            [{ ...sameOrigin, Origin: 'https://attacker.example' }, false],
            [{ ...sameOrigin, Origin: 'null' }, false],
            [{ ...sameOrigin, Referer: 'https://attacker.example/' }, false],
            [{ ...sameOrigin, Referer: 'invalid' }, false],
            [{ ...sameOrigin, 'Sec-Fetch-Site': 'same-site' }, false],
            [{ ...sameOrigin, 'Sec-Fetch-Site': 'cross-site' }, false],
            [{ 'Sec-Fetch-Site': 'same-origin' }, false],
            [{ Referer: sameOrigin.Referer }, false],
            [{}, false],
          ];
          await Promise.all(
            cases.map(async ([headers, expected]) => {
              expect(
                await connected(transport, headers),
                `${transport}: ${JSON.stringify(headers)}`,
              ).to.equal(expected);
            }),
          );
        }),
      );
    } finally {
      await server.close();
    }
  });
});

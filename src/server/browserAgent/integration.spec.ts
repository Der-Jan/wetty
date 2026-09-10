import { EventEmitter } from 'node:events';
import { expect } from 'chai';
import 'mocha';
import { sshDefault } from '../../shared/defaults';
import { browserSshIntegration } from './integration';
import { browserOriginOptions } from './origin';
import type { Server, Socket } from 'socket.io';

function socket() {
  const client = Object.assign(new EventEmitter(), { connected: true });
  return Object.assign(client, {
    disconnect: () => {
      if (client.connected) {
        client.connected = false;
        client.emit('disconnect');
      }
    },
  });
}

describe('Browser SSH server integration', () => {
  it('should leave legacy authentication and origin handling untouched', async () => {
    const integration = await browserSshIntegration({
      ...sshDefault,
      auth: 'password',
      knownHosts: '/dev/null',
    });
    const http = new EventEmitter();
    let closed = 0;
    const sessions = integration.attach(
      { httpServer: http } as unknown as Server,
      'login',
      () => {
        closed += 1;
      },
    );
    const client = socket();
    expect(integration.origin).to.equal(undefined);
    expect(browserOriginOptions(integration.origin)).to.deep.equal({});
    expect(sessions.handle(client as unknown as Socket)).to.equal(false);
    await sessions.close();
    expect(client.connected).to.equal(true);
    expect(http.listenerCount('close')).to.equal(0);
    expect(closed).to.equal(0);
  });
  it('should close all pending browser sessions on server shutdown exactly once', async () => {
    const integration = await browserSshIntegration({
      ...sshDefault,
      auth: 'browser-key',
      user: 'fixed',
      host: 'server',
      knownHosts: 'browser',
      browserOrigin: 'https://terminal.example',
    });
    const http = new EventEmitter();
    let closed = 0;
    const sessions = integration.attach(
      { httpServer: http } as unknown as Server,
      'login',
      () => {
        closed += 1;
      },
    );
    const first = socket();
    const second = socket();
    expect(sessions.handle(first as unknown as Socket)).to.equal(true);
    expect(sessions.handle(second as unknown as Socket)).to.equal(true);
    http.emit('close');
    await sessions.close();
    await sessions.close();
    expect(first.connected).to.equal(false);
    expect(second.connected).to.equal(false);
    expect(first.listenerCount('browser-key:hello')).to.equal(0);
    expect(second.listenerCount('browser-key:hello')).to.equal(0);
    expect(closed).to.equal(2);
  });
});

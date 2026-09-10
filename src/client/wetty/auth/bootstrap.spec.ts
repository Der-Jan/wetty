import { EventEmitter } from 'node:events';
import { expect } from 'chai';
import { JSDOM } from 'jsdom';
import 'mocha';
import { setupBrowserSsh } from './bootstrap';
import type { Socket } from 'socket.io-client';

describe('Browser SSH initialization', () => {
  it('should install the feature once and notify the backend after terminal setup on each connection', () => {
    const previousWindow = globalThis.window;
    const previousDocument = globalThis.document;
    const dom = new JSDOM('<!doctype html><body></body>');
    globalThis.window = dom.window as unknown as Window & typeof globalThis;
    globalThis.document = dom.window.document;
    const socket = Object.assign(new EventEmitter(), {
      connected: true,
      id: 'connection',
    });
    try {
      const events: string[] = [];
      socket.on('connect', () => {
        events.push('terminal');
      });
      socket.on('browser-key:hello', () => {
        events.push('hello');
      });
      setupBrowserSsh(socket as unknown as Socket);
      setupBrowserSsh(socket as unknown as Socket);
      expect(document.querySelectorAll('#ssh-key-tools')).to.have.length(1);
      expect(socket.listenerCount('browser-key:prepare')).to.equal(1);
      expect(socket.listenerCount('browser-key:sign')).to.equal(1);
      expect(socket.listenerCount('browser-host:request')).to.equal(1);
      socket.emit('connect');
      socket.emit('disconnect');
      socket.emit('connect');
      expect(events).to.deep.equal(['terminal', 'hello', 'terminal', 'hello']);
    } finally {
      socket.emit('disconnect');
      dom.window.close();
      globalThis.window = previousWindow;
      globalThis.document = previousDocument;
    }
  });
});

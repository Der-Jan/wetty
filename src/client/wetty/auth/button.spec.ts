import { EventEmitter } from 'node:events';
import { expect } from 'chai';
import { IDBFactory } from 'fake-indexeddb';
import { JSDOM } from 'jsdom';
import 'mocha';
import sinon from 'sinon';
import { setupSshKeyButton } from './button';
import type { Term } from '../term';

describe('Public key paste button', function buttonSuite() {
  this.timeout(10000);
  let dom: JSDOM;
  let previousWindow: Window & typeof globalThis;
  let previousDocument: Document;
  let previousFactory: IDBFactory;
  let button: HTMLButtonElement;
  const sandbox = sinon.createSandbox();
  beforeEach(() => {
    previousWindow = globalThis.window;
    previousDocument = globalThis.document;
    previousFactory = globalThis.indexedDB;
    dom = new JSDOM(
      '<button id="ssh-key-create"><i class="fa-key"></i></button><p id="ssh-key-status"></p>',
    );
    globalThis.window = dom.window as unknown as Window & typeof globalThis;
    globalThis.document = dom.window.document;
    globalThis.indexedDB = new IDBFactory();
    sandbox.stub(console, 'table');
    sandbox.stub(console, 'log');
    const element = document.querySelector('button');
    if (!element) throw new Error('Missing key button');
    button = element;
    setupSshKeyButton();
  });
  afterEach(() => {
    sandbox.restore();
    dom.window.close();
    globalThis.window = previousWindow;
    globalThis.document = previousDocument;
    globalThis.indexedDB = previousFactory;
  });
  function terminal() {
    const input = new EventEmitter();
    const term = {
      socket: Object.assign(new EventEmitter(), {
        id: 'first',
        connected: true,
      }),
      input,
      onData: (listener: (data: string) => void) => {
        input.on('data', listener);
        return {
          dispose: () => {
            input.off('data', listener);
          },
        };
      },
      paste: sandbox.spy((text: string) => {
        input.emit('data', text);
      }),
      focus: sandbox.spy(),
    };
    window.wetty_term = term as unknown as Term;
    return term;
  }
  function click(): Promise<void> {
    return new Promise((resolve) => {
      const observer = new dom.window.MutationObserver(() => {
        if (!button.disabled) {
          observer.disconnect();
          resolve();
        }
      });
      observer.observe(button, { attributes: true });
      button.click();
    });
  }
  it('should paste only the public key without Enter and preserve the key icon', async () => {
    const term = terminal();
    const icon = button.querySelector('i');
    await click();
    expect(term.paste.calledOnce).to.equal(true);
    const [value] = term.paste.firstCall.args;
    expect(value).to.match(/^ssh-rsa [A-Za-z0-9+/]+={0,2}$/);
    expect(term.focus.calledOnce).to.equal(true);
    expect(button.querySelector('i')).to.equal(icon);
    expect(button.hasAttribute('aria-busy')).to.equal(false);
  });
  it('should keep console output available without a connected terminal', async () => {
    await click();
    expect(document.getElementById('ssh-key-status')?.textContent).to.contain(
      'browser console',
    );
  });
  it('should never paste into a replacement session after reconnect', async () => {
    const old = terminal();
    const done = click();
    old.socket.connected = false;
    const replacement = terminal();
    replacement.socket.id = 'second';
    await done;
    expect(old.paste.called).to.equal(false);
    expect(replacement.paste.called).to.equal(false);
    expect(document.getElementById('ssh-key-status')?.textContent).to.contain(
      'browser console',
    );
  });
  it('should dismiss the paste confirmation on the next terminal input', async () => {
    const term = terminal();
    await click();
    expect(document.getElementById('ssh-key-status')?.textContent).to.contain(
      'Public key pasted',
    );
    term.input.emit('data', 'x');
    expect(document.getElementById('ssh-key-status')?.textContent).to.equal('');
    expect(term.input.listenerCount('data')).to.equal(0);
    expect(term.socket.listenerCount('disconnect')).to.equal(0);
  });
  it('should expire the confirmation after five seconds and reset on another click', async () => {
    const clock = sandbox.useFakeTimers({
      toFake: ['setTimeout', 'clearTimeout'],
    });
    const term = terminal();
    await click();
    clock.tick(4000);
    await click();
    clock.tick(1000);
    expect(document.getElementById('ssh-key-status')?.textContent).to.contain(
      'Public key pasted',
    );
    clock.tick(4000);
    expect(document.getElementById('ssh-key-status')?.textContent).to.equal('');
    expect(term.input.listenerCount('data')).to.equal(0);
    expect(term.socket.listenerCount('disconnect')).to.equal(0);
  });
  it('should clear the confirmation and input listener on disconnect', async () => {
    const term = terminal();
    await click();
    term.socket.emit('disconnect');
    expect(document.getElementById('ssh-key-status')?.textContent).to.equal('');
    expect(term.input.listenerCount('data')).to.equal(0);
  });
});

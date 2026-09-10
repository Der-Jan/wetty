import { expect } from 'chai';
import { JSDOM } from 'jsdom';
import 'mocha';
import { sshString } from '../../../shared/browserAgent';
import { hostFingerprint } from '../../../shared/hostKey';
import { promptHostTrust } from './hostPrompt';

const key = (value: number): string =>
  `ssh-ed25519 ${btoa(String.fromCharCode(...new Uint8Array([...sshString('ssh-ed25519'), ...sshString(new Uint8Array(32).fill(value))])))}`;
describe('Host trust dialog', () => {
  let dom: JSDOM;
  let original: Document;
  beforeEach(() => {
    original = globalThis.document;
    dom = new JSDOM('<!doctype html><body></body>');
    globalThis.document = dom.window.document;
    dom.window.HTMLDialogElement.prototype.showModal = function showModal() {
      this.open = true;
    };
    dom.window.HTMLDialogElement.prototype.close = function close() {
      this.open = false;
    };
  });
  afterEach(() => {
    globalThis.document = original;
    dom.window.close();
  });
  async function open(previous?: string): Promise<{
    result: Promise<boolean>;
    controller: AbortController;
    dialog: HTMLDialogElement;
  }> {
    const controller = new AbortController();
    const visible = new Promise<HTMLDialogElement>((resolve) => {
      const observer = new dom.window.MutationObserver(() => {
        const dialog = document.querySelector('dialog');
        if (dialog) {
          observer.disconnect();
          resolve(dialog);
        }
      });
      observer.observe(document.body, { childList: true });
    });
    const result = promptHostTrust(
      { host: 'server.example', port: 2222 },
      key(1),
      previous,
      controller.signal,
    );
    return {
      result: Promise.resolve(result),
      controller,
      dialog: await visible,
    };
  }
  it('should show the destination and fingerprint and default focus to Cancel', async () => {
    const { result, dialog } = await open();
    expect(dialog.textContent)
      .to.contain('server.example')
      .and.contain('2222')
      .and.contain(await hostFingerprint(key(1)));
    const [cancel] = dialog.querySelectorAll('button');
    expect(document.activeElement).to.equal(cancel);
    cancel.click();
    expect(await result).to.equal(false);
    expect(document.querySelector('dialog')).to.equal(null);
  });
  it('should require the exact new fingerprint to replace a changed key', async () => {
    const { result, dialog } = await open(key(2));
    expect(dialog.textContent).to.contain(await hostFingerprint(key(2)));
    const trust = dialog.querySelectorAll('button')[1];
    const input = dialog.querySelector('input');
    if (!input) throw new Error('Missing replacement confirmation');
    expect(trust.disabled).to.equal(true);
    input.value = 'yes';
    input.dispatchEvent(new dom.window.Event('input'));
    expect(trust.disabled).to.equal(true);
    input.value = await hostFingerprint(key(1));
    input.dispatchEvent(new dom.window.Event('input'));
    expect(trust.disabled).to.equal(false);
    trust.click();
    expect(await result).to.equal(true);
  });
  it('should close and reject approval when the connection is aborted', async () => {
    const { result, controller } = await open();
    controller.abort();
    expect(await result).to.equal(false);
    expect(document.querySelector('dialog')).to.equal(null);
  });
});

import { expect } from 'chai';
import { JSDOM } from 'jsdom';
import sinon from 'sinon';
import 'mocha';
import { promptForwardSign } from './forwardPrompt';

describe('Forwarded signing approval', () => {
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
    sinon.restore();
  });
  it('should show the user safely, explain the unknown destination and default to denial', async () => {
    const result = promptForwardSign(
      '<img src=x>',
      new AbortController().signal,
    );
    expect(document.querySelector('img')).to.equal(null);
    expect(document.body.textContent)
      .to.contain('<img src=x>')
      .and.contain('destination is not verified');
    const deny = document.querySelector('button');
    expect(document.activeElement).to.equal(deny);
    deny?.click();
    expect(await result).to.equal(false);
    expect(document.querySelector('dialog')).to.equal(null);
  });
  it('should describe imported-key initial login separately', async () => {
    const result = promptForwardSign(
      'alice',
      new AbortController().signal,
      true,
    );
    expect(document.body.textContent)
      .to.contain('configured SSH server')
      .and.not.to.contain('remote process');
    document.querySelector('button')?.click();
    expect(await result).to.equal(false);
  });
  it('should approve just the current request', async () => {
    const result = promptForwardSign('git', new AbortController().signal);
    document.querySelectorAll('button')[1].click();
    expect(await result).to.equal(true);
    expect(document.querySelector('dialog')).to.equal(null);
  });
  it('should dismiss and deny an aborted request', async () => {
    const controller = new AbortController();
    const result = promptForwardSign('git', controller.signal);
    controller.abort();
    expect(await result).to.equal(false);
    expect(document.querySelector('dialog')).to.equal(null);
  });
  it('should expire without approval after 45 seconds', async () => {
    const clock = sinon.useFakeTimers();
    try {
      const result = promptForwardSign('git', new AbortController().signal);
      clock.tick(45000);
      expect(await result).to.equal(false);
      expect(document.querySelector('dialog')).to.equal(null);
    } finally {
      clock.restore();
    }
  });
  it('offers session consent only for a verified host-bound request and displays its path safely', async () => {
    const result = promptForwardSign(
      'git',
      new AbortController().signal,
      false,
      {
        hostFingerprint: 'SHA256:destination<img>',
        forwardingHostFingerprints: ['SHA256:hop'],
        canRemember: true,
      },
    );
    expect(document.querySelector('img')).to.equal(null);
    expect(document.body.textContent)
      .to.contain('SHA256:destination<img>')
      .and.contain('Forwarding host 1: SHA256:hop');
    const buttons = document.querySelectorAll('button');
    expect(buttons[2].textContent).to.equal('Allow until disconnected');
    expect(document.activeElement).to.equal(buttons[0]);
    buttons[2].click();
    expect(await result).to.equal('session');
  });
  it('keeps non-hostbound authentication on one-use approval', async () => {
    const result = promptForwardSign(
      'git',
      new AbortController().signal,
      false,
      {
        hostFingerprint: 'SHA256:host',
        forwardingHostFingerprints: [],
        canRemember: false,
      },
    );
    expect(document.querySelectorAll('button')).to.have.length(2);
    expect(document.body.textContent).to.contain(
      'approval is for this use only',
    );
    document.querySelector('button')?.click();
    expect(await result).to.equal(false);
  });
});

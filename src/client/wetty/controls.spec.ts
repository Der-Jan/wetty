import { expect } from 'chai';
import { JSDOM } from 'jsdom';
import 'mocha';
import { setupControls } from './controls';

describe('CSP-compatible controls', () => {
  it('should dispatch all controls without inline code and use updated callbacks', () => {
    const names = [
      'reconnect',
      'toggleFunctions',
      'toggleCTRL',
      'pressESC',
      'pressTAB',
      'pressLEFT',
      'pressUP',
      'pressRIGHT',
      'pressDOWN',
    ];
    const dom = new JSDOM(
      names
        .map(
          (name) =>
            `<a href="#" data-wetty-action="${name}"><span>Control</span></a>`,
        )
        .join(''),
    );
    const calls: string[] = [];
    const target = Object.fromEntries(
      names.map((name) => [name, () => calls.push(name)]),
    );
    const browser = {
      ...target,
      pressESC: target.pressESC,
      location: { reload: () => calls.push('reconnect') },
    };
    try {
      setupControls(dom.window.document, browser as unknown as Window);
      dom.window.document.querySelectorAll('span').forEach((element) => {
        const event = new dom.window.MouseEvent('click', {
          bubbles: true,
          cancelable: true,
        });
        element.dispatchEvent(event);
        expect(event.defaultPrevented).to.equal(true);
      });
      expect(calls).to.deep.equal(names);
      browser.pressESC = () => calls.push('new terminal');
      dom.window.document
        .querySelector<HTMLElement>('[data-wetty-action="pressESC"]')
        ?.click();
      expect(calls[calls.length - 1]).to.equal('new terminal');
    } finally {
      dom.window.close();
    }
  });
});

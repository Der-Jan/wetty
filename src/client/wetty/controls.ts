/** Bind once at page startup; callbacks use the current terminal after reconnect. */
export function setupControls(doc: Document, target: Window): void {
  const actions: Record<string, () => void> = {
    reconnect: () => {
      target.location.reload();
    },
    toggleFunctions: () => target.toggleFunctions?.(),
    toggleCTRL: () => target.toggleCTRL?.(),
    pressESC: () => target.pressESC?.(),
    pressTAB: () => target.pressTAB?.(),
    pressLEFT: () => target.pressLEFT?.(),
    pressUP: () => target.pressUP?.(),
    pressRIGHT: () => target.pressRIGHT?.(),
    pressDOWN: () => target.pressDOWN?.(),
  };
  doc
    .querySelectorAll<HTMLElement>('[data-wetty-action]')
    .forEach((element) => {
      const action = element.dataset.wettyAction;
      if (!action || !Object.prototype.hasOwnProperty.call(actions, action)) {
        return;
      }
      element.addEventListener('click', (event) => {
        event.preventDefault();
        actions[action]();
      });
    });
}

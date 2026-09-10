import { EventEmitter } from 'node:events';
import { expect } from 'chai';
import 'mocha';
import sinon from 'sinon';
import { ptyLifecycle } from './lifecycle';
import type { IPty } from 'node-pty';
import type { Socket } from 'socket.io';

function fixture(signal?: AbortSignal) {
  const socket = Object.assign(new EventEmitter(), { connected: true });
  const events = new EventEmitter();
  const term = {
    kill: sinon.stub(),
    onExit: (listener: (event: { exitCode: number }) => void) => {
      events.on('exit', listener);
      return {
        dispose: () => {
          events.off('exit', listener);
        },
      };
    },
  };
  const onExit = sinon.spy();
  const lifecycle = ptyLifecycle(
    socket as unknown as Socket,
    term as unknown as IPty,
    { signal, onExit },
  );
  return { socket, events, term, onExit, lifecycle };
}

describe('Generic PTY lifecycle', () => {
  let clock: sinon.SinonFakeTimers;
  beforeEach(() => {
    clock = sinon.useFakeTimers();
  });
  afterEach(() => {
    clock.restore();
  });
  it('should remove only owned listeners and release output resources on exit', () => {
    const f = fixture();
    const external = sinon.spy();
    const input = sinon.spy();
    const dispose = sinon.spy();
    f.socket.on('input', external);
    f.lifecycle.on('input', input);
    f.lifecycle.own({ dispose });
    f.lifecycle.start();
    f.socket.emit('input', 'before');
    f.events.emit('exit', { exitCode: 0 });
    f.events.emit('exit', { exitCode: 0 });
    f.socket.emit('input', 'after');
    expect(input.calledOnceWithExactly('before')).to.equal(true);
    expect(external.callCount).to.equal(2);
    expect(dispose.calledOnce).to.equal(true);
    expect(f.onExit.calledOnce).to.equal(true);
    expect(f.socket.listenerCount('disconnect')).to.equal(0);
    expect(f.events.listenerCount('exit')).to.equal(0);
    clock.tick(3000);
    expect(f.term.kill.called).to.equal(false);
  });
  it('should request termination only once and force a stubborn child to exit', () => {
    const controller = new AbortController();
    const f = fixture(controller.signal);
    f.lifecycle.start();
    f.lifecycle.start();
    controller.abort();
    f.socket.emit('disconnect');
    expect(f.term.kill.callCount).to.equal(1);
    clock.tick(2000);
    expect(f.term.kill.callCount).to.equal(2);
    expect(f.term.kill.secondCall.args).to.deep.equal(['SIGKILL']);
    f.events.emit('exit', { exitCode: 137 });
    expect(f.onExit.calledOnce).to.equal(true);
  });
  it('should not leave a timer when termination reports exit synchronously', () => {
    const f = fixture();
    f.term.kill.callsFake(() => {
      f.events.emit('exit', { exitCode: 0 });
    });
    f.lifecycle.start();
    f.socket.emit('disconnect');
    expect(f.onExit.calledOnce).to.equal(true);
    expect(clock.countTimers()).to.equal(0);
  });
  it('should cancel forced termination when the child exits normally', () => {
    const f = fixture();
    f.lifecycle.start();
    f.socket.emit('disconnect');
    f.events.emit('exit', { exitCode: 0 });
    clock.tick(3000);
    expect(f.term.kill.callCount).to.equal(1);
    expect(clock.countTimers()).to.equal(0);
  });
  it('should handle abort or disconnect during setup', () => {
    const controller = new AbortController();
    const f = fixture(controller.signal);
    controller.abort();
    f.socket.connected = false;
    f.lifecycle.start();
    expect(f.term.kill.calledOnce).to.equal(true);
    f.events.emit('exit', { exitCode: 0 });
    expect(clock.countTimers()).to.equal(0);
  });
  it('should keep concurrent PTY lifecycles isolated', () => {
    const first = fixture();
    const second = fixture();
    const input = sinon.spy();
    first.lifecycle.start();
    second.lifecycle.on('input', input).start();
    first.socket.emit('disconnect');
    first.events.emit('exit', { exitCode: 0 });
    second.socket.emit('input', 'still live');
    expect(second.term.kill.called).to.equal(false);
    expect(input.calledOnceWithExactly('still live')).to.equal(true);
    second.events.emit('exit', { exitCode: 0 });
  });
});

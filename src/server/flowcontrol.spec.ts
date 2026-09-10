import { expect } from 'chai';
import 'mocha';
import sinon from 'sinon';
import { tinybuffer } from './flowcontrol';
import type { Socket } from 'socket.io';

describe('Disposable PTY output buffer', () => {
  let clock: sinon.SinonFakeTimers;
  beforeEach(() => {
    clock = sinon.useFakeTimers();
  });
  afterEach(() => {
    clock.restore();
  });
  function fixture() {
    const socket = { emit: sinon.spy() };
    return { socket, send: tinybuffer(socket as unknown as Socket, 2, 8) };
  }
  it('should preserve upstream timed batching and immediate size-limit flushing', () => {
    const { socket, send } = fixture();
    send('one');
    send('two');
    expect(socket.emit.called).to.equal(false);
    clock.tick(2);
    expect(socket.emit.firstCall.args).to.deep.equal(['data', 'onetwo']);
    send('123456789');
    expect(socket.emit.secondCall.args).to.deep.equal(['data', '123456789']);
    clock.tick(2);
    expect(socket.emit.callCount).to.equal(2);
    send.dispose();
  });
  it('should flush final output exactly once before disposal', () => {
    const { socket, send } = fixture();
    send('final');
    send.flush();
    send.flush();
    send.dispose();
    send.dispose();
    clock.tick(10);
    expect(socket.emit.calledOnceWithExactly('data', 'final')).to.equal(true);
    expect(clock.countTimers()).to.equal(0);
  });
  it('should discard pending output on disposal and refuse later writes', () => {
    const { socket, send } = fixture();
    send('pending');
    send.dispose();
    send('late');
    send.flush();
    clock.tick(10);
    expect(socket.emit.called).to.equal(false);
    expect(clock.countTimers()).to.equal(0);
  });
});

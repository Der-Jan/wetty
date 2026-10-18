import assert from 'node:assert/strict';
import 'mocha';
import {
  bindingHost,
  bindingSession,
  boundAuth,
} from '../../../shared/sessionBinding.test-utils';
import { ForwardedApprovals } from './forwardedApprovals';
import type { ForwardApproval } from './forwardPrompt';

describe('In-memory forwarded SSH grants', () => {
  const key = new Uint8Array([1, 2, 3]);
  let controller: AbortController;
  let approvals: ForwardedApprovals;
  beforeEach(() => {
    controller = new AbortController();
    approvals = new ForwardedApprovals(controller.signal);
  });
  afterEach(() => {
    controller.abort();
  });

  it('reuses a grant only after independently verifying the new connection', async () => {
    const host = bindingHost();
    let prompts = 0;
    const approve: ForwardApproval = (
      _user,
      _signal,
      _initial,
      destination,
    ) => {
      prompts += 1;
      assert.equal(destination?.canRemember, true);
      assert.match(destination.hostFingerprint, /^SHA256:/);
      return 'session';
    };
    await approvals.bind('first', host.packet());
    await approvals.approve(
      'first',
      boundAuth(key, host.host),
      key,
      'rsa-sha2-256',
      approve,
    );
    approvals.close('first');
    const session = new Uint8Array(32).fill(9);
    await approvals.bind('second', host.packet(session));
    await approvals.approve(
      'second',
      boundAuth(key, host.host, session),
      key,
      'rsa-sha2-256',
      approve,
    );
    assert.equal(prompts, 1);
    await assert.rejects(
      approvals.approve(
        'unbound',
        boundAuth(key, host.host, session),
        key,
        'rsa-sha2-256',
        () => false,
      ),
    );
  });

  it('scopes grants to the exact key, user, host and complete forwarding path', async () => {
    const host = bindingHost();
    const other = bindingHost();
    let prompts = 0;
    const approve: ForwardApproval = () => {
      prompts += 1;
      return 'session';
    };
    const attempt = async (
      id: string,
      identity = key,
      user = 'git',
      destination = host,
      via = false,
    ) => {
      if (via) {
        await approvals.bind(
          id,
          other.packet(new Uint8Array(32).fill(3), true),
        );
      }
      await approvals.bind(id, destination.packet());
      await approvals.approve(
        id,
        boundAuth(identity, destination.host, bindingSession, user),
        identity,
        'rsa-sha2-256',
        approve,
      );
      approvals.close(id);
    };
    await attempt('one');
    await attempt('two', key, 'alice');
    await attempt('three', new Uint8Array([4]));
    await attempt('four', key, 'git', other);
    await attempt('five', key, 'git', host, true);
    await attempt('six');
    assert.equal(prompts, 5);
  });

  it('never remembers unbound requests, non-hostbound signatures, or Allow once', async () => {
    const host = bindingHost();
    let prompts = 0;
    const remember: ForwardApproval = () => {
      prompts += 1;
      return 'session';
    };
    await approvals.approve(
      undefined,
      boundAuth(key),
      key,
      'rsa-sha2-256',
      remember,
    );
    await approvals.approve(
      undefined,
      boundAuth(key),
      key,
      'rsa-sha2-256',
      remember,
    );
    await approvals.bind('plain', host.packet());
    await approvals.approve(
      'plain',
      boundAuth(key),
      key,
      'rsa-sha2-256',
      remember,
    );
    await approvals.approve(
      'plain',
      boundAuth(key),
      key,
      'rsa-sha2-256',
      remember,
    );
    const once: ForwardApproval = () => {
      prompts += 1;
      return true;
    };
    await approvals.approve(
      'plain',
      boundAuth(key, host.host),
      key,
      'rsa-sha2-256',
      once,
    );
    await approvals.approve(
      'plain',
      boundAuth(key, host.host),
      key,
      'rsa-sha2-256',
      once,
    );
    assert.equal(prompts, 6);
  });

  it('rejects mismatched sessions, host keys and incomplete forwarding chains before consent', async () => {
    const host = bindingHost();
    const other = bindingHost();
    const never: ForwardApproval = () => {
      throw new Error('Must not prompt');
    };
    await approvals.bind('bound', host.packet());
    await assert.rejects(
      approvals.approve(
        'bound',
        boundAuth(key, host.host, new Uint8Array(32)),
        key,
        'rsa-sha2-256',
        never,
      ),
    );
    await assert.rejects(
      approvals.approve(
        'bound',
        boundAuth(key, other.host),
        key,
        'rsa-sha2-256',
        never,
      ),
    );
    await approvals.bind('forwarding', host.packet(bindingSession, true));
    await assert.rejects(
      approvals.approve(
        'forwarding',
        boundAuth(key, host.host),
        key,
        'rsa-sha2-256',
        never,
      ),
    );
  });

  it('poisons failed binding connections, isolates sockets and forbids rebinding after authentication', async () => {
    const host = bindingHost();
    const corrupt = host.packet();
    corrupt[corrupt.length - 2] = (corrupt[corrupt.length - 2] + 1) % 256;
    await assert.rejects(approvals.bind('bad', corrupt));
    await assert.rejects(approvals.bind('bad', host.packet()));
    await approvals.bind('good', host.packet(bindingSession, true));
    await approvals.bind('good', host.packet(bindingSession, true));
    const final = new Uint8Array(32).fill(8);
    await approvals.bind('good', host.packet(final));
    await approvals.approve(
      'good',
      boundAuth(key, host.host, final),
      key,
      'rsa-sha2-256',
      () => true,
    );
    await assert.rejects(approvals.bind('good', host.packet()));
    approvals.close('good');
    await assert.rejects(approvals.bind('good', host.packet()));
  });

  it('aborts pending consent on agent close and drops all grants when the browser session ends', async () => {
    const host = bindingHost();
    await approvals.bind('pending', host.packet());
    let finish: (answer: 'session') => void = () => {
      throw new Error('No prompt');
    };
    let prompted: () => void = () => {
      throw new Error('No waiter');
    };
    const ready = new Promise<void>((resolve) => {
      prompted = resolve;
    });
    const waiting = approvals.approve(
      'pending',
      boundAuth(key, host.host),
      key,
      'rsa-sha2-256',
      (_user, signal) => {
        const result = new Promise<'session'>((resolve) => {
          finish = resolve;
        });
        signal.addEventListener(
          'abort',
          () => {
            finish('session');
          },
          { once: true },
        );
        prompted();
        return result;
      },
    );
    const rejected = assert.rejects(waiting);
    await ready;
    approvals.close('pending');
    await rejected;
    await approvals.bind('new', host.packet());
    await assert.rejects(
      approvals.approve(
        'new',
        boundAuth(key, host.host),
        key,
        'rsa-sha2-256',
        () => false,
      ),
    );
    await approvals.approve(
      'new',
      boundAuth(key, host.host),
      key,
      'rsa-sha2-256',
      () => 'session',
    );
    controller.abort();
    await assert.rejects(
      approvals.approve(
        'new',
        boundAuth(key, host.host),
        key,
        'rsa-sha2-256',
        () => true,
      ),
    );
    const fresh = new ForwardedApprovals(new AbortController().signal);
    await fresh.bind('fresh', host.packet());
    await assert.rejects(
      fresh.approve(
        'fresh',
        boundAuth(key, host.host),
        key,
        'rsa-sha2-256',
        () => false,
      ),
    );
  });

  it('bounds active sockets and forwarding chain lengths', async () => {
    const host = bindingHost();
    for (const id of ['one', 'two', 'three', 'four']) {
      // eslint-disable-next-line no-await-in-loop
      await approvals.bind(id, host.packet(bindingSession, true));
    }
    await assert.rejects(approvals.bind('five', host.packet()));
    approvals.close('one');
    await approvals.bind('five', host.packet(bindingSession, true));
    for (let index = 0; index < 15; index += 1) {
      // eslint-disable-next-line no-await-in-loop
      await approvals.bind(
        'five',
        host.packet(new Uint8Array(32).fill(index + 20), true),
      );
    }
    await assert.rejects(
      approvals.bind('five', host.packet(new Uint8Array(32).fill(80))),
    );
    await assert.rejects(
      approvals.approve(
        'five',
        boundAuth(key, host.host),
        key,
        'rsa-sha2-256',
        () => true,
      ),
    );
  });
});

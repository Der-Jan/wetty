import { equalBytes, bytes } from '../../../shared/browserAgent';
import { forwardedAuth } from '../../../shared/forwardedAuth';
import { base64url } from '../../../shared/importedKeys';
import { verifySessionBinding } from '../../../shared/sessionBinding';
import type { ForwardApproval, ForwardDestination } from './forwardPrompt';
import type { SessionBinding } from '../../../shared/sessionBinding';

interface Connection {
  bindings: SessionBinding[];
  failed: boolean;
  pending: boolean;
  controller: AbortController;
}

/** One browser/WeTTY connection owns these grants. Nothing is persisted. */
export class ForwardedApprovals {
  private connections = new Map<string, Connection>();
  private closed = new Set<string>();
  private grants = new Set<string>();
  private stopped = false;

  constructor(private readonly signal: AbortSignal) {
    signal.addEventListener(
      'abort',
      () => {
        this.stopped = true;
        for (const state of this.connections.values()) state.controller.abort();
        this.connections.clear();
        this.grants.clear();
        this.closed.clear();
      },
      { once: true },
    );
  }

  private connection(id: unknown): Connection {
    this.signal.throwIfAborted();
    if (
      this.stopped ||
      typeof id !== 'string' ||
      !id.length ||
      id.length > 64 ||
      this.closed.has(id)
    ) {
      throw new Error('Invalid agent connection');
    }
    let state = this.connections.get(id);
    if (!state) {
      if (this.connections.size >= 4) {
        throw new Error('Too many agent connections');
      }
      state = {
        bindings: [],
        failed: false,
        pending: false,
        controller: new AbortController(),
      };
      this.connections.set(id, state);
    }
    if (state.failed || state.controller.signal.aborted) {
      throw new Error('Agent connection unavailable');
    }
    return state;
  }

  close(id: unknown): void {
    if (typeof id !== 'string' || !id.length || id.length > 64) return;
    this.connections.get(id)?.controller.abort();
    this.connections.delete(id);
    if (this.closed.size >= 256) {
      this.stopped = true;
      for (const state of this.connections.values()) state.controller.abort();
      this.connections.clear();
      this.grants.clear();
    } else this.closed.add(id);
  }

  async bind(id: unknown, packet: unknown): Promise<void> {
    const state = this.connection(id);
    try {
      if (
        state.pending ||
        state.bindings.length >= 16 ||
        (state.bindings.length > 0 &&
          !state.bindings[state.bindings.length - 1].forwarded)
      ) {
        throw new Error('Binding chain closed or full');
      }
      state.pending = true;
      const binding = await verifySessionBinding(bytes(packet, 16384));
      state.controller.signal.throwIfAborted();
      this.signal.throwIfAborted();
      if (state.failed) throw new Error('Binding failed');
      const previous = state.bindings.find((value) =>
        equalBytes(value.session, binding.session),
      );
      if (previous) {
        if (
          !equalBytes(previous.host, binding.host) ||
          previous.forwarded !== binding.forwarded
        ) {
          throw new Error('Inconsistent duplicate binding');
        }
      } else state.bindings.push(binding);
    } catch (error) {
      state.failed = true;
      state.controller.abort();
      throw error;
    } finally {
      state.pending = false;
    }
  }

  assertCurrent(id: unknown): void {
    this.signal.throwIfAborted();
    if (this.stopped) throw new Error('Forwarding stopped');
    if (id !== undefined) {
      this.connection(id).controller.signal.throwIfAborted();
    }
  }

  async approve(
    id: unknown,
    data: Uint8Array,
    key: Uint8Array,
    algorithm: string,
    approve: ForwardApproval,
    description?: string,
  ): Promise<void> {
    this.signal.throwIfAborted();
    if (this.stopped) throw new Error('Forwarding stopped');
    const auth = forwardedAuth(data, key, algorithm);
    const state = id === undefined ? undefined : this.connection(id);
    const signal = state?.controller.signal ?? this.signal;
    if (state?.pending) throw new Error('Binding in progress');
    const bindings = state?.bindings ?? [];
    const destination = bindings.length
      ? bindings[bindings.length - 1]
      : undefined;
    let details: ForwardDestination | undefined;
    let grant: string | undefined;
    if (destination) {
      if (
        destination.forwarded ||
        !equalBytes(destination.session, auth.session) ||
        (auth.host !== undefined && !equalBytes(destination.host, auth.host))
      ) {
        throw new Error('Authentication does not match its binding');
      }
      const fingerprints = await Promise.all(
        bindings.map(async (binding) => {
          const digest = await crypto.subtle.digest(
            'SHA-256',
            bytes(binding.host),
          );
          return `SHA256:${btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/=+$/, '')}`;
        }),
      );
      details = {
        hostFingerprint: fingerprints[fingerprints.length - 1],
        forwardingHostFingerprints: fingerprints.slice(0, -1),
        // A forwarding grant must bind the signature itself to the destination.
        // Plain publickey authentication remains available with one-use consent.
        canRemember: auth.host !== undefined,
      };
      if (details.canRemember) {
        grant = JSON.stringify([
          base64url(key),
          auth.user,
          bindings.map((binding) => base64url(binding.host)),
        ]);
      }
    }
    signal.throwIfAborted();
    this.signal.throwIfAborted();
    if (grant && this.grants.has(grant)) return;
    const result = await approve(
      description ?? auth.user,
      signal,
      false,
      details,
    );
    signal.throwIfAborted();
    this.signal.throwIfAborted();
    if (result !== true && result !== 'session') {
      throw new Error('Signing declined');
    }
    if (result === 'session' && grant && this.grants.size < 128) {
      this.grants.add(grant);
    }
  }
}

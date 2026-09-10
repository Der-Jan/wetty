# PTY integration and lifecycle

`src/server/spawn.ts` retains the upstream command selection, terminal resize
validation, input forwarding, and flow-control wiring. Without optional
settings, it runs through `/usr/bin/env`, including the existing coreutils
version check and `-S` argument handling.

The optional `SpawnOptions` interface is independent of browser authentication:

- `env`: execute the provided executable and argv directly with this per-session
  environment. Global environment variables and the shared xterm configuration
  are not modified.
- `signal`: terminate the child when the session is aborted.
- `onExit`: notify the owner after terminal output is flushed and local
  resources are released. The browser bridge uses this to close its private
  agent and known-hosts sockets.

Browser-specific SSH command arguments and environment values remain in
`src/server/browserAgent/command.ts`; authentication and host verification stay
in their existing feature modules. There is one PTY implementation for all
modes, not a separate copy for browser sessions.

`src/server/spawn/lifecycle.ts` owns PTY subscriptions and registered socket
listeners. On disconnect or abort it requests normal termination once, then
sends SIGKILL after two seconds if the child has not exited. Exit releases
subscriptions, removes only owned listeners, cancels the termination timer, and
invokes the exit callback once. Listeners belonging to other features remain
registered. `start()` checks for disconnects or aborts that occurred during
setup. Adding a resource after exit immediately disposes it.

`tinybuffer` retains its upstream timed/size-based batching algorithm. Its
additional `flush()` method delivers pending output immediately, and `dispose()`
cancels pending timers, discards buffered output, and rejects later writes. The
PTY exit callback flushes before disposal and emits logout afterward, so final
output is delivered before the terminal session ends.

## Verification

```bash
npm test                  # Includes generic lifecycle and buffer unit tests
npm run test:pty          # Real node-pty processes; no SSH server required
npm run test:browser-key  # Real OpenSSH and browser-agent integration
npm run lint
```

The PTY integration suite requires Unix `/bin/sh`, coreutils and a working
node-pty installation. It covers the legacy launch path, final output,
concurrent isolated environments, literal argv, normal resource cleanup,
pre-spawn rejection, and children ignoring hangup. The SSH integration suite
checks key login, interactive password fallback, host trust and disconnects
through the same optional interface.

This step is intentionally separate from the extraction of feature UI, styles,
browser initialization, origin validation and backend session management.

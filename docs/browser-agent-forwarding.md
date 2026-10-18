# Browser agent forwarding

Enable `--browser-agent-forwarding` (or `BROWSER_AGENT_FORWARDING=true`)
together with `--ssh-auth=browser-key`. Forwarding is disabled by default. It
requires an available browser key and a browser client that explicitly
advertises support for forwarding approval. Reload older tabs after upgrading.

On a fresh remote SSH session:

```sh
ssh-add -L
ssh -o PubkeyAuthentication=yes -o PubkeyAcceptedAlgorithms=rsa-sha2-256 user@destination
```

The destination must authorize the browser public key. Approve the request in
the browser with **Allow once**, or **Allow until disconnected** when the
request has a verified session binding and a host-bound signature. Remembered
approvals apply only to the exact key, username and complete host-key forwarding
path. A fresh SSH connection must verify its own binding before reusing a grant.
Requests without these proofs continue to require one-use approval, even when
the onward username matches the initial SSH username. Denial, closing the
dialog, 45 seconds without approval, browser disconnect or logout prevents
completion. Only one approval dialog is allowed per browser signing session.

For Git, select the same SSH options, for example:

```sh
GIT_SSH_COMMAND='ssh -o PubkeyAuthentication=yes -o PubkeyAcceptedAlgorithms=rsa-sha2-256' git fetch
```

The browser-generated key remains tied to RSA SHA-256. Imported RSA keys support
both SHA-256 and SHA-512, and imported Ed25519 keys use native Ed25519
signatures. Password fallback for the initial connection remains enabled.

## Importing keys with ssh-add

In the remote terminal, using the forwarded SSH_AUTH_SOCK:

```sh
ssh-add ~/.ssh/id_ed25519
# Or an RSA key (2048–8192 bits):
ssh-add ~/.ssh/id_rsa
ssh-add -L
```

If the file is encrypted, ssh-add asks for its passphrase in the remote
terminal. The browser then shows the key comment and SHA256 fingerprint. Select
**Import key** to persist the key as a non-extractable CryptoKey in the separate
`wetty-imported-ssh-keys` IndexedDB database. The browser-generated login key is
never replaced. Imported identities are also available for the initial SSH login
after reconnecting with that browser, even if agent forwarding is disabled. The
generated key is advertised first, followed by all imported keys. Imported-key
login requires **Allow once**, while the generated key retains its automatic
initial-login behavior. Password fallback remains enabled. Older browser clients
retain the single-key login behavior until reloaded.

OpenSSH stops once a key succeeds. The SSH server's authentication-attempt limit
can disconnect a client before all advertised keys or password fallback are
tried if many keys are rejected; this change does not alter that server policy.

Imports require an active WebSocket transport. They fail under HTTP polling to
prevent private-key material from entering the service worker HTTP cache. Older
clients without the key-management capability cannot import keys. Reload the
browser after upgrading. No private keys or request payloads are logged by the
import handler or written to backend key files. They do pass through backend
memory while ssh-add transfers them; these keys originally existed on the host,
unlike the browser-generated key. JavaScript does not guarantee complete memory
zeroization. Only the browser's persisted copy is non-extractable.

Both ordinary `publickey` and OpenSSH's `publickey-hostbound-v00@openssh.com`
authentication formats are accepted for forwarded signing. OpenSSH
`session-bind@openssh.com` proofs are verified independently in the browser with
WebCrypto. The final session identifier and any signed destination host key must
match the connection binding. Only a host-bound signature with a verified
binding can reuse an approval. The original payload is signed unchanged. Initial
login retains its unbound-only policy.

Generated and imported keys use the same approval policy. Importing a key does
not grant signing permission. Select a particular imported identity using its
public-key file, for example:

```sh
ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519.pub user@destination
```

At most eight imported identities are stored. Reimporting the same public key
updates the existing record after approval. ECDSA, DSA, security-key/hardware
identities, certificates, SHA-1, arbitrary-data signing, remove/lock operations,
and constrained imports (`ssh-add -t`, `-c`, `-h`) are not supported and fail
explicitly; their constraints are never silently dropped. This is not a full
replacement for every OpenSSH agent feature. To remove persisted imported keys
at present, delete the `wetty-imported-ssh-keys` database in browser developer
tools and reconnect; this leaves the original key and known-host databases
alone.

## Security and lifecycle

The initial login agent retains its fixed-username restriction. A second
per-session Unix socket is supplied explicitly through OpenSSH's `ForwardAgent`
option; only that socket permits other usernames and requests browser approval.
The automatic login socket is never forwarded. Both sockets have mode 0600
inside mode 0700 temporary directories and are cleaned up on disconnect/exit.

Forwarded requests must be ordinary SSH public-key authentication payloads for
an enrolled key and supported signature algorithm. The browser parses the
username independently, checks correlation IDs and rejects replay. There is a
shared limit of 32 signing requests per connection (including declined
requests), four clients per socket, and bounded packets/queues. Imported-key
management has a separate limit of 128 requests per connection, including
identity listings, imports and signatures. Reconnect after reaching a request
limit.

Verified requests display the destination host-key fingerprint and the complete
forwarding path. A verified session binding proves possession of the host key;
it does not establish trust in a hostname. Hostname verification remains the
onward SSH client's responsibility. OpenSSH clients and servers that do not
provide a verifiable host-bound request retain **Allow once**. Do not force
`PubkeyAuthentication=unbound` when you want reusable approvals; `yes`
negotiates host-bound authentication when supported, and `host-bound` requires
it.

Grants live only in browser memory for the current WeTTY connection. Closing the
tab/browser, reloading, disconnecting or logging out discards them. There is no
persistent grant store or extra clearing button. Closing an individual agent
socket clears its bindings and cancels its pending approval; grants remain
usable by new connections only after they verify the same exact host-key path.

Binding state is isolated per agent socket connection, limited to four active
connections and 16 bindings per connection. Authentication closes a binding
chain; it cannot be extended or rebound. Invalid bindings disable that
connection. Session grants are capped at 128, and binding requests at 128 per
WeTTY session. Ed25519, RSA SHA-256/SHA-512 and NIST P-256/P-384/P-521 host
signatures are supported; certificates and security-key host formats are
rejected. This does not implement `ssh-add -h` destination constraints. The
WeTTY backend remains trusted, and processes with access to the remote agent
socket can request authentication to an approved key/user/host path while the
browser remains connected.

The local Compose command refreshes `~/.ssh/agent.sock` before attaching to
tmux. Existing panes must have SSH_AUTH_SOCK set to that stable path. The
browser must remain connected for signing.

## Validation and deployment

`npm test` covers parsing, authorization, approval UI, cancellation and replay.
`npm run test:browser-key` exercises real OpenSSH forwarding to a loopback sshd,
identity listing, approved/denied onward login, real RSA and Ed25519 ssh-add
imports, persistence, rejected constraints and refusal under HTTP polling.

For the hardened local deployment, rebuild `wetty.local` using the repository
Dockerfile, then rebuild/deploy the wrapper in `/opt/containers/wetty` as
described in its `HARDENING.md`. Keep its runtime restrictions and existing
proxy/network configuration in place; the only new deployment option is
`--browser-agent-forwarding` on the WeTTY command.

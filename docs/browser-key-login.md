# Log in with the browser key (authorized_keys)

This mode uses the RSA key created by the **key icon**, including keys created
before the signing bridge was added. The private CryptoKey remains in IndexedDB
and is never exported. The SSH server checks its public key against the fixed
account's `authorized_keys`. Vault and certificates are not used yet.

Click the key icon while your SSH terminal is ready to paste the public key at
the cursor, without pressing Enter. For example, open `~/.ssh/authorized_keys`
in an editor, enter insert mode on a new line, click the icon, then save the
file yourself. The button does not execute a command or edit the file for you.
It also prints the public key to the browser console, which remains available
when disconnected. If the terminal reconnects while the key is loading, no key
is pasted into the replacement session.

After building, start WeTTY with your actual values:

```bash
node build/main.js \
  --ssh-auth browser-key \
  --ssh-host ssh.example.com \
  --ssh-user alice \
  --ssh-port 22 \
  --known-hosts browser \
  --browser-origin https://terminal.example.com
```

Keep your existing TLS, reverse-proxy, base-path and listening-port settings.
`--browser-origin` must exactly match the address bar's origin (scheme,
hostname, and port, without path or trailing slash). Use the same browser
profile and origin where you created the enrolled key; IndexedDB keys do not
move between origins. HTTPS is required except for local development on HTTP
localhost/loopback. `BROWSER_ORIGIN` is the equivalent environment variable.

The equivalent `ssh` configuration is:

```json5
{
  ssh: {
    auth: 'browser-key',
    user: 'alice',
    host: 'ssh.example.com',
    port: 22,
    knownHosts: 'browser',
    browserOrigin: 'https://terminal.example.com',
    allowRemoteHosts: false,
    allowRemoteCommand: false,
  },
}
```

With `--known-hosts browser`, the browser stores trusted public host keys in
IndexedDB (`wetty-known-hosts`, store `hosts`), indexed by hostname and port.
The first connection shows the destination, key type, and SHA-256 fingerprint.
Choose **Trust and connect** only after comparing the fingerprint with a trusted
source. For example, on the SSH host itself:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Use the public host-key file corresponding to the key type shown in the dialog.
Acceptance without independent comparison is trust on first use. A matching
saved key reconnects without a prompt. A changed key blocks authentication until
the user explicitly reviews the old/new fingerprints and types the full new
fingerprint to replace the saved key. Cancellation never changes stored trust.
Each browser profile and WeTTY origin has its own store; clearing site data
removes trust and causes a first-use prompt again. Storage failures stop the
connection, including password authentication. The separate browser SSH key
store is unaffected by host-key replacement.

OpenSSH's `KnownHostsCommand` calls a Node helper through a private per-session
Unix socket. The `ORDER` lookup retrieves the saved key to prefer its algorithm;
the `HOSTNAME` lookup sends the actual negotiated public key for browser
verification. There is no separate key scan. Browser messages use
`browser-host:request` with `v`, `sessionId`, `requestId`, `target`, and a
`phase` of `lookup` or `verify` (the latter includes `key`). Correlated
`browser-key:result` replies contain `key` or `error`; only an exact approved
key is returned to OpenSSH. Approval requests time out after two minutes; the
SSH server's login grace period can impose a shorter deadline.

`StrictHostKeyChecking=yes` remains enabled. Host trust is persisted only in
IndexedDB: no known-hosts file is created or updated on the backend. The helper
holds public keys in memory and its socket is removed on session cleanup.
Ed25519, RSA SHA-2, and ECDSA NIST P-256/P-384/P-521 host keys are supported.
Host certificates and automatic host-key rotation are not enabled in this mode.

The existing managed-file mode remains available: pass an absolute path to a
regular trusted known-hosts file instead of `browser`. Browser mode does not
import existing backend trust automatically. A `/dev/null` value is not a valid
trusted-file configuration.

Rebuild with `pnpm build`, restart WeTTY, and reload the page. On connection the
browser loads its enrolled key, then OpenSSH attempts public-key authentication.
The browser key is tried first. If it is unavailable or rejected, OpenSSH offers
password or keyboard-interactive authentication when the SSH server permits it.
If the key has not yet been enrolled, use the key button (available after
disconnect), add its public line to the correct remote account's
`authorized_keys`, and reconnect.

Server-side user/host/port and command are authoritative. URL parameters and
`remote-user` do not select the SSH destination in this mode. It always runs
SSH, including for localhost when WeTTY runs as root. Stored password
configuration, private key files, custom SSH config and remote URL overrides are
incompatible and cause startup to fail. Other authentication modes retain their
existing behavior.

## Automatically attach to an existing tmux session

Use the existing server-side `--command` option to check for a tmux session on
the SSH host after authentication. This shares an existing session without
detaching its other clients. If tmux is absent, no session exists, or attachment
fails, it starts the account's login shell. Detaching from tmux ends the WeTTY
connection and leaves the session running. With multiple sessions, tmux chooses
its default target; add `-t SESSION_NAME` to select one explicitly.

```bash
--command='if command -v tmux >/dev/null 2>&1 && tmux has-session 2>/dev/null; then tmux attach-session && exit 0; fi; exec "${SHELL:-/bin/sh}" -l'
```

In a Docker Compose `command` list, escape the dollar sign as `$$` to prevent
Compose from substituting the container host's shell:

```yaml
- >-
  --command=if command -v tmux >/dev/null 2>&1 && tmux has-session 2>/dev/null;
  then tmux attach-session && exit 0; fi; exec "$${SHELL:-/bin/sh}" -l
```

## How the bridge works

A new Unix socket in a private 0700 temporary directory belongs to each browser
session; the socket has mode 0600. Only the child SSH process receives its path
as `SSH_AUTH_SOCK`. The agent advertises the browser public key and relays
signing requests over that socket's existing Socket.IO connection. WebCrypto
signs the original SSH authentication bytes with RSA PKCS#1 v1.5 and SHA-256.
The backend verifies the signature before returning an SSH-agent response.

The agent supports identity listing and RSA SHA-256 signing. Mutating
operations, SHA-1/SHA-512 signing and extensions (including session binding) are
rejected. OpenSSH uses `PubkeyAuthentication=unbound` and
`PubkeyAcceptedAlgorithms=rsa-sha2-256` to select the ordinary public-key
protocol this implementation supports. The client still verifies the SSH server
host key using browser-approved trust or the configured managed known-hosts
file. Agent framing follows
[RFC 9987](https://datatracker.ietf.org/doc/html/rfc9987); OpenSSH options are
documented in [ssh_config](https://man.openbsd.org/ssh_config).

Each signing operation is correlated with a fresh request ID and backend session
ID, restricted to the fixed SSH username and enrolled public key, and times out
after ten seconds. Browser preparation times out after sixty seconds. Packet
sizes, Unix clients and queued/signing requests are bounded. Agent forwarding,
local key files and SSH connection sharing are disabled. Signing bypasses
terminal flow control. Disconnect, PTY exit and graceful server shutdown close
the agent and kill the SSH process; reconnect creates a fresh session, with the
same persisted key. A hard process crash cannot run cleanup; use a
service/container supervisor that also terminates child processes.

## Authentication boundary

This temporary authorized_keys mode relies on SSH key possession for remote
login. Both Socket.IO transports require the configured Origin. When a
same-origin polling GET omits Origin, it must instead have
`Sec-Fetch-Site: same-origin` and a Referer whose origin matches the configured
origin. Requests lacking both forms of evidence are rejected; proxies must
preserve these headers. This does **not** add a separate web login or issue
certificates. Retain any existing authenticated reverse proxy and restrict
network access to WeTTY as appropriate. Origin checking protects browser
requests; it is not an identity check for arbitrary network clients. The
original certificate design's verified web-principal prerequisite still applies
before adding Vault issuance.

The current key scope is the temporary `development-diagnostic-v1` record,
shared with the create/show button and developer diagnostic. It is not yet
scoped by a web account. Served JavaScript, the backend and other processes
running under the backend's Unix UID remain trusted. Non-extractability does not
stop same-origin code from invoking signing, nor guarantee hardware storage.

## Validation and troubleshooting

- A password prompt is expected if the browser key is unavailable/rejected or
  the SSH server requires an additional authentication step.
- `Permission denied (publickey)` means the offered key was not accepted,
  signing failed, or SSH server policy denied the account. Confirm that the
  button prints the same public key installed in that account's
  `authorized_keys`.
- Host-key verification failure requires reviewing the browser trust prompt or,
  in managed-file mode, correcting the trusted known-hosts entry.
- A failed Socket.IO handshake can mean `browser-origin` differs from the
  address bar. Include any non-default port, and omit the application path.
- Missing WebCrypto/IndexedDB support, blocked storage or a deleted browser
  profile prevents use of the enrolled private key. A newly generated key needs
  enrollment.

`pnpm test` runs protocol, key storage, browser host trust/dialog, request
validation and origin tests. `pnpm run test:browser-key` is an opt-in
integration suite using local `/usr/bin/ssh`, `/usr/sbin/sshd`, node-pty,
Socket.IO and the real browser signing module with Node WebCrypto and simulated
IndexedDB. It starts an isolated loopback sshd, creates ephemeral host
keys/authorized_keys and runs commands as the current Unix account. It does not
edit the system SSH configuration or the user's authorized_keys. The host must
permit running this isolated sshd (including its privilege-separation runtime
directory).

The integration suite covers successful key login, password prompts after key
rejection or unavailable browser storage, failed host verification before
signing, and disconnect during signing. Actual Edge persistence across a full
browser restart remains a manual check.

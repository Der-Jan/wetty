# WeTTY deployment hardening

This directory repackages the existing `wetty.local` application image into
`wetty.hardened.local`. No application source or proxy/network configuration is
changed. The `public20` network and mTLS router settings are preserved.

The runtime uses UID/GID 1000, a read-only filesystem, a 64 MiB
noexec/nosuid/nodev /tmp tmpfs, no Linux capabilities, no-new-privileges, an
init process, and limits of 512 MiB RAM (no additional swap), 128
processes/threads and one CPU. Container logs rotate at 10 MiB with three files.
Only runtime packages, built application files and production dependencies are
copied into the image.

After updating/rebuilding the application image `wetty.local`:

```sh
cd /opt/containers/wetty
docker compose build wetty
docker compose run --rm --no-deps -T --entrypoint node wetty --input-type=module < runtime-smoke.mjs
docker compose up -d --no-deps wetty
```

Do not run the old repository deployment instructions directly: this deployment
now needs the extra runtime-image build. Avoid publishing port 3000.

Password and keyboard-interactive fallback remain enabled. SSH agent and browser
known-host sockets live in /tmp and disappear with the container. The SSH target
and tmux command are unchanged. Browser keys and trust records remain in
IndexedDB.

The shared network still allows reachable peers to bypass the proxy mTLS gate;
this change does not provide network isolation or application-level session
limits. SSH authentication still applies. Host administrators and Docker
administrators remain trusted. The resource limits bound total resource use, not
individual sessions.

Rollback (disconnects active browser sessions):

```sh
cd /opt/containers/wetty
cp compose.yaml.before-hardening compose.yaml
docker compose up -d --no-deps wetty
```

The original application image `wetty.local` is retained for rollback.

## Browser agent forwarding

The deployment enables `--browser-agent-forwarding`. The forwarded socket is
separate from the login socket and each onward signing request requires browser
approval. Forwarding requires a freshly loaded client with approval support. Use
`ssh-add -L` to list the browser key. For onward SSH use:

```sh
ssh -o PubkeyAuthentication=unbound -o PubkeyAcceptedAlgorithms=rsa-sha2-256 user@destination
```

The Compose login command refreshes a stable agent symlink before attaching to
tmux. Existing panes must set SSH_AUTH_SOCK to ~/.ssh/agent.sock once. RSA and
Ed25519 keys can be imported with ssh-add after browser approval. Imports
require WebSocket transport and persist as non-extractable CryptoKeys in
IndexedDB. The onward destination is not verified by the browser; approve only
operations you started.

To roll back only forwarding, restore `compose.yaml.before-forwarding`, set its
image to `wetty.hardened.before-forwarding`, then run
`docker compose up -d --no-deps --no-build wetty`. This retains runtime
hardening.

## Imported keys

Reload WeTTY after upgrading, then run `ssh-add ~/.ssh/id_ed25519` or
`ssh-add ~/.ssh/id_rsa` in the remote terminal and approve the fingerprint in
the browser. Imported RSA keys support SHA-256 and SHA-512; Ed25519 uses its
native algorithm. The eight-key imported store is separate from the generated
login key. Every use still needs approval. Constraints and removal are not
implemented; see the repository's docs/browser-agent-forwarding.md for
limitations.

The Compose login command continues to update ~/.ssh/agent.sock before tmux
attachment. Keep SSH_AUTH_SOCK set to that stable path in existing panes.

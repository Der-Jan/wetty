# Local deployment configuration

Versioned copies of the active deployment as of 2026-09-14. These files contain
host-specific names and addresses and are not a portable default configuration.
Copying them into this repository does not change the running deployment.

| Repository file    | Live location                            |
| ------------------ | ---------------------------------------- |
| compose.yaml       | /opt/containers/wetty/compose.yaml       |
| Dockerfile.runtime | /opt/containers/wetty/Dockerfile.runtime |
| runtime-smoke.mjs  | /opt/containers/wetty/runtime-smoke.mjs  |
| HARDENING.md       | /opt/containers/wetty/HARDENING.md       |
| wetty-stable.yml   | /opt/traefik/conf/wetty-stable.yml       |

The persistent Traefik file route takes priority over the Docker route and keeps
the `vault-mtls@file` policy active while WeTTY restarts. Both services use the
existing `public20` Docker network. The backend is addressed by its Docker DNS
name, `wetty:3000`. The referenced TLS option and its client CA configuration
already exist in Traefik and must be retained. Certificates, private keys, logs,
and historical rollback backup files/images are not part of this snapshot.
Rollback commands in HARDENING.md refer to backups present on the deployment
host.

To rebuild after application changes, first run from the repository root:

```sh
docker build -t wetty.local -f containers/wetty/Dockerfile .
```

Then synchronize the deployment files intentionally and follow HARDENING.md to
rebuild, smoke-test and deploy the hardened runtime. Install wetty-stable.yml in
Traefik's watched configuration directory; it reloads without a proxy restart.
The application container keeps its non-root user, read-only filesystem,
resource limits, browser-managed keys and password fallback.

The remote login command refreshes ~/.ssh/agent.sock before tmux attachment.
Existing panes need `export SSH_AUTH_SOCK="$HOME/.ssh/agent.sock"` once. The
latest browser connection supplies the agent behind that symlink.

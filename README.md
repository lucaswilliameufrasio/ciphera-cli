# ciphera-cli

Official CLI client for [Ciphera](https://github.com/lucaswilliameufrasio/ciphera),
a secret management system with envelope encryption, multi-tenant RBAC, and
per-environment machine tokens.

This repository builds and distributes prebuilt `ciphera` binaries. The
server/backend source lives in a separate, private repository — ask your
Ciphera admin for your tenant's API URL.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/lucaswilliameufrasio/ciphera-cli/main/scripts/install.sh | sh
```

Or build from source:

```bash
cargo install --git https://github.com/lucaswilliameufrasio/ciphera-cli ciphera-cli
```

See [SECURITY.md](SECURITY.md) for how release artifacts are verified.

## Quick usage

```bash
# Human login (device code flow — opens a browser, no password in the terminal)
ciphera login --api-url https://your-ciphera-instance.example.com

# Machine / CI / VPS usage — a service token scoped to one project+environment
export CIPHERA_TOKEN="<service token>"
ciphera run --project my-project --environment prod -- ./my-app
```

`ciphera run` fetches the environment's secrets, injects them as environment
variables into the target process (`exec`, never written to disk), and exits
when the child process exits.

## Commands

| Command | Purpose |
|---|---|
| `ciphera login` | Browser-based device-code login (human) |
| `ciphera login-password` | Email/password login (human) |
| `ciphera run -- <cmd>` | Inject secrets into a child process |
| `ciphera token create/list/revoke` | Manage per-environment machine tokens |
| `ciphera admin devices list/approve/deny` | Approve pending device logins (if the tenant requires it) |

Run `ciphera --help` or `ciphera <command> --help` for full flag reference.

## Releasing

This repo is a release mirror, not the development source — see the
`ciphera-core`/`ciphera-cli` crates here for the client-side contract types
and CLI implementation, kept in sync with the private backend repo.

## License

MIT — see [LICENSE](LICENSE).

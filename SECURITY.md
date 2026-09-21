# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅ |

## Reporting a Vulnerability

`ciphera-cli` is a client that authenticates against a Ciphera server, stores
session/refresh tokens in the OS keyring, and injects decrypted secrets into
child processes (`ciphera run`). It never writes secret values to disk, but a
compromised build of this CLI could exfiltrate credentials or the OS keyring
contents.

If you find a security vulnerability:

1. **Do not** open a public GitHub Issue.
2. Send an email to **lucas@eufrasio.dev** with details.
3. Include:
   - Affected version / commit SHA
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

You should receive a response within 48 hours. If you don't, please follow up.

## Scope

The following are **in scope**:
- Credential handling: OS keyring storage, `--token`/`CIPHERA_TOKEN` handling,
  `ciphera run`'s secret-to-child-process injection
- CI/CD supply-chain attacks on this repo's release pipeline (unpinned
  actions, compromised dependencies, tampered release artifacts)
- Anything that would let a malicious server response make the CLI behave
  unsafely (path traversal in downloaded config, command injection via
  `ciphera run`'s argument handling, etc.)

The following are **out of scope**:
- Vulnerabilities in the Ciphera backend/server itself (report those against
  the server's own channel, not this repo)
- Attacks requiring physical access or an already-compromised user account
- Social engineering against server operators

## Recognition

We will credit researchers who report valid vulnerabilities in the release notes,
unless they prefer to remain anonymous.

## Verifying a release

Release archives on this repo are published via `cargo-dist` from a tagged
CI run and are accompanied by a `.sha256` checksum served from the same
GitHub Release. This protects against transport corruption but not against a
compromised release pipeline — see `scripts/install.sh`'s header comment for
stronger trust-anchor options (building from source, verifying against a
maintainer signature).

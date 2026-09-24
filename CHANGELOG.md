# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-09-24

### Features

- Refresh session tokens transparently instead of requiring `ciphera refresh`

## [0.3.0] - 2026-09-23

### Features

- Instance-wide, paced KEK rotation sweep
- Resolve --project by name, clearer root --help
- OIDC trust policies for CI/CD service-token exchange

## [0.2.1] - 2026-09-22

### Bug Fixes

- Add package metadata cargo-dist needs on the public mirror

## [0.2.0] - 2026-09-22

### Bug Fixes

- Allow existing accounts to claim initial admin
- Harden auth and secret boundaries

### Features

- Implement Master KEK Key Rotation, Secret Soft-Delete, OS Keyring CLI integration, and Compliance Audit Logging
- Add real authentication, tenant isolation, and hardened service tokens
- Built-in web dashboard + list projects endpoint
- First-class environments + UI management
- Reveal secrets on demand in the web UI
- Add global configurable API URL default
- Interactive project selection with auto-save to ciphera.toml
- Org member invites with administrator/developer roles
- Add rfc 8628 device flow for browser-based cli login
- Browser-based login via device flow
- Approve CLI login from existing browser session
- System admin bootstrap, admin area and security hardening
- Device sessions with immediate revocation and account area
- Machine tokens, personal audit, device labels and admin sessions
- Add audit and member offboarding
- Support authenticated initial setup
- Add user blocking controls
- Require and cap machine token expiry
- Lock machine tokens to a CIDR allowlist
- Require admin approval for new devices

### Performance

- Upload import batches concurrently

### Testing

- Expand suite from 8 to 73 tests and fix reveal of deleted secret
- Isolate resolve_context test from ambient ciphera.toml

## [0.1.0] - 2026-09-21

### Chores

- Scaffold release tooling

### Features

- Mirror ciphera-cli and ciphera-core sources

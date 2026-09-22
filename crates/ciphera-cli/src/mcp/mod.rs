//! `ciphera mcp`: the metadata-only MCP server (Phase B), its installer for
//! Claude Code and other AI tools (Phase C/C1), and the hidden guard hook
//! used by the installer.

pub mod guard;
pub mod install;
pub mod opencode;
pub mod server;

pub use server::serve;

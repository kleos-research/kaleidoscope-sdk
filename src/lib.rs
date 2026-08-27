//! Public control-plane manager for the proprietary Kaleidoscope engine.
//!
//! This crate deliberately contains no memory operation implementation and no
//! MCP proxy. It invokes the native control contract and writes reversible host
//! configuration that launches the engine directly.

pub mod account;
pub mod config;
pub mod discovery;
pub mod doctor;
pub mod engine;
pub mod error;
pub mod fs_safe;
pub mod hooks;
pub mod host;
pub mod instructions;
pub mod json_span;
pub mod manager;
pub mod model;

pub use error::{ManagerError, Result};
pub use manager::Manager;

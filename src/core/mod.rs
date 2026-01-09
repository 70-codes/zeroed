//! Core module containing fundamental types, error definitions, and configuration structures
//! for the Zeroed DoS protection daemon.

pub mod config;
pub mod error;
pub mod types;

pub use config::ZeroedConfig as Config;
pub use error::{Result, ZeroedError};
pub use types::*;

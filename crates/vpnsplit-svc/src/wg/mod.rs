//! Туннель: загрузка wireguard.dll, конфиг, адаптер.

pub mod adapter;
pub mod config;
pub mod ffi;

pub use adapter::{Driver, ADAPTER_NAME};
pub use config::TunnelConfig;

//! Платформенная часть, общая для службы, лончера и UI: поиск интерфейса
//! туннеля, слежение за изменениями сети и за стартом процессов, канал до
//! службы.

pub mod devpath;
pub mod divert;
pub mod dns;
pub mod etw;
pub mod iface;
pub mod ipv4;
pub mod pipe;
pub mod proc;
pub mod routes;
pub mod tcptable;
pub mod udptable;
pub mod watch;
pub mod wfp;

/// Текущее состояние туннеля по таблице адаптеров.
pub fn detect_tunnel(filter: Option<&str>) -> vpnsplit_core::TunnelState {
    match iface::find_tunnel(filter) {
        Ok(adapter) => vpnsplit_core::TunnelState::Up(adapter.to_info()),
        Err(_) => vpnsplit_core::TunnelState::Down,
    }
}

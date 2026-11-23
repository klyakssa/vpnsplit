//! Сырые типы и экспорты wireguard.dll (WireGuardNT 1.1).
//!
//! Раскладка структур повторяет `include/wireguard.h` один в один: все три
//! структуры объявлены там с `ALIGNED(8)`, поэтому здесь `repr(C, align(8))`.
//! Порядок полей менять нельзя — драйвер читает блок памяти как есть.

// Здесь описана вся поверхность экспортов wireguard.dll, включая ту, что
// понадобится на следующих этапах (чтение конфига, состояние адаптера).
// Описывать её по частям дороже, чем один раз целиком.
#![allow(dead_code)]

use std::ffi::c_void;

pub const WIREGUARD_KEY_LENGTH: usize = 32;

pub const WIREGUARD_STATE_DOWN: i32 = 0;
pub const WIREGUARD_STATE_UP: i32 = 1;

// Флаги интерфейса.
pub const WIREGUARD_INTERFACE_HAS_PUBLIC_KEY: u32 = 1 << 0;
pub const WIREGUARD_INTERFACE_HAS_PRIVATE_KEY: u32 = 1 << 1;
pub const WIREGUARD_INTERFACE_HAS_LISTEN_PORT: u32 = 1 << 2;
pub const WIREGUARD_INTERFACE_REPLACE_PEERS: u32 = 1 << 3;

// Флаги пира.
pub const WIREGUARD_PEER_HAS_PUBLIC_KEY: u32 = 1 << 0;
pub const WIREGUARD_PEER_HAS_PRESHARED_KEY: u32 = 1 << 1;
pub const WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
pub const WIREGUARD_PEER_HAS_ENDPOINT: u32 = 1 << 3;
pub const WIREGUARD_PEER_REPLACE_ALLOWED_IPS: u32 = 1 << 5;

/// Непрозрачный хэндл адаптера.
pub type AdapterHandle = *mut c_void;

/// `SOCKADDR_IN`. Объявлен здесь, а не взят из windows-sys, чтобы раскладка
/// внутри `SockaddrInet` не зависела от версии чужого крейта.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

/// `SOCKADDR_IN6`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

/// `SOCKADDR_INET` — объединение v4, v6 и голого семейства адресов.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SockaddrInet {
    pub ipv4: SockaddrIn,
    pub ipv6: SockaddrIn6,
    pub family: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union IpAddress {
    pub v4: [u8; 4],
    pub v6: [u8; 16],
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardAllowedIp {
    pub address: IpAddress,
    pub address_family: u16,
    pub cidr: u8,
    pub flags: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardPeer {
    pub flags: u32,
    pub reserved: u32,
    pub public_key: [u8; WIREGUARD_KEY_LENGTH],
    pub preshared_key: [u8; WIREGUARD_KEY_LENGTH],
    pub persistent_keepalive: u16,
    pub endpoint: SockaddrInet,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Время последнего handshake в интервалах по 100 нс с 1601-01-01 UTC.
    pub last_handshake: u64,
    pub allowed_ips_count: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct WireguardInterface {
    pub flags: u32,
    pub listen_port: u16,
    pub private_key: [u8; WIREGUARD_KEY_LENGTH],
    pub public_key: [u8; WIREGUARD_KEY_LENGTH],
    pub peers_count: u32,
}

pub type CreateAdapterFn =
    unsafe extern "system" fn(name: *const u16, tunnel_type: *const u16, guid: *const c_void) -> AdapterHandle;
pub type OpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> AdapterHandle;
pub type CloseAdapterFn = unsafe extern "system" fn(adapter: AdapterHandle);
pub type GetAdapterLuidFn = unsafe extern "system" fn(adapter: AdapterHandle, luid: *mut u64);
pub type GetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;
pub type SetAdapterStateFn = unsafe extern "system" fn(adapter: AdapterHandle, state: i32) -> i32;
pub type GetAdapterStateFn = unsafe extern "system" fn(adapter: AdapterHandle, state: *mut i32) -> i32;
pub type SetConfigurationFn =
    unsafe extern "system" fn(adapter: AdapterHandle, config: *const WireguardInterface, bytes: u32) -> i32;
pub type GetConfigurationFn =
    unsafe extern "system" fn(adapter: AdapterHandle, config: *mut WireguardInterface, bytes: *mut u32) -> i32;

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    // Если эти значения разойдутся с wireguard.h, драйвер прочитает мусор,
    // причём молча. Поэтому раскладка зафиксирована тестом.

    #[test]
    fn interface_layout_matches_header() {
        assert_eq!(align_of::<WireguardInterface>(), 8);
        // 4 флаги + 2 порт + 32 приватный + 32 публичный = 70, DWORD выравнивается
        // до 72, плюс 4 байта счётчика = 76, хвост до кратности 8 = 80.
        assert_eq!(size_of::<WireguardInterface>(), 80);
    }

    #[test]
    fn peer_layout_matches_header() {
        assert_eq!(align_of::<WireguardPeer>(), 8);
        assert_eq!(size_of::<SockaddrInet>(), 28);
        assert_eq!(size_of::<WireguardPeer>(), 136);
    }

    #[test]
    fn allowed_ip_layout_matches_header() {
        assert_eq!(align_of::<WireguardAllowedIp>(), 8);
        assert_eq!(size_of::<WireguardAllowedIp>(), 24);
    }
}

//! Безопасная обёртка над wireguard.dll.

use super::config::{TunnelConfig, KEY_LEN};
use super::ffi::*;
use std::ffi::c_void;
use std::fmt;
use std::mem::size_of;
use std::net::IpAddr;
use std::path::Path;
use vpnsplit_core::InterfaceIndex;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};

/// Имя адаптера. Оно же видно в «Сетевых подключениях».
pub const ADAPTER_NAME: &str = "vpnsplit";
const TUNNEL_TYPE: &str = "VpnSplit";

/// Фиксированный GUID адаптера: с ним Windows не заводит новую запись
/// «Сеть N» при каждом подъёме туннеля.
const ADAPTER_GUID: Guid = Guid {
    data1: 0x7b9d_1f42,
    data2: 0x4c3e,
    data3: 0x4a51,
    data4: [0x9e, 0x2d, 0x5f, 0x11, 0xc8, 0x40, 0x3b, 0x76],
};

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[derive(Debug)]
pub enum WgError {
    DllNotFound { path: String, code: u32 },
    ExportMissing(&'static str),
    CreateAdapter(u32),
    SetConfiguration(u32),
    SetState(u32),
    LuidToIndex(u32),
}

impl fmt::Display for WgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WgError::DllNotFound { path, code } => {
                write!(f, "не удалось загрузить {path} (код {code})")
            }
            WgError::ExportMissing(name) => write!(f, "в wireguard.dll нет экспорта {name}"),
            WgError::CreateAdapter(code) => write!(f, "не удалось создать адаптер (код {code})"),
            WgError::SetConfiguration(code) => write!(f, "не удалось применить конфиг (код {code})"),
            WgError::SetState(code) => write!(f, "не удалось сменить состояние адаптера (код {code})"),
            WgError::LuidToIndex(code) => write!(f, "LUID не преобразуется в индекс (код {code})"),
        }
    }
}

impl std::error::Error for WgError {}

struct Exports {
    create_adapter: CreateAdapterFn,
    close_adapter: CloseAdapterFn,
    get_adapter_luid: GetAdapterLuidFn,
    get_running_driver_version: GetRunningDriverVersionFn,
    set_adapter_state: SetAdapterStateFn,
    set_configuration: SetConfigurationFn,
}

/// Загруженная библиотека и её экспорты. Живёт столько же, сколько адаптер.
pub struct Driver {
    exports: Exports,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

impl Driver {
    /// Загружает wireguard.dll строго из каталога приложения или System32.
    /// Поиск по PATH и текущему каталогу намеренно отключён: это драйвер
    /// режима ядра, подменять его чужой библиотекой нельзя.
    pub fn load(dll_path: &Path) -> Result<Self, WgError> {
        let wide_path = wide(&dll_path.to_string_lossy());
        let module = unsafe {
            LoadLibraryExW(
                wide_path.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(WgError::DllNotFound {
                path: dll_path.display().to_string(),
                code: unsafe { GetLastError() },
            });
        }

        macro_rules! export {
            ($name:literal, $ty:ty) => {{
                let symbol = concat!($name, "\0");
                let addr = unsafe { GetProcAddress(module, symbol.as_ptr()) };
                match addr {
                    // GetProcAddress отдаёт FARPROC; оба типа указаны явно,
                    // иначе transmute легко промахнётся при правке сигнатур.
                    Some(addr) => unsafe {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(addr)
                    },
                    None => return Err(WgError::ExportMissing($name)),
                }
            }};
        }

        Ok(Driver {
            exports: Exports {
                create_adapter: export!("WireGuardCreateAdapter", CreateAdapterFn),
                close_adapter: export!("WireGuardCloseAdapter", CloseAdapterFn),
                get_adapter_luid: export!("WireGuardGetAdapterLUID", GetAdapterLuidFn),
                get_running_driver_version: export!(
                    "WireGuardGetRunningDriverVersion",
                    GetRunningDriverVersionFn
                ),
                set_adapter_state: export!("WireGuardSetAdapterState", SetAdapterStateFn),
                set_configuration: export!("WireGuardSetConfiguration", SetConfigurationFn),
            },
        })
    }

    /// Версия загруженного драйвера, или 0 если он ещё не поднят.
    pub fn running_version(&self) -> u32 {
        unsafe { (self.exports.get_running_driver_version)() }
    }

    pub fn create_adapter(&self) -> Result<Adapter<'_>, WgError> {
        let name = wide(ADAPTER_NAME);
        let kind = wide(TUNNEL_TYPE);
        let handle = unsafe {
            (self.exports.create_adapter)(
                name.as_ptr(),
                kind.as_ptr(),
                &ADAPTER_GUID as *const Guid as *const c_void,
            )
        };
        if handle.is_null() {
            return Err(WgError::CreateAdapter(unsafe { GetLastError() }));
        }
        Ok(Adapter {
            driver: self,
            handle,
        })
    }
}

pub struct Adapter<'a> {
    driver: &'a Driver,
    handle: AdapterHandle,
}

impl Adapter<'_> {
    /// Индекс интерфейса. Именно он уходит в `IP_UNICAST_IF` на Этапе 2.
    pub fn interface_index(&self) -> Result<InterfaceIndex, WgError> {
        let mut luid: u64 = 0;
        unsafe { (self.driver.exports.get_adapter_luid)(self.handle, &mut luid) };
        let luid_lh = NET_LUID_LH { Value: luid };
        let mut index: u32 = 0;
        let status = unsafe { ConvertInterfaceLuidToIndex(&luid_lh, &mut index) };
        if status != 0 {
            return Err(WgError::LuidToIndex(status));
        }
        Ok(InterfaceIndex::new(index))
    }

    pub fn luid(&self) -> u64 {
        let mut luid: u64 = 0;
        unsafe { (self.driver.exports.get_adapter_luid)(self.handle, &mut luid) };
        luid
    }

    pub fn apply(&self, config: &TunnelConfig) -> Result<(), WgError> {
        let blob = build_config_blob(config);
        let bytes = blob.len() as u32;
        let ok = unsafe {
            (self.driver.exports.set_configuration)(
                self.handle,
                blob.as_ptr() as *const WireguardInterface,
                bytes,
            )
        };
        if ok == 0 {
            return Err(WgError::SetConfiguration(unsafe { GetLastError() }));
        }
        Ok(())
    }

    pub fn set_state(&self, up: bool) -> Result<(), WgError> {
        let state = if up { WIREGUARD_STATE_UP } else { WIREGUARD_STATE_DOWN };
        let ok = unsafe { (self.driver.exports.set_adapter_state)(self.handle, state) };
        if ok == 0 {
            return Err(WgError::SetState(unsafe { GetLastError() }));
        }
        Ok(())
    }
}

impl Drop for Adapter<'_> {
    fn drop(&mut self) {
        unsafe { (self.driver.exports.close_adapter)(self.handle) };
    }
}

/// Байты, которые драйвер читает как единый блок: интерфейс, за ним пиры,
/// за каждым пиром его allowed IPs. Буфер выровнен на 8 байт — для этого
/// он собирается в `Vec<u64>`, а не в `Vec<u8>`.
struct Blob {
    words: Vec<u64>,
    len: usize,
}

impl Blob {
    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr() as *const u8
    }

    fn len(&self) -> usize {
        self.len
    }
}

fn build_config_blob(config: &TunnelConfig) -> Blob {
    let allowed = &config.peer.allowed_ips;
    let total = size_of::<WireguardInterface>()
        + size_of::<WireguardPeer>()
        + allowed.len() * size_of::<WireguardAllowedIp>();
    let mut words = vec![0u64; total.div_ceil(8)];
    let base = words.as_mut_ptr() as *mut u8;

    let mut iface_flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY | WIREGUARD_INTERFACE_REPLACE_PEERS;
    if config.listen_port != 0 {
        iface_flags |= WIREGUARD_INTERFACE_HAS_LISTEN_PORT;
    }

    let iface = WireguardInterface {
        flags: iface_flags,
        listen_port: config.listen_port,
        private_key: config.private_key,
        public_key: [0u8; KEY_LEN],
        peers_count: 1,
    };

    let mut peer_flags = WIREGUARD_PEER_HAS_PUBLIC_KEY
        | WIREGUARD_PEER_HAS_ENDPOINT
        | WIREGUARD_PEER_REPLACE_ALLOWED_IPS;
    if config.peer.preshared_key.is_some() {
        peer_flags |= WIREGUARD_PEER_HAS_PRESHARED_KEY;
    }
    if config.peer.persistent_keepalive != 0 {
        peer_flags |= WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE;
    }

    let peer = WireguardPeer {
        flags: peer_flags,
        reserved: 0,
        public_key: config.peer.public_key,
        preshared_key: config.peer.preshared_key.unwrap_or([0u8; KEY_LEN]),
        persistent_keepalive: config.peer.persistent_keepalive,
        endpoint: to_sockaddr_inet(config.peer.endpoint),
        tx_bytes: 0,
        rx_bytes: 0,
        last_handshake: 0,
        allowed_ips_count: allowed.len() as u32,
    };

    unsafe {
        let iface_ptr = base as *mut WireguardInterface;
        iface_ptr.write(iface);

        let peer_ptr = base.add(size_of::<WireguardInterface>()) as *mut WireguardPeer;
        peer_ptr.write(peer);

        let mut ip_ptr = base
            .add(size_of::<WireguardInterface>() + size_of::<WireguardPeer>())
            as *mut WireguardAllowedIp;
        for net in allowed {
            ip_ptr.write(to_allowed_ip(net.addr, net.cidr));
            ip_ptr = ip_ptr.add(1);
        }
    }

    Blob { words, len: total }
}

fn to_allowed_ip(addr: IpAddr, cidr: u8) -> WireguardAllowedIp {
    match addr {
        IpAddr::V4(v4) => WireguardAllowedIp {
            address: IpAddress { v4: v4.octets() },
            address_family: AF_INET,
            cidr,
            flags: 0,
        },
        IpAddr::V6(v6) => WireguardAllowedIp {
            address: IpAddress { v6: v6.octets() },
            address_family: AF_INET6,
            cidr,
            flags: 0,
        },
    }
}

fn to_sockaddr_inet(addr: std::net::SocketAddr) -> SockaddrInet {
    match addr {
        std::net::SocketAddr::V4(v4) => SockaddrInet {
            ipv4: SockaddrIn {
                sin_family: AF_INET,
                // Порт в структуре сокета всегда в сетевом порядке.
                sin_port: v4.port().to_be(),
                sin_addr: v4.ip().octets(),
                sin_zero: [0u8; 8],
            },
        },
        std::net::SocketAddr::V6(v6) => SockaddrInet {
            ipv6: SockaddrIn6 {
                sin6_family: AF_INET6,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: v6.ip().octets(),
                sin6_scope_id: v6.scope_id(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TunnelConfig {
        TunnelConfig::parse(
            "[Interface]\n\
             PrivateKey = 6GjYPQOCqPdW1h0cJWMrmNxDLhPNeMBPYxOhBDSHPWs=\n\
             Address = 10.8.0.2/32\n\
             [Peer]\n\
             PublicKey = Xo1eYOYNbrgLq0rq6kuOg1BvzSNNEIyrCOJHxBEXaXo=\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = 127.0.0.1:51820\n",
        )
        .unwrap()
    }

    #[test]
    fn blob_size_matches_struct_sizes() {
        let blob = build_config_blob(&sample());
        let expected = size_of::<WireguardInterface>()
            + size_of::<WireguardPeer>()
            + 2 * size_of::<WireguardAllowedIp>();
        assert_eq!(blob.len(), expected);
        assert_eq!(blob.as_ptr() as usize % 8, 0, "буфер обязан быть выровнен на 8");
    }

    #[test]
    fn blob_header_reads_back() {
        let config = sample();
        let blob = build_config_blob(&config);
        let iface = unsafe { &*(blob.as_ptr() as *const WireguardInterface) };
        assert_eq!(iface.peers_count, 1);
        assert_eq!(iface.private_key, config.private_key);
        assert_ne!(iface.flags & WIREGUARD_INTERFACE_HAS_PRIVATE_KEY, 0);
        assert_ne!(iface.flags & WIREGUARD_INTERFACE_REPLACE_PEERS, 0);
        // ListenPort не задан, значит флага быть не должно.
        assert_eq!(iface.flags & WIREGUARD_INTERFACE_HAS_LISTEN_PORT, 0);
    }

    #[test]
    fn peer_follows_the_interface_in_memory() {
        let config = sample();
        let blob = build_config_blob(&config);
        let peer = unsafe {
            &*(blob.as_ptr().add(size_of::<WireguardInterface>()) as *const WireguardPeer)
        };
        assert_eq!(peer.public_key, config.peer.public_key);
        assert_eq!(peer.allowed_ips_count, 2);
        assert_eq!(peer.reserved, 0);
        // Порт в SOCKADDR_IN хранится в сетевом порядке.
        assert_eq!(unsafe { peer.endpoint.ipv4.sin_port }, 51820u16.to_be());
    }

    #[test]
    fn allowed_ips_follow_the_peer() {
        let blob = build_config_blob(&sample());
        let first = unsafe {
            &*(blob
                .as_ptr()
                .add(size_of::<WireguardInterface>() + size_of::<WireguardPeer>())
                as *const WireguardAllowedIp)
        };
        assert_eq!(first.address_family, AF_INET);
        assert_eq!(first.cidr, 0);
    }
}

//! Адреса, метрики, MTU и маршруты.
//!
//! Ключевое решение схемы живёт здесь: маршрут по умолчанию на физическом
//! адаптере не трогается, а `0.0.0.0/0` и `::/0` на WG-интерфейсе получают
//! метрику `WG_ROUTE_METRIC`. Маршрут существует для сокетов, привязанных
//! к интерфейсу через `IP_UNICAST_IF`, но сам трафик не притягивает.

use std::fmt;
use std::mem::zeroed;
use std::net::{IpAddr, SocketAddr};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, AF_INET, AF_INET6, SOCKADDR_INET,
};

#[derive(Debug)]
pub enum RouteError {
    AddAddress(u32),
    ReadInterface(u32),
    WriteInterface(u32),
    AddRoute { what: &'static str, code: u32 },
    DeleteRoute(u32),
    NoRouteToEndpoint(u32),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::AddAddress(code) => write!(f, "не удалось назначить адрес (код {code})"),
            RouteError::ReadInterface(code) => write!(f, "не удалось прочитать интерфейс (код {code})"),
            RouteError::WriteInterface(code) => write!(f, "не удалось настроить интерфейс (код {code})"),
            RouteError::AddRoute { what, code } => {
                write!(f, "не удалось добавить маршрут {what} (код {code})")
            }
            RouteError::DeleteRoute(code) => write!(f, "не удалось удалить маршрут (код {code})"),
            RouteError::NoRouteToEndpoint(code) => {
                write!(f, "нет маршрута до endpoint через физический адаптер (код {code})")
            }
        }
    }
}

impl std::error::Error for RouteError {}

/// Куда уходит трафик до endpoint'а, если туннеля нет. Снимается ДО подъёма
/// туннеля: после него картина маршрутов уже другая.
// Debug не выводится: SOCKADDR_INET — объединение, читать его можно только
// зная семейство адресов.
#[derive(Clone, Copy)]
pub struct PhysicalPath {
    pub interface_index: u32,
    pub interface_luid: u64,
    pub next_hop: SOCKADDR_INET,
}

pub fn sockaddr_from_ip(addr: IpAddr) -> SOCKADDR_INET {
    let mut out: SOCKADDR_INET = unsafe { zeroed() };
    // Запись в поле объединения безопасна, небезопасно только чтение:
    // прочитать можно лишь тот вариант, который был записан.
    match addr {
        IpAddr::V4(v4) => {
            out.Ipv4.sin_family = AF_INET;
            out.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            out.Ipv6.sin6_family = AF_INET6;
            out.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    out
}

/// Маршрут до endpoint'а в обход туннеля. Без него handshake уйдёт внутрь
/// собственного туннеля (а при поднятом OpenVPN — внутрь чужого).
pub fn find_physical_path(endpoint: SocketAddr) -> Result<PhysicalPath, RouteError> {
    let destination = sockaddr_from_ip(endpoint.ip());
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
    let mut source: SOCKADDR_INET = unsafe { zeroed() };

    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut row,
            &mut source,
        )
    };
    if status != 0 {
        return Err(RouteError::NoRouteToEndpoint(status));
    }

    Ok(PhysicalPath {
        interface_index: row.InterfaceIndex,
        interface_luid: unsafe { row.InterfaceLuid.Value },
        next_hop: row.NextHop,
    })
}

/// Назначает адрес на интерфейс.
pub fn add_address(luid: u64, addr: IpAddr, cidr: u8) -> Result<(), RouteError> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid.Value = luid;
    row.Address = sockaddr_from_ip(addr);
    row.OnLinkPrefixLength = cidr;
    // Адрес туннеля не подлежит дублирующей проверке: отвечать на неё некому.
    row.DadState = IpDadStatePreferred;

    let status = unsafe { CreateUnicastIpAddressEntry(&row) };
    // ERROR_OBJECT_ALREADY_EXISTS — адрес уже назначен, это не ошибка.
    if status != 0 && status != 5010 {
        return Err(RouteError::AddAddress(status));
    }
    Ok(())
}

/// MTU и метрика интерфейса. Метрика ставится вручную, иначе Windows
/// подберёт её сама и может сделать туннель привлекательнее физики.
pub fn configure_interface(luid: u64, family: u16, mtu: u32, metric: u32) -> Result<(), RouteError> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
    row.Family = family;
    row.InterfaceLuid.Value = luid;

    let status = unsafe { GetIpInterfaceEntry(&mut row) };
    if status != 0 {
        return Err(RouteError::ReadInterface(status));
    }

    row.NlMtu = mtu;
    row.UseAutomaticMetric = 0;
    row.Metric = metric;
    // Документированная особенность: после чтения строки это поле надо
    // обнулить, иначе запись вернёт ошибку для IPv4.
    if family == AF_INET {
        row.SitePrefixLength = 0;
    }

    let status = unsafe { SetIpInterfaceEntry(&mut row) };
    if status != 0 {
        return Err(RouteError::WriteInterface(status));
    }
    Ok(())
}

/// Добавляет маршрут. `next_hop` равный `None` означает маршрут на интерфейс.
pub fn add_route(
    what: &'static str,
    luid: u64,
    destination: IpAddr,
    cidr: u8,
    next_hop: Option<SOCKADDR_INET>,
    metric: u32,
) -> Result<(), RouteError> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid.Value = luid;
    row.DestinationPrefix.Prefix = sockaddr_from_ip(destination);
    row.DestinationPrefix.PrefixLength = cidr;
    if let Some(hop) = next_hop {
        row.NextHop = hop;
    } else {
        row.NextHop = sockaddr_from_ip(match destination {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        });
    }
    row.Metric = metric;

    let status = unsafe { CreateIpForwardEntry2(&row) };
    if status != 0 && status != 5010 {
        return Err(RouteError::AddRoute { what, code: status });
    }
    Ok(())
}

pub fn delete_route(
    luid: u64,
    destination: IpAddr,
    cidr: u8,
    next_hop: Option<SOCKADDR_INET>,
) -> Result<(), RouteError> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid.Value = luid;
    row.DestinationPrefix.Prefix = sockaddr_from_ip(destination);
    row.DestinationPrefix.PrefixLength = cidr;
    if let Some(hop) = next_hop {
        row.NextHop = hop;
    }

    let status = unsafe { DeleteIpForwardEntry2(&row) };
    // ERROR_NOT_FOUND — маршрута уже нет, значит цель достигнута.
    if status != 0 && status != 1168 {
        return Err(RouteError::DeleteRoute(status));
    }
    Ok(())
}

pub fn family_of(addr: IpAddr) -> u16 {
    if addr.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    }
}

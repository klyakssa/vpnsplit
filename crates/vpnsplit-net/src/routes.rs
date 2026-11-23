//! Таблица маршрутов: куда уйдёт пакет и с каким адресом источника.

use std::net::Ipv4Addr;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetBestRoute2, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

/// Куда система отправит пакет к этому адресу, если её не трогать.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub interface_index: u32,
    /// Адрес источника, который выберет стек. Для входящего пакета, который
    /// мы переписываем обратно, это и есть тот адрес, которого ждёт сокет.
    pub source: Ipv4Addr,
}

/// Обычный выбор маршрута — тот же, что сделает стек для несвязанного
/// сокета. Нужен, чтобы знать «домашний» интерфейс и адрес, не угадывая их
/// по именам адаптеров.
pub fn best_route(destination: Ipv4Addr) -> Option<Route> {
    let mut target: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    target.Ipv4.sin_family = AF_INET;
    target.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(destination.octets());

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    let code = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &target,
            0,
            &mut row,
            &mut source,
        )
    };
    if code != 0 {
        return None;
    }
    let bytes = unsafe { source.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes();
    Some(Route {
        interface_index: row.InterfaceIndex,
        source: Ipv4Addr::from(bytes),
    })
}

/// Стоят ли на интерфейсе маршруты `0.0.0.0/1` и `128.0.0.0/1`. Вместе они
/// покрывают весь IPv4 и точнее маршрута по умолчанию, поэтому выигрывают
/// при любой метрике: весь трафик системы уходит в этот интерфейс.
pub fn captures_all_traffic(interface_index: u32) -> bool {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != 0 || table.is_null() {
        return false;
    }
    let (mut low, mut high) = (false, false);
    unsafe {
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.InterfaceIndex != interface_index || row.DestinationPrefix.PrefixLength != 1 {
                continue;
            }
            let prefix = &row.DestinationPrefix.Prefix;
            if prefix.si_family != AF_INET {
                continue;
            }
            match prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()[0] {
                0 => low = true,
                128 => high = true,
                _ => {}
            }
        }
        FreeMibTable(table as _);
    }
    low && high
}

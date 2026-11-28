//! Поиск интерфейса туннеля по имени адаптера.
//!
//! Индекс интерфейса нельзя вбивать в код: он меняется при переподключении,
//! а у OpenVPN рядом живёт второй адаптер (DCO) со своим номером.

use std::net::Ipv4Addr;
use vpnsplit_core::InterfaceIndex;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

#[derive(Clone, Debug)]
pub struct Adapter {
    pub index: InterfaceIndex,
    pub name: String,
    pub description: String,
    pub up: bool,
    pub ipv4: Option<Ipv4Addr>,
}

impl Adapter {
    /// Подходит ли адаптер под строку поиска (без учёта регистра, по имени
    /// или описанию).
    pub fn matches(&self, needle: &str) -> bool {
        let needle = needle.to_lowercase();
        self.name.to_lowercase().contains(&needle) || self.description.to_lowercase().contains(&needle)
    }

    /// Похож ли адаптер на туннель. Используется, когда имя не задано явно.
    pub fn looks_like_tunnel(&self) -> bool {
        ["tap-windows", "openvpn", "wireguard", "vpnsplit", "wintun"]
            .iter()
            .any(|marker| self.matches(marker))
    }

    /// Пригоден ли для привязки: поднят и имеет настоящий адрес IPv4.
    /// Адрес 169.254.x Windows выдаёт сама, когда адрес не получен, — с ним
    /// адаптер поднят, но туннеля за ним нет.
    pub fn usable(&self) -> bool {
        self.up && self.ipv4.is_some_and(|a| !a.is_link_local())
    }

    pub fn to_info(&self) -> vpnsplit_core::TunnelInfo {
        vpnsplit_core::TunnelInfo {
            index: self.index.get(),
            name: self.name.clone(),
            ipv4: self.ipv4,
            captures_all: crate::routes::captures_all_traffic(self.index.get()),
            dns: Vec::new(),
        }
    }
}

pub fn list() -> Result<Vec<Adapter>, String> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buffer: Vec<u64>;
    loop {
        // Vec<u64> ради выравнивания структур, как и с блоком WireGuard.
        buffer = vec![0u64; (size as usize).div_ceil(8)];
        let status = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match status {
            0 => break,
            111 => continue, // ERROR_BUFFER_OVERFLOW: size уже обновлён
            232 => return Ok(Vec::new()), // ERROR_NO_DATA: адаптеров нет
            code => return Err(format!("GetAdaptersAddresses вернул {code}")),
        }
    }

    let mut out = Vec::new();
    let mut cursor = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cursor.is_null() {
        let adapter = unsafe { &*cursor };
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        out.push(Adapter {
            index: InterfaceIndex::new(index),
            name: unsafe { wide_to_string(adapter.FriendlyName) },
            description: unsafe { wide_to_string(adapter.Description) },
            up: adapter.OperStatus == IfOperStatusUp,
            ipv4: unsafe { first_ipv4(adapter) },
        });
        cursor = adapter.Next;
    }
    Ok(out)
}

/// Выбирает интерфейс туннеля: по явной строке поиска или по признакам.
pub fn find_tunnel(needle: Option<&str>) -> Result<Adapter, String> {
    let adapters = list()?;
    let candidates: Vec<&Adapter> = match needle {
        Some(text) => adapters.iter().filter(|a| a.matches(text)).collect(),
        None => adapters.iter().filter(|a| a.looks_like_tunnel()).collect(),
    };

    if let Some(found) = candidates.iter().find(|a| a.usable()) {
        return Ok((*found).clone());
    }

    let what = needle
        .map(|t| format!("подходящий под «{t}»"))
        .unwrap_or_else(|| "похожий на туннель".to_owned());
    if candidates.is_empty() {
        Err(format!("не найден адаптер, {what}. Список: vpnsplit-launch --list"))
    } else {
        Err(format!(
            "адаптер, {what}, найден, но не поднят или без адреса IPv4 — туннель не подключён?"
        ))
    }
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// Первый настоящий адрес IPv4, а если такого нет — хоть какой-то
/// (169.254.x), чтобы `--list` показывал, что адаптер без адреса.
unsafe fn first_ipv4(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Option<Ipv4Addr> {
    let mut fallback = None;
    let mut unicast = adapter.FirstUnicastAddress;
    while !unicast.is_null() {
        let sockaddr = (*unicast).Address.lpSockaddr;
        if !sockaddr.is_null() && (*sockaddr).sa_family == AF_INET {
            let v4 = &*(sockaddr as *const SOCKADDR_IN);
            let addr = Ipv4Addr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes());
            if !addr.is_link_local() {
                return Some(addr);
            }
            fallback.get_or_insert(addr);
        }
        unicast = (*unicast).Next;
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::Adapter;
    use std::net::Ipv4Addr;
    use vpnsplit_core::InterfaceIndex;

    fn tap(up: bool, ipv4: Option<Ipv4Addr>) -> Adapter {
        Adapter {
            index: InterfaceIndex::new(8),
            name: "OpenVPN TAP-Windows6".into(),
            description: "TAP-Windows Adapter V9".into(),
            up,
            ipv4,
        }
    }

    #[test]
    fn apipa_address_is_not_a_tunnel() {
        assert!(!tap(true, Some(Ipv4Addr::new(169, 254, 199, 54))).usable());
    }

    #[test]
    fn real_address_on_up_adapter_is_usable() {
        assert!(tap(true, Some(Ipv4Addr::new(10, 5, 5, 2))).usable());
        assert!(!tap(false, Some(Ipv4Addr::new(10, 5, 5, 2))).usable());
        assert!(!tap(true, None).usable());
    }

    #[test]
    fn tap_looks_like_tunnel() {
        assert!(tap(true, None).looks_like_tunnel());
    }
}

//! Индекс сетевого интерфейса и его представление для опций сокета.

/// Индекс сетевого интерфейса Windows (`InterfaceIndex` из `MIB_IPINTERFACE_ROW`).
///
/// Главная ловушка `IP_UNICAST_IF`: для IPv4 значение опции передаётся
/// в **сетевом** порядке байт, а для IPv6 в `IPV6_UNICAST_IF` — в **хостовом**.
/// Несимметрия намеренная и задокументирована Microsoft. На ней спотыкаются все,
/// поэтому доступ к сырому числу идёт только через эти два метода.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct InterfaceIndex(u32);

impl InterfaceIndex {
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Сырой индекс, как его отдаёт IP Helper API.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Значение для `setsockopt(IPPROTO_IP, IP_UNICAST_IF, ...)` — сетевой порядок.
    pub const fn ipv4_sockopt_value(self) -> u32 {
        self.0.to_be()
    }

    /// Значение для `setsockopt(IPPROTO_IPV6, IPV6_UNICAST_IF, ...)` — хостовой порядок.
    pub const fn ipv6_sockopt_value(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::InterfaceIndex;

    // setsockopt читает четыре байта из памяти, поэтому проверяется именно
    // раскладка в памяти (to_ne_bytes), а не числовое значение.

    #[test]
    fn ipv4_value_lands_in_memory_in_network_order() {
        let idx = InterfaceIndex::new(14);
        assert_eq!(idx.ipv4_sockopt_value().to_ne_bytes(), [0, 0, 0, 14]);
    }

    #[test]
    fn ipv6_value_lands_in_memory_in_host_order() {
        let idx = InterfaceIndex::new(14);
        assert_eq!(idx.ipv6_sockopt_value(), 14);
        assert_eq!(idx.ipv6_sockopt_value().to_ne_bytes(), [14, 0, 0, 0]);
    }

    #[test]
    fn the_two_differ_on_little_endian() {
        // Если это равенство когда-нибудь станет истинным, значит сборка идёт
        // на big-endian и всю работу с порядком байт надо перепроверить.
        let idx = InterfaceIndex::new(14);
        assert_ne!(idx.ipv4_sockopt_value(), idx.ipv6_sockopt_value());
    }
}

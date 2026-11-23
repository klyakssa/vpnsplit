//! Минимальный разбор заголовка IPv4 — ровно столько, сколько нужно, чтобы
//! подменить адрес и прочитать порты.
//!
//! Своей арифметики контрольных сумм здесь нет: её пересчитывает
//! `divert::fix_checksums`. Задача этого модуля — не выйти за границы
//! буфера на пакете, пришедшем из сети, то есть на данных, которым нельзя
//! доверять.

use std::net::Ipv4Addr;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

const MIN_HEADER: usize = 20;
const SOURCE: usize = 12;
const DESTINATION: usize = 16;
const PROTOCOL: usize = 9;

/// Заголовок IPv4 внутри пакета. Создаётся только после проверок, поэтому
/// дальше можно читать и писать без оглядки.
pub struct Header<'a> {
    bytes: &'a mut [u8],
    /// Длина заголовка: она переменная, за ней начинаются порты.
    length: usize,
}

impl<'a> Header<'a> {
    /// `None`, если это не IPv4 или заголовок не влезает в пакет.
    pub fn new(packet: &'a mut [u8]) -> Option<Header<'a>> {
        if packet.len() < MIN_HEADER || packet[0] >> 4 != 4 {
            return None;
        }
        let length = (packet[0] & 0x0F) as usize * 4;
        if length < MIN_HEADER || length > packet.len() {
            return None;
        }
        Some(Header { bytes: packet, length })
    }

    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::from(read4(&self.bytes[SOURCE..]))
    }

    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::from(read4(&self.bytes[DESTINATION..]))
    }

    pub fn set_source(&mut self, address: Ipv4Addr) {
        self.bytes[SOURCE..SOURCE + 4].copy_from_slice(&address.octets());
    }

    pub fn set_destination(&mut self, address: Ipv4Addr) {
        self.bytes[DESTINATION..DESTINATION + 4].copy_from_slice(&address.octets());
    }

    pub fn protocol(&self) -> u8 {
        self.bytes[PROTOCOL]
    }

    /// Порты источника и получателя — только для TCP и UDP, у которых они
    /// лежат в первых четырёх байтах после заголовка. Для осколка пакета
    /// (не первого фрагмента) портов нет, и это честное `None`.
    pub fn ports(&self) -> Option<(u16, u16)> {
        if !matches!(self.protocol(), PROTO_TCP | PROTO_UDP) {
            return None;
        }
        if self.fragment_offset() != 0 {
            return None;
        }
        let rest = self.bytes.get(self.length..self.length + 4)?;
        Some((
            u16::from_be_bytes([rest[0], rest[1]]),
            u16::from_be_bytes([rest[2], rest[3]]),
        ))
    }

    fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]]) & 0x1FFF
    }
}

fn read4(bytes: &[u8]) -> [u8; 4] {
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// Данные дейтаграммы UDP: то, что идёт после заголовков IP и UDP.
///
/// Длина заголовка IP переменная, и считать её на месте каждый раз — верный
/// способ однажды посчитать иначе. `None`, если это не IPv4, не UDP или
/// пакет обрывается.
pub fn udp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < MIN_HEADER || packet[0] >> 4 != 4 || packet[PROTOCOL] != PROTO_UDP {
        return None;
    }
    let header = (packet[0] & 0x0F) as usize * 4;
    if header < MIN_HEADER {
        return None;
    }
    // Восемь байт заголовка UDP: порты, длина, контрольная сумма.
    packet.get(header + 8..)
}

/// Адрес, который в туннель не уводится: своя сеть и рассылки.
///
/// Раздельное туннелирование уводит то, что идёт наружу. Принтер, роутер и
/// соседний компьютер остаются там же, где были: уведи их пакеты в туннель
/// — и на том конце таких адресов просто нет. Kill-switch пути A устроен
/// так же: локальная сеть остаётся доступной.
pub fn stays_home(address: Ipv4Addr) -> bool {
    address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_loopback()
        || address.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Заголовок IPv4 без опций, TCP, с портами 50000 → 443.
    fn packet() -> Vec<u8> {
        let mut bytes = vec![0u8; 24];
        bytes[0] = 0x45; // версия 4, длина заголовка 5 слов
        bytes[9] = PROTO_TCP;
        bytes[SOURCE..SOURCE + 4].copy_from_slice(&[192, 168, 31, 35]);
        bytes[DESTINATION..DESTINATION + 4].copy_from_slice(&[104, 26, 12, 205]);
        bytes[20..22].copy_from_slice(&50000u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
        bytes
    }

    #[test]
    fn addresses_and_ports_are_read() {
        let mut bytes = packet();
        let header = Header::new(&mut bytes).unwrap();
        assert_eq!(header.source(), Ipv4Addr::new(192, 168, 31, 35));
        assert_eq!(header.destination(), Ipv4Addr::new(104, 26, 12, 205));
        assert_eq!(header.protocol(), PROTO_TCP);
        assert_eq!(header.ports(), Some((50000, 443)));
    }

    #[test]
    fn source_is_replaced_in_place() {
        let mut bytes = packet();
        let mut header = Header::new(&mut bytes).unwrap();
        header.set_source(Ipv4Addr::new(10, 5, 5, 2));
        assert_eq!(header.source(), Ipv4Addr::new(10, 5, 5, 2));
        // Остальное не тронуто: порты на месте, получатель на месте.
        assert_eq!(header.ports(), Some((50000, 443)));
        assert_eq!(header.destination(), Ipv4Addr::new(104, 26, 12, 205));
    }

    #[test]
    fn destination_is_replaced_in_place() {
        let mut bytes = packet();
        let mut header = Header::new(&mut bytes).unwrap();
        header.set_destination(Ipv4Addr::new(192, 168, 31, 35));
        assert_eq!(header.destination(), Ipv4Addr::new(192, 168, 31, 35));
        assert_eq!(header.source(), Ipv4Addr::new(192, 168, 31, 35));
    }

    #[test]
    fn options_shift_where_the_ports_are() {
        let mut bytes = vec![0u8; 28];
        bytes[0] = 0x46; // длина заголовка 6 слов = 24 байта
        bytes[9] = PROTO_UDP;
        bytes[24..26].copy_from_slice(&53u16.to_be_bytes());
        bytes[26..28].copy_from_slice(&1024u16.to_be_bytes());
        let header = Header::new(&mut bytes).unwrap();
        assert_eq!(header.ports(), Some((53, 1024)));
    }

    #[test]
    fn a_later_fragment_has_no_ports() {
        let mut bytes = packet();
        bytes[6..8].copy_from_slice(&185u16.to_be_bytes()); // смещение не ноль
        let header = Header::new(&mut bytes).unwrap();
        assert_eq!(header.ports(), None);
    }

    #[test]
    fn icmp_has_no_ports() {
        let mut bytes = packet();
        bytes[9] = PROTO_ICMP;
        let header = Header::new(&mut bytes).unwrap();
        assert_eq!(header.ports(), None);
    }

    #[test]
    fn udp_data_starts_after_both_headers() {
        // Заголовок IP 20 байт, UDP 8, дальше три байта данных.
        let mut bytes = vec![0u8; 31];
        bytes[0] = 0x45;
        bytes[9] = PROTO_UDP;
        bytes[28] = 0xAA;
        bytes[29] = 0xBB;
        bytes[30] = 0xCC;
        assert_eq!(udp_payload(&bytes), Some(&[0xAAu8, 0xBB, 0xCC][..]));

        // С опциями в заголовке данные начинаются дальше.
        let mut with_options = vec![0u8; 35];
        with_options[0] = 0x46; // 6 слов = 24 байта
        with_options[9] = PROTO_UDP;
        with_options[32] = 0x11;
        assert_eq!(udp_payload(&with_options), Some(&[0x11u8, 0, 0][..]));
    }

    #[test]
    fn udp_data_is_refused_for_anything_else() {
        // TCP — не наш случай.
        assert_eq!(udp_payload(&packet()), None);
        // Слишком короткий пакет и не IPv4.
        assert_eq!(udp_payload(&[]), None);
        let mut six = vec![0u8; 40];
        six[0] = 0x60;
        six[9] = PROTO_UDP;
        assert_eq!(udp_payload(&six), None);
        // Заголовки заявлены, а данных нет вовсе.
        let mut bare = vec![0u8; 20];
        bare[0] = 0x45;
        bare[9] = PROTO_UDP;
        assert_eq!(udp_payload(&bare), None);
    }

    #[test]
    fn garbage_is_refused() {
        // Слишком короткий пакет.
        let mut short = vec![0x45u8; 10];
        assert!(Header::new(&mut short).is_none());
        // Не IPv4.
        let mut six = vec![0u8; 40];
        six[0] = 0x60;
        assert!(Header::new(&mut six).is_none());
        // Длина заголовка больше самого пакета.
        let mut lying = vec![0u8; 24];
        lying[0] = 0x4F; // 15 слов = 60 байт
        assert!(Header::new(&mut lying).is_none());
        // Длина заголовка меньше минимальной.
        let mut tiny = vec![0u8; 24];
        tiny[0] = 0x44; // 4 слова = 16 байт
        assert!(Header::new(&mut tiny).is_none());
    }

    #[test]
    fn ports_are_absent_when_the_packet_ends_right_after_the_header() {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x45;
        bytes[9] = PROTO_TCP;
        let header = Header::new(&mut bytes).unwrap();
        assert_eq!(header.ports(), None);
    }
}

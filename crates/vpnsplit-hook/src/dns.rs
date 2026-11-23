//! Минимальный DNS-клиент: имя разрешается своим сокетом, привязанным к
//! туннелю.
//!
//! Зачем он вообще нужен. Обычный `GetAddrInfoW` не делает запрос сам: он
//! обращается к службе DNS Client, а та живёт в `svchost.exe` — другой
//! процесс, другие сокеты. Наша привязка туда не достаёт, поэтому
//! приложение шло через VPN, а имена резолвил домашний роутер. Утечка не
//! в трафике, а в том, кто видит список имён.
//!
//! Разбор ответа идёт по данным из сети, то есть по недоверенным: ни
//! одного индекса без проверки границ, ни одной паники. Всё, что не
//! разобралось, — это `None`, и тогда вызов уходит системному резолверу.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use vpnsplit_core::hook::{DEFAULT_DNS, DNS_ENV};
use vpnsplit_core::InterfaceIndex;
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, getsockname, recv, send, socket, AF_INET, INVALID_SOCKET, IPPROTO_IP,
    IPPROTO_UDP, IP_UNICAST_IF, SOCKADDR, SOCKADDR_IN, SOCKET, SOCK_DGRAM, SOL_SOCKET,
    SO_RCVTIMEO,
};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Длина имени и метки по RFC 1035.
const MAX_NAME: usize = 253;
const MAX_LABEL: usize = 63;

/// Запрос DNS. `None` — имя для DNS не годится, и спрашивать нечего.
pub fn build_query(id: u16, host: &str, qtype: u16) -> Option<Vec<u8>> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_NAME {
        return None;
    }

    let mut out = Vec::with_capacity(host.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    // RD — «проси рекурсию»: сами по цепочке серверов мы не ходим.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // вопрос один
    out.extend_from_slice(&[0; 6]); // ответов, авторитетов, дополнений — ноль

    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL {
            return None;
        }
        // Не-ASCII означает международное имя: его надо кодировать в
        // punycode, а это отдельная история. Такие имена отдаём системе.
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(out)
}

/// Чтение по недоверенному пакету: любой выход за границу — `None`.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, at: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let value = *self.data.get(self.at)?;
        self.at += 1;
        Some(value)
    }

    fn word(&mut self) -> Option<u16> {
        let high = self.byte()? as u16;
        let low = self.byte()? as u16;
        Some((high << 8) | low)
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        self.at = self.at.checked_add(count)?;
        (self.at <= self.data.len()).then_some(())
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(count)?;
        let slice = self.data.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    /// Пропускает имя. Сжатое имя (старшие биты длины — единицы) заканчивает
    /// имя сразу: дальше указатель, и переходить по нему нам незачем —
    /// содержимое имени мы всё равно не читаем.
    fn skip_name(&mut self) -> Option<()> {
        // Имя не длиннее 255 байт, значит и меток в нём немного. Счётчик
        // стоит на случай пакета, составленного нарочно.
        for _ in 0..MAX_NAME {
            let len = self.byte()?;
            if len == 0 {
                return Some(());
            }
            if len & 0xC0 == 0xC0 {
                self.byte()?;
                return Some(());
            }
            if len as usize > MAX_LABEL {
                return None;
            }
            self.skip(len as usize)?;
        }
        None
    }
}

/// Адрес из ответа. Берётся первая подходящая запись: сервер и так отдаёт
/// их в случайном порядке, а выбирать лучшую нам не из чего.
pub fn parse_response(packet: &[u8], id: u16, qtype: u16) -> Option<IpAddr> {
    let mut reader = Reader::new(packet);
    if reader.word()? != id {
        return None;
    }
    let flags = reader.word()?;
    if flags & 0x8000 == 0 {
        return None; // не ответ
    }
    if flags & 0x000F != 0 {
        return None; // сервер сказал «нет» — пусть решает система
    }
    let questions = reader.word()?;
    let answers = reader.word()?;
    reader.skip(4)?; // авторитеты и дополнения не нужны

    for _ in 0..questions {
        reader.skip_name()?;
        reader.skip(4)?; // тип и класс вопроса
    }

    for _ in 0..answers {
        reader.skip_name()?;
        let rtype = reader.word()?;
        let class = reader.word()?;
        reader.skip(4)?; // TTL
        let length = reader.word()? as usize;
        let data = reader.take(length)?;
        if class != CLASS_IN || rtype != qtype {
            // Чаще всего это CNAME: цепочку сервер уже развернул, и нужная
            // запись лежит дальше в том же ответе.
            continue;
        }
        match (rtype, data.len()) {
            (TYPE_A, 4) => {
                return Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
            }
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                return Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => continue,
        }
    }
    None
}

/// Номер запроса. Настоящего генератора случайных чисел здесь нет и тянуть
/// его ради этого незачем: от подделки ответа защищает в первую очередь
/// случайный порт отправителя, который выдаёт Windows.
pub fn next_id() -> u16 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    (nanos ^ counter.rotate_left(7)) as u16
}

// ---------- сеть ----------

/// Сколько ждать ответа от одного сервера. Если не ответил — пробуем
/// следующий, а если молчат все, имя уходит системному резолверу.
const TIMEOUT_MS: u32 = 1200;

/// Ответ вместе с тем, как он был получен: это нужно журналу, а журнал —
/// единственный способ убедиться, что запрос ушёл именно в туннель.
pub struct Answer {
    pub address: IpAddr,
    pub server: Ipv4Addr,
    /// Адрес, с которого ушёл запрос. Адрес туннеля здесь означает, что
    /// привязка сработала; домашний адрес означал бы утечку.
    pub source: Option<Ipv4Addr>,
    pub millis: u128,
}

fn servers() -> &'static [Ipv4Addr] {
    static LIST: OnceLock<Vec<Ipv4Addr>> = OnceLock::new();
    LIST.get_or_init(|| {
        let configured: Vec<Ipv4Addr> = std::env::var(DNS_ENV)
            .map(|raw| raw.split(',').filter_map(|part| part.trim().parse().ok()).collect())
            .unwrap_or_default();
        if configured.is_empty() {
            DEFAULT_DNS.iter().map(|octets| Ipv4Addr::from(*octets)).collect()
        } else {
            configured
        }
    })
}

/// Чем кончился разбор имени.
pub enum Outcome {
    Found(Answer),
    /// Сервер не ответил или ответ не разобрался. Пусть попробует система:
    /// туннель цел, и утечки в этом нет.
    NoAnswer,
    /// Сокет не удалось привязать к туннелю — туннеля больше нет. Отдавать
    /// имя системе нельзя: оно уйдёт домашнему роутеру, то есть наружу. Это
    /// и есть kill-switch для имён.
    TunnelGone,
}

pub fn resolve(host: &str, qtype: u16, index: u32) -> Outcome {
    let started = std::time::Instant::now();
    let mut gone = false;
    for server in servers() {
        match ask(*server, host, qtype, index) {
            Reply::Address(address, source) => {
                return Outcome::Found(Answer {
                    address,
                    server: *server,
                    source,
                    millis: started.elapsed().as_millis(),
                })
            }
            Reply::NoTunnel => {
                gone = true;
                break; // Следующий сервер упрётся в то же самое.
            }
            Reply::Silence => {}
        }
    }
    if gone {
        Outcome::TunnelGone
    } else {
        Outcome::NoAnswer
    }
}

enum Reply {
    Address(IpAddr, Option<Ipv4Addr>),
    Silence,
    NoTunnel,
}

fn ask(server: Ipv4Addr, host: &str, qtype: u16, index: u32) -> Reply {
    let id = next_id();
    let Some(query) = build_query(id, host, qtype) else {
        return Reply::Silence;
    };
    let sock = unsafe { socket(AF_INET as i32, SOCK_DGRAM, IPPROTO_UDP) };
    if sock == INVALID_SOCKET {
        return Reply::Silence;
    }
    let result = exchange(sock, server, &query, id, qtype, index);
    unsafe { closesocket(sock) };
    result
}

fn exchange(
    sock: SOCKET,
    server: Ipv4Addr,
    query: &[u8],
    id: u16,
    qtype: u16,
    index: u32,
) -> Reply {
    // Если привязать сокет к туннелю не вышло, значит туннеля больше нет:
    // Windows отказывает в несуществующем индексе интерфейса. Отправлять
    // запрос нельзя — он ушёл бы домашнему роутеру.
    let iface = InterfaceIndex::new(index);
    if !crate::hooks::set_u32(sock, IPPROTO_IP, IP_UNICAST_IF, iface.ipv4_sockopt_value()) {
        return Reply::NoTunnel;
    }
    if !crate::hooks::set_u32(sock, SOL_SOCKET, SO_RCVTIMEO, TIMEOUT_MS) {
        return Reply::Silence;
    }

    // UDP-сокет соединяется с сервером, хотя мог бы просто слать `sendto`.
    // Два повода: ядро выбирает исходящий адрес прямо сейчас, и его можно
    // спросить (иначе `getsockname` отвечает 0.0.0.0), а ответы с любых
    // других адресов отбрасываются ядром — подделать их становится заметно
    // труднее.
    let to = to_sockaddr(server, 53);
    let connected = unsafe {
        connect(
            sock,
            &to as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if connected != 0 {
        // Маршрута к серверу нет — обычно это тоже упавший туннель.
        return Reply::NoTunnel;
    }

    let sent = unsafe { send(sock, query.as_ptr(), query.len() as i32, 0) };
    if sent != query.len() as i32 {
        return Reply::NoTunnel;
    }

    // Без EDNS ответ по UDP не бывает длиннее 512 байт; запас — на случай,
    // если сервер решит иначе.
    let mut buffer = [0u8; 1232];
    let got = unsafe { recv(sock, buffer.as_mut_ptr(), buffer.len() as i32, 0) };
    if got <= 0 {
        // Молчание сервера — не признак упавшего туннеля: он мог просто
        // не ответить. Решение отдать имя системе остаётся за вызывающим.
        return Reply::Silence;
    }
    let Some(packet) = buffer.get(..got as usize) else {
        return Reply::Silence;
    };
    match parse_response(packet, id, qtype) {
        Some(address) => Reply::Address(address, local_address(sock)),
        None => Reply::Silence,
    }
}

fn to_sockaddr(address: Ipv4Addr, port: u16) -> SOCKADDR_IN {
    let mut out: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    out.sin_family = AF_INET;
    out.sin_port = port.to_be();
    out.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
    out
}

/// С какого адреса ушёл запрос. Спрашивается после отправки: до неё
/// Windows адрес ещё не выбрала.
fn local_address(sock: SOCKET) -> Option<Ipv4Addr> {
    let mut address: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<SOCKADDR_IN>() as i32;
    let ok = unsafe {
        getsockname(sock, &mut address as *mut SOCKADDR_IN as *mut SOCKADDR, &mut length)
    };
    if ok != 0 {
        return None;
    }
    Some(Ipv4Addr::from(unsafe { address.sin_addr.S_un.S_addr }.to_ne_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_are_read_from_the_environment() {
        // Разбор строки проверяется отдельно от кеша: сам кеш одноразовый.
        let parsed: Vec<Ipv4Addr> = " 9.9.9.9 , мусор, 8.8.4.4"
            .split(',')
            .filter_map(|part| part.trim().parse().ok())
            .collect();
        assert_eq!(parsed, vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(8, 8, 4, 4)]);
    }

    #[test]
    fn default_servers_are_public_resolvers() {
        let list: Vec<Ipv4Addr> = DEFAULT_DNS.iter().map(|o| Ipv4Addr::from(*o)).collect();
        assert_eq!(list, vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn query_carries_the_name_in_labels() {
        let query = build_query(0x1234, "example.com", TYPE_A).unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(&query[2..4], &[0x01, 0x00]); // RD
        assert_eq!(&query[4..6], &[0x00, 0x01]); // один вопрос
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
    }

    #[test]
    fn trailing_dot_is_not_an_empty_label() {
        assert_eq!(
            build_query(1, "example.com.", TYPE_A),
            build_query(1, "example.com", TYPE_A)
        );
    }

    #[test]
    fn names_dns_cannot_carry_are_refused() {
        assert!(build_query(1, "", TYPE_A).is_none());
        assert!(build_query(1, "a..b", TYPE_A).is_none());
        assert!(build_query(1, "почта.рф", TYPE_A).is_none());
        assert!(build_query(1, &"a".repeat(64), TYPE_A).is_none());
        assert!(build_query(1, &format!("{}.com", "a".repeat(250)), TYPE_A).is_none());
    }

    /// Ответ: заголовок, вопрос, затем записи.
    fn response(id: u16, answers: &[(u16, &[u8])], flags: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(b"\x07example\x03com\x00");
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (rtype, data) in answers {
            out.extend_from_slice(&[0xC0, 0x0C]); // сжатое имя
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn address_is_taken_from_the_answer() {
        let packet = response(7, &[(TYPE_A, &[93, 184, 216, 34])], 0x8180);
        assert_eq!(
            parse_response(&packet, 7, TYPE_A),
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
    }

    #[test]
    fn cname_before_the_address_is_stepped_over() {
        let packet = response(
            7,
            &[(5, b"\x03www\x07example\x03com\x00"), (TYPE_A, &[1, 2, 3, 4])],
            0x8180,
        );
        assert_eq!(
            parse_response(&packet, 7, TYPE_A),
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
    }

    #[test]
    fn ipv6_answer_is_read_whole() {
        let octets = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let packet = response(9, &[(TYPE_AAAA, &octets)], 0x8180);
        assert_eq!(
            parse_response(&packet, 9, TYPE_AAAA),
            Some(IpAddr::V6("2001:db8::1".parse().unwrap()))
        );
    }

    #[test]
    fn answer_to_another_question_is_ignored() {
        let packet = response(7, &[(TYPE_A, &[1, 2, 3, 4])], 0x8180);
        assert_eq!(parse_response(&packet, 8, TYPE_A), None);
    }

    #[test]
    fn refusal_and_absence_look_the_same_to_us() {
        // RCODE 3 — имени нет. Решать, что с этим делать, будет система.
        let packet = response(7, &[], 0x8183);
        assert_eq!(parse_response(&packet, 7, TYPE_A), None);
        let empty = response(7, &[], 0x8180);
        assert_eq!(parse_response(&empty, 7, TYPE_A), None);
    }

    #[test]
    fn a_request_is_not_mistaken_for_a_response() {
        let query = build_query(7, "example.com", TYPE_A).unwrap();
        assert_eq!(parse_response(&query, 7, TYPE_A), None);
    }

    #[test]
    fn broken_packets_do_not_panic() {
        let whole = response(7, &[(TYPE_A, &[1, 2, 3, 4])], 0x8180);
        // Обрыв в любом месте должен разбираться без паники.
        for cut in 0..whole.len() {
            let _ = parse_response(&whole[..cut], 7, TYPE_A);
        }
        // Длина записи больше самого пакета.
        let mut lying = whole.clone();
        let last = lying.len() - 6;
        lying[last] = 0xFF;
        assert_eq!(parse_response(&lying, 7, TYPE_A), None);
        // Бесконечная метка.
        assert_eq!(parse_response(&[0u8; 12], 0, TYPE_A), None);
        assert_eq!(parse_response(&[], 7, TYPE_A), None);
    }

    #[test]
    fn identifiers_differ_from_call_to_call() {
        let first = next_id();
        let second = next_id();
        assert_ne!(first, second);
    }
}

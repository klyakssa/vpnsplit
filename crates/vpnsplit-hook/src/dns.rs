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
//! разобралось, считается молчанием сервера. Системному резолверу имя
//! после этого не отдаётся: он спросил бы домашний роутер, а это и есть
//! утечка, ради которой модуль написан.
//!
//! Кого спрашиваем, по порядку (`lookup_servers`): DNS, который назначил
//! VPN (лончер кладёт его в `VPNSPLIT_DNS`), затем все DNS адаптера
//! туннеля, затем публичные 1.1.1.1 и 8.8.8.8. Все — через туннель.
//! Публичные не первыми: многие VPN режут порт 53 к чужим резолверам, а
//! внутренние имена компании знает только её сервер.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use vpnsplit_core::hook::{DEFAULT_DNS, DNS_ENV};
use vpnsplit_core::InterfaceIndex;
use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, getsockname, recv, send, socket, WSAGetLastError, WSAStartup, AF_INET,
    AF_UNSPEC, INVALID_SOCKET, IPPROTO_IP, IPPROTO_UDP, IP_UNICAST_IF, SOCKADDR, SOCKADDR_IN, SOCKET,
    SOCK_DGRAM, SOL_SOCKET, SO_RCVTIMEO, WSADATA, WSANOTINITIALISED,
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
        // Международные имена сюда приходят уже в punycode (это делает
        // `hooks::decide`). Всё остальное, что в DNS не записать, получает
        // «нет такого имени» без запроса в сеть — системе не отдаётся.
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

/// Что сказал сервер.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Address(IpAddr),
    /// NXDOMAIN: такого имени нет вовсе.
    NoName,
    /// Имя есть, но записей нужного типа у него нет.
    NoData,
    /// Сервер не справился (SERVFAIL, REFUSED, обрезанный ответ): стоит
    /// спросить следующий.
    Failed,
}

const RCODE_NXDOMAIN: u16 = 3;
/// Бит TC: ответ не влез в UDP и обрезан.
const FLAG_TRUNCATED: u16 = 0x0200;
/// Бит AA: ответил хозяин зоны.
const FLAG_AUTHORITATIVE: u16 = 0x0400;
/// Бит RA: сервер рекурсивный и искал имя сам.
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;

/// Разбирает ответ. `None` — пакет не наш или битый, это то же молчание.
/// Адрес берётся из первой подходящей записи: сервер и так отдаёт их в
/// случайном порядке, а выбирать лучшую нам не из чего.
pub fn parse_response(packet: &[u8], id: u16, qtype: u16) -> Option<Parsed> {
    let mut reader = Reader::new(packet);
    if reader.word()? != id {
        return None;
    }
    let flags = reader.word()?;
    if flags & 0x8000 == 0 {
        return None; // не ответ
    }
    // «Нет» засчитывается только от сервера, который искал по-настоящему:
    // рекурсивного (RA) или хозяина зоны (AA). Теперь первым спрашивается
    // DNS самого VPN, а он бывает только авторитетным для своей зоны: на
    // чужое имя такой отдаёт пустую отсылку, и её нельзя принять за
    // окончательное «адресов нет» — надо спросить следующий сервер.
    let searched = flags & (FLAG_RECURSION_AVAILABLE | FLAG_AUTHORITATIVE) != 0;
    match flags & 0x000F {
        0 => {}
        RCODE_NXDOMAIN if searched => return Some(Parsed::NoName),
        _ => return Some(Parsed::Failed),
    }
    let truncated = flags & FLAG_TRUNCATED != 0;
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
                let address = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                return Some(Parsed::Address(IpAddr::V4(address)));
            }
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                return Some(Parsed::Address(IpAddr::V6(Ipv6Addr::from(octets))));
            }
            _ => continue,
        }
    }
    // Записей нет. В обрезанном ответе они могли просто не поместиться —
    // это не «нет данных», а повод спросить другой сервер.
    Some(if truncated || !searched { Parsed::Failed } else { Parsed::NoData })
}

/// Имена, которые живут только в своей сети и публичному резолверу
/// неизвестны: их по-прежнему разрешает система (через роутер или
/// корпоративный DNS). Список — зарезервированные и общепринятые для
/// домашних и офисных сетей суффиксы.
const LOCAL_SUFFIXES: &[&str] = &[
    "local",
    "lan",
    "home",
    "home.arpa",
    "internal",
    "intranet",
    "corp",
    "private",
    "localdomain",
    "localhost",
    "fritz.box",
    // Виртуальные машины Hyper-V и MagicDNS Tailscale: их имена знает
    // только свой адаптер, а он отвечает системе.
    "mshome.net",
    "ts.net",
];

/// Локальное ли имя. Домен Active Directory (`USERDNSDOMAIN`) сюда не
/// входит: он часто совпадает с публичным доменом компании, и такие имена
/// сначала спрашиваются через туннель (см. `Mode::Unanimous`).
pub fn is_local_name(name: &str) -> bool {
    LOCAL_SUFFIXES.iter().any(|suffix| is_under(name, suffix))
}

/// Лежит ли имя в зоне `suffix` (или совпадает с ней). Без учёта регистра
/// и точки в конце.
pub fn is_under(name: &str, suffix: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    let suffix = suffix.strip_suffix('.').unwrap_or(suffix);
    if suffix.is_empty() || name.len() < suffix.len() {
        return false;
    }
    let split = name.len() - suffix.len();
    // Суффикс — только целыми метками: «mylan» не в «lan».
    name.is_char_boundary(split)
        && name[split..].eq_ignore_ascii_case(suffix)
        && (split == 0 || name.as_bytes()[split - 1] == b'.')
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
/// следующий, а если молчат все, приложение получает «попробуйте позже».
const TIMEOUT_MS: u32 = 1200;

/// Сколько всего ждать одного ответа, сколько бы серверов ни было в
/// списке. Столько же, сколько раньше уходило на два публичных: мёртвый
/// DNS VPN не должен множить задержку каждого имени.
const BUDGET_MS: u32 = 2500;

/// Меньше этого серверу не даём: через туннель на другой континент ответ
/// идёт сотни миллисекунд, и короче ждать — значит не дождаться никогда.
const MIN_TIMEOUT_MS: u32 = 400;

/// Если от бюджета осталось меньше, спрашивать уже незачем.
const MIN_LEFT_MS: u32 = 150;

/// Больше серверов не спрашиваем: при бюджете на всех остальным всё равно
/// не досталось бы времени.
const MAX_SERVERS: usize = 6;

/// Сколько ждать очередной сервер: всё, что осталось от бюджета, за
/// вычетом `MIN_TIMEOUT_MS` на каждый следующий, но не меньше
/// `MIN_TIMEOUT_MS` и не больше `TIMEOUT_MS`. `None` — бюджет исчерпан.
///
/// Не поровну: первым стоит DNS самого VPN, и он важнее всех. Через
/// далёкий туннель с холодным кешем он отвечает и за секунду, а поздний
/// ответ в уже закрытый сокет пропадает — поровну на троих (833 мс) его
/// бы не дождались, хотя публичные за ним на таком VPN молчат вовсе.
fn share(left_ms: u32, servers_left: usize) -> Option<u32> {
    if left_ms < MIN_LEFT_MS {
        return None;
    }
    let later = (servers_left.max(1) - 1).min(u32::MAX as usize) as u32;
    let first = left_ms.saturating_sub(MIN_TIMEOUT_MS.saturating_mul(later));
    Some(first.clamp(MIN_TIMEOUT_MS, TIMEOUT_MS).min(left_ms))
}

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

/// Разбор `VPNSPLIT_DNS`: адреса IPv4 через запятую, непонятное
/// пропускается.
fn parse_servers(raw: &str) -> Vec<Ipv4Addr> {
    raw.split(',').filter_map(|part| part.trim().parse().ok()).collect()
}

/// Серверы из `VPNSPLIT_DNS`: DNS, который VPN назначил подключению (его
/// кладёт лончер), или то, что пользователь задал сам.
fn configured() -> &'static [Ipv4Addr] {
    static LIST: OnceLock<Vec<Ipv4Addr>> = OnceLock::new();
    LIST.get_or_init(|| std::env::var(DNS_ENV).map(|raw| parse_servers(&raw)).unwrap_or_default())
}

fn public() -> &'static [Ipv4Addr] {
    static LIST: OnceLock<Vec<Ipv4Addr>> = OnceLock::new();
    LIST.get_or_init(|| DEFAULT_DNS.iter().map(|octets| Ipv4Addr::from(*octets)).collect())
}

/// Порядок серверов без повторов: из переменной, адаптера туннеля,
/// публичные. Публичные стоят последними, но есть всегда: назначенный VPN
/// сервер может и молчать. Поэтому предел `MAX_SERVERS` режет только
/// первую часть — места публичным оставлены заранее.
fn server_order(configured: &[Ipv4Addr], adapter: &[Ipv4Addr], public: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::with_capacity(MAX_SERVERS);
    for &server in configured.iter().chain(adapter).chain(public) {
        if server.is_unspecified() || out.contains(&server) {
            continue;
        }
        // Места для публичных, которых в списке ещё нет (кроме этого).
        let reserved = public.iter().filter(|&&p| p != server && !out.contains(&p)).count();
        if out.len() + reserved < MAX_SERVERS {
            out.push(server);
        }
    }
    out
}

/// Кого спрашивать об имени, по порядку (см. описание модуля).
pub fn lookup_servers(index: u32) -> Vec<Ipv4Addr> {
    server_order(configured(), &tunnel_dns(index).servers, public())
}

/// Один ли это из серверов, которые спрашивает наш резолвер: публичных или
/// DNS самого VPN. Нужно для соединений самого приложения: встроенный
/// резолвер браузера, спрашивающий DNS туннеля в 10.x, — не утечка.
pub fn is_server(address: Ipv4Addr) -> bool {
    configured().contains(&address)
        || public().contains(&address)
        || tunnel_dns(crate::IFINDEX.load(Ordering::Relaxed)).servers.contains(&address)
}

// ---------- DNS самого VPN ----------

/// Серверы, которые VPN выдал своему адаптеру (корпоративный сервер 10.x
/// внутри туннеля). Спрашиваются все, а не только для зон-суффиксов
/// адаптера: у WireGuard и OpenVPN часто задан один `DNS = 10.0.0.1` без
/// домена поиска, а внутренние имена компании знает только он.
#[derive(Default)]
pub struct TunnelDns {
    servers: Vec<Ipv4Addr>,
}

/// `GetAdaptersAddresses` из iphlpapi — по адресу, найденному при установке
/// хуков: таблицу импорта hook.dll ради неё не расширяем.
pub static GET_ADAPTERS: AtomicUsize = AtomicUsize::new(0);
type GetAdaptersAddressesFn =
    unsafe extern "system" fn(u32, u32, *const c_void, *mut IP_ADAPTER_ADDRESSES_LH, *mut u32) -> u32;

/// Сколько держать прочитанные настройки адаптера: VPN может
/// переподключиться и получить другие, а спрашивать на каждое имя —
/// лишняя работа.
const TUNNEL_DNS_TTL: Duration = Duration::from_secs(30);

pub fn tunnel_dns(index: u32) -> Arc<TunnelDns> {
    static CACHE: Mutex<Option<(u32, Instant, Arc<TunnelDns>)>> = Mutex::new(None);
    if index == 0 {
        return Arc::default();
    }
    {
        let cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached, read_at, table)) = cache.as_ref() {
            if *cached == index && read_at.elapsed() < TUNNEL_DNS_TTL {
                return table.clone();
            }
        }
    }
    // Читаем без замка: этот же замок берёт `is_server` из перехвата
    // `connect`, и повторный вход в него из системного вызова стал бы
    // взаимной блокировкой. Два потока прочтут настройки дважды — не беда.
    let table = Arc::new(read_tunnel_dns(index));
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *cache = Some((index, Instant::now(), table.clone()));
    table
}

fn read_tunnel_dns(index: u32) -> TunnelDns {
    let function = GET_ADAPTERS.load(Ordering::Acquire);
    if function == 0 {
        return TunnelDns::default();
    }
    let function: GetAdaptersAddressesFn = unsafe { std::mem::transmute(function) };
    let flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME;
    // Буфер из u64 — ради выравнивания структур. Растёт по просьбе
    // системы, но не больше мегабайта: память процесса не наша.
    let mut size: u32 = 16 << 10;
    for _ in 0..3 {
        if size > 1 << 20 {
            return TunnelDns::default();
        }
        let mut buffer: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let status = unsafe {
            function(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match status {
            0 => return unsafe { tunnel_dns_from(buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH, index) },
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return TunnelDns::default(),
        }
    }
    TunnelDns::default()
}

/// Разбор списка адаптеров: берётся только адаптер туннеля.
unsafe fn tunnel_dns_from(mut adapter: *const IP_ADAPTER_ADDRESSES_LH, index: u32) -> TunnelDns {
    let mut out = TunnelDns::default();
    // Адаптеров и записей в них конечное число, но счётчик стоит на случай
    // испорченного списка.
    for _ in 0..1024 {
        let Some(current) = adapter.as_ref() else {
            break;
        };
        adapter = current.Next;
        if current.Anonymous1.Anonymous.IfIndex != index && current.Ipv6IfIndex != index {
            continue;
        }
        let mut server = current.FirstDnsServerAddress as *const IP_ADAPTER_DNS_SERVER_ADDRESS_XP;
        for _ in 0..64 {
            let Some(entry) = server.as_ref() else {
                break;
            };
            server = entry.Next;
            let address = entry.Address.lpSockaddr as *const SOCKADDR_IN;
            if address.is_null() || (entry.Address.iSockaddrLength as usize) < std::mem::size_of::<SOCKADDR_IN>() {
                continue;
            }
            // Наш клиент спрашивает только по IPv4.
            if (*address).sin_family == AF_INET {
                let v4 = Ipv4Addr::from((*address).sin_addr.S_un.S_addr.to_ne_bytes());
                if !v4.is_unspecified() && !out.servers.contains(&v4) {
                    out.servers.push(v4);
                }
            }
        }
        break;
    }
    out
}

/// Чем кончился разбор имени.
///
/// Ни один исход, кроме `Found`, не ведёт к системному резолверу. Раньше
/// при молчании сервера имя отдавалось системе, а та спрашивала домашний
/// роутер: так наружу уходили опечатки, NXDOMAIN, имена с одной лишь
/// AAAA-записью — ровно то, что приложение хотело спрятать в туннель.
pub enum Outcome {
    Found(Answer),
    /// Сервер ответил: такого имени нет.
    NoName,
    /// Имя есть, но адресов нужного семейства у него нет.
    NoData,
    /// Ни один сервер не ответил толком. Туннель, возможно, цел, но
    /// спросить больше некого.
    Unavailable,
    /// Сокет не удалось привязать к туннелю — туннеля больше нет. Отдавать
    /// имя системе нельзя: оно уйдёт домашнему роутеру, то есть наружу. Это
    /// и есть kill-switch для имён.
    TunnelGone,
}

/// Как читать ответы серверов списка.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Обычное имя. Адрес, «нет такого имени» и «нет адресов» от любого
    /// сервера окончательны: сервер искал сам (см. `parse_response`), и
    /// следующий скажет то же, только позже. Молчание, отказ и битый
    /// ответ — повод спросить следующий.
    First,
    /// Имя из домена пользователя (`USERDNSDOMAIN`). Адрес и «нет адресов»
    /// окончательны, как обычно. А «нет такого имени» значит `NoName` (и
    /// имя уходит системе, то есть контроллеру домена), только если так
    /// ответил каждый DNS самого VPN — из `VPNSPLIT_DNS` и адаптера
    /// туннеля. Если хоть один из них промолчал, итог — `Unavailable`:
    /// он мог знать имя, а угадывать в пользу утечки нельзя.
    ///
    /// Публичные 1.1.1.1 и 8.8.8.8 при этом голоса не имеют, если молчат:
    /// многие VPN режут порт 53 к ним, и иначе внутренние имена домена не
    /// разрешались бы на таком VPN никогда. Их «нет» тоже не обязательно:
    /// все они смотрят в один и тот же публичный DNS. Только если DNS VPN
    /// не известен вовсе (или до него не дойти), нужно «нет» хоть от
    /// одного публичного.
    Unanimous,
}

/// Разрешает имя через туннель, спрашивая серверы `list` по очереди
/// (обычно это `lookup_servers`).
pub fn resolve_via(host: &str, qtype: u16, index: u32, list: &[Ipv4Addr], mode: Mode) -> Outcome {
    // Имя, которое нельзя записать в запрос DNS, через DNS не найдёт и
    // система. Говорим «нет такого», никого не спрашивая.
    if build_query(0, host, qtype).is_none() {
        return Outcome::NoName;
    }
    resolve_with(list, public(), mode, BUDGET_MS, |server, timeout| ask(server, host, qtype, index, timeout))
}

/// Сам обход списка; `ask` спрашивает один сервер с заданным временем
/// ожидания, `public` — какие из серверов списка публичные (см.
/// `Mode::Unanimous`). Отдельно от сети — ради тестов.
fn resolve_with(
    list: &[Ipv4Addr],
    public: &[Ipv4Addr],
    mode: Mode,
    budget_ms: u32,
    mut ask: impl FnMut(Ipv4Addr, u32) -> Reply,
) -> Outcome {
    let started = Instant::now();
    // DNS самого VPN: в `Mode::Unanimous` «нет» нужно от каждого из них.
    // Недостижимый (`NoRoute`) из этого счёта выбывает: он не ответит
    // никогда, и знать имя за нас не может.
    let mut vpn_left = list.iter().filter(|server| !public.contains(server)).count();
    let mut vpn_denied = 0usize;
    let mut public_denied = 0usize;
    let mut asked = 0usize;
    let mut unroutable = 0usize;
    for (at, &server) in list.iter().enumerate() {
        let spent = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
        let Some(mut timeout) = share(budget_ms.saturating_sub(spent), list.len() - at) else {
            break;
        };
        if mode == Mode::Unanimous && vpn_left > 0 && vpn_denied == vpn_left {
            // DNS VPN уже сказали «нет»; публичных спрашиваем только на
            // случай, если имя есть снаружи. Ждать их долго незачем: их
            // молчание итог не меняет, а на VPN, режущем порт 53, они
            // молчат всегда — и каждое внутреннее имя ждало бы весь бюджет.
            timeout = timeout.min(MIN_TIMEOUT_MS);
        }
        let is_public = public.contains(&server);
        asked += 1;
        match ask(server, timeout) {
            Reply::Address(address, source) => {
                return Outcome::Found(Answer { address, server, source, millis: started.elapsed().as_millis() })
            }
            Reply::NoName if mode == Mode::First => return Outcome::NoName,
            Reply::NoName if is_public => public_denied += 1,
            Reply::NoName => vpn_denied += 1,
            Reply::NoData => return Outcome::NoData,
            // Следующий сервер упрётся в то же самое.
            Reply::NoTunnel => return Outcome::TunnelGone,
            // Нет маршрута к этому серверу через туннель — бывает, что VPN
            // назначил DNS вне своих сетей. Публичный может и пройти.
            Reply::NoRoute => {
                unroutable += 1;
                if !is_public {
                    vpn_left -= 1;
                }
            }
            Reply::Silence => {}
        }
    }
    // Сюда `Mode::First` с «нет такого» не доходит: он вернулся выше.
    let confirmed = if vpn_left > 0 { vpn_denied == vpn_left } else { public_denied > 0 };
    if confirmed {
        Outcome::NoName
    } else if unroutable > 0 && unroutable == asked {
        // Ни до одного сервера не дойти — так выглядит упавший туннель.
        Outcome::TunnelGone
    } else {
        Outcome::Unavailable
    }
}

#[derive(Debug)]
enum Reply {
    Address(IpAddr, Option<Ipv4Addr>),
    NoName,
    NoData,
    Silence,
    /// Сокет не привязать к туннелю: туннеля нет.
    NoTunnel,
    /// До этого сервера через туннель не дойти (`connect` или `send`
    /// отказали).
    NoRoute,
}

/// Сокет для запроса. `DnsQuery_*` можно звать без `WSAStartup`, и тогда
/// `socket` отказывает с `WSANOTINITIALISED`: в этом случае поднимаем
/// Winsock сами, один раз на процесс. Парного `WSACleanup` нет намеренно:
/// из хука его звать нельзя, он мог бы закрыть Winsock самому приложению.
///
/// Замок, а не флаг: второй поток, пришедший сюда, пока первый ещё внутри
/// `WSAStartup`, должен дождаться его и повторить `socket`, а не получить
/// отказ. Неудачный `WSAStartup` не запоминается — следующий запрос
/// попробует снова.
fn open_socket() -> SOCKET {
    static STARTED: Mutex<bool> = Mutex::new(false);
    let sock = unsafe { socket(AF_INET as i32, SOCK_DGRAM, IPPROTO_UDP) };
    if sock != INVALID_SOCKET || unsafe { WSAGetLastError() } != WSANOTINITIALISED {
        return sock;
    }
    {
        let mut started = STARTED.lock().unwrap_or_else(|e| e.into_inner());
        if !*started {
            let mut data: WSADATA = unsafe { std::mem::zeroed() };
            if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
                return INVALID_SOCKET;
            }
            *started = true;
        }
    }
    unsafe { socket(AF_INET as i32, SOCK_DGRAM, IPPROTO_UDP) }
}

fn ask(server: Ipv4Addr, host: &str, qtype: u16, index: u32, timeout_ms: u32) -> Reply {
    let id = next_id();
    let Some(query) = build_query(id, host, qtype) else {
        return Reply::Silence;
    };
    let sock = open_socket();
    if sock == INVALID_SOCKET {
        return Reply::Silence;
    }
    let result = exchange(sock, server, &query, id, qtype, index, timeout_ms);
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
    timeout_ms: u32,
) -> Reply {
    // Если привязать сокет к туннелю не вышло, значит туннеля больше нет:
    // Windows отказывает в несуществующем индексе интерфейса. Отправлять
    // запрос нельзя — он ушёл бы домашнему роутеру.
    let iface = InterfaceIndex::new(index);
    if !crate::hooks::set_u32(sock, IPPROTO_IP, IP_UNICAST_IF, iface.ipv4_sockopt_value()) {
        return Reply::NoTunnel;
    }
    // Ноль значил бы «ждать вечно»; `share` нуля не даёт, но запрос из
    // перехвата повесить нельзя ни при каком раскладе.
    if !crate::hooks::set_u32(sock, SOL_SOCKET, SO_RCVTIMEO, timeout_ms.max(1)) {
        return Reply::Silence;
    }

    // UDP-сокет соединяется с сервером, хотя мог бы просто слать `sendto`.
    // Два повода: ядро выбирает исходящий адрес прямо сейчас, и его можно
    // спросить (иначе `getsockname` отвечает 0.0.0.0), а ответы с любых
    // других адресов отбрасываются ядром — подделать их становится заметно
    // труднее.
    //
    // Соединяемся в обход своего же перехвата `connect`: для частного
    // адреса (DNS VPN в 10.x) он снял бы привязку к туннелю, и запрос
    // ушёл бы по таблице маршрутов — то есть, возможно, домашнему роутеру.
    let to = to_sockaddr(server, 53);
    let connected = unsafe {
        crate::hooks::connect_unhooked(
            sock,
            &to as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if connected != 0 {
        // Маршрута к серверу нет. Чаще всего это упавший туннель, но
        // бывает и DNS VPN вне его сетей — решает `resolve_with` по всем.
        return Reply::NoRoute;
    }

    let sent = unsafe { send(sock, query.as_ptr(), query.len() as i32, 0) };
    if sent != query.len() as i32 {
        return Reply::NoRoute;
    }

    // Без EDNS ответ по UDP не бывает длиннее 512 байт; запас — на случай,
    // если сервер решит иначе.
    let mut buffer = [0u8; 1232];
    let got = unsafe { recv(sock, buffer.as_mut_ptr(), buffer.len() as i32, 0) };
    if got <= 0 {
        // Молчание сервера — не признак упавшего туннеля: он мог просто
        // не ответить. Тогда спросим следующий.
        return Reply::Silence;
    }
    let Some(packet) = buffer.get(..got as usize) else {
        return Reply::Silence;
    };
    match parse_response(packet, id, qtype) {
        Some(Parsed::Address(address)) => Reply::Address(address, local_address(sock)),
        Some(Parsed::NoName) => Reply::NoName,
        Some(Parsed::NoData) => Reply::NoData,
        Some(Parsed::Failed) | None => Reply::Silence,
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
        // Формат тот же, что пишет лончер: адреса через запятую.
        let parsed = parse_servers(" 9.9.9.9 , мусор, 8.8.4.4,,::1");
        assert_eq!(parsed, vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(8, 8, 4, 4)]);
        assert!(parse_servers("").is_empty());
        assert_eq!(parse_servers("10.8.0.1"), vec![Ipv4Addr::new(10, 8, 0, 1)]);
    }

    #[test]
    fn default_servers_are_public_resolvers() {
        assert_eq!(public(), &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn vpn_dns_goes_first_then_adapter_then_public() {
        let vpn = [Ipv4Addr::new(10, 8, 0, 1)];
        let adapter = [Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 1)];
        let order = server_order(&vpn, &adapter, public());
        assert_eq!(
            order,
            vec![
                Ipv4Addr::new(10, 8, 0, 1),
                Ipv4Addr::new(10, 8, 0, 2),
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(8, 8, 8, 8)
            ]
        );
        // Без DNS VPN — как раньше, только публичные.
        assert_eq!(server_order(&[], &[], public()), public());
        // Пользователь сам задал публичный — повтора нет.
        assert_eq!(server_order(&[Ipv4Addr::new(8, 8, 8, 8)], &[], public()).len(), 2);
        // Длинный список обрезается: бюджета на всех всё равно не хватит.
        // Но публичные остаются в конце — запасной путь есть всегда.
        let many: Vec<Ipv4Addr> = (1..=20).map(|n| Ipv4Addr::new(10, 0, 0, n)).collect();
        let order = server_order(&many, &many, public());
        assert_eq!(order.len(), MAX_SERVERS);
        assert_eq!(order[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(order[MAX_SERVERS - 2..], *public());
        // Публичный, заданный пользователем, стоит на своём месте и второго
        // раза не занимает.
        let mut mixed = many.clone();
        mixed.insert(1, Ipv4Addr::new(8, 8, 8, 8));
        let order = server_order(&mixed, &[], public());
        assert_eq!(order.len(), MAX_SERVERS);
        assert_eq!(order[1], Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(order.iter().filter(|a| **a == Ipv4Addr::new(8, 8, 8, 8)).count(), 1);
        assert_eq!(order[MAX_SERVERS - 1], Ipv4Addr::new(1, 1, 1, 1));
        // 0.0.0.0 — не сервер.
        assert!(!server_order(&[Ipv4Addr::UNSPECIFIED], &[], public()).contains(&Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn waiting_is_shared_within_the_budget() {
        // Два сервера — по-прежнему по 1,2 с.
        assert_eq!(share(BUDGET_MS, 2), Some(TIMEOUT_MS));
        // Три (DNS VPN и два публичных): первому, DNS VPN, — полные 1,2 с,
        // остальным — что останется, и всё вместе не дольше бюджета.
        assert_eq!(share(BUDGET_MS, 3), Some(TIMEOUT_MS));
        assert_eq!(share(BUDGET_MS - TIMEOUT_MS, 2), Some(900));
        assert_eq!(share(BUDGET_MS - TIMEOUT_MS - 900, 1), Some(400));
        assert_eq!(share(BUDGET_MS, 4), Some(TIMEOUT_MS));
        // Полный список: первому — сколько можно, не отняв нижней границы
        // у остальных.
        let first = BUDGET_MS - MIN_TIMEOUT_MS * (MAX_SERVERS as u32 - 1);
        assert_eq!(share(BUDGET_MS, MAX_SERVERS), Some(first.max(MIN_TIMEOUT_MS)));
        // Много — не меньше нижней границы.
        assert_eq!(share(BUDGET_MS, 10), Some(MIN_TIMEOUT_MS));
        // Под конец бюджета — сколько осталось, и не дольше.
        assert_eq!(share(300, 3), Some(300));
        assert_eq!(share(MIN_LEFT_MS - 1, 1), None);
        assert_eq!(share(0, 1), None);
        assert_eq!(share(1000, 0), Some(TIMEOUT_MS.min(1000)));
        assert_eq!(share(u32::MAX, usize::MAX), Some(MIN_TIMEOUT_MS));
    }

    #[test]
    fn the_vpn_dns_gets_the_full_wait_even_with_public_servers_behind() {
        // DNS VPN отвечает за 1,1 с, публичные молчат (VPN режет порт 53):
        // ответ всё равно дождались.
        let list = [v4(10, 8, 0, 1), v4(1, 1, 1, 1), v4(8, 8, 8, 8)];
        let found = IpAddr::V4(v4(10, 1, 2, 3));
        let mut waits = Vec::new();
        let outcome = resolve_with(&list, public(), Mode::First, BUDGET_MS, |server, timeout| {
            waits.push(timeout);
            if server == list[0] && timeout >= 1100 {
                Reply::Address(found, None)
            } else {
                Reply::Silence
            }
        });
        assert!(matches!(outcome, Outcome::Found(ref answer) if answer.address == found));
        assert_eq!(waits, [TIMEOUT_MS]);
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// Обход списка с заранее заданными ответами серверов. Возвращает
    /// итог и тех, кого спросили.
    fn run(list: &[Ipv4Addr], mode: Mode, replies: &[Reply]) -> (Outcome, Vec<Ipv4Addr>) {
        let mut asked = Vec::new();
        let mut replies = replies.iter();
        let outcome = resolve_with(list, public(), mode, BUDGET_MS, |server, timeout| {
            assert!((1..=TIMEOUT_MS).contains(&timeout));
            asked.push(server);
            match replies.next() {
                Some(Reply::Address(address, source)) => Reply::Address(*address, *source),
                Some(Reply::NoName) => Reply::NoName,
                Some(Reply::NoData) => Reply::NoData,
                Some(Reply::NoTunnel) => Reply::NoTunnel,
                Some(Reply::NoRoute) => Reply::NoRoute,
                Some(Reply::Silence) | None => Reply::Silence,
            }
        });
        (outcome, asked)
    }

    #[test]
    fn silent_vpn_dns_falls_through_to_the_next_server() {
        let list = [v4(10, 8, 0, 1), v4(1, 1, 1, 1), v4(8, 8, 8, 8)];
        let found = IpAddr::V4(v4(93, 184, 216, 34));
        let (outcome, asked) = run(&list, Mode::First, &[Reply::Silence, Reply::Address(found, None)]);
        match outcome {
            Outcome::Found(answer) => {
                assert_eq!(answer.address, found);
                assert_eq!(answer.server, v4(1, 1, 1, 1));
            }
            _ => panic!("ожидался адрес"),
        }
        assert_eq!(asked, list[..2]);
        // Молчат все — «попробуйте позже», а не система.
        let (outcome, asked) = run(&list, Mode::First, &[]);
        assert!(matches!(outcome, Outcome::Unavailable));
        assert_eq!(asked, list);
    }

    #[test]
    fn a_real_no_is_final_for_ordinary_names() {
        let list = [v4(10, 8, 0, 1), v4(1, 1, 1, 1)];
        let (outcome, asked) = run(&list, Mode::First, &[Reply::NoName]);
        assert!(matches!(outcome, Outcome::NoName));
        assert_eq!(asked, list[..1]);
        let (outcome, asked) = run(&list, Mode::First, &[Reply::Silence, Reply::NoData]);
        assert!(matches!(outcome, Outcome::NoData));
        assert_eq!(asked, list);
        // Отвязать сокет от туннеля не вышло — дальше не спрашиваем.
        let (outcome, asked) = run(&list, Mode::First, &[Reply::NoTunnel]);
        assert!(matches!(outcome, Outcome::TunnelGone));
        assert_eq!(asked, list[..1]);
        // До DNS VPN не дойти — спрашиваем следующий; не дойти ни до кого —
        // туннеля нет.
        let found = IpAddr::V4(v4(93, 184, 216, 34));
        let (outcome, _) = run(&list, Mode::First, &[Reply::NoRoute, Reply::Address(found, None)]);
        assert!(matches!(outcome, Outcome::Found(_)));
        let (outcome, asked) = run(&list, Mode::First, &[Reply::NoRoute, Reply::NoRoute]);
        assert!(matches!(outcome, Outcome::TunnelGone));
        assert_eq!(asked, list);
        let (outcome, _) = run(&list, Mode::First, &[Reply::NoRoute, Reply::Silence]);
        assert!(matches!(outcome, Outcome::Unavailable));
    }

    #[test]
    fn user_domain_goes_to_the_system_only_if_every_vpn_dns_says_no() {
        let list = [v4(10, 8, 0, 1), v4(1, 1, 1, 1), v4(8, 8, 8, 8)];
        let (outcome, asked) = run(&list, Mode::Unanimous, &[Reply::NoName, Reply::NoName, Reply::NoName]);
        assert!(matches!(outcome, Outcome::NoName));
        assert_eq!(asked, list);
        // VPN режет порт 53 к публичным: они молчат, но голоса не имеют —
        // внутреннее имя домена уходит системе. Ждём их недолго.
        let mut waits = Vec::new();
        let outcome = resolve_with(&list, public(), Mode::Unanimous, BUDGET_MS, |server, timeout| {
            waits.push(timeout);
            if server == list[0] { Reply::NoName } else { Reply::Silence }
        });
        assert!(matches!(outcome, Outcome::NoName));
        assert_eq!(waits.len(), 3);
        assert!(waits[1..].iter().all(|&wait| wait <= MIN_TIMEOUT_MS));
        let (outcome, _) = run(&list, Mode::Unanimous, &[Reply::NoName, Reply::NoRoute, Reply::Silence]);
        assert!(matches!(outcome, Outcome::NoName));
        // Промолчал DNS VPN — он мог знать имя: системе не отдаём, что бы
        // ни сказали публичные.
        let (outcome, _) = run(&list, Mode::Unanimous, &[Reply::Silence, Reply::NoName, Reply::NoName]);
        assert!(matches!(outcome, Outcome::Unavailable));
        let two_vpn = [v4(10, 8, 0, 1), v4(10, 8, 0, 2), v4(1, 1, 1, 1)];
        let (outcome, _) = run(&two_vpn, Mode::Unanimous, &[Reply::NoName, Reply::Silence, Reply::NoName]);
        assert!(matches!(outcome, Outcome::Unavailable));
        // До DNS VPN не дойти — решают публичные, как без него.
        let (outcome, _) = run(&list, Mode::Unanimous, &[Reply::NoRoute, Reply::Silence, Reply::NoName]);
        assert!(matches!(outcome, Outcome::NoName));
        // DNS VPN не известен: нужно «нет» хоть от одного публичного.
        let only_public = [v4(1, 1, 1, 1), v4(8, 8, 8, 8)];
        let (outcome, _) = run(&only_public, Mode::Unanimous, &[Reply::Silence, Reply::NoName]);
        assert!(matches!(outcome, Outcome::NoName));
        let (outcome, _) = run(&only_public, Mode::Unanimous, &[Reply::Silence, Reply::Silence]);
        assert!(matches!(outcome, Outcome::Unavailable));
        let (outcome, _) = run(&only_public, Mode::Unanimous, &[Reply::NoRoute, Reply::NoRoute]);
        assert!(matches!(outcome, Outcome::TunnelGone));
        // Кто-то знает имя — оно и отдаётся, хоть первый и сказал «нет».
        let found = IpAddr::V4(v4(203, 0, 113, 5));
        let (outcome, asked) = run(&list, Mode::Unanimous, &[Reply::NoName, Reply::Address(found, None)]);
        assert!(matches!(outcome, Outcome::Found(ref answer) if answer.address == found));
        assert_eq!(asked, list[..2]);
        // «Нет адресов» — имя есть, это окончательно.
        let (outcome, _) = run(&list, Mode::Unanimous, &[Reply::NoName, Reply::NoData]);
        assert!(matches!(outcome, Outcome::NoData));
        // Молчат все — тоже не система.
        let (outcome, _) = run(&list, Mode::Unanimous, &[]);
        assert!(matches!(outcome, Outcome::Unavailable));
    }

    #[test]
    fn spent_budget_stops_the_walk() {
        let list = [v4(10, 8, 0, 1), v4(1, 1, 1, 1)];
        let mut asked = 0;
        let outcome = resolve_with(&list, public(), Mode::First, 0, |_, _| {
            asked += 1;
            Reply::Silence
        });
        assert!(matches!(outcome, Outcome::Unavailable));
        assert_eq!(asked, 0);
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
            Some(Parsed::Address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))))
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
            Some(Parsed::Address(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))))
        );
    }

    #[test]
    fn ipv6_answer_is_read_whole() {
        let octets = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let packet = response(9, &[(TYPE_AAAA, &octets)], 0x8180);
        assert_eq!(
            parse_response(&packet, 9, TYPE_AAAA),
            Some(Parsed::Address(IpAddr::V6("2001:db8::1".parse().unwrap())))
        );
    }

    #[test]
    fn answer_to_another_question_is_ignored() {
        let packet = response(7, &[(TYPE_A, &[1, 2, 3, 4])], 0x8180);
        assert_eq!(parse_response(&packet, 8, TYPE_A), None);
    }

    #[test]
    fn absence_refusal_and_empty_answer_are_told_apart() {
        // RCODE 3 — имени нет.
        let packet = response(7, &[], 0x8183);
        assert_eq!(parse_response(&packet, 7, TYPE_A), Some(Parsed::NoName));
        // Имя есть, адресов нет (или есть только записи другого типа).
        let empty = response(7, &[], 0x8180);
        assert_eq!(parse_response(&empty, 7, TYPE_A), Some(Parsed::NoData));
        let other = response(7, &[(TYPE_AAAA, &[0; 16])], 0x8180);
        assert_eq!(parse_response(&other, 7, TYPE_A), Some(Parsed::NoData));
        // SERVFAIL — повод спросить другой сервер.
        let failed = response(7, &[], 0x8182);
        assert_eq!(parse_response(&failed, 7, TYPE_A), Some(Parsed::Failed));
        // Обрезанный пустой ответ — не «нет данных».
        let cut = response(7, &[], 0x8380);
        assert_eq!(parse_response(&cut, 7, TYPE_A), Some(Parsed::Failed));
    }

    #[test]
    fn a_no_counts_only_from_a_server_that_searched() {
        // Только авторитетный DNS VPN на чужое имя: ни RA, ни AA, пустая
        // отсылка или NXDOMAIN — это не ответ, спросим следующий.
        let referral = response(7, &[], 0x8100);
        assert_eq!(parse_response(&referral, 7, TYPE_A), Some(Parsed::Failed));
        let lazy_no = response(7, &[], 0x8103);
        assert_eq!(parse_response(&lazy_no, 7, TYPE_A), Some(Parsed::Failed));
        // Хозяин зоны (AA) отвечает за свою зону окончательно.
        let owner_no = response(7, &[], 0x8503);
        assert_eq!(parse_response(&owner_no, 7, TYPE_A), Some(Parsed::NoName));
        let owner_empty = response(7, &[], 0x8500);
        assert_eq!(parse_response(&owner_empty, 7, TYPE_A), Some(Parsed::NoData));
        // Адрес берётся от любого сервера.
        let address = response(7, &[(TYPE_A, &[10, 1, 2, 3])], 0x8100);
        assert_eq!(
            parse_response(&address, 7, TYPE_A),
            Some(Parsed::Address(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))))
        );
    }

    #[test]
    fn names_dns_cannot_carry_are_not_found_without_asking() {
        // До сети дело не доходит: ответ известен ещё до запроса.
        let list = server_order(&[], &[], public());
        for mode in [Mode::First, Mode::Unanimous] {
            assert!(matches!(resolve_via("bad name.com", TYPE_A, 0, &list, mode), Outcome::NoName));
            assert!(matches!(resolve_via("a..b", TYPE_A, 0, &list, mode), Outcome::NoName));
        }
    }

    #[test]
    fn local_names_stay_with_the_system() {
        assert!(is_local_name("printer.local"));
        assert!(is_local_name("nas.lan."));
        assert!(is_local_name("router.HOME"));
        assert!(is_local_name("x.home.arpa"));
        assert!(is_local_name("fritz.box"));
        assert!(is_local_name("vm1.mshome.net"));
        assert!(is_local_name("laptop.tail1234.ts.net"));
        assert!(!is_local_name("example.com"));
        assert!(!is_local_name("mylan")); // суффикс — только целой меткой
        assert!(!is_local_name("cats.net"));
        assert!(!is_local_name("почта.рф"));
        // Домен AD сам по себе локальным больше не считается: его имена
        // сначала спрашиваются через туннель.
        assert!(!is_local_name("dc1.corp.example.com"));
    }

    #[test]
    fn without_a_tunnel_there_is_no_vpn_dns() {
        assert!(tunnel_dns(0).servers.is_empty());
        // Несуществующий адаптер — тоже пусто, а не паника.
        let kernel = unsafe {
            windows_sys::Win32::System::LibraryLoader::LoadLibraryA(c"iphlpapi.dll".as_ptr() as *const u8)
        };
        let function = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel, c"GetAdaptersAddresses".as_ptr() as *const u8)
        };
        GET_ADAPTERS.store(function.map_or(0, |f| f as usize), Ordering::Release);
        assert!(read_tunnel_dns(u32::MAX - 7).servers.is_empty());
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

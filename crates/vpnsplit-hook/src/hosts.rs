//! Файл hosts: его записи важнее туннельного резолвера.
//!
//! Системный резолвер отвечает из hosts, не спрашивая сеть. Наш перехват
//! спрашивает публичный DNS раньше системы, и без этой проверки блокировки
//! вида `0.0.0.0 telemetry.example.com` и подмены для разработки
//! (`127.0.0.1 api.myapp.com`) переставали действовать в туннельных
//! приложениях. Адрес из hosts отдаётся так же, как найденный в DNS —
//! числом, поэтому сеть при этом не трогается вовсе.
//!
//! Файл читается один раз и перечитывается, когда меняется его время
//! изменения или длина. Путь — `%SystemRoot%\System32\drivers\etc\hosts`;
//! перенос каталога через `DataBasePath` в реестре не учитывается.

use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Больше этого не читаем: hook.dll живёт в чужом процессе, и память там
/// не наша. Самые большие списки блокировок — несколько мегабайт.
const MAX_FILE: u64 = 32 << 20;
const MAX_ENTRIES: usize = 1 << 20;
const MAX_NAME: usize = 253;

/// Что нашлось в hosts.
#[derive(Debug, PartialEq, Eq)]
pub enum Hit {
    Address(IpAddr),
    /// Имя в hosts есть, но адресов нужного семейства у него нет.
    OtherFamily,
    Miss,
}

/// Записи hosts. Имена лежат в одной строке, а записи ссылаются на них
/// смещением: так большой список блокировок занимает в памяти примерно
/// столько же, сколько сам файл, а не втрое больше.
#[derive(Default)]
pub struct Table {
    names: String,
    entries: Vec<Entry>,
}

struct Entry {
    start: u32,
    len: u8,
    address: IpAddr,
}

impl Table {
    pub fn parse(text: &str) -> Table {
        let mut table = Table::default();
        'lines: for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut words = line.split_ascii_whitespace();
            let Some(first) = words.next() else {
                continue;
            };
            // Зона у link-local (`fe80::1%3`) адресу из hosts не нужна.
            let Ok(address) = first.split('%').next().unwrap_or(first).parse::<IpAddr>() else {
                continue;
            };
            for name in words {
                if table.entries.len() >= MAX_ENTRIES {
                    break 'lines;
                }
                let name = normalize(name);
                if name.is_empty() || name.len() > MAX_NAME {
                    continue;
                }
                let Ok(start) = u32::try_from(table.names.len()) else {
                    break 'lines;
                };
                table.names.push_str(&name);
                table.entries.push(Entry { start, len: name.len() as u8, address });
            }
        }
        // Сортировка устойчивая: среди одинаковых имён первым остаётся то,
        // что раньше в файле, — как у системы.
        let names = &table.names;
        table.entries.sort_by(|a, b| a.name(names).cmp(b.name(names)));
        table
    }

    /// Адрес для имени. `family` — из подсказок `getaddrinfo`: при
    /// `AF_UNSPEC` предпочитается IPv4, как и при разрешении через DNS.
    pub fn lookup(&self, name: &str, family: i32) -> Hit {
        let name = normalize(name);
        let first = self.entries.partition_point(|e| e.name(&self.names) < name.as_str());
        let mut found = false;
        let mut fallback = None;
        for entry in self.entries[first..].iter().take_while(|e| e.name(&self.names) == name) {
            found = true;
            let v4 = entry.address.is_ipv4();
            if family == AF_INET as i32 && v4 || family == AF_INET6 as i32 && !v4 {
                return Hit::Address(entry.address);
            }
            if family != AF_INET as i32 && family != AF_INET6 as i32 {
                if v4 {
                    return Hit::Address(entry.address);
                }
                fallback.get_or_insert(entry.address);
            }
        }
        match (found, fallback) {
            (_, Some(address)) => Hit::Address(address),
            (true, None) => Hit::OtherFamily,
            (false, None) => Hit::Miss,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Entry {
    fn name<'a>(&self, names: &'a str) -> &'a str {
        let start = self.start as usize;
        names.get(start..start + self.len as usize).unwrap_or("")
    }
}

fn normalize(name: &str) -> String {
    let name = name.strip_suffix('.').unwrap_or(name);
    name.to_lowercase()
}

/// Отметка версии файла: время изменения и длина.
type Stamp = (Option<SystemTime>, u64);

struct Cached {
    stamp: Stamp,
    table: Arc<Table>,
}

static CACHE: Mutex<Option<Cached>> = Mutex::new(None);
/// Перечитывает файл только один поток за раз: разбор большого списка
/// блокировок — десятки мегабайт, и делать его параллельно в каждом потоке,
/// который сейчас разрешает имя, в чужом процессе нельзя.
static LOADING: Mutex<()> = Mutex::new(());

fn path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32").join("drivers").join("etc").join("hosts")
    })
}

/// Таблица из кеша, если она снята с файла этой версии; иначе — прежняя
/// таблица (вторым значением), если она вообще есть.
fn cached(stamp: Stamp) -> Result<Arc<Table>, Option<Arc<Table>>> {
    let cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match cache.as_ref() {
        Some(cached) if cached.stamp == stamp => Ok(cached.table.clone()),
        Some(cached) => Err(Some(cached.table.clone())),
        None => Err(None),
    }
}

/// Текущее содержимое hosts. `None` — файла нет или он недоступен.
pub fn current() -> Option<Arc<Table>> {
    let meta = std::fs::metadata(path()).ok()?;
    let stamp: Stamp = (meta.modified().ok(), meta.len());
    let previous = match cached(stamp) {
        Ok(table) => return Some(table),
        Err(previous) => previous,
    };
    // Файл уже перечитывает другой поток. Есть прежняя версия — отвечаем
    // ей, а не ждём. Нет никакой (первое чтение) — ждём: без hosts
    // блокировки вида `0.0.0.0 ...` в это время не действовали бы.
    let _loading = match previous {
        Some(old) => match LOADING.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Some(old),
        },
        None => LOADING.lock().unwrap_or_else(|e| e.into_inner()),
    };
    // Пока ждали замка, файл мог перечитать кто-то другой.
    let previous = match cached(stamp) {
        Ok(table) => return Some(table),
        Err(previous) => previous,
    };
    // Читаем без замка кеша: файл может быть большим, а другие потоки тем
    // временем пусть пользуются прежней версией.
    let Some(table) = read(path()) else {
        // Файл не прочитался (его держит антивирус или резервное
        // копирование, не пускают права). Пустую таблицу не запоминаем:
        // иначе до следующей правки файла все блокировки из hosts молча
        // перестали бы действовать. Отвечаем прежней версией, а в
        // следующий раз попробуем снова.
        return previous;
    };
    let table = Arc::new(table);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *cache = Some(Cached { stamp, table: table.clone() });
    Some(table)
}

/// `None` — файл не открылся или не прочитался.
fn read(path: &PathBuf) -> Option<Table> {
    let mut bytes = Vec::new();
    let file = std::fs::File::open(path).ok()?;
    file.take(MAX_FILE).read_to_end(&mut bytes).ok()?;
    Some(Table::parse(&String::from_utf8_lossy(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    const UNSPEC: i32 = AF_UNSPEC as i32;
    const V4: i32 = AF_INET as i32;
    const V6: i32 = AF_INET6 as i32;

    const SAMPLE: &str = "\
# Copyright (c) 1993-2009 Microsoft Corp.
#
#      102.54.94.97     rhino.acme.com          # source server
127.0.0.1       localhost
::1             localhost
0.0.0.0 telemetry.example.com   ads.example.com # блокировка
127.0.0.1\tApi.MyApp.com.
fe80::1%3 router6.example.com
10.0.0.1 dup.example.com
10.0.0.2 dup.example.com
not-an-address broken.example.com
";

    #[test]
    fn comments_and_garbage_are_skipped() {
        let table = Table::parse(SAMPLE);
        assert_eq!(table.lookup("rhino.acme.com", UNSPEC), Hit::Miss);
        assert_eq!(table.lookup("broken.example.com", UNSPEC), Hit::Miss);
        assert_eq!(table.lookup("example.com", UNSPEC), Hit::Miss);
    }

    #[test]
    fn every_name_on_a_line_is_an_entry() {
        let table = Table::parse(SAMPLE);
        let blocked = Hit::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(table.lookup("telemetry.example.com", V4), blocked);
        assert_eq!(table.lookup("ads.example.com", UNSPEC), blocked);
    }

    #[test]
    fn names_compare_without_case_and_trailing_dot() {
        let table = Table::parse(SAMPLE);
        let local = Hit::Address(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(table.lookup("api.myapp.com", UNSPEC), local);
        assert_eq!(table.lookup("API.MYAPP.COM.", UNSPEC), local);
    }

    #[test]
    fn family_picks_the_matching_entry() {
        let table = Table::parse(SAMPLE);
        assert_eq!(table.lookup("localhost", V6), Hit::Address(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(table.lookup("localhost", V4), Hit::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(table.lookup("localhost", UNSPEC), Hit::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        // Только IPv6: при AF_UNSPEC отдаём его, при AF_INET — «не того семейства».
        let six = Hit::Address(IpAddr::V6("fe80::1".parse().unwrap()));
        assert_eq!(table.lookup("router6.example.com", UNSPEC), six);
        assert_eq!(table.lookup("router6.example.com", V4), Hit::OtherFamily);
        assert_eq!(table.lookup("telemetry.example.com", V6), Hit::OtherFamily);
    }

    #[test]
    fn first_entry_in_the_file_wins() {
        let table = Table::parse(SAMPLE);
        assert_eq!(
            table.lookup("dup.example.com", V4),
            Hit::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn overlong_names_are_ignored() {
        let text = format!("1.2.3.4 {}.com ok.com", "a".repeat(260));
        let table = Table::parse(&text);
        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup("ok.com", V4), Hit::Address(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn unreadable_file_is_not_an_empty_table() {
        let missing = std::env::temp_dir().join("vpnsplit-hosts-test-missing");
        assert!(read(&missing).is_none());
        let file = std::env::temp_dir().join(format!("vpnsplit-hosts-test-{}", std::process::id()));
        std::fs::write(&file, "0.0.0.0 blocked.example.com\n").unwrap();
        let table = read(&file).expect("файл читается");
        let _ = std::fs::remove_file(&file);
        assert_eq!(table.lookup("blocked.example.com", V4), Hit::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn empty_file_finds_nothing() {
        assert_eq!(Table::parse("").lookup("example.com", UNSPEC), Hit::Miss);
    }
}

//! Наблюдение пути B: кто открывает соединения, по данным ядра.
//!
//! Этап 11a только смотрит. Ручка WinDivert открыта на чтение и в режиме
//! sniff — ни задержать, ни изменить, ни уронить пакет она не может. Задача
//! одна: убедиться, что из ядра видно то, чего не видит путь A, — прежде
//! всего Store-приложения, которые живут в общих хост-процессах и по пути
//! к образу не опознаются.
//!
//! Наблюдение включается по команде и само гаснет через несколько секунд.
//! Держать его постоянно нельзя: в Этапе 10 замерено, что служба в простое
//! не тратит процессорное время вовсе, и менять это ради журнала незачем.

use crate::store::Store;
use std::collections::HashMap;
use vpnsplit_net::{divert, proc};

/// Сколько событий записывать подробно. Дальше — только счётчики: за
/// десять секунд их набегают тысячи, и журнал превратился бы в мусор.
const DETAILED: usize = 40;

/// Кто открывал соединения за время наблюдения.
#[derive(Default)]
struct Seen {
    connects: usize,
    binds: usize,
    image: Option<String>,
    package: Option<String>,
}

/// Наблюдение на слое потоков: событие на каждое открытие и закрытие, с
/// полной пятёркой. Для Этапа 11b это главный источник: таблицу «чей это
/// поток» надо строить на открытии и снимать на закрытии, а слой сокетов
/// для этого грубее — там одно соединение приходит несколько раз.
pub fn run_flows(store: &Store, seconds: u32) -> Result<(), String> {
    let watcher = divert::Handle::sniff_flows("not loopback")?;
    store.log(&format!("путь B: потоки, наблюдение на {seconds} с начато"));

    let stop = std::time::Instant::now() + std::time::Duration::from_secs(seconds as u64);
    let mut opened = 0usize;
    let mut closed = 0usize;
    let mut detailed = 0usize;
    // Таблица набивается **всеми** потоками машины, а не только нашими:
    // это нарочно худший случай. Нужно узнать, какой длины выходит фильтр и
    // сколько потоков живёт одновременно, прежде чем строить на этом
    // перенаправление.
    let mut table = crate::flows::Table::default();
    let mut peak = 0usize;
    let handle = &watcher;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(seconds as u64));
            handle.stop();
        });
        while let Ok(address) = watcher.next() {
            let Some(socket) = address.socket().copied() else {
                continue;
            };
            let key = match address.remote() {
                std::net::IpAddr::V4(remote) => Some(crate::flows::Key {
                    protocol: socket.protocol,
                    local_port: socket.local_port,
                    remote,
                    remote_port: socket.remote_port,
                }),
                std::net::IpAddr::V6(_) => None,
            };
            match divert::describe_event(address.event()) {
                "поток открыт" => {
                    opened += 1;
                    if let Some(key) = key {
                        table.opened(key, socket.process_id);
                        peak = peak.max(table.len());
                    }
                }
                "поток закрыт" => {
                    closed += 1;
                    if let Some(key) = key {
                        table.closed(&key);
                    }
                }
                _ => {}
            }
            if detailed < DETAILED {
                detailed += 1;
                let package = proc::package_family(socket.process_id)
                    .map(|p| format!(" [Store: {p}]"))
                    .unwrap_or_default();
                let image = proc::image_path(socket.process_id)
                    .map(|p| {
                        p.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default()
                    })
                    .unwrap_or_else(|| "образ неизвестен".to_owned());
                store.log(&format!(
                    "путь B: {} pid {} {} {}:{} → {}:{} ({}) соединение {}{}",
                    divert::describe_event(address.event()),
                    socket.process_id,
                    image,
                    address.local(),
                    socket.local_port,
                    address.remote(),
                    socket.remote_port,
                    divert::describe_protocol(socket.protocol),
                    socket.endpoint_id,
                    package
                ));
            }
            if std::time::Instant::now() >= stop {
                break;
            }
        }
    });
    store.log(&format!(
        "путь B: потоков открыто {opened}, закрыто {closed}, \
         одновременно самое большее {peak}, осталось {}",
        table.len()
    ));
    // Худший случай для фильтра: все потоки машины сразу. Настоящий фильтр
    // будет перечислять только потоки выбранных приложений, то есть
    // короче, — но предел надо знать по верхней границе.
    match table.filter() {
        Some(filter) => store.log(&format!(
            "путь B: фильтр на эти потоки — {} байт на {} из {} (предел {})",
            filter.len(),
            table.len().min(crate::flows::MAX_IN_FILTER),
            table.len(),
            crate::flows::MAX_IN_FILTER
        )),
        None => store.log("путь B: живых потоков не осталось, фильтр не нужен"),
    }
    Ok(())
}

pub fn run(store: &Store, seconds: u32) -> Result<(), String> {
    // Нас интересует исходящая связь наружу. Петля отсекается фильтром,
    // иначе почти всё, что видно, — разговор программ самих с собой.
    let watcher = divert::Handle::sniff_sockets("not loopback")?;
    store.log(&format!("путь B: наблюдение на {seconds} с начато"));

    let stop = std::time::Instant::now() + std::time::Duration::from_secs(seconds as u64);
    {
        // Отдельный поток только для того, чтобы разбудить recv по времени:
        // сам recv ждёт события, а не часы.
        let handle = &watcher;
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(std::time::Duration::from_secs(seconds as u64));
                handle.stop();
            });
            collect(store, &watcher, stop);
        });
    }
    Ok(())
}

fn collect(store: &Store, watcher: &divert::Handle, stop: std::time::Instant) {
    let mut by_pid: HashMap<u32, Seen> = HashMap::new();
    let mut detailed = 0usize;
    let mut total = 0usize;

    while let Ok(address) = watcher.next() {
        total += 1;
        let Some(socket) = address.socket().copied() else {
            continue;
        };
        let seen = by_pid.entry(socket.process_id).or_default();
        if seen.image.is_none() {
            seen.image = proc::image_path(socket.process_id)
                .map(|path| path.display().to_string());
            seen.package = proc::package_family(socket.process_id);
        }
        match divert::describe_event(address.event()) {
            "connect" => seen.connects += 1,
            "bind" => seen.binds += 1,
            _ => {}
        }

        if detailed < DETAILED {
            detailed += 1;
            store.log(&format!(
                "путь B: {} pid {} → {}:{} ({}) соединение {}{}",
                divert::describe_event(address.event()),
                socket.process_id,
                address.remote(),
                socket.remote_port,
                divert::describe_protocol(socket.protocol),
                socket.endpoint_id,
                seen.package
                    .as_ref()
                    .map(|p| format!(" пакет {p}"))
                    .unwrap_or_default()
            ));
        }
        if std::time::Instant::now() >= stop {
            break;
        }
    }

    store.log(&format!("путь B: событий {total}, процессов {}", by_pid.len()));
    let mut rows: Vec<(u32, Seen)> = by_pid.into_iter().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1.connects));
    for (pid, seen) in rows.into_iter().take(15) {
        store.log(&format!(
            "путь B:   pid {pid:<6} connect {:<4} bind {:<4} {}{}",
            seen.connects,
            seen.binds,
            seen.image.unwrap_or_else(|| "образ неизвестен".to_owned()),
            seen.package.map(|p| format!("  [Store: {p}]")).unwrap_or_default()
        ));
    }
}

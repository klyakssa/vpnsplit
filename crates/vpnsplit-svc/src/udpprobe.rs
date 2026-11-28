//! Этап 12, UDP: замер, от которого зависит устройство перехвата.
//!
//! У TCP есть SYN: начало соединения можно поймать узким фильтром,
//! подержать в руках, опознать хозяина, перестроить фильтр потоков и только
//! потом отпустить. У UDP начала нет — первый же пакет несёт данные. Чтобы
//! увести поток UDP без утечки, о нём надо узнать **раньше первого пакета**,
//! причём с запасом на перестройку фильтра (худшая замеренная — 3121 мкс).
//!
//! Источников такого знания два: событие слоя сокетов (`bind`, `connect`) и
//! событие слоя потоков («поток открыт»). Здесь меряется, насколько они
//! опережают первый пакет на проводе у настоящих программ. Меряется по
//! меткам времени, которые ставит драйвер в ядре, а не по времени чтения
//! нашими потоками: второе зависит от планировщика и на микросекундах
//! бессмысленно.
//!
//! Второе число — сколько на машине вообще исходящего UDP. Если события не
//! успевают, остаётся держать в руках **весь** исходящий UDP, и цена этого
//! — число пакетов в секунду, умноженное на 33 мкс (Этап 11b).
//!
//! Только чтение: все три ручки открыты на подслушивание.

use crate::store::Store;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;
use vpnsplit_net::{divert, ipv4, proc};

/// Сколько события должно опережать пакет, чтобы мы успели перестроить
/// фильтр. Худшая перестройка, замеренная в Этапе 11b.
const NEEDED_MICROS: i64 = 3121;

/// Цена перехвата одного пакета, оттуда же.
const PACKET_MICROS: f64 = 33.0;

const DETAILED: usize = 14;

/// Поток UDP, каким он виден на всех трёх слоях: местный порт и собеседник.
type Flow = (u16, Ipv4Addr, u16);

#[derive(Default)]
struct Seen {
    packets: usize,
    names: usize,
    local: usize,
    outside: usize,
    /// Пакетов наружу по секундам — чтобы знать не только среднее, но и пик.
    per_second: HashMap<i64, usize>,
    /// Первое событие сокета на порту: метка и процесс.
    binds: HashMap<u16, (i64, u32)>,
    /// Событие «поток открыт»: метка и процесс.
    opened: HashMap<Flow, (i64, u32)>,
    /// Первый пакет потока наружу.
    first_packet: HashMap<Flow, i64>,
    /// Пакетов наружу по местному порту — чтобы назвать, чьи они.
    by_port: HashMap<u16, usize>,
}

use vpnsplit_net::ipv4::stays_home;

pub fn run(store: &Store, seconds: u32) -> Result<(), String> {
    let packets = divert::Handle::sniff_network("outbound and udp and not loopback")?;
    let flows = divert::Handle::sniff_flows("not loopback")?;
    let sockets = divert::Handle::sniff_sockets("not loopback")?;
    let ticks = divert::ticks_per_second();
    let seen = Mutex::new(Seen::default());
    store.log(&format!("UDP: замер на {seconds} с начат"));

    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_secs(seconds as u64));
            packets.stop();
            flows.stop();
            sockets.stop();
        });

        scope.spawn(|| {
            let mut buffer = vec![0u8; divert::MAX_PACKET];
            while let Ok((length, address)) = packets.next_packet(&mut buffer) {
                let Some(header) = ipv4::Header::new(&mut buffer[..length]) else {
                    continue;
                };
                let Some((local_port, remote_port)) = header.ports() else {
                    continue;
                };
                let remote = header.destination();
                let mut seen = seen.lock().unwrap_or_else(|e| e.into_inner());
                seen.packets += 1;
                if remote_port == 53 {
                    seen.names += 1;
                } else if stays_home(remote) {
                    seen.local += 1;
                } else {
                    seen.outside += 1;
                    *seen.per_second.entry(address.timestamp / ticks).or_default() += 1;
                    *seen.by_port.entry(local_port).or_default() += 1;
                    seen.first_packet
                        .entry((local_port, remote, remote_port))
                        .or_insert(address.timestamp);
                }
            }
        });

        scope.spawn(|| {
            while let Ok(address) = flows.next() {
                let Some(socket) = address.socket().copied() else {
                    continue;
                };
                if socket.protocol != ipv4::PROTO_UDP
                    || divert::describe_event(address.event()) != "поток открыт"
                {
                    continue;
                }
                let IpAddr::V4(remote) = address.remote() else {
                    continue;
                };
                let mut seen = seen.lock().unwrap_or_else(|e| e.into_inner());
                seen.opened
                    .entry((socket.local_port, remote, socket.remote_port))
                    .or_insert((address.timestamp, socket.process_id));
            }
        });

        scope.spawn(|| {
            while let Ok(address) = sockets.next() {
                let Some(socket) = address.socket().copied() else {
                    continue;
                };
                if socket.protocol != ipv4::PROTO_UDP || address.ipv6() {
                    continue;
                }
                if !matches!(divert::describe_event(address.event()), "bind" | "connect") {
                    continue;
                }
                let mut seen = seen.lock().unwrap_or_else(|e| e.into_inner());
                seen.binds
                    .entry(socket.local_port)
                    .or_insert((address.timestamp, socket.process_id));
            }
        });
    });

    let seen = seen.into_inner().unwrap_or_else(|e| e.into_inner());
    report(store, &seen, seconds, ticks);
    Ok(())
}

fn micros(from: i64, to: i64, ticks: i64) -> i64 {
    (to - from) * 1_000_000 / ticks
}

fn image_name(pid: u32) -> String {
    proc::image_path(pid)
        .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "процесс завершился".to_owned())
}

/// Наименьшее, срединное, наибольшее. Пустой набор — `None`.
fn spread(values: &mut [i64]) -> Option<(i64, i64, i64)> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some((values[0], values[values.len() / 2], values[values.len() - 1]))
}

fn report(store: &Store, seen: &Seen, seconds: u32, ticks: i64) {
    let average = seen.outside as f64 / seconds.max(1) as f64;
    let peak = seen.per_second.values().copied().max().unwrap_or(0);
    store.log(&format!(
        "UDP: исходящих пакетов {} — имён {}, в свою сеть и рассылки {}, наружу {} \
         (в среднем {average:.1} в секунду, пик {peak} в секунду)",
        seen.packets, seen.names, seen.local, seen.outside
    ));
    store.log(&format!(
        "UDP: держать в руках весь исходящий наружу — это {:.2}% ядра в среднем и {:.2}% на пике \
         (по {PACKET_MICROS} мкс на пакет)",
        average * PACKET_MICROS / 10_000.0,
        peak as f64 * PACKET_MICROS / 10_000.0
    ));

    // Чьи это пакеты. Хозяин порта известен, если за время замера на нём
    // было событие сокета или открылся поток. Иначе сокет открыт до замера,
    // и спросить можно только у таблицы ядра — если он ещё жив. Без этого
    // первый же замер под нагрузкой назвал 2813 пакетов из 2818 «хозяин
    // неизвестен», то есть не ответил на вопрос, ради которого делался.
    let table = match vpnsplit_net::udptable::sockets() {
        Ok(table) => table,
        Err(e) => {
            // Это замер: без таблицы хозяева старых сокетов останутся
            // неизвестными, и это надо видеть, а не принимать за «ничьи».
            store.log(&format!("UDP: таблица сокетов ядра не прочиталась ({e})"));
            Vec::new()
        }
    };
    let owner = |port: u16| -> Option<u32> {
        seen.binds
            .get(&port)
            .map(|(_, pid)| *pid)
            .or_else(|| {
                seen.opened
                    .iter()
                    .find(|((local, _, _), _)| *local == port)
                    .map(|(_, (_, pid))| *pid)
            })
            .or_else(|| table.iter().find(|(local, _)| *local == port).map(|(_, pid)| *pid))
    };
    let mut talkers: HashMap<String, usize> = HashMap::new();
    for (port, count) in &seen.by_port {
        let name = owner(*port).map(image_name).unwrap_or_else(|| "хозяин неизвестен".to_owned());
        *talkers.entry(name).or_default() += count;
    }
    let mut talkers: Vec<(String, usize)> = talkers.into_iter().collect();
    talkers.sort_by_key(|row| std::cmp::Reverse(row.1));
    for (name, count) in talkers.into_iter().take(6) {
        store.log(&format!("UDP:   наружу {count:<6} {name}"));
    }

    // Главный вопрос: насколько событие опережает первый пакет.
    let mut after_flow = Vec::new();
    let mut after_bind = Vec::new();
    let mut orphans = 0usize;
    let mut rows: Vec<(Flow, i64)> = seen.first_packet.iter().map(|(k, v)| (*k, *v)).collect();
    rows.sort_by_key(|row| row.1);
    let mut detailed = 0usize;
    for (flow, packet_at) in rows {
        let Some((opened_at, pid)) = seen.opened.get(&flow).copied() else {
            // Поток открылся до начала замера: сравнивать не с чем.
            orphans += 1;
            continue;
        };
        let by_flow = micros(opened_at, packet_at, ticks);
        after_flow.push(by_flow);
        let by_bind = seen.binds.get(&flow.0).map(|(at, _)| micros(*at, packet_at, ticks));
        if let Some(gap) = by_bind {
            after_bind.push(gap);
        }
        if detailed < DETAILED {
            detailed += 1;
            store.log(&format!(
                "UDP:   порт {} → {}:{} ({}): пакет через {by_flow} мкс после «поток открыт»{}",
                flow.0,
                flow.1,
                flow.2,
                image_name(pid),
                match by_bind {
                    Some(gap) => format!(", через {gap} мкс после события сокета"),
                    None => ", события сокета за время замера не было".to_owned(),
                }
            ));
        }
    }

    store.log(&format!(
        "UDP: новых потоков наружу {}, ещё {orphans} открылись до замера и не считаются",
        after_flow.len()
    ));
    for (label, values) in [("«поток открыт»", &mut after_flow), ("событие сокета", &mut after_bind)] {
        let in_time = values.iter().filter(|gap| **gap >= NEEDED_MICROS).count();
        let late = values.iter().filter(|gap| **gap < 0).count();
        let total = values.len();
        match spread(values) {
            Some((least, middle, most)) => store.log(&format!(
                "UDP: {label} опережает первый пакет: наименьшее {least} мкс, срединное {middle}, \
                 наибольшее {most}; запаса на перестройку фильтра ({NEEDED_MICROS} мкс) хватило \
                 {in_time} раз из {total}, событие позже пакета {late} раз"
            )),
            None => store.log(&format!("UDP: {label} — сравнивать не с чем")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_network_and_broadcasts_are_not_our_business() {
        for address in ["192.168.31.1", "10.5.5.1", "224.0.0.251", "255.255.255.255", "169.254.1.1"] {
            assert!(stays_home(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "104.26.13.205"] {
            assert!(!stays_home(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn spread_of_nothing_is_nothing() {
        assert_eq!(spread(&mut []), None);
        assert_eq!(spread(&mut [5, -2, 9]), Some((-2, 5, 9)));
    }

    #[test]
    fn ticks_turn_into_microseconds_with_the_sign_kept() {
        // Событие позже пакета должно дать отрицательное число, а не
        // исчезнуть: это и есть ответ «не успевает».
        assert_eq!(micros(0, 10_000_000, 10_000_000), 1_000_000);
        assert_eq!(micros(30, 10, 10_000_000), -2);
    }
}

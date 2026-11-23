//! Этап 11b, первый вопрос: можно ли увести чужой пакет в туннель, не
//! трогая его сокет.
//!
//! Путь A просит у сокета `IP_UNICAST_IF`, и стек сам выбирает маршрут на
//! этом интерфейсе. Для Store-приложения сокета у нас нет, поэтому остаётся
//! одно: перехватить пакет, подменить адрес источника на адрес туннеля и
//! отдать его обратно. Весь вопрос в том, по чему стек выберет маршрут для
//! такого подсунутого пакета — по адресу назначения (тогда пакет уйдёт
//! домой, потому что метрика Ethernet лучше) или с оглядкой на адрес
//! источника (тогда он уйдёт в туннель, как нам и нужно).
//!
//! Угадывать тут нечего, это надо измерить. Опыт устроен так, чтобы ничего
//! лишнего не сломать:
//!
//! - фильтр сужен до **одного адреса назначения**: что бы ни случилось,
//!   пострадать может только обращение к нему;
//! - ручка живёт заданное число секунд и закрывается сама;
//! - пакет, который мы не узнали, отправляется обратно без изменений.
//!
//! Обратный путь переписывается тоже: ответ придёт на адрес туннеля, а
//! сокет ждёт его на домашнем адресе. И отдавать такой пакет надо на
//! домашний интерфейс: модель узла на этой машине строгая (`WeakHostReceive`
//! выключен), и пакет, поданный не на тот интерфейс, будет отброшен.

use crate::store::Store;
use std::net::Ipv4Addr;
use vpnsplit_net::{divert, iface, ipv4, routes};

/// Сколько пакетов записать подробно.
const DETAILED: usize = 24;

#[derive(Default)]
struct Counters {
    out_rewritten: usize,
    in_rewritten: usize,
    passed: usize,
    impostor: usize,
    failed: usize,
    last_error: u32,
}

pub fn run(store: &Store, target: Ipv4Addr, seconds: u32) -> Result<(), String> {
    let tunnel = iface::find_tunnel(None).map_err(|e| format!("туннель не найден: {e}"))?;
    let tunnel_address = tunnel
        .ipv4
        .ok_or_else(|| "у туннеля нет адреса IPv4".to_owned())?;
    let home = routes::best_route(target)
        .ok_or_else(|| format!("нет обычного маршрута к {target}"))?;

    if home.source == tunnel_address {
        return Err(format!(
            "к {target} система и так ходит через туннель ({tunnel_address}) — \
             подменять нечего"
        ));
    }

    store.log(&format!(
        "путь B: опыт перенаправления к {target} на {seconds} с: \
         источник {} (интерфейс {}) → {} (интерфейс {})",
        home.source,
        home.interface_index,
        tunnel_address,
        tunnel.index.get()
    ));

    // Узко, насколько позволяет язык фильтров: только один адрес и только
    // то, чем мы собираемся проверять.
    let filter = format!("(tcp or icmp) and (ip.DstAddr == {target} or ip.SrcAddr == {target})");
    let handle = divert::Handle::intercept_network(&filter)?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds as u64);
    let finished = std::sync::atomic::AtomicBool::new(false);
    let counters = std::thread::scope(|scope| {
        let waker = &handle;
        let done = &finished;
        scope.spawn(move || watchdog(store, waker, done, deadline));
        let counters = pump(store, &handle, deadline, tunnel_address, home);
        finished.store(true, std::sync::atomic::Ordering::Release);
        counters
    });

    store.log(&format!(
        "путь B: опыт закончен. Переписано наружу {}, обратно {}, \
         пропущено без изменений {}, своих {}, не отправлено {} (последний код {})",
        counters.out_rewritten,
        counters.in_rewritten,
        counters.passed,
        counters.impostor,
        counters.failed,
        counters.last_error
    ));
    Ok(())
}

/// Сторож: следит за временем и за тем, что приём действительно закрылся.
///
/// Раньше здесь был простой `sleep` на всё время опыта, и этого хватало,
/// пока закрытие приёма работало. Теперь сторож проверяет, вышел ли насос,
/// и если через две секунды тот всё ещё висит — закрывает ручку жёстко.
/// Перехватывающая ручка, забытая открытой, глотает пакеты, и такой случай
/// должен лечиться сам, а не ждать перезапуска службы.
fn watchdog(
    store: &Store,
    handle: &divert::Handle,
    finished: &std::sync::atomic::AtomicBool,
    deadline: std::time::Instant,
) {
    use std::sync::atomic::Ordering;
    let step = std::time::Duration::from_millis(200);
    while std::time::Instant::now() < deadline {
        if finished.load(Ordering::Acquire) {
            return;
        }
        std::thread::sleep(step);
    }
    handle.stop();
    for _ in 0..10 {
        std::thread::sleep(step);
        if finished.load(Ordering::Acquire) {
            return;
        }
    }
    store.log("путь B: приём не закрылся по-хорошему, закрываю ручку жёстко");
    handle.stop_hard();
}

fn pump(
    store: &Store,
    handle: &divert::Handle,
    deadline: std::time::Instant,
    tunnel_address: Ipv4Addr,
    home: routes::Route,
) -> Counters {
    let mut counters = Counters::default();
    let mut buffer = vec![0u8; divert::MAX_PACKET];
    let mut detailed = 0usize;

    loop {
        let (length, mut address) = match handle.next_packet(&mut buffer) {
            Ok(packet) => packet,
            Err(code) => {
                // 232 (ERROR_NO_DATA) — ручку закрыли, это нормальный конец.
                if code != 232 {
                    store.log(&format!("путь B: приём прекращён, код {code}"));
                }
                break;
            }
        };
        let packet = &mut buffer[..length];
        let outbound = address.outbound();
        let came_from = address.interface().map(|n| n.interface_index).unwrap_or(0);

        // Свой же реинжект возвращается с пометкой «подсунут». Второй раз
        // его трогать нельзя, иначе адрес будет переписан дважды.
        let mut action = if address.impostor() {
            counters.impostor += 1;
            "наш же, не трогаю"
        } else {
            "без изменений"
        };

        let mut rewritten = false;
        if !address.impostor() {
            if let Some(mut header) = ipv4::Header::new(packet) {
                if outbound && header.source() == home.source {
                    rewritten = true;
                    header.set_source(tunnel_address);
                    // Интерфейс оставляем тем, с которым пакет пришёл:
                    // в опыте меняется ровно одна величина — адрес
                    // источника, — иначе результат нечем будет объяснить.
                    action = "источник подменён на туннель";
                    counters.out_rewritten += 1;
                } else if !outbound && header.destination() == tunnel_address {
                    rewritten = true;
                    header.set_destination(home.source);
                    // А вот для входящего интерфейс решает всё.
                    address.set_interface(home.interface_index, 0);
                    action = "получатель возвращён домой";
                    counters.in_rewritten += 1;
                } else {
                    counters.passed += 1;
                }
            } else {
                counters.passed += 1;
            }
        }

        if rewritten {
            // Адреса входят в псевдозаголовок TCP, так что пересчитать надо
            // и сумму заголовка IP, и сумму самого TCP.
            divert::fix_checksums(packet, &address);
        }

        if detailed < DETAILED {
            detailed += 1;
            let header = ipv4::Header::new(packet);
            let (source, destination, ports) = match &header {
                Some(h) => (
                    h.source().to_string(),
                    h.destination().to_string(),
                    h.ports().map(|(a, b)| format!(" {a}→{b}")).unwrap_or_default(),
                ),
                None => ("?".to_owned(), "?".to_owned(), String::new()),
            };
            store.log(&format!(
                "путь B: {} {} {source} → {destination}{ports} {} байт, интерфейс {came_from}",
                if outbound { "наружу" } else { "внутрь" },
                action,
                length
            ));
        }

        if let Err(code) = handle.send(packet, &address) {
            counters.failed += 1;
            counters.last_error = code;
            if counters.failed <= 4 {
                store.log(&format!("путь B: пакет не отправлен, код {code}"));
            }
        }

        if std::time::Instant::now() >= deadline {
            break;
        }
    }
    counters
}

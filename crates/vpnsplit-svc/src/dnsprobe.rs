//! Этап 12, вопрос первый: можно ли привязать запрос имени к приложению.
//!
//! Почему это вообще вопрос. Приложение не спрашивает имена само — за него
//! это делает системная служба кеша, один процесс на всю машину. На проводе
//! запрос принадлежит ей, и по пакету привязать его к приложению нечем: в
//! родословной службы кеша нет и быть не может.
//!
//! Надежда на провайдер `Microsoft-Windows-DNS-Client`: его события пишутся
//! в контексте того, кто спросил, то есть номер процесса в заголовке должен
//! быть наш. Это и проверяется — наблюдением, а не рассуждением. Если
//! догадка верна, появляется связка «процесс спросил имя» → «имя на
//! проводе», и запрос можно уводить в туннель вместе с трафиком.
//!
//! Если неверна — выбор останется из двух нехороших: весь DNS машины в
//! туннель либо резолвинг внутри процессов, и то и другое с ценой.

use crate::store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vpnsplit_net::{etw, proc};

/// Сколько событий записать подробно.
const DETAILED: usize = 30;

/// Насколько свежей должна быть привязка, чтобы считаться относящейся к
/// этому запросу. Полсекунды — с запасом: запрос уходит на провод через
/// доли миллисекунды после того, как приложение его заказало.
const FRESH: std::time::Duration = std::time::Duration::from_millis(500);

pub fn run(store: &Store, seconds: u32) -> Result<(), String> {
    let seen: Arc<Mutex<HashMap<(u32, u16), usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let names: Arc<Mutex<Vec<(u32, String)>>> = Arc::new(Mutex::new(Vec::new()));

    store.log(&format!("DNS: наблюдение за событиями на {seconds} с начато"));

    {
        let log = store.clone();
        let detailed = Mutex::new(0usize);
        let (seen, names) = (seen.clone(), names.clone());
        // Ключевое слово 0 — все события провайдера: какие из них несут имя
        // и чей номер процесса в них стоит, мы как раз и выясняем.
        let _trace = etw::Trace::start(etw::DNS_SESSION, &etw::DNS_CLIENT, 0, move |raw| {
            {
                let mut seen = seen.lock().unwrap_or_else(|e| e.into_inner());
                *seen.entry((raw.pid, raw.id)).or_insert(0) += 1;
            }
            let name = etw::leading_string(raw.payload);
            if let Some(name) = &name {
                // Имена с точкой и без пробелов — похоже на доменное имя.
                if name.contains('.') && !name.contains(' ') {
                    let mut names = names.lock().unwrap_or_else(|e| e.into_inner());
                    if names.len() < 200 {
                        names.push((raw.pid, name.clone()));
                    }
                }
            }
            let mut count = detailed.lock().unwrap_or_else(|e| e.into_inner());
            if *count < DETAILED {
                *count += 1;
                let image = proc::image_path(raw.pid)
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    .unwrap_or_else(|| "образ неизвестен".to_owned());
                log.log(&format!(
                    "DNS: событие {} версия {} процесс {} ({image}) {} байт{}",
                    raw.id,
                    raw.version,
                    raw.pid,
                    raw.payload.len(),
                    name.as_deref()
                        .map(|n| format!(", первая строка «{n}»"))
                        .unwrap_or_default()
                ));
            }
        })?;

        std::thread::sleep(std::time::Duration::from_secs(seconds as u64));
    }

    // Сводка: кто сколько каких событий записал. Из неё и видно, чей номер
    // процесса стоит в событиях — заказчика или службы кеша.
    let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut by_pid: HashMap<u32, usize> = HashMap::new();
    for ((pid, _), count) in &seen {
        *by_pid.entry(*pid).or_insert(0) += count;
    }
    let mut rows: Vec<(u32, usize)> = by_pid.into_iter().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1));
    store.log(&format!("DNS: событий от {} процессов", rows.len()));
    for (pid, count) in rows.into_iter().take(12) {
        let image = proc::image_path(pid)
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "образ неизвестен".to_owned());
        store.log(&format!("DNS:   процесс {pid:<7} событий {count:<5} {image}"));
    }

    let names = names.lock().unwrap_or_else(|e| e.into_inner()).clone();
    store.log(&format!("DNS: имён в событиях {}", names.len()));
    for (pid, name) in names.iter().take(15) {
        store.log(&format!("DNS:   процесс {pid} спросил {name}"));
    }
    Ok(())
}

/// Второй вопрос, и он решающий: успевает ли привязка к процессу прийти
/// **раньше**, чем запрос уходит на провод.
///
/// Привязка есть только в событии 3006, а события ETW доставляются пачками.
/// Запрос же уходит сразу. Если привязка опаздывает, перехватить по ней
/// нечего — остаётся выбор из двух нехороших вариантов, и знать это надо
/// до того, как под привязку написан код.
///
/// Замер устроен так: на каждое событие 3006 запоминается имя и время по
/// монотонным часам, и одновременно ручка WinDivert слушает запросы к
/// порту 53. Для каждого запроса на проводе смотрим, была ли привязка, и
/// насколько раньше. Положительная разница — привязка успела.
pub fn race(store: &Store, seconds: u32) -> Result<(), String> {
    use std::time::Instant;

    let asked: Arc<Mutex<HashMap<String, (u32, Instant)>>> = Arc::new(Mutex::new(HashMap::new()));
    let started = Instant::now();

    store.log(&format!(
        "DNS: замер опережения на {seconds} с — что раньше, привязка или запрос"
    ));

    let watcher = vpnsplit_net::divert::Handle::sniff_network(
        "outbound and udp and udp.DstPort == 53 and not loopback",
    )?;

    {
        let events = asked.clone();
        let _trace = etw::Trace::start(etw::DNS_SESSION, &etw::DNS_CLIENT, 0, move |raw| {
            // 3006 — «приложение спросило имя»; только в нём стоит номер
            // процесса-заказчика.
            if raw.id != 3006 {
                return;
            }
            if let Some(name) = etw::leading_string(raw.payload) {
                let mut events = events.lock().unwrap_or_else(|e| e.into_inner());
                // Храним **последнюю** привязку, а не первую. С первой
                // замер врал: на повторный запрос того же имени он
                // показывал «успела», хотя это была привязка от прошлого
                // раза, многосекундной давности.
                events.insert(name.to_lowercase(), (raw.pid, Instant::now()));
            }
        })?;

        let mut buffer = vec![0u8; vpnsplit_net::divert::MAX_PACKET];
        let (mut ahead, mut behind, mut unknown) = (0usize, 0usize, 0usize);
        let mut shown = 0usize;
        let deadline = started + std::time::Duration::from_secs(seconds as u64);

        let handle = &watcher;
        std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(seconds as u64));
                handle.stop();
            });

            while let Ok((length, _)) = watcher.next_packet(&mut buffer) {
                let seen = Instant::now();
                let packet = &buffer[..length];
                // Заголовок IP переменной длины, дальше восемь байт UDP.
                let header = (packet.first().copied().unwrap_or(0) & 0x0F) as usize * 4;
                let Some(datagram) = packet.get(header + 8..) else {
                    continue;
                };
                let Some(name) = vpnsplit_net::dns::question_name(datagram) else {
                    continue;
                };
                let found = {
                    let events = asked.lock().unwrap_or_else(|e| e.into_inner());
                    events.get(&name.to_lowercase()).copied()
                };
                match found {
                    // Привязка считается успевшей только если она свежая.
                    // Старая — это привязка от прошлого запроса того же
                    // имени, и к нынешнему она отношения не имеет.
                    Some((pid, at)) if seen.duration_since(at) < FRESH => {
                        ahead += 1;
                        if shown < 12 {
                            shown += 1;
                            store.log(&format!(
                                "DNS: {name} — привязка к процессу {pid} успела на {} мкс",
                                (seen - at).as_micros()
                            ));
                        }
                    }
                    Some((pid, at)) => {
                        behind += 1;
                        if shown < 12 {
                            shown += 1;
                            store.log(&format!(
                                "DNS: {name} — привязка к {pid} старая, {} мс назад",
                                (seen - at).as_millis()
                            ));
                        }
                    }
                    None => {
                        unknown += 1;
                        if shown < 12 {
                            shown += 1;
                            store.log(&format!("DNS: {name} — привязки к моменту запроса нет"));
                        }
                    }
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
        });

        store.log(&format!(
            "DNS: запросов на проводе {}, привязка успела {ahead}, опоздала {behind}, \
             не нашлась {unknown}",
            ahead + behind + unknown
        ));
    }
    Ok(())
}

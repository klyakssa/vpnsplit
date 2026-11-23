//! Этап 12, запускатели: с каким опозданием доходит событие о запуске
//! процесса и чем это опоздание можно сократить.
//!
//! Зачем это меряется. Правило «приложение и все потомки» держится на
//! родословной, а родословную процесса, чей родитель уже умер, знают
//! только события запуска. События же доставляются пачками, с задержкой до
//! секунды, и запущенная запускателем программа успевает соединиться
//! раньше. Первая попытка — попросить систему отдать события сейчас и
//! подождать 50 мс — в деле не сработала: событие не пришло. Почему, по
//! двум строкам журнала не понять, а гадать здесь нельзя: от ответа
//! зависит, держится ли свойство «ничего мимо туннеля» в первую секунду
//! жизни программы.
//!
//! Способ: свой сеанс ETW (рабочий сеанс службы не трогается), в нём по
//! очереди разные настройки доставки. В каждой запускается пустой процесс,
//! и меряется время от «процесс создан» до «событие у нас в руках».
//!
//! Перехвата здесь нет: только запуск `cmd /c exit` и чтение событий.

use crate::store::Store;
use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use vpnsplit_net::etw::{self, ProcessEvent, ProcessWatcher, Tuning};

/// Отдельное имя: сеанс с рабочим именем уже занят службой, и второй под
/// тем же именем первым делом закрыл бы его.
const SESSION: &str = "vpnsplit-flush-probe";

/// Сколько ждать одно событие. Обычная доставка укладывается в секунду;
/// не пришло за полторы — эта настройка события не доставляет.
const PATIENCE: Duration = Duration::from_millis(1500);

/// CREATE_NO_WINDOW: у службы нет консоли, и заводить её ради пустого
/// процесса незачем.
const NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Copy)]
enum Ask {
    Nothing,
    ByName,
    ByHandle,
}

struct Variant {
    label: &'static str,
    tuning: Tuning,
    ask: Ask,
}

fn variants() -> Vec<Variant> {
    let second = Tuning::default();
    vec![
        Variant { label: "как было: таймер 1 с, без просьбы", tuning: second, ask: Ask::Nothing },
        Variant { label: "таймер 1 с + просьба по имени сеанса", tuning: second, ask: Ask::ByName },
        Variant { label: "таймер 1 с + просьба по хэндлу", tuning: second, ask: Ask::ByHandle },
        Variant {
            label: "таймер 1 с, один набор буферов + просьба по имени",
            tuning: Tuning { mode: etw::MODE_SINGLE_BUFFER, flush_timer: 1 },
            ask: Ask::ByName,
        },
        // Без просьбы: сколько ждут события те, кто их не торопит (отметка
        // «идёт мимо туннеля» в пути A, снятие потоков умершего процесса).
        Variant {
            label: "таймер 1 с, один набор буферов, без просьбы",
            tuning: Tuning { mode: etw::MODE_SINGLE_BUFFER, flush_timer: 1 },
            ask: Ask::Nothing,
        },
        Variant {
            label: "таймер 50 мс (бит миллисекунд), без просьбы",
            tuning: Tuning { mode: etw::MODE_MS_FLUSH_TIMER, flush_timer: 50 },
            ask: Ask::Nothing,
        },
        Variant {
            label: "таймер 10 мс (бит миллисекунд), без просьбы",
            tuning: Tuning { mode: etw::MODE_MS_FLUSH_TIMER, flush_timer: 10 },
            ask: Ask::Nothing,
        },
    ]
}

type Arrivals = Arc<(Mutex<HashMap<u32, Instant>>, Condvar)>;

pub fn run(store: &Store, rounds: u32) -> Result<(), String> {
    let shell = std::env::var("SystemRoot")
        .map(|root| format!("{root}\\System32\\cmd.exe"))
        .unwrap_or_else(|_| "cmd.exe".to_owned());
    store.log(&format!(
        "замер событий запуска: по {rounds} запусков на каждую настройку; \
         время — от создания процесса до события у нас в руках"
    ));
    let mut worked = 0;
    for variant in variants() {
        match measure(&shell, &variant, rounds) {
            Ok(line) => {
                worked += 1;
                store.log(&format!("замер событий запуска: {} — {line}", variant.label));
            }
            Err(e) => store.log(&format!(
                "замер событий запуска: {} — НЕ ВЫШЛО: {e}",
                variant.label
            )),
        }
    }
    store.log("замер событий запуска: конец");
    if worked == 0 {
        return Err("ни одна настройка не запустилась; подробности в журнале службы".to_owned());
    }
    Ok(())
}

fn measure(shell: &str, variant: &Variant, rounds: u32) -> Result<String, String> {
    let arrivals: Arrivals = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
    let watcher = {
        let arrivals = arrivals.clone();
        ProcessWatcher::start_tuned(SESSION, variant.tuning, move |event| {
            if let ProcessEvent::Started { pid, .. } = event {
                let now = Instant::now();
                let (map, changed) = &*arrivals;
                map.lock().unwrap_or_else(|e| e.into_inner()).insert(pid, now);
                changed.notify_all();
            }
        })?
    };
    // Сеансу нужно время, чтобы провайдер включился: первый запуск иначе
    // мерил бы не доставку, а раскачку.
    std::thread::sleep(Duration::from_millis(400));

    let mut delays: Vec<u128> = Vec::new();
    let mut lost = 0usize;
    let mut ask_micros: Vec<u128> = Vec::new();
    let mut ask_errors: Vec<u32> = Vec::new();
    for round in 0..rounds {
        let mut child = std::process::Command::new(shell)
            .args(["/c", "exit"])
            .creation_flags(NO_WINDOW)
            .spawn()
            .map_err(|e| format!("не запустился {shell}: {e}"))?;
        let born = Instant::now();
        let pid = child.id();

        let asked = Instant::now();
        let outcome = match variant.ask {
            Ask::Nothing => None,
            Ask::ByName => Some(etw::flush_by_name(SESSION)),
            Ask::ByHandle => Some(watcher.flush()),
        };
        if let Some(outcome) = outcome {
            ask_micros.push(asked.elapsed().as_micros());
            if let Err(code) = outcome {
                ask_errors.push(code);
            }
        }

        let arrived = {
            let (map, changed) = &*arrivals;
            let deadline = born + PATIENCE;
            let mut map = map.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(at) = map.get(&pid) {
                    break Some(*at);
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break None;
                }
                map = changed.wait_timeout(map, left).unwrap_or_else(|e| e.into_inner()).0;
            }
        };
        match arrived {
            // Событие могло прийти, пока запуск ещё возвращался, — тогда
            // опоздания нет вовсе.
            Some(at) => delays.push(at.saturating_duration_since(born).as_micros()),
            None => lost += 1,
        }
        let _ = child.wait();
        // Паузы разной длины: иначе запуски попадали бы в одну и ту же
        // долю секунды таймера, и замер показывал бы одно везение.
        std::thread::sleep(Duration::from_millis(130 + (round as u64 * 173) % 410));
    }
    drop(watcher);
    Ok(summarize(&delays, lost, &ask_micros, &ask_errors))
}

/// Строка итога по одной настройке. Отдельно от замера, чтобы проверять
/// её без сеанса ETW и без прав.
fn summarize(delays: &[u128], lost: usize, ask_micros: &[u128], ask_errors: &[u32]) -> String {
    let total = delays.len() + lost;
    let mut line = format!("событий {} из {total}", delays.len());
    if !delays.is_empty() {
        let mut sorted = delays.to_vec();
        sorted.sort_unstable();
        let average = sorted.iter().sum::<u128>() / sorted.len() as u128;
        let each = delays
            .iter()
            .map(|micros| format!("{:.1}", *micros as f64 / 1000.0))
            .collect::<Vec<_>>()
            .join(" ");
        line += &format!(
            "; опоздание мс: меньшее {:.1}, среднее {:.1}, худшее {:.1}; по порядку: {each}",
            sorted[0] as f64 / 1000.0,
            average as f64 / 1000.0,
            sorted[sorted.len() - 1] as f64 / 1000.0
        );
    }
    if lost > 0 {
        line += &format!("; НЕ ДОЖДАЛИСЬ за {} мс: {lost}", PATIENCE.as_millis());
    }
    if !ask_micros.is_empty() {
        let average = ask_micros.iter().sum::<u128>() / ask_micros.len() as u128;
        let worst = ask_micros.iter().max().copied().unwrap_or(0);
        line += &format!("; сама просьба: в среднем {average} мкс, худшая {worst} мкс");
        if !ask_errors.is_empty() {
            line += &format!(", отказов {} (первый код {})", ask_errors.len(), ask_errors[0]);
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_names_what_was_lost() {
        let line = summarize(&[1500, 500, 2500], 2, &[40, 60], &[]);
        assert!(line.contains("событий 3 из 5"), "{line}");
        assert!(line.contains("меньшее 0.5, среднее 1.5, худшее 2.5"), "{line}");
        // Порядок запусков сохраняется: по нему видно, везение это или нет.
        assert!(line.contains("по порядку: 1.5 0.5 2.5"), "{line}");
        assert!(line.contains("НЕ ДОЖДАЛИСЬ за 1500 мс: 2"), "{line}");
        assert!(line.contains("в среднем 50 мкс, худшая 60 мкс"), "{line}");
    }

    #[test]
    fn nothing_arrived_is_said_plainly() {
        let line = summarize(&[], 4, &[], &[]);
        assert!(line.contains("событий 0 из 4"), "{line}");
        assert!(!line.contains("опоздание"), "{line}");
        assert!(!line.contains("просьба"), "{line}");
    }

    #[test]
    fn refused_requests_are_counted_with_the_code() {
        let line = summarize(&[900_000], 0, &[10, 10], &[4201, 4201]);
        assert!(line.contains("отказов 2 (первый код 4201)"), "{line}");
    }

    #[test]
    fn every_variant_is_distinct() {
        // Две одинаковые настройки под разными названиями — это замер,
        // который выглядит шире, чем он есть.
        let all = variants();
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                let same = a.tuning == b.tuning
                    && std::mem::discriminant(&a.ask) == std::mem::discriminant(&b.ask);
                assert!(!same, "{} и {}", a.label, b.label);
            }
        }
    }
}

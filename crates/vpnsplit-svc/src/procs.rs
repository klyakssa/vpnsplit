//! Какие приложения из списка сейчас работают и идут ли они через туннель.
//!
//! Признак один: загружена ли в процессе `vpnsplit_hook.dll`. Загружена —
//! сокеты привязаны к туннелю. Не загружена — приложение из списка работает,
//! но идёт мимо VPN, и пользователь обязан это видеть: молчание здесь хуже
//! ошибки, потому что выглядит как «всё хорошо».

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use vpnsplit_core::hook::DLL_NAME;
use vpnsplit_core::AppTarget;
use vpnsplit_net::proc;

/// Сколько ждать появления хуков в только что запущенном процессе.
///
/// Лончер внедряет DLL в приостановленный процесс, то есть к моменту, когда
/// процесс оживёт, она уже на месте. Но событие ETW приходит раньше — в миг
/// создания процесса, — и первая же проверка сказала бы «хуков нет».
const PATIENCE: Duration = Duration::from_secs(2);

/// Запущенное приложение из списка.
#[derive(Clone, Debug)]
pub struct Running {
    pub target: AppTarget,
    pub image: PathBuf,
    pub hooked: bool,
}

#[derive(Default)]
pub struct Table {
    running: HashMap<u32, Running>,
}

impl Table {
    pub fn insert(&mut self, pid: u32, running: Running) {
        self.running.insert(pid, running);
    }

    pub fn remove(&mut self, pid: u32) -> Option<Running> {
        self.running.remove(&pid)
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.running.contains_key(&pid)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &Running)> {
        self.running.iter().map(|(pid, running)| (*pid, running))
    }

    /// Сколько приложений идёт через туннель.
    pub fn attached(&self) -> usize {
        self.running.values().filter(|running| running.hooked).count()
    }

    /// Сколько работает мимо туннеля.
    pub fn unhooked(&self) -> usize {
        self.running.len() - self.attached()
    }

    /// Кого мы сейчас считаем запущенным: номер процесса и путь к образу.
    pub fn tracked(&self) -> Vec<(u32, PathBuf)> {
        self.running
            .iter()
            .map(|(pid, running)| (*pid, running.image.clone()))
            .collect()
    }

    pub fn forget(&mut self, pids: &[u32]) {
        for pid in pids {
            self.running.remove(pid);
        }
    }
}

/// Кого из отслеживаемых пора забыть.
///
/// Свежий обход (`alive`) — главный источник правды, но он идёт не мгновенно,
/// и процесс, запущенный прямо во время обхода, в него не попадёт. Поэтому
/// запись выбрасывается, только если её правила больше нет или если процесс
/// действительно кончился; `lives` отвечает на второй вопрос и в тестах
/// подменяется.
pub fn stale(
    tracked: &[(u32, PathBuf)],
    alive: &[u32],
    policy: &vpnsplit_core::Policy,
    lives: impl Fn(u32) -> bool,
) -> Vec<u32> {
    tracked
        .iter()
        .filter(|(pid, image)| {
            !alive.contains(pid) && (policy.hook_rule_for_image(image).is_none() || !lives(*pid))
        })
        .map(|(pid, _)| *pid)
        .collect()
}

/// Стоят ли хуки в процессе. `None` — процесса уже нет, и говорить не о чем.
///
/// Проверка повторяется, пока не истечёт терпение: процесс, который ещё
/// поднимается, не отдаёт список модулей вовсе, а внедрение DLL занимает
/// заметное время.
pub fn hooked_within(pid: u32, patience: Duration) -> Option<bool> {
    let deadline = Instant::now() + patience;
    let mut step = Duration::from_millis(50);
    loop {
        if let Ok(true) = proc::has_module(pid, DLL_NAME) {
            return Some(true);
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(step);
        // Шаг растёт: обычный случай решается первой проверкой, а редкий
        // долгий старт не должен стоить сотни снимков.
        step = (step * 2).min(Duration::from_millis(400));
    }
    // Хуков нет. Осталось отличить «приложение идёт мимо туннеля» от
    // «процесс кончился, пока мы ждали».
    proc::image_path(pid).map(|_| false)
}

pub fn hooked(pid: u32) -> Option<bool> {
    hooked_within(pid, PATIENCE)
}

/// Приложения из списка, которые работают прямо сейчас.
///
/// Полный путь спрашивается только у тех процессов, чьё имя файла совпало с
/// правилом: открывать ради этого каждый процесс системы незачем.
///
/// Считаются только правила пути A. Правила «приложение и все его потомки»
/// ведёт движок перехвата, хуков в таких процессах нет, и место им не
/// здесь: иначе служба объявляла бы их работающими мимо туннеля.
pub fn scan(policy: &vpnsplit_core::Policy) -> Vec<(u32, Running)> {
    let names: Vec<String> = policy
        .rules
        .iter()
        .filter(|rule| rule.mechanism() == vpnsplit_core::Mechanism::Inject)
        .filter_map(|rule| match &rule.target {
            AppTarget::Executable(path) => {
                path.file_name().map(|name| name.to_string_lossy().to_lowercase())
            }
            AppTarget::Package(_) => None,
        })
        .collect();
    if names.is_empty() {
        return Vec::new();
    }

    let mut found = Vec::new();
    for (pid, exe) in proc::list() {
        let exe = exe.to_lowercase();
        if !names.contains(&exe) {
            continue;
        }
        let Some(image) = proc::image_path(pid) else {
            continue;
        };
        let Some(rule) = policy.hook_rule_for_image(&image) else {
            continue;
        };
        // Эти процессы работают давно, ждать появления хуков незачем:
        // если их не внедрили при старте, позже они не появятся.
        let hooked = matches!(proc::has_module(pid, DLL_NAME), Ok(true));
        found.push((pid, Running { target: rule.target.clone(), image, hooked }));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpnsplit_core::{AppRule, Policy};

    fn running(path: &str, hooked: bool) -> Running {
        Running {
            target: AppTarget::Executable(PathBuf::from(path)),
            image: PathBuf::from(path),
            hooked,
        }
    }

    #[test]
    fn counts_split_by_hooks() {
        let mut table = Table::default();
        table.insert(1, running(r"C:\a.exe", true));
        table.insert(2, running(r"C:\b.exe", false));
        table.insert(3, running(r"C:\c.exe", false));
        assert_eq!(table.attached(), 1);
        assert_eq!(table.unhooked(), 2);
    }

    fn policy_for(paths: &[&str]) -> Policy {
        let mut policy = Policy::default();
        for path in paths {
            policy
                .rules
                .push(AppRule::tunnel(AppTarget::Executable(PathBuf::from(path))));
        }
        policy
    }

    #[test]
    fn removing_a_rule_drops_its_processes() {
        let tracked = vec![(1, PathBuf::from(r"C:\a.exe")), (2, PathBuf::from(r"C:\b.exe"))];
        let policy = policy_for(&[r"C:\a.exe"]);
        // Оба процесса живы, обход их не застал — но правила для b.exe больше нет.
        assert_eq!(stale(&tracked, &[], &policy, |_| true), vec![2]);
    }

    #[test]
    fn a_process_that_ended_is_forgotten() {
        let tracked = vec![(1, PathBuf::from(r"C:\a.exe")), (2, PathBuf::from(r"C:\a.exe"))];
        let policy = policy_for(&[r"C:\a.exe"]);
        assert_eq!(stale(&tracked, &[], &policy, |pid| pid == 1), vec![2]);
    }

    #[test]
    fn a_process_seen_by_the_scan_stays_whatever_else_says() {
        let tracked = vec![(7, PathBuf::from(r"C:\a.exe"))];
        let policy = policy_for(&[r"C:\a.exe"]);
        assert!(stale(&tracked, &[7], &policy, |_| false).is_empty());
    }

    #[test]
    fn forget_removes_exactly_the_listed_processes() {
        let mut table = Table::default();
        table.insert(1, running(r"C:\a.exe", true));
        table.insert(2, running(r"C:\b.exe", true));
        table.forget(&[2]);
        assert!(table.contains(1));
        assert!(!table.contains(2));
    }

    #[test]
    fn our_own_process_is_seen_as_running() {
        // Проверка всей цепочки «список → путь → правило» на живом процессе.
        let me = std::env::current_exe().unwrap();
        let mut policy = Policy::default();
        policy.rules.push(AppRule::tunnel(AppTarget::Executable(me.clone())));

        let found = scan(&policy);
        assert!(found.iter().any(|(pid, _)| *pid == std::process::id()), "{found:?}");
        // Хуков в тестовом процессе, разумеется, нет.
        assert!(found.iter().all(|(_, running)| !running.hooked));
    }

    #[test]
    fn empty_policy_scans_nothing() {
        assert!(scan(&Policy::default()).is_empty());
    }

    #[test]
    fn a_dead_process_has_no_answer() {
        // Номера такого размера Windows не выдаёт.
        assert_eq!(hooked_within(0xFFFF_FFF0, Duration::from_millis(1)), None);
    }
}

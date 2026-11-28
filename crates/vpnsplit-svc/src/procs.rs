//! Какие приложения из списка сейчас работают и идут ли они через туннель.
//!
//! Признак — загружена ли в процессе `vpnsplit_hook.dll` и сработал ли её
//! init (признак `hook::READY_EXPORT`). Загружена и сработал — сокеты
//! привязаны к туннелю. Иначе — приложение из списка работает,
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

/// Сколько ждать, когда DLL уже загружена, а хуки ещё не поставлены: init
/// в потомке внедряющий ждёт до 15 с, и всё это время он может ещё успеть.
const INIT_PATIENCE: Duration = Duration::from_secs(20);

/// Запущенное приложение из списка.
#[derive(Clone, Debug)]
pub struct Running {
    pub target: AppTarget,
    pub image: PathBuf,
    pub hooked: bool,
    /// Время создания процесса, если его удалось узнать. Вместе с номером
    /// называет процесс однозначно: номер переиспользуется.
    pub created: Option<u64>,
}

#[derive(Default)]
pub struct Table {
    running: HashMap<u32, Running>,
    /// Чьих хуков сейчас ждут потоки «hooked?», и сколько их на номер.
    /// Чтобы пересмотр списка не заводил по новому ожиданию на тот же
    /// процесс, пока прежнее ещё идёт.
    waiting: HashMap<u32, usize>,
}

/// Как новое знание о процессе соотносится с записанным (`Table`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Записи нет.
    New,
    /// Тот же процесс (или отличить не по чему), и сказать о нём нового
    /// нечего.
    Same,
    /// Тот же процесс был записан идущим мимо туннеля, а теперь видно, что
    /// хуки встали: init закончился позже, чем на него посмотрели.
    Hooked,
    /// Номер у нового процесса, а о завершении прежнего события не было:
    /// прежняя запись — о мёртвом.
    Reused,
}

/// Что делать с новым знанием о процессе (`created`, `hooked`), если о нём
/// уже записано `known`. Обратно, «через туннель» → «мимо», не меняется:
/// признак готовности hook.dll однажды выставленным не сбрасывается, и
/// «мимо» тут может быть только запоздалым ответом вроде истёкшего ожидания.
pub fn change(known: Option<&Running>, created: Option<u64>, hooked: bool) -> Change {
    match known {
        None => Change::New,
        Some(known) if known.created.is_none() || created.is_none() || known.created == created => {
            if hooked && !known.hooked {
                Change::Hooked
            } else {
                Change::Same
            }
        }
        Some(_) => Change::Reused,
    }
}

impl Table {
    pub fn insert(&mut self, pid: u32, running: Running) {
        self.running.insert(pid, running);
    }

    pub fn remove(&mut self, pid: u32) -> Option<Running> {
        self.running.remove(&pid)
    }

    #[cfg(test)]
    pub fn contains(&self, pid: u32) -> bool {
        self.running.contains_key(&pid)
    }

    pub fn get(&self, pid: u32) -> Option<&Running> {
        self.running.get(&pid)
    }

    /// Записано ли о номере ровно это (`created`, `hooked`): не заменил ли
    /// запись кто-то другой, пока записавший её до неё не дошёл.
    pub fn holds(&self, pid: u32, created: Option<u64>, hooked: bool) -> bool {
        self.running.get(&pid).is_some_and(|running| running.created == created && running.hooked == hooked)
    }

    /// Снимает запись, только если она о процессе с этим временем создания:
    /// номер мог за это время достаться другому, и его запись не наша.
    pub fn remove_if_created(&mut self, pid: u32, created: Option<u64>) -> Option<Running> {
        if self.running.get(&pid).is_some_and(|running| running.created == created) {
            return self.running.remove(&pid);
        }
        None
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

    /// Ждут ли сейчас хуков процесса с этим номером.
    pub fn waiting(&self, pid: u32) -> bool {
        self.waiting.contains_key(&pid)
    }

    pub fn wait_begins(&mut self, pid: u32) {
        *self.waiting.entry(pid).or_insert(0) += 1;
    }

    pub fn wait_ends(&mut self, pid: u32) {
        if let Some(count) = self.waiting.get_mut(&pid) {
            *count -= 1;
            if *count == 0 {
                self.waiting.remove(&pid);
            }
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

/// Поставила ли загруженная в процессе hook.dll свои хуки.
///
/// Загруженная DLL — ещё не хуки: потомка, у которого init вернул ошибку
/// или не уложился в срок, внедряющий всё равно отпускает работать, и его
/// сокеты не привязаны. Поэтому читается признак, который DLL выставляет
/// после успешного init (`hook::READY_EXPORT`).
fn readiness(pid: u32) -> vpnsplit_inject::Readiness {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if process.is_null() {
        return vpnsplit_inject::Readiness::Unknown;
    }
    let answer = vpnsplit_inject::readiness(process, std::path::Path::new(DLL_NAME));
    unsafe { CloseHandle(process) };
    answer
}

/// Что сказать по загруженной DLL и её признаку. `None` — пока сказать
/// нечего, надо ждать или проверять заново.
///
/// «Не известно» (нет прав на чтение памяти, старая сборка DLL без
/// признака) считается «хуки стоят», как было до признака: иначе после
/// обновления каждое уже работающее приложение объявлялось бы идущим мимо
/// туннеля.
fn verdict(readiness: vpnsplit_inject::Readiness) -> Option<bool> {
    use vpnsplit_inject::Readiness;
    match readiness {
        Readiness::Ready | Readiness::Unknown => Some(true),
        Readiness::NotReady | Readiness::Absent => None,
    }
}

/// Что сказать о давно работающем процессе по одному взгляду (`None` на
/// входе — hook.dll в нём нет). Init ещё идёт (или не сработал) — по
/// одному взгляду не решить, `None`: ложное «мимо туннеля», вынесенное
/// здесь, потом уже не исправилось бы.
fn at_a_glance(readiness: Option<vpnsplit_inject::Readiness>) -> Option<bool> {
    use vpnsplit_inject::Readiness;
    match readiness {
        None => Some(false),
        Some(Readiness::NotReady) => None,
        Some(answer) => Some(verdict(answer).unwrap_or(false)),
    }
}

/// Стоят ли хуки в процессе. `None` — процесса уже нет, и говорить не о чем.
///
/// Проверка повторяется, пока не истечёт терпение: процесс, который ещё
/// поднимается, не отдаёт список модулей вовсе, а внедрение DLL занимает
/// заметное время. Если DLL уже загружена, а хуки ещё нет, терпения больше
/// (`INIT_PATIENCE`): init может быть ещё в пути.
pub fn hooked_within(pid: u32, patience: Duration) -> Option<bool> {
    let started = Instant::now();
    let mut deadline = started + patience;
    let mut step = Duration::from_millis(50);
    loop {
        if let Ok(true) = proc::has_module(pid, DLL_NAME) {
            let answer = readiness(pid);
            if let Some(hooked) = verdict(answer) {
                return Some(hooked);
            }
            if answer == vpnsplit_inject::Readiness::NotReady {
                deadline = deadline.max(started + INIT_PATIENCE);
            }
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

/// Что нашёл обход.
#[derive(Debug, Default)]
pub struct Scan {
    /// Приложения, о которых всё ясно.
    pub found: Vec<(u32, Running)>,
    /// Приложения, в которых hook.dll загружена, а её init ещё не
    /// закончился (внедряющий ждёт его до 15 с). Решать по обходу рано —
    /// ответ даст ожидание (`hooked`); `hooked` в этих записях ничего не
    /// значит.
    pub pending: Vec<(u32, Running)>,
}

/// Приложения из списка, которые работают прямо сейчас.
///
/// Полный путь спрашивается только у тех процессов, чьё имя файла совпало с
/// правилом: открывать ради этого каждый процесс системы незачем.
///
/// Считаются только правила пути A. Правила «приложение и все его потомки»
/// ведёт движок перехвата, хуков в таких процессах нет, и место им не
/// здесь: иначе служба объявляла бы их работающими мимо туннеля.
pub fn scan(policy: &vpnsplit_core::Policy) -> Scan {
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
        return Scan::default();
    }

    let mut found = Scan::default();
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
        // Эти процессы работают давно, ждать появления DLL незачем: если
        // её не внедрили при старте, позже она не появится. А вот init
        // уже внедрённой может быть ещё в пути.
        let loaded = matches!(proc::has_module(pid, DLL_NAME), Ok(true));
        let glance = at_a_glance(loaded.then(|| readiness(pid)));
        let created = proc::created(pid);
        let running =
            Running { target: rule.target.clone(), image, hooked: glance.unwrap_or(false), created };
        match glance {
            Some(_) => found.found.push((pid, running)),
            None => found.pending.push((pid, running)),
        }
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
            created: None,
        }
    }

    /// DLL загружена, но init не сработал — это «мимо туннеля», а не
    /// «через туннель». Старая сборка без признака — как раньше, «через».
    #[test]
    fn a_loaded_dll_without_hooks_is_not_hooked() {
        use vpnsplit_inject::Readiness;
        assert_eq!(verdict(Readiness::Ready), Some(true));
        assert_eq!(verdict(Readiness::Unknown), Some(true));
        assert_eq!(verdict(Readiness::NotReady), None);
        assert_eq!(verdict(Readiness::Absent), None);
    }

    /// Обход не выносит «мимо туннеля», пока init hook.dll ещё может
    /// закончиться.
    #[test]
    fn a_scan_does_not_judge_an_unfinished_init() {
        use vpnsplit_inject::Readiness;
        assert_eq!(at_a_glance(None), Some(false));
        assert_eq!(at_a_glance(Some(Readiness::NotReady)), None);
        assert_eq!(at_a_glance(Some(Readiness::Ready)), Some(true));
        assert_eq!(at_a_glance(Some(Readiness::Unknown)), Some(true));
        assert_eq!(at_a_glance(Some(Readiness::Absent)), Some(false));
    }

    #[test]
    fn a_late_init_turns_an_unhooked_record_into_a_hooked_one() {
        let mut known = running(r"C:\a.exe", false);
        known.created = Some(1000);
        assert_eq!(change(None, Some(1000), false), Change::New);
        assert_eq!(change(Some(&known), Some(1000), true), Change::Hooked);
        assert_eq!(change(Some(&known), None, true), Change::Hooked);
        assert_eq!(change(Some(&known), Some(1000), false), Change::Same);
        assert_eq!(change(Some(&known), Some(2000), true), Change::Reused);
        // Обратно — никогда: признак готовности не сбрасывается.
        known.hooked = true;
        assert_eq!(change(Some(&known), Some(1000), false), Change::Same);
        assert_eq!(change(Some(&known), Some(1000), true), Change::Same);
    }

    #[test]
    fn waits_are_counted_per_number() {
        let mut table = Table::default();
        table.wait_begins(5);
        table.wait_begins(5);
        table.wait_ends(5);
        assert!(table.waiting(5));
        table.wait_ends(5);
        assert!(!table.waiting(5));
        // Лишнее окончание ничего не ломает.
        table.wait_ends(5);
        assert!(!table.waiting(5));
    }

    #[test]
    fn a_record_is_removed_only_for_the_same_process() {
        let mut table = Table::default();
        let mut first = running(r"C:\a.exe", true);
        first.created = Some(1000);
        table.insert(1, first);
        // Номер уже у другого процесса — его запись не трогаем.
        assert!(table.remove_if_created(1, Some(2000)).is_none());
        assert!(table.contains(1));
        assert!(table.remove_if_created(1, Some(1000)).is_some());
        assert!(!table.contains(1));
    }

    /// Записавший «мимо туннеля» узнаёт, что запись уже заменили на
    /// «через туннель» (или на другой процесс с тем же номером).
    #[test]
    fn a_record_replaced_meanwhile_is_not_held() {
        let mut table = Table::default();
        assert!(!table.holds(1, Some(1000), false));
        let mut first = running(r"C:\a.exe", false);
        first.created = Some(1000);
        table.insert(1, first.clone());
        assert!(table.holds(1, Some(1000), false));
        table.insert(1, Running { hooked: true, ..first.clone() });
        assert!(!table.holds(1, Some(1000), false));
        assert!(table.holds(1, Some(1000), true));
        table.insert(1, Running { created: Some(2000), ..first });
        assert!(!table.holds(1, Some(1000), false));
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

        let scanned = scan(&policy);
        let found = &scanned.found;
        assert!(found.iter().any(|(pid, _)| *pid == std::process::id()), "{scanned:?}");
        // Хуков в тестовом процессе, разумеется, нет — и ждать нечего.
        assert!(found.iter().all(|(_, running)| !running.hooked));
        assert!(scanned.pending.is_empty());
    }

    #[test]
    fn empty_policy_scans_nothing() {
        let scanned = scan(&Policy::default());
        assert!(scanned.found.is_empty() && scanned.pending.is_empty());
    }

    #[test]
    fn a_dead_process_has_no_answer() {
        // Номера такого размера Windows не выдаёт.
        assert_eq!(hooked_within(0xFFFF_FFF0, Duration::from_millis(1)), None);
    }
}

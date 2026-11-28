//! Работа службы: состояние, канал для клиентов, слежение за туннелем.
//!
//! Одинаково работает и как служба Windows, и в консоли (`vpnsplit-svc run`):
//! отличается только хранилище.
//!
//! Ни таймеров, ни опросов: канал ждёт клиента в ConnectNamedPipe, сеть
//! сообщает о себе обработчиком, процессы — событиями ETW. Просыпается
//! служба только тогда, когда в системе что-то действительно произошло.
//!
//! У слежения за процессами цена выше, чем у остального: ETW будит нас на
//! каждый старт и каждое завершение процесса в системе, а не только своих.
//! Поэтому в обработчике нельзя делать ничего тяжёлого — там только один
//! вопрос «чей это образ», а всё остальное уходит в отдельный поток и
//! только для приложений из списка.

use crate::procs::{self, Running, Table};
use crate::store::Store;
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use vpnsplit_core::{Event, Policy, Request, Response, Status, TunnelState};
use vpnsplit_net::etw::{ProcessEvent, ProcessWatcher};
use vpnsplit_net::pipe::{Connection, Instance, Server};
use vpnsplit_net::stall::{Remote, Watch};
use vpnsplit_net::watch::Watcher;
use vpnsplit_net::wfp;

/// Сколько держится запрет при проверке. Достаточно, чтобы успеть
/// запустить приложение и увидеть отказ, и мало, чтобы о нём забыть.
const CHECK_SECONDS: u64 = 12;

struct State {
    policy: Policy,
    tunnel: TunnelState,
    processes: Table,
}

pub struct Shared {
    state: Mutex<State>,
    /// Очереди подписчиков и чем прервать запись того, кто не читает.
    subscribers: Mutex<Vec<(SyncSender<Event>, Remote)>>,
    store: Store,
    /// Kill-switch. `None` — движок фильтрации открыть не удалось (в
    /// консоли без прав администратора это обычное дело), и тогда защиты
    /// от утечки для незахученных приложений нет.
    guard: Mutex<Option<wfp::Guard>>,
    /// Самопроверка разбора родителя в событиях ETW.
    parent_check: Mutex<ParentCheck>,
    /// Такая же самопроверка пути к образу из события: он находится в
    /// нагрузке по своему началу и переводится из записи ядра в привычную,
    /// и оба шага могут ошибиться молча. Счётчики те же, смысл тот же.
    image_check: Mutex<ParentCheck>,
    /// Работающий путь B, если он сейчас включён.
    engine: Mutex<Option<EngineSlot>>,
    /// Решения о движке пути B — по одному за раз: «посмотреть в ячейку,
    /// собрать и запустить движок, положить его туда» (`refresh_engine`,
    /// `path_b`) и «забрать и остановить». Без этого два одновременных
    /// SetPolicy оба видели пустую ячейку и поднимали два движка, и один
    /// из них, выброшенный из ячейки, продолжал перехватывать без присмотра.
    ///
    /// Порядок замков: `policy_serial` → `engine_serial` → всё остальное
    /// (`state`, ячейка `engine`, `divert_error`). Держащий его ждёт
    /// остановки рабочих потоков движка и открытия ручек; ни рабочие потоки,
    /// ни поток ETW этот замок не берут, поэтому ждать их под ним можно.
    /// Сам опыт (`path_b`) свои секунды под ним не спит.
    engine_serial: Mutex<()>,
    /// Запись о тех, кто был под присмотром до остановки службы, ещё не
    /// прочитана. Читает её (и удаляет файл) тот `refresh_engine`, который
    /// первым после старта действительно создаёт движок, — под
    /// `engine_serial`: канал работает раньше, чем старт доходит до пути B,
    /// и SetPolicy, успевший первым, иначе поднимал движок без неё, а
    /// стартовый вызов находил движок готовым и выбрасывал её.
    family_unread: std::sync::atomic::AtomicBool,
    /// Правки списка (SetPolicy) — по одной за раз, целиком: проверка,
    /// запись на диск, состояние и всё, что от списка зависит. Иначе две
    /// одновременные правки могли оставить на диске одну политику, а в
    /// памяти другую. Берётся первым, раньше всех остальных замков.
    policy_serial: Mutex<()>,
    /// Запись `learned.json` и `alone.json` — по одной за раз, со снимком,
    /// снятым уже под этим замком: последней на диск ложится самая свежая
    /// копия. Сами данные под своими замками на время записи не держатся —
    /// их на каждый запуск процесса спрашивает поток ETW. Берутся раньше
    /// замков `learned` и `alone`.
    learned_disk: Mutex<()>,
    alone_disk: Mutex<()>,
    /// Программы, виденные под правилами пути B. Нужны запретам на время
    /// простоя: правило называет одну программу, а ведёт и её потомков; у
    /// правила на значок-запускатель настоящая программа вообще другая.
    learned: Mutex<crate::store::Learned>,
    /// Программы, которые видели и под правилом, и запущенными сами по
    /// себе (`git`, `wsl`, запущенные приложением из списка). Им сеть на
    /// время простоя не закрывается: запрет стоит на образ и оставил бы
    /// без неё всех. Решение пользователя от 22.11.2026.
    alone: Mutex<crate::store::Alone>,
    /// Каким приложениям сейчас закрыта сеть на время простоя службы.
    standing: Mutex<Vec<std::path::PathBuf>>,
    /// Запреты пересматриваются по одному разу за раз: пересмотр — это
    /// «посмотрел и поправил», и два одновременных сошлись бы на разном.
    standing_serial: Mutex<()>,
    /// Каталог Windows: программы из него под запреты на время простоя не
    /// берутся (см. `store::worth_remembering`).
    system_root: std::path::PathBuf,
    /// Запись родословной на диск идёт из двух мест — из потока, который
    /// пишет её при каждой перемене, и при штатной остановке. Писать разом
    /// им нельзя: файл один, временный файл тоже.
    family_serial: Mutex<()>,
    /// Служба уходит: пишущему родословную пора остановиться, последнее
    /// слово за записью при остановке.
    leaving: std::sync::atomic::AtomicBool,
    /// Своё подключение OpenVPN: служба сама держит туннель, если ей дали
    /// конфиг. Без конфига туннель — по-прежнему забота другой программы.
    vpn: Arc<crate::vpn::Vpns>,
    /// Состояние подключений, каким его разослали в последний раз: о том,
    /// что не изменилось, подписчикам не сообщается.
    vpn_seen: Mutex<Vec<vpnsplit_core::VpnState>>,
    /// Почему перехват (путь B) не поднялся, если не поднялся. Окно
    /// показывает это человеку: «подробности в журнале» на чужой машине —
    /// не ответ.
    divert_error: Mutex<Option<String>>,
}

/// Как часто пишущий родословную просыпается без повода — проверить, не
/// сменился ли движок и не уходит ли служба.
const FAMILY_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// Сколько ждать после перемены, прежде чем писать. Приложение заводит
/// потомков пачкой, и писать файл на каждого незачем; а после падения
/// службы потеряется самое большее то, что случилось за это время.
const FAMILY_SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// Пишет родословную на диск при каждой её перемене.
///
/// Раньше она записывалась только при штатной остановке, и падение службы
/// её теряло: браузер, запущенный значком из списка, после возвращения
/// службы снова получал сеть, но шёл мимо туннеля. Теперь после падения
/// теряются только последние доли секунды.
///
/// Файл читается при старте один раз и стирается — здесь он появляется
/// заново при первой же перемене, то есть сразу: старт службы сам её
/// создаёт.
fn keep_family(service: std::sync::Weak<Shared>) {
    // Какой движок и какую его перемену мы уже записали.
    let mut seen: Option<(usize, u64)> = None;
    let mut saved: Option<Vec<crate::flows::Remembered>> = None;
    let mut complained = false;
    loop {
        let Some(shared) = service.upgrade() else { return };
        if shared.leaving.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let Some(engine) = shared.policy_engine() else {
            drop(shared);
            std::thread::sleep(FAMILY_POLL);
            continue;
        };
        // Службу на время ожидания не держим: иначе она не смогла бы уйти.
        drop(shared);
        let id = Arc::as_ptr(&engine) as usize;
        let last = match seen {
            Some((engine, generation)) if engine == id => generation,
            // Новый движок — число, которого у него быть не может: первое
            // же ожидание вернётся сразу.
            _ => u64::MAX,
        };
        if engine.wait_change(last, FAMILY_POLL) == last {
            continue;
        }
        std::thread::sleep(FAMILY_SETTLE);
        let now = engine.wait_change(last, std::time::Duration::ZERO);
        let members = engine.export();
        seen = Some((id, now));
        if saved.as_ref() == Some(&members) {
            continue;
        }
        let Some(shared) = service.upgrade() else { return };
        let _serial = shared.family_serial.lock().unwrap_or_else(|e| e.into_inner());
        if shared.leaving.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        match shared.store.save_family(&members) {
            Ok(()) => {
                if saved.is_none() {
                    shared.store.log(&format!(
                        "путь B: родословная записывается при каждой перемене (сейчас под \
                         присмотром {}) — после падения службы она вернётся",
                        members.len()
                    ));
                }
                saved = Some(members);
            }
            Err(e) if !complained => {
                complained = true;
                shared.store.log(&format!(
                    "путь B: НЕ удалось записать родословную ({e}); после падения службы \
                     запущенное запускателями останется без присмотра"
                ));
            }
            Err(_) => {}
        }
    }
}

/// Движок пути B и то, откуда он взялся.
///
/// Разница существенная. Движок по списку живёт, пока в списке есть
/// подходящее правило, и гаснет сам, когда последнее снято. Движок опыта
/// (`pathb` из консоли) живёт отведённые ему секунды и уходит. Второй не
/// должен быть погашен правкой списка, а первый — не должен остаться
/// забытым: открытая ручка WinDivert глотает пакеты.
struct EngineSlot {
    engine: Arc<crate::redirect::Engine>,
    from_policy: bool,
}

/// Сверка разбора родителя с независимым источником — снимком системы.
///
/// Смещение родителя в нагрузке события зависит от версии события, и
/// ошибка в нём дала бы не отказ, а правдоподобное чужое число. Проверять
/// это надо там же, где код работает в бою, а не в отдельном опыте;
/// поэтому первые события после запуска сверяются, результат пишется в
/// журнал, и дальше проверка выключается и ничего не стоит.
#[derive(Default)]
struct ParentCheck {
    matched: usize,
    mismatched: usize,
    done: bool,
}

/// Сколько событий сверить. Больше незачем: ошибка в смещении проявится на
/// первом же.
const PARENT_CHECKS: usize = 20;

/// Работающая служба. Пока объект жив, слежение за сетью и за процессами идёт.
pub struct Daemon {
    _watcher: Watcher,
    /// Нет, если сеанс ETW не удалось завести: в консоли без прав
    /// администратора это обычное дело, и служба работает дальше без
    /// пометки процессов.
    _processes: Option<ProcessWatcher>,
    shared: Arc<Shared>,
}

impl Daemon {
    pub fn log(&self, message: &str) {
        self.shared.store.log(message);
    }
}

/// Служба уходит — перехват должен уйти вместе с ней. В службе Windows
/// процесс всё равно завершается, и ручки закрылись бы сами, но в консоли
/// (`vpnsplit-svc run`) объект может быть выпущен и без выхода, а
/// оставленная открытой ручка WinDivert глотает пакеты.
impl Drop for Daemon {
    fn drop(&mut self) {
        // Кто под присмотром — записать до остановки движка: после
        // перезапуска службы родословную иначе не восстановить, её знает
        // только память. Движок опыта не записывается: его цель —
        // подстрока, а не правило.
        // Пишущий родословную при переменах дальше не пишет: последнее
        // слово — за этой записью.
        self.shared.leaving.store(true, std::sync::atomic::Ordering::Release);
        // Своё подключение опускается первым, пока перехват ещё стоит:
        // туннель пропал — движок выбрасывает пакеты выбранных приложений.
        // В обратном порядке они на эти секунды пошли бы домашним
        // интернетом.
        self.shared.vpn.shutdown();
        let _serial = self.shared.family_serial.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(engine) = self.shared.policy_engine() {
            let members = engine.export();
            match self.shared.store.save_family(&members) {
                Ok(()) => self.shared.store.log(&format!(
                    "путь B: записано процессов под присмотром: {} — следующий запуск службы \
                     вернёт тех из них, кто доживёт",
                    members.len()
                )),
                // Не записалось — после перезапуска окно скажет «не
                // ведётся»; молчать об этом здесь нельзя.
                Err(e) => self.shared.store.log(&format!(
                    "путь B: НЕ удалось записать, кто под присмотром ({e}); после перезапуска \
                     службы запущенное запускателями останется без присмотра"
                )),
            }
        }
        // Под замком решений о движке: правка списка, начатая до нас,
        // успеет положить свой движок — и он будет остановлен здесь же, а
        // начатые после увидят, что служба уходит (`refresh_engine`).
        let _engine = self.shared.engine_serial.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(engine) = self.shared.engine() {
            let stats = engine.stop();
            self.shared
                .store
                .log(&format!("путь B: выключен вместе со службой. {}", crate::redirect::describe(&stats)));
        }
        *self.shared.engine.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Паника в рабочем потоке службы не видна нигде: консоли нет, поток просто
/// исчезает, а клиент продолжает ждать ответа. Один такой случай в Этапе 11b
/// обошёлся часом поисков, поэтому паники теперь попадают в журнал.
fn log_panics(shared: Arc<Shared>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let place = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "место неизвестно".to_owned());
        shared.store.log(&format!("ПАНИКА в {place}: {info}"));
        previous(info);
    }));
}

pub fn start(store: Store) -> Result<Daemon, String> {
    // Канал создаётся первым: если он уже занят другим экземпляром службы,
    // об этом надо узнать сразу и ничего не писать в журнал.
    let server = Server::new()?;
    let first = server.create_instance()?;
    // До первого фильтра: каждое приложение перед ним сверяется с тем
    // файлом, который нашла Windows (см. `rights::vet`).
    wfp::vet_apps(crate::rights::vet);
    // Канал наш — значит, другой службы, которая могла бы писать в этот
    // каталог прямо сейчас, нет, и временные файлы в нём — остатки.
    store.sweep_leftovers();

    let policy = store.load();
    let tunnel = vpnsplit_net::detect_tunnel(None);
    store.log(&format!(
        "старт: данные в {}, правил {}, туннель {}",
        store.dir().display(),
        policy.rules.len(),
        describe(&tunnel)
    ));
    if store.diagnostics_open() {
        // Не по умолчанию и не молча: это ослабление, и в журнале оно
        // должно быть видно с первой строки.
        store.log(
            "ВНИМАНИЕ: проверки и опыты разрешены всем вошедшим пользователям \
             (в каталоге данных лежит diagnostics.allow)",
        );
    }

    let guard = match wfp::Guard::open() {
        Ok(guard) => Some(guard),
        Err(e) => {
            store.log(&format!("kill-switch: движок фильтрации недоступен — {e}"));
            None
        }
    };

    let learned = store.load_learned();
    // Программ, которых на диске больше нет, в списке «сами по себе»
    // держать незачем: удалённая программа никому не мешает, а строка о
    // ней в `status` только путает. Другой чистки у этого списка нет.
    let alone = {
        let mut alone = store.load_alone();
        let before = alone.len();
        alone.retain(|_, path| path.exists());
        if alone.len() != before {
            if let Err(e) = store.save_alone(&alone) {
                store.log(&format!("не удалось записать программы «сами по себе»: {e}"));
            }
            store.log(&format!(
                "программ «сами по себе» забыто: {} — их больше нет на диске",
                before - alone.len()
            ));
        }
        alone
    };
    let vpn = crate::vpn::Vpns::open(store.clone());
    let shared = Arc::new(Shared {
        vpn,
        vpn_seen: Mutex::new(Vec::new()),
        divert_error: Mutex::new(None),
        state: Mutex::new(State { policy, tunnel, processes: Table::default() }),
        subscribers: Mutex::new(Vec::new()),
        store,
        guard: Mutex::new(guard),
        parent_check: Mutex::new(ParentCheck::default()),
        image_check: Mutex::new(ParentCheck::default()),
        engine: Mutex::new(None),
        engine_serial: Mutex::new(()),
        family_unread: std::sync::atomic::AtomicBool::new(true),
        policy_serial: Mutex::new(()),
        learned_disk: Mutex::new(()),
        alone_disk: Mutex::new(()),
        learned: Mutex::new(learned),
        alone: Mutex::new(alone),
        standing: Mutex::new(Vec::new()),
        standing_serial: Mutex::new(()),
        system_root: std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows")),
        family_serial: Mutex::new(()),
        leaving: std::sync::atomic::AtomicBool::new(false),
    });

    log_panics(shared.clone());

    // Первым делом — разрешения «служба жива». Пока службы не было,
    // приложениям из списка сеть была закрыта постоянными запретами, и
    // каждая секунда до этого места — секунда, которую они ждут зря.
    Shared::refresh_standing(&shared, "старт");

    {
        let shared = shared.clone();
        std::thread::Builder::new()
            .name("pipe".into())
            .spawn(move || serve(server, first, shared))
            .map_err(|e| format!("не удалось запустить поток канала: {e}"))?;
    }

    let watcher = {
        let shared = shared.clone();
        Watcher::start(move || shared.refresh_tunnel())?
    };
    // Между первым определением и подпиской туннель мог смениться.
    shared.refresh_tunnel();

    let started = {
        let sink = shared.clone();
        ProcessWatcher::start(move |event| Shared::on_process(&sink, event))
    };
    let processes = match started {
        Ok(watcher) => Some(watcher),
        Err(e) => {
            // Не повод падать: всё остальное работает и без этого.
            shared.store.log(&format!("процессы: слежение не поднялось — {e}"));
            None
        }
    };
    // Приложения из списка могли запуститься до нас.
    shared.rescan("старт");
    // И туннеля могло не быть ещё до нашего запуска.
    shared.refresh_killswitch();
    // А путь B нужен ровно тогда, когда в списке есть его правила. Запись
    // о тех, кто был под присмотром до остановки, забирает себе тот, кто
    // создаёт движок (см. `family_unread`); не создал никто — она всё
    // равно читается и удаляется здесь: она верна для одного запуска,
    // следующего за остановкой, и лежать до лучших времён ей незачем.
    Shared::refresh_engine(&shared, "старт");
    {
        let _serial = shared.engine_serial.lock().unwrap_or_else(|e| e.into_inner());
        if shared.family_unread.swap(false, std::sync::atomic::Ordering::AcqRel) {
            let _ = shared.store.take_family();
        }
    }
    // Запреты на время простоя могли остаться на программах, которые
    // работают и сами по себе: пока службы не было, заметить это было
    // некому. Сейчас, когда родословная восстановлена, это видно.
    Shared::review_learned(&shared);
    // Родословная пишется на диск при каждой перемене: после падения
    // службы взять её больше неоткуда.
    {
        let weak = Arc::downgrade(&shared);
        if let Err(e) = std::thread::Builder::new().name("family".into()).spawn(move || keep_family(weak)) {
            shared.store.log(&format!(
                "путь B: поток записи родословной не завёлся ({e}); она запишется только при \
                 штатной остановке"
            ));
        }
    }
    // Своё подключение — последним: перехват уже стоит, и когда туннель
    // поднимется, вести в него есть кому. Слушатель держит службу слабой
    // ссылкой по той же причине, что и у движка.
    {
        let weak = Arc::downgrade(&shared);
        shared.vpn.listen(Box::new(move || {
            if let Some(shared) = weak.upgrade() {
                // Сначала дорожки, потом событие: пока окно рисует
                // «подключено», вести туда уже должно быть кому.
                shared.refresh_lanes();
                shared.announce_vpns();
            }
        }));
    }
    let policy = shared.state.lock().unwrap_or_else(|e| e.into_inner()).policy.clone();
    shared.vpn.start(&policy);
    // Обновления — самыми последними: всё остальное уже работает, и новый
    // выпуск, если он есть, застанет службу в порядке.
    crate::update::start(shared.store.clone());

    Ok(Daemon { _watcher: watcher, _processes: processes, shared })
}

fn describe(tunnel: &TunnelState) -> String {
    tunnel.describe()
}

impl Shared {
    /// Вызывается Windows при любом изменении сети. Событие рассылается,
    /// только если туннель действительно изменился: изменения других
    /// интерфейсов приходят сюда же, и шуметь из-за них незачем.
    fn refresh_tunnel(&self) {
        // Путь B узнаёт о сети раньше всего остального и при **любом**
        // изменении, а не только когда изменился туннель: домашний адрес
        // тоже может смениться (другая сеть Wi-Fi, другой кабель), а
        // переписывать пакеты с прежним адресом источника — значит молча
        // перестать переписывать вообще.
        // Вместе с вестью идут дорожки: у поднявшегося подключения
        // появились адрес и то, что назначил ему сервер.
        self.refresh_lanes();
        // Своим подключениям перемена сети тоже новость: чужой туннель мог
        // уйти — тогда пора поднимать свои.
        self.vpn.poke();
        // «Подключаюсь» и «подключено» различаются только адресом туннеля,
        // и сказать о нём надо, даже если главный туннель остался тем же.
        self.announce_vpns();
        let fresh = vpnsplit_net::detect_tunnel(None);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.tunnel == fresh {
            return;
        }
        self.store.log(&format!("туннель: {} → {}", describe(&state.tunnel), describe(&fresh)));
        state.tunnel = fresh.clone();
        drop(state);
        // Сначала фильтры, потом событие: пока подписчик рисует «туннеля
        // нет», утечка уже должна быть закрыта.
        self.refresh_killswitch();
        self.broadcast(Event::TunnelChanged(fresh));
    }

    /// Дорожки перехвату: какое правило в какое подключение вести. Для
    /// перехвата это заодно и весть о смене сети — адреса туннелей он
    /// пересчитывает там же.
    fn refresh_lanes(&self) {
        let Some(engine) = self.engine() else { return };
        let policy = self.state.lock().unwrap_or_else(|e| e.into_inner()).policy.clone();
        engine.set_lanes(self.vpn.specs(&policy));
    }

    /// Рассылает состояние своих подключений, если оно изменилось.
    fn announce_vpns(&self) {
        let states = self.vpn.states();
        {
            let mut seen = self.vpn_seen.lock().unwrap_or_else(|e| e.into_inner());
            if *seen == states {
                return;
            }
            *seen = states.clone();
        }
        self.broadcast(Event::VpnChanged(states));
    }

    /// Пока туннеля нет, приложениям из списка закрыта сеть — кроме
    /// локальной. Когда туннель возвращается, запреты снимаются.
    ///
    /// Это страховка от того, чего хук не видит: приложение из списка,
    /// запущенное мимо лончера, хуков не имеет вовсе и без фильтра
    /// спокойно пойдёт через домашний интернет.
    ///
    /// Замок фильтров берётся **первым**, и состояние читается уже под ним
    /// (порядок `guard` → `state`; обратного нигде нет). Иначе вызов,
    /// прочитавший «туннеля нет» и вытесненный, мог взять замок после того,
    /// кто уже увидел туннель поднятым и снял запреты, — и поставить их при
    /// живом туннеле.
    ///
    /// Запреты приводятся к нужным разностью: сначала ставятся недостающие,
    /// потом снимаются лишние, а стоящие не трогаются. Снять всё и поставить
    /// заново значило бы на время пересоздания оставить приложения из
    /// списка при упавшем туннеле без запрета.
    fn refresh_killswitch(&self) {
        let mut guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        let Some(guard) = guard.as_mut() else {
            return;
        };
        let (down, apps) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let apps: Vec<std::path::PathBuf> = state
                .policy
                .rules
                .iter()
                // Как и у запретов на время простоя: правило «напрямую»
                // просили пускать мимо туннеля, и без туннеля оно сеть не
                // теряет.
                .filter(|rule| rule.routing == vpnsplit_core::Routing::Tunnel)
                .filter_map(|rule| match &rule.target {
                    vpnsplit_core::AppTarget::Executable(path) => Some(path.clone()),
                    vpnsplit_core::AppTarget::Package(_) => None,
                })
                .collect();
            (matches!(state.tunnel, TunnelState::Down), apps)
        };

        if !down {
            let had = guard.blocked();
            guard.clear();
            if had > 0 {
                // Это и возвращение туннеля, и конец проверки — оба случая
                // приходят сюда, и называть причину мы не вправе.
                self.store.log("kill-switch: запреты сняты, туннель поднят");
            }
            return;
        }
        let mut failed = 0;
        for app in &apps {
            if let Err(e) = guard.block(app) {
                failed += 1;
                self.store.log(&format!("kill-switch: {} — {e}", app.display()));
            }
        }
        // Лишние — после: убранные из списка и проверочный запрет.
        guard.unblock_except(&apps);
        if !apps.is_empty() {
            self.store.log(&format!(
                "kill-switch: туннеля нет, приложений под запретом {} из {}",
                apps.len() - failed,
                apps.len()
            ));
        }
    }

    /// Кому закрывать сеть на время простоя службы: цели правил «в VPN» и
    /// программы, виденные под правилами пути B. Заодно забывает
    /// программы тех правил, которых в списке больше нет.
    fn standing_apps(&self) -> Vec<std::path::PathBuf> {
        let (mut apps, rules) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let apps: Vec<std::path::PathBuf> = state
                .policy
                .rules
                .iter()
                .filter(|rule| rule.routing == vpnsplit_core::Routing::Tunnel)
                .filter_map(|rule| match &rule.target {
                    vpnsplit_core::AppTarget::Executable(path) => Some(path.clone()),
                    // Пакеты Store опознаются не по пути; запрета на время
                    // простоя у них пока нет.
                    vpnsplit_core::AppTarget::Package(_) => None,
                })
                .collect();
            let rules: Vec<String> =
                state.policy.divert_targets().iter().map(|target| target.key()).collect();
            (apps, rules)
        };
        let forgot = {
            let mut learned = self.learned.lock().unwrap_or_else(|e| e.into_inner());
            let before = learned.len();
            learned.retain(|rule, _| rules.contains(rule));
            apps.extend(learned.values().flat_map(|images| images.values().cloned()));
            learned.len() != before
        };
        if forgot {
            self.persist_learned();
        }
        // Одна программа может прийти и как цель правила, и как виденная.
        let mut seen = std::collections::HashSet::new();
        apps.retain(|app| seen.insert(app.to_string_lossy().to_lowercase()));
        apps
    }

    /// Записывает виденные программы на диск — нынешние, снятые уже под
    /// замком записи. Две записи подряд из разных потоков поэтому не могут
    /// лечь в обратном порядке: какая бы ни была последней, она пишет
    /// самое свежее. Звать без замка `learned`.
    fn persist_learned(&self) {
        let _disk = self.learned_disk.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = self.learned.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Err(e) = self.store.save_learned(&snapshot) {
            self.store.log(&format!("не удалось записать виденные программы: {e}"));
        }
    }

    /// То же для программ «сами по себе». Звать без замка `alone`.
    fn persist_alone(&self) {
        let _disk = self.alone_disk.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = self.alone.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Err(e) = self.store.save_alone(&snapshot) {
            self.store.log(&format!("не удалось записать программы «сами по себе»: {e}"));
        }
    }

    /// Приводит запреты на время простоя в согласие со списком.
    ///
    /// Устройство — в `vpnsplit_net::wfp`: на каждом приложении стоит
    /// постоянный запрет, а работающая служба кладёт поверх динамическое
    /// разрешение. Порядок шагов здесь существен. **Сначала разрешение,
    /// потом запрет:** наоборот у работающего приложения на миг остался бы
    /// один запрет, и Windows оборвала бы его соединения. **И запрет только
    /// тем, кому разрешение удалось поставить:** приложение, закрытое при
    /// живой службе, — это поломка, а не защита.
    fn refresh_standing(shared: &Arc<Shared>, why: &str) {
        let _serial = shared.standing_serial.lock().unwrap_or_else(|e| e.into_inner());
        // Служба уходит — запреты больше не пересматриваются. Её могут
        // удалять: `uninstall` снимает запреты после остановки, и
        // поставленный сейчас запрет пережил бы службу, которая его уже
        // никогда не снимет.
        if shared.leaving.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let apps = shared.standing_apps();
        let mut permitted = Vec::new();
        {
            let mut guard = shared.guard.lock().unwrap_or_else(|e| e.into_inner());
            // Движка нет — мы без прав администратора (консольный режим).
            // Ни разрешений, ни запретов поставить нельзя, и молчать об
            // этом каждый раз незачем: о движке уже сказано при старте.
            let Some(guard) = guard.as_mut() else { return };
            for app in &apps {
                match guard.permit_alive(app) {
                    Ok(_) => permitted.push(app.clone()),
                    Err(e) => shared.store.log(&format!(
                        "запреты на время простоя: {} пропущен — {e}",
                        app.display()
                    )),
                }
            }
        }

        let outcome = wfp::Standing::open().and_then(|standing| standing.sync(&permitted));
        // У убранных из списка разрешение снимается только **после** того,
        // как с них снят постоянный запрет: в обратном порядке у работающего
        // приложения на миг остался бы один запрет, и Windows оборвала бы
        // его соединения. А если запреты обновить не удалось, разрешения
        // остаются как были: иначе приложение, которого в списке уже нет,
        // осталось бы при живой службе без сети.
        if outcome.is_ok() {
            let mut guard = shared.guard.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(guard) = guard.as_mut() {
                guard.revoke_alive_except(&permitted);
            }
        }
        match outcome {
            Ok(change) => {
                let failed: Vec<&std::path::PathBuf> = change.failed.iter().map(|(app, _)| app).collect();
                let standing: Vec<std::path::PathBuf> =
                    permitted.iter().filter(|app| !failed.contains(app)).cloned().collect();
                let total = standing.len();
                *shared.standing.lock().unwrap_or_else(|e| e.into_inner()) = standing;
                for (app, reason) in &change.failed {
                    shared.store.log(&format!(
                        "запреты на время простоя: {} НЕ закрыт — {reason}",
                        app.display()
                    ));
                }
                if !change.added.is_empty() || !change.removed.is_empty() || why == "старт" {
                    let names = |apps: &[std::path::PathBuf]| {
                        apps.iter()
                            .map(|app| app.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    shared.store.log(&format!(
                        "запреты на время простоя ({why}): приложений под запретом {total}; \
                         добавлено {}{}; снято {}{}. Пока служба работает, запреты перекрыты \
                         её разрешениями; не станет службы — этим приложениям останется только \
                         локальная сеть",
                        change.added.len(),
                        if change.added.is_empty() { String::new() } else { format!(" ({})", names(&change.added)) },
                        change.removed.len(),
                        if change.removed.is_empty() { String::new() } else { format!(" ({})", change.removed.join(", ")) },
                    ));
                }
            }
            Err(e) => shared.store.log(&format!(
                "запреты на время простоя ({why}): НЕ обновлены — {e}. Что стояло, то и стоит"
            )),
        }
    }

    /// Под правилом пути B замечена программа. Если она новая и не из
    /// каталога Windows — запомнить и закрыть ей сеть на время простоя.
    ///
    /// Зовётся из потоков движка, иногда с пакетом в руках, поэтому сама
    /// работа с фильтрами и запись на диск уходят в отдельный поток. Новая программа под
    /// правилом — редкость: у браузера их две-три за всю жизнь правила.
    ///
    /// `alone_now` — эта же программа прямо сейчас работает и вне правил.
    /// Такую не запоминаем, а записываем в «сами по себе»; туда же она
    /// попадает, если её когда-то уже видели запущенной отдельно.
    fn learn(shared: &Arc<Shared>, rule: &str, image: &std::path::Path, alone_now: bool) {
        if !crate::store::worth_remembering(image, &shared.system_root) {
            return;
        }
        let key = image.to_string_lossy().to_lowercase();
        if shared.alone.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&key) {
            return;
        }
        if alone_now {
            Shared::set_free(shared, image, "замечена под правилом, но работает и вне его");
            return;
        }
        {
            let mut learned = shared.learned.lock().unwrap_or_else(|e| e.into_inner());
            let images = learned.entry(rule.to_owned()).or_default();
            let key = image.to_string_lossy().to_lowercase();
            if images.contains_key(&key) {
                return;
            }
            images.insert(key, image.to_owned());
        }
        shared.store.log(&format!(
            "под правилом {rule} замечена программа {} — на время простоя службы сеть ей \
             будет закрыта",
            image.display()
        ));
        // И запись на диск — в том же потоке, что и пересмотр: она ждёт
        // сброса файла на диск, а держать столько пакет нельзя.
        let worker = shared.clone();
        let spawned = std::thread::Builder::new().name("standing".into()).spawn(move || {
            worker.persist_learned();
            Shared::refresh_standing(&worker, "новая программа под правилом");
        });
        if let Err(e) = spawned {
            // Запрет встанет при следующем пересмотре — при правке списка
            // или старте службы; программа записывается здесь же.
            eprintln!("не удалось завести поток запретов: {e}");
            shared.persist_learned();
        }
    }

    /// Программа работает и сама по себе: записать это и снять с неё
    /// запрет на время простоя, если он стоял.
    ///
    /// Цена названа пользователю до решения и остаётся в силе: с этого
    /// места программа на время простоя службы ходит домашним интернетом,
    /// даже когда её запустило приложение из списка. Для `git` это и нужно.
    /// Для браузера, открытого не тем значком, что в правиле, — следствие,
    /// с которым согласились: раз он запускается и мимо правила, запрет на
    /// образ всё равно закрывал бы не только «свой» запуск.
    fn set_free(shared: &Arc<Shared>, image: &std::path::Path, why: &str) {
        let key = image.to_string_lossy().to_lowercase();
        let fresh = {
            let mut alone = shared.alone.lock().unwrap_or_else(|e| e.into_inner());
            if alone.contains_key(&key) {
                false
            } else {
                alone.insert(key.clone(), image.to_owned());
                true
            }
        };
        if !fresh {
            return;
        }
        let forgotten = {
            let mut learned = shared.learned.lock().unwrap_or_else(|e| e.into_inner());
            let mut removed = false;
            for images in learned.values_mut() {
                removed |= images.remove(&key).is_some();
            }
            removed
        };
        shared.store.log(&format!(
            "программа {} {why} — сеть на время простоя службы ей не закрывается{}",
            image.display(),
            if forgotten { "; запрет снимается" } else { "" }
        ));
        // Запись на диск и пересмотр запретов — в своём потоке, как и в
        // `learn`: сюда приходят и из потоков движка, и из потока ETW, а
        // запись ждёт сброса файла на диск.
        let worker = shared.clone();
        let spawned = std::thread::Builder::new().name("standing".into()).spawn(move || {
            worker.persist_alone();
            if forgotten {
                worker.persist_learned();
                Shared::refresh_standing(&worker, "программа работает и сама по себе");
            }
        });
        if let Err(e) = spawned {
            eprintln!("не удалось завести поток запретов: {e}");
            shared.persist_alone();
            if forgotten {
                shared.persist_learned();
            }
        }
    }

    /// Процесс запущен и под присмотр не принят. Если это программа, которую
    /// мы запомнили под правилом, — значит, она работает и сама по себе.
    ///
    /// Зовётся на каждый запуск процесса в системе, поэтому сначала самое
    /// дешёвое: есть ли вообще что проверять. Путь берётся из события, а
    /// не у процесса: `git status` живёт десятки миллисекунд и к этому
    /// времени уже завершился.
    fn notice_alone(shared: &Arc<Shared>, pid: u32, event_image: Option<&str>) {
        if shared.learned.lock().unwrap_or_else(|e| e.into_inner()).values().all(|i| i.is_empty()) {
            return;
        }
        let Some(image) = event_image
            .and_then(vpnsplit_net::devpath::to_dos)
            .or_else(|| vpnsplit_net::proc::image_path(pid))
        else {
            return;
        };
        let key = image.to_string_lossy().to_lowercase();
        // Программа пакета Store под присмотр берётся по имени пакета, а его
        // у завершившегося процесса уже не спросить: «не принят» здесь может
        // значить всего лишь «не успели узнать». Отдельно от своего пакета
        // такая программа не запускается, так что и терять нечего.
        if key.contains("\\windowsapps\\") {
            return;
        }
        let ours = shared
            .learned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|images| images.contains_key(&key));
        if ours {
            Shared::set_free(shared, &image, "запущена сама по себе, вне правил");
        }
    }

    /// Пересмотр запомненных программ при старте службы: кто из них прямо
    /// сейчас работает вне правил.
    fn review_learned(shared: &Arc<Shared>) {
        let Some(engine) = shared.policy_engine() else { return };
        let images: Vec<std::path::PathBuf> = shared
            .learned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .flat_map(|images| images.values().cloned())
            .collect();
        for image in images {
            if engine.runs_alone(&image) {
                Shared::set_free(shared, &image, "работает вне правил на момент старта службы");
            }
        }
    }

    /// Поставить запрет на несколько секунд, чтобы его можно было увидеть
    /// своими глазами при живом туннеле. Снимается не по таймеру, а
    /// обычным пересмотром состояния — тем же, что снимает запреты, когда
    /// туннель возвращается.
    fn check_killswitch(shared: &Arc<Shared>, app: &std::path::Path) -> Result<(), String> {
        {
            let mut guard = shared.guard.lock().unwrap_or_else(|e| e.into_inner());
            let Some(guard) = guard.as_mut() else {
                return Err("движок фильтрации недоступен: нужны права администратора".to_owned());
            };
            guard.block(app)?;
        }
        shared.store.log(&format!("kill-switch: проверка на {}", app.display()));

        let shared = shared.clone();
        std::thread::Builder::new()
            .name("killswitch-check".into())
            .spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(CHECK_SECONDS));
                shared.refresh_killswitch();
                shared.store.log("kill-switch: проверка закончена");
            })
            .map_err(|e| format!("не удалось завести поток проверки: {e}"))?;
        Ok(())
    }

    fn killswitch_on(&self) -> bool {
        let guard = self.guard.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().is_some_and(|guard| guard.blocked() > 0)
    }

    fn broadcast(&self, event: Event) {
        let mut subscribers = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        // Отправка в канал отписавшегося клиента не удаётся — он и выпадает.
        // Так же выпадает и тот, кто подписался, но не читает: его очередь
        // полна, и копить для него события дальше значило бы растить
        // память службы без предела. Его поток, скорее всего, завис на
        // записи в канал (буфер канала полон): запись прерывается сторожем,
        // иначе поток и место его пользователя висели бы, пока клиент жив.
        subscribers.retain(|(tx, remote)| match tx.try_send(event.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                remote.doom();
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        });
    }

    fn status(&self) -> Status {
        // Замок kill-switch берётся первым и отпускается до замка
        // состояния. Вложенно они берутся только в `refresh_killswitch`, и
        // там порядок тот же: сначала фильтры, потом состояние.
        let killswitch = self.killswitch_on();
        // Так же и путь B: замок его ячейки берётся до замка состояния.
        let engine = self.policy_engine();
        let divert = self.engine().map(|engine| engine.summary());
        let live = engine.as_ref().map(|engine| engine.live_rules()).unwrap_or_default();
        let counted = engine.map(|engine| engine.rule_traffic()).unwrap_or_default();
        let supervised = self.supervised_among(&live);
        let standing = self.standing.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let vpns = self.vpn.states();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Счётчики движок ведёт по именам правил, а показывать надо цели.
        // Правила, которого в списке уже нет, в ответе нет: спрашивают о
        // нынешнем списке.
        let traffic = state
            .policy
            .divert_targets()
            .into_iter()
            .filter_map(|target| {
                let key = target.key();
                let (_, seen, processes) = counted.iter().find(|(rule, _, _)| *rule == key)?;
                Some(vpnsplit_core::RuleTraffic {
                    target,
                    processes: *processes,
                    connects: seen.connects,
                    led: seen.led,
                    past: seen.past,
                    before: seen.before,
                    v6: seen.v6,
                    local: seen.local,
                    udp: seen.udp,
                })
            })
            .collect();
        let mut status = Status {
            standing,
            alone: self.alone.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect(),
            traffic,
            tunnel: state.tunnel.clone(),
            rules: state.policy.rules.len(),
            attached_processes: state.processes.attached(),
            divert_active: divert.is_some(),
            divert,
            supervised,
            killswitch,
            vpns,
            build: vpnsplit_core::BUILD,
            divert_error: self.divert_error.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        };
        drop(state);
        // DNS подключения — для лончера: он передаст его hook.dll. В
        // `state.tunnel` его нет намеренно: туннель сравнивается при каждой
        // перемене сети, а журнал OpenVPN читается с диска, и делать это
        // стоит только по вопросу и без замка состояния.
        if let TunnelState::Up(info) = &mut status.tunnel {
            info.dns = self.vpn.dns_of(&info.name);
        }
        status
    }

    /// Правила списка, под которыми сейчас кто-то есть: движок называет их
    /// своими именами, а окну нужны сами цели.
    fn supervised_among(&self, live: &[String]) -> Vec<vpnsplit_core::AppTarget> {
        if live.is_empty() {
            return Vec::new();
        }
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state
            .policy
            .divert_targets()
            .into_iter()
            .filter(|target| live.contains(&target.key()))
            .collect()
    }

    /// Движок, поднятый по списку. Движок опыта сюда не годится: его
    /// «правило» — подстрока, и к целям списка она отношения не имеет.
    fn policy_engine(&self) -> Option<Arc<crate::redirect::Engine>> {
        self.engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|slot| slot.from_policy)
            .map(|slot| slot.engine.clone())
    }

    /// Вызывается из потока ETW на каждый старт и каждое завершение процесса
    /// в системе. Поэтому здесь нельзя ничего ждать: всё, что долго, уходит
    /// в отдельный поток, и только для процессов из списка.
    fn on_process(shared: &Arc<Shared>, event: ProcessEvent) {
        match event {
            ProcessEvent::Started { pid, parent, image } => {
                // Путь B узнаёт о запуске раньше всего остального: именно
                // здесь решается, попадёт ли процесс в родословную, и
                // этого решения может ждать соединение, которое держат в
                // руках. Самопроверки — после: каждая стоит снимка системы.
                if let Some(engine) = shared.engine() {
                    if !engine.on_process_started(pid, parent, image.as_deref()) {
                        Shared::notice_alone(shared, pid, image.as_deref());
                    }
                }
                Shared::verify_parent(shared, pid, parent);
                Shared::verify_image(shared, pid, image.as_deref());
                Shared::process_started(shared, pid)
            }
            ProcessEvent::Stopped(pid) => {
                if let Some(engine) = shared.engine() {
                    engine.on_process_stopped(pid);
                }
                shared.process_stopped(pid)
            }
        }
    }

    fn engine(&self) -> Option<Arc<crate::redirect::Engine>> {
        self.engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|slot| slot.engine.clone())
    }

    /// Приводит путь B в согласие со списком: есть правила «приложение и
    /// все его потомки» — движок работает, не осталось ни одного — гаснет.
    ///
    /// Вызывается при старте службы и после каждой правки списка. Движок
    /// не поднимается и не гасится сам по себе: решает это список, и
    /// только он.
    ///
    /// Создающий движок вызов первым после старта восстанавливает в нём
    /// тех, кто был под присмотром до остановки службы (`family_unread`),
    /// — кто бы это ни был: стартовый вызов или успевший раньше SetPolicy.
    /// Без этого перезапуск службы оставлял без присмотра всё, что запущено
    /// запускателем из списка.
    ///
    /// Всё решение — под `engine_serial`, от взгляда в ячейку до того, как
    /// движок в ней лёг или из неё ушёл и остановился: иначе два вызова
    /// разом оба видели пустую ячейку и поднимали по движку. Список
    /// читается уже под ним — решает самый свежий.
    fn refresh_engine(shared: &Arc<Shared>, why: &str) {
        let _serial = shared.engine_serial.lock().unwrap_or_else(|e| e.into_inner());
        // Служба уходит: движок, поднятый сейчас, остановить было бы уже
        // некому.
        if shared.leaving.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let (targets, mode) = {
            let state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            (state.policy.divert_targets(), state.policy.mode)
        };
        if mode != vpnsplit_core::Mode::OnlySelected && !targets.is_empty() {
            // Молчать здесь нельзя: пользователь считал бы, что защита
            // стоит, а она стоит не на то.
            shared.store.log(
                "путь B: режим «всё, кроме выбранных» не поддерживается — \
                 правила применены как «только выбранные»",
            );
        }

        // Движок опыта трогать нельзя: он живёт отведённые ему секунды, и
        // правка списка его не касается.
        let experiment = {
            let slot = shared.engine.lock().unwrap_or_else(|e| e.into_inner());
            slot.as_ref().is_some_and(|slot| !slot.from_policy)
        };
        if experiment {
            if !targets.is_empty() {
                shared
                    .store
                    .log(&format!("{why}: путь B занят опытом; правила подхватятся после него"));
            }
            return;
        }

        if targets.is_empty() {
            // Забрать движок из ячейки и только потом останавливать:
            // остановка ждёт рабочие потоки, а они на каждый запуск
            // процесса спрашивают ячейку.
            let gone = shared.engine.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(slot) = gone {
                let stats = slot.engine.stop();
                shared.store.log(&format!(
                    "{why}: правил пути B не осталось, перехват выключен. {}",
                    crate::redirect::describe(&stats)
                ));
            }
            return;
        }

        let watch = crate::redirect::Watch::Rules(targets);
        if let Some(engine) = shared.engine() {
            engine.retarget(watch);
            return;
        }

        // Слушатель держит службу слабой ссылкой: движок лежит в самой
        // службе, и сильная замкнула бы их друг на друга навсегда.
        let listener: crate::redirect::Listener = {
            let weak = Arc::downgrade(shared);
            Box::new(move |rules: &[String]| {
                if let Some(shared) = weak.upgrade() {
                    let supervised = shared.supervised_among(rules);
                    shared.broadcast(Event::SupervisedChanged(supervised));
                }
            })
        };
        let learner: crate::redirect::Learner = {
            let weak = Arc::downgrade(shared);
            Box::new(move |rule: &str, image: &std::path::Path, alone_now: bool| {
                if let Some(shared) = weak.upgrade() {
                    Shared::learn(&shared, rule, image, alone_now);
                }
            })
        };
        let engine = crate::redirect::Engine::new(
            shared.store.clone(),
            watch,
            Some(listener),
            Some(learner),
        );
        // До начала перехвата: первое же соединение должно застать
        // родословную уже восстановленной. Под `engine_serial` — поэтому
        // запись достаётся ровно одному движку.
        if shared.family_unread.swap(false, std::sync::atomic::Ordering::AcqRel) {
            engine.restore(&shared.store.take_family());
        }
        // И дорожки — до начала: первое же соединение должно уйти в своё
        // подключение, а не в то, которое нашлось.
        {
            let policy = shared.state.lock().unwrap_or_else(|e| e.into_inner()).policy.clone();
            engine.set_lanes(shared.vpn.specs(&policy));
        }
        if let Err(e) = engine.start() {
            // Без прав администратора или без драйвера путь B не
            // поднимается. Это не повод падать, но и делать вид, что
            // приложения уведены, нельзя.
            shared
                .store
                .log(&format!("{why}: путь B НЕ поднялся — {e}. Приложения из списка идут мимо туннеля"));
            *shared.divert_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
            return;
        }
        *shared.divert_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *shared.engine.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(EngineSlot { engine, from_policy: true });
        shared.store.log(&format!("{why}: путь B поднят по списку"));
    }

    /// Опыт из консоли: включить путь B на заданное время по подстроке.
    /// В бою движком распоряжается список, а это нужно для замеров.
    fn path_b(shared: &Arc<Shared>, target: &str, seconds: u32) -> Result<String, String> {
        {
            // Проверка, сборка, запуск и установка — под `engine_serial`:
            // кроме нас, класть в ячейку может только `refresh_engine`, а
            // он берёт тот же замок, так что пустая ячейка пустой и
            // останется. Поэтому сам замок ячейки на время сборки и запуска
            // не держится: на нём висит обработчик запуска процессов.
            let _serial = shared.engine_serial.lock().unwrap_or_else(|e| e.into_inner());
            if shared.engine.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                return Err("путь B уже работает — по списку правил или другим опытом".to_owned());
            }
            let engine = crate::redirect::Engine::new(
                shared.store.clone(),
                crate::redirect::Watch::Needle(target.to_lowercase()),
                // Опыт окну не докладывает и запретов не заводит: его цель —
                // не правило из списка.
                None,
                None,
            );
            engine.start()?;
            *shared.engine.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(EngineSlot { engine, from_policy: false });
        }
        // Свои секунды опыт спит без замков: правки списка в это время
        // проходят (и откладывают путь B до конца опыта).
        std::thread::sleep(std::time::Duration::from_secs(seconds as u64));
        let line = {
            let _serial = shared.engine_serial.lock().unwrap_or_else(|e| e.into_inner());
            // Забрать из ячейки и только потом останавливать: остановка
            // ждёт рабочие потоки, а они спрашивают ячейку.
            // Движок списка опыт не трогает: остановить его значило бы снять
            // перехват по списку.
            let slot = {
                let mut cell = shared.engine.lock().unwrap_or_else(|e| e.into_inner());
                if cell.as_ref().is_some_and(|slot| !slot.from_policy) {
                    cell.take()
                } else {
                    None
                }
            };
            match slot {
                Some(slot) => crate::redirect::describe(&slot.engine.stop()),
                // Движок унесли из-под нас — такого быть не должно, но
                // придумывать итог нельзя.
                None => "итог неизвестен: движок остановлен не нами".to_owned(),
            }
        };
        shared.store.log(&format!("путь B: опыт закончен. {line}"));
        // Список мог измениться, пока шёл опыт.
        Shared::refresh_engine(shared, "после опыта");
        Ok(line)
    }

    /// Сверяет разобранного родителя со снимком системы — и только на
    /// первых событиях после запуска.
    ///
    /// Снимок для этого не годится как источник в бою (номера процессов
    /// переиспользуются), но как независимый свидетель на один раз — вполне.
    /// Несовпадение означает, что смещение в нагрузке прочитано неверно, и
    /// тогда родословная строилась бы по чужим числам.
    fn verify_parent(shared: &Arc<Shared>, pid: u32, parent: u32) {
        if shared.parent_check.lock().unwrap_or_else(|e| e.into_inner()).done {
            return;
        }
        let actual = vpnsplit_net::proc::parents()
            .into_iter()
            .find(|(candidate, _, _)| *candidate == pid)
            .map(|(_, parent, _)| parent);
        // Процесс уже умер — судить не о чем, это не ошибка разбора.
        let Some(actual) = actual else {
            return;
        };
        let mut check = shared.parent_check.lock().unwrap_or_else(|e| e.into_inner());
        if check.done {
            return;
        }
        if actual == parent {
            check.matched += 1;
        } else {
            check.mismatched += 1;
            if check.mismatched <= 3 {
                shared.store.log(&format!(
                    "родитель из события не сошёлся со снимком: процесс {pid}, \
                     в событии {parent}, в снимке {actual}"
                ));
            }
        }
        if check.matched + check.mismatched >= PARENT_CHECKS {
            check.done = true;
            shared.store.log(&format!(
                "разбор родителя в событиях ETW: сошлось {} из {}",
                check.matched,
                check.matched + check.mismatched
            ));
        }
    }

    /// Сверяет путь к образу из события с тем, что отвечает сам процесс, —
    /// на первых событиях после запуска, как и родителя.
    ///
    /// В бою путь из события нужен ровно тогда, когда процесс уже умер и
    /// свидетеля нет. Поэтому проверить его можно только заранее, на
    /// живых: если здесь сходится, запускателю из списка можно верить.
    fn verify_image(shared: &Arc<Shared>, pid: u32, image: Option<&str>) {
        if shared.image_check.lock().unwrap_or_else(|e| e.into_inner()).done {
            return;
        }
        // Процесс уже умер — судить не о чем.
        let Some(actual) = vpnsplit_net::proc::image_path(pid) else {
            return;
        };
        let translated = image.and_then(vpnsplit_net::devpath::to_dos);
        let same = translated.as_ref().is_some_and(|found| {
            found.to_string_lossy().to_lowercase() == actual.to_string_lossy().to_lowercase()
        });
        let mut check = shared.image_check.lock().unwrap_or_else(|e| e.into_inner());
        if check.done {
            return;
        }
        if same {
            check.matched += 1;
        } else {
            check.mismatched += 1;
            if check.mismatched <= 3 {
                shared.store.log(&format!(
                    "образ из события не сошёлся с ответом процесса {pid}: в событии {}, \
                     после перевода {}, сам процесс говорит {}",
                    image.unwrap_or("ничего"),
                    translated
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "ничего".to_owned()),
                    actual.display()
                ));
            }
        }
        if check.matched + check.mismatched >= PARENT_CHECKS {
            check.done = true;
            shared.store.log(&format!(
                "путь к образу в событиях ETW: сошлось {} из {}",
                check.matched,
                check.matched + check.mismatched
            ));
        }
    }

    fn process_started(shared: &Arc<Shared>, pid: u32) {
        // Путь к образу — единственное, что мы спрашиваем у каждого процесса
        // системы. Это одно открытие хэндла; всё остальное только для своих.
        let Some(image) = vpnsplit_net::proc::image_path(pid) else {
            return;
        };
        let target = {
            let state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            // Только правила пути A: у правил «приложение и все потомки»
            // хуков нет и быть не должно, и объявлять их «работающими мимо
            // туннеля» было бы ложной тревогой.
            match state.policy.hook_rule_for_image(&image) {
                Some(rule) => rule.target.clone(),
                None => return,
            }
        };

        // Время создания — сейчас, пока процесс точно жив: по нему потом
        // видно, тот ли это процесс или номер уже у другого.
        let created = vpnsplit_net::proc::created(pid);

        Shared::await_hooks(shared, pid, Running { target, image, hooked: false, created });
    }

    /// Ждёт в отдельном потоке «hooked?», встанут ли хуки в процессе, и
    /// записывает ответ. `hooked` в `running` не читается.
    fn await_hooks(shared: &Arc<Shared>, pid: u32, running: Running) {
        /// Снимает отметку «ждём» и при панике потока: иначе пересмотр
        /// списка больше никогда не заводил бы ожидание на этот номер.
        struct Waiting(Arc<Shared>, u32);
        impl Drop for Waiting {
            fn drop(&mut self) {
                self.0.state.lock().unwrap_or_else(|e| e.into_inner()).processes.wait_ends(self.1);
            }
        }
        shared.state.lock().unwrap_or_else(|e| e.into_inner()).processes.wait_begins(pid);
        let waiting = Waiting(shared.clone(), pid);
        // Поток не завёлся — замыкание со стражем уничтожается, и отметка
        // снимается его Drop.
        let _ = std::thread::Builder::new().name("hooked?".into()).spawn(move || {
            let Some(hooked) = procs::hooked(pid) else {
                return; // Процесс кончился, не дождавшись ответа.
            };
            waiting.0.remember(pid, Running { hooked, ..running });
        });
    }

    fn remember(&self, pid: u32, running: Running) {
        let event = if running.hooked {
            Event::ProcessAttached { pid, target: running.target.clone() }
        } else {
            Event::ProcessUnhooked { pid, image: running.image.clone() }
        };
        let name = running.target.display_name();
        let hooked = running.hooked;
        let created = running.created;
        let (replaced, upgraded) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            // Reused — номер у нового процесса, а о завершении прежнего
            // события не было. Hooked — «мимо туннеля» было сказано раньше,
            // чем закончился init: окно этот процесс уже знает, и
            // ProcessAttached ниже заменит у него запись.
            let change = procs::change(state.processes.get(pid), created, hooked);
            if change == procs::Change::Same {
                return;
            }
            state.processes.insert(pid, running);
            (change == procs::Change::Reused, change == procs::Change::Hooked)
        };
        // Процесс мог завершиться, пока ждали его хуков: событие о его
        // завершении тогда уже обработано, и запись осталась бы навсегда.
        // Проверка после записи, а не до: завершение, обработанное позже,
        // снимет запись само. Именно «работает», а не «открывается»:
        // вышедший процесс открывается, пока его ручку держит родитель, а
        // короткоживущего помощника родитель держит почти всегда.
        let running = vpnsplit_net::proc::running_since(pid);
        let alive = match created {
            Some(created) => running == Some(created),
            None => running.is_some(),
        };
        if !alive {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .processes
                .remove_if_created(pid, created);
            // Прежнюю запись окно уже видело — ему надо сказать, что её нет.
            if replaced || upgraded {
                self.broadcast(Event::ProcessGone { pid });
            }
            return;
        }
        // Объявляется под замком состояния и только если запись всё ещё та,
        // что внесена здесь. Обход и ожидание хуков могут запоминать один
        // процесс разом: решают и вносят они под замком, а объявляли бы
        // после него, и «мимо туннеля», ушедшее последним, перекрыло бы в
        // окне «через туннель», которое уже в таблице. Заменивший запись
        // объявит её сам, и позже. Замок подписчиков под замком состояния
        // брать можно: наоборот их не берёт никто.
        let announced = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let ours = state.processes.holds(pid, created, hooked);
            if ours {
                if replaced {
                    self.broadcast(Event::ProcessGone { pid });
                }
                self.broadcast(event);
            }
            ours
        };
        if !announced {
            return;
        }
        self.store.log(&format!(
            "процесс {name} ({pid}): {}",
            if hooked { "через туннель" } else { "МИМО туннеля — запущен не лончером" }
        ));
    }

    fn process_stopped(&self, pid: u32) {
        let gone = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.processes.remove(pid)
        };
        if let Some(running) = gone {
            self.store.log(&format!("процесс {} ({pid}) завершился", running.target.display_name()));
            self.broadcast(Event::ProcessGone { pid });
        }
    }

    /// Пересмотреть, что из списка работает прямо сейчас. Нужно при старте
    /// службы и после правки списка: приложение могло быть запущено раньше,
    /// чем попало в список, и тогда события о нём уже не придёт.
    fn rescan(self: &Arc<Self>, why: &str) {
        let (policy, tracked) = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            (state.policy.clone(), state.processes.tracked())
        };

        let procs::Scan { found, pending } = procs::scan(&policy);
        let alive: Vec<u32> = found.iter().chain(&pending).map(|(pid, _)| *pid).collect();
        // Опрос «жив ли процесс» идёт вне замка: это обращение к ядру,
        // и держать на нём общее состояние незачем.
        let dropped = procs::stale(&tracked, &alive, &policy, |pid| {
            vpnsplit_net::proc::image_path(pid).is_some()
        });
        if !dropped.is_empty() {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .processes
                .forget(&dropped);
            for pid in dropped {
                self.broadcast(Event::ProcessGone { pid });
            }
        }

        for (pid, running) in found {
            self.remember(pid, running);
        }
        // init hook.dll ещё идёт: ответ даст ожидание. Если процесс уже ждут
        // (поток из `process_started`) или о нём уже записано «через
        // туннель», второе ожидание ничего нового не скажет. А записанное
        // «мимо» могло быть ответом ожидания, истёкшего раньше, чем DLL
        // показалась в процессе: его ожидание ещё может исправить (`true` —
        // «Same» только при записи «через туннель»).
        for (pid, running) in pending {
            let known = {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                state.processes.waiting(pid)
                    || procs::change(state.processes.get(pid), running.created, true) == procs::Change::Same
            };
            if !known {
                Shared::await_hooks(self, pid, running);
            }
        }

        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.processes.attached() + state.processes.unhooked() > 0 {
            self.store.log(&format!(
                "{why}: из списка работает {} приложений, из них мимо туннеля {}",
                state.processes.attached() + state.processes.unhooked(),
                state.processes.unhooked()
            ));
        }
    }
}

/// Сколько соединений одного пользователя служба обслуживает одновременно.
/// Окно держит одну подписку и изредка спрашивает ещё; лончер и консоль —
/// по соединению на запрос. Предел — на пользователя, а не общий: иначе
/// любой вошедший пользователь, открыв и бросив соединения, отрезал бы от
/// службы окно и лончер всех остальных. Повышенные клиенты того же
/// пользователя считаются отдельно (см. `SeatKey`).
const PER_USER: usize = 16;

/// Всего опознанных соединений — запас от ошибки в счёте, а не рабочий
/// предел: пользователей на машине куда меньше, чем `MAX_CLIENTS / PER_USER`.
const MAX_CLIENTS: usize = 256;

/// Сколько соединений одновременно ждут первого запроса. Чьё соединение,
/// до первого запроса не узнать (Windows не даёт примерить личность
/// клиента, пока от него ничего не прочитано), поэтому квоты тут нет.
/// Вместо отказа новое соединение вытесняет самое старое из ждущих, причём
/// сперва из тех, от кого не пришло ни байта: наплыв молчащих соединений
/// вытесняет сам себя, а не клиента, который передаёт длинную политику.
///
/// Вытесненного не обрывают, а торопят (`Remote::hurry`): запрос, который
/// уже лежит в канале, он дочитает и обслужит, а ждать остального не
/// станет. Так не теряется свой клиент, чей поток просто не успел дойти до
/// чтения. Что остаётся: наплыв соединений, которые шлют по байту без
/// перевода строки, вытеснит и длинный запрос, если тот передаётся дольше,
/// чем наплыв обновляет очередь.
const MAX_WAITING: usize = 32;

/// Срок первого запроса. Свой клиент шлёт его сразу; самый длинный —
/// политика с конфигом VPN — это десятки килобайт по локальному каналу.
const FIRST_REQUEST: std::time::Duration = std::time::Duration::from_secs(5);

/// Сколько событий ждут подписчика, который не успевает их читать.
const SUBSCRIBER_QUEUE: usize = 256;

/// Как часто подписка без событий проверяет, не закрыл ли окно свой конец.
/// Без этого закрытое окно держало бы место своего пользователя до
/// следующего события, а на тихой машине его может не быть часами.
const SUBSCRIBER_PROBE: std::time::Duration = std::time::Duration::from_secs(20);

/// Чьё соединение для счёта мест: SID пользователя (`None` — не узнали) и
/// повышен ли клиент. Повышенные — отдельный запас: необычные программы
/// того же пользователя не займут место окна администратора.
type SeatKey = (Option<String>, bool);

/// Места клиентов канала. `R` — чем вытеснять ждущего (в службе —
/// `stall::Remote`; в тестах — что угодно).
struct Seats<R> {
    /// Ждущие первого запроса, старые впереди, и пришло ли от них хоть что-то.
    waiting: VecDeque<(u64, R, Arc<AtomicBool>)>,
    next: u64,
    users: HashMap<SeatKey, usize>,
    total: usize,
    /// О вытеснениях и отказах — одна строка на волну, а не на каждое:
    /// иначе тот же наплыв соединений раздувал бы журнал.
    crowded: bool,
    refusing: bool,
}

impl<R> Seats<R> {
    fn new() -> Self {
        Seats {
            waiting: VecDeque::new(),
            next: 0,
            users: HashMap::new(),
            total: 0,
            crowded: false,
            refusing: false,
        }
    }

    /// Новое соединение ждёт первого запроса: его номер и тот, кого оно
    /// вытеснило: самое старое из молчащих, а если молчащих нет — самое
    /// старое вообще.
    fn wait(&mut self, remote: R, heard: Arc<AtomicBool>) -> (u64, Option<R>) {
        let evicted = if self.waiting.len() >= MAX_WAITING {
            let at = self.waiting.iter().position(|(_, _, heard)| !heard.load(Ordering::Relaxed)).unwrap_or(0);
            self.waiting.remove(at).map(|(_, remote, _)| remote)
        } else {
            None
        };
        let id = self.next;
        self.next += 1;
        self.waiting.push_back((id, remote, heard));
        (id, evicted)
    }

    /// Ожидание кончилось: запрос пришёл, срок вышел или поток ушёл.
    fn served(&mut self, id: u64) {
        self.waiting.retain(|(waiting, _, _)| *waiting != id);
    }

    /// Занять место пользователя; `false` — его места кончились.
    fn take(&mut self, key: &SeatKey) -> bool {
        if self.users.get(key).copied().unwrap_or(0) >= PER_USER || self.total >= MAX_CLIENTS {
            return false;
        }
        *self.users.entry(key.clone()).or_insert(0) += 1;
        self.total += 1;
        true
    }

    fn leave(&mut self, key: &SeatKey) {
        if let Some(count) = self.users.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                self.users.remove(key);
            }
            self.total = self.total.saturating_sub(1);
        }
    }
}

type SharedSeats = Arc<Mutex<Seats<Remote>>>;

/// Соединение среди ждущих первого запроса; уходит оттуда вместе с этим.
struct Waiting(SharedSeats, u64);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).served(self.1);
    }
}

/// Занятое место пользователя; освобождается, когда поток клиента кончается.
struct Seat(SharedSeats, SeatKey);

impl Drop for Seat {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).leave(&self.1);
    }
}

fn serve(server: Server, first: Instance, shared: Arc<Shared>) {
    let mut next = Some(first);
    let seats: SharedSeats = Arc::new(Mutex::new(Seats::new()));
    loop {
        let waiting = next.take().map(Instance::wait);
        let connection = match waiting {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                shared.store.log(&format!("канал: {e}"));
                continue;
            }
            None => match server.accept() {
                Ok(c) => c,
                Err(e) => {
                    shared.store.log(&format!("канал: {e}"));
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }
            },
        };
        let shared = shared.clone();
        let seats = seats.clone();
        let _ = std::thread::Builder::new().name("client".into()).spawn(move || client(connection, shared, seats));
    }
}

/// Отказ «мест нет». Ответ ложится в пустой буфер канала (служба ещё ничего
/// не писала), и клиент, который не читает, поток не задержит.
fn refuse_busy(connection: &mut Connection) {
    let _ = connection.send(&Response::Error(
        "служба занята: открыто слишком много соединений. Попробуй ещё раз позже".to_owned(),
    ));
}

/// Поток одного клиента: первый запрос — в срок, место — из квоты его
/// пользователя, дальше обычный разговор.
fn client(mut connection: Connection, shared: Arc<Shared>, seats: SharedSeats) {
    let watch = match Watch::this_thread() {
        Ok(watch) => watch,
        Err(e) => {
            shared.store.log(&format!("канал: не удалось поставить сторожа на соединение: {e}"));
            refuse_busy(&mut connection);
            return;
        }
    };
    let heard = Arc::new(AtomicBool::new(false));
    let waiting = {
        let mut places = seats.lock().unwrap_or_else(|e| e.into_inner());
        let (id, evicted) = places.wait(watch.remote(), heard.clone());
        match evicted {
            Some(evicted) => {
                evicted.hurry();
                if !places.crowded {
                    places.crowded = true;
                    shared.store.log(&format!(
                        "канал: первого запроса ждут {MAX_WAITING} соединений, самые старые больше не ждут"
                    ));
                }
            }
            None => places.crowded = false,
        }
        Waiting(seats.clone(), id)
    };
    let first = watch.guard(Some(FIRST_REQUEST), || connection.receive_noting::<Request>(&heard));
    drop(waiting);
    // Соединение ушло из очереди ждущих, и торопить его больше некому.
    // Просьба, пришедшая уже после чтения запроса, не должна задеть
    // дальнейший разговор — подписку, например.
    watch.pardon();
    let first = match first {
        Ok(Some(request)) => request,
        Ok(None) => return,
        // Промолчал до срока или вытеснен: отвечать некому — ответ мог бы
        // застрять в записи.
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return,
        Err(e) => {
            let _ = connection.send(&Response::Error(format!("непонятный запрос: {e}")));
            return;
        }
    };

    let identity = connection.client();
    let key: SeatKey = (
        identity.as_ref().and_then(|client| client.sid.clone()),
        identity.as_ref().is_some_and(|client| client.elevated),
    );
    let seat = {
        let mut places = seats.lock().unwrap_or_else(|e| e.into_inner());
        if places.take(&key) {
            places.refusing = false;
            Some(Seat(seats.clone(), key))
        } else {
            if !places.refusing {
                places.refusing = true;
                shared.store.log(&format!(
                    "канал: у клиента {} {} открыто слишком много соединений, новые не принимаются, \
                     пока не закроются старые",
                    key.0.as_deref().unwrap_or("(не опознан)"),
                    if key.1 { "с повышенными правами" } else { "без повышения" },
                ));
            }
            None
        }
    };
    let Some(_seat) = seat else {
        refuse_busy(&mut connection);
        return;
    };
    handle(connection, shared, &watch, first);
}

fn handle(mut connection: Connection, shared: Arc<Shared>, watch: &Watch, first: Request) {
    let mut first = Some(first);
    loop {
        let request = match first.take() {
            Some(request) => request,
            None => match connection.receive::<Request>() {
                Ok(Some(request)) => request,
                Ok(None) => return,
                Err(e) => {
                    let _ = connection.send(&Response::Error(format!("непонятный запрос: {e}")));
                    return;
                }
            },
        };

        // Проверки и опыты перехватывают чужие пакеты или отрезают
        // приложения от сети. Принимаются они только от процесса с
        // повышенными правами — или если администратор сам разрешил их
        // всем, положив файл в защищённый каталог данных.
        if request.privileged() && !connection.client_elevated() && !shared.store.diagnostics_open() {
            let mut what = format!("{request:?}");
            what.truncate(what.char_indices().nth(60).map(|(at, _)| at).unwrap_or(what.len()));
            shared.store.log(&format!("отказано без прав администратора: {what}"));
            let refusal = Response::Error(
                "эта команда принимается только от администратора — запусти её из окна \
                 с повышенными правами"
                    .to_owned(),
            );
            if connection.send(&refusal).is_err() {
                return;
            }
            continue;
        }

        let response = match request {
            Request::GetStatus => Response::Status(shared.status()),
            Request::GetPolicy => {
                Response::Policy(shared.state.lock().unwrap_or_else(|e| e.into_inner()).policy.clone())
            }
            // Правка списка — целиком под `policy_serial`: от проверки и
            // записи на диск до последнего следствия. Две правки разом иначе
            // могли оставить на диске одну политику, а в памяти и в
            // перехвате другую.
            Request::SetPolicy(policy) => {
                let _serial = shared.policy_serial.lock().unwrap_or_else(|e| e.into_inner());
                match admit_policy(&connection, &shared, &policy).and_then(|()| {
                    shared.store.save(&policy).map_err(|e| format!("не удалось сохранить политику: {e}"))
                }) {
                    Ok(()) => {
                        shared.store.log(&format!("политика обновлена: правил {}", policy.rules.len()));
                        shared.state.lock().unwrap_or_else(|e| e.into_inner()).policy = policy.clone();
                        // Приложение могли добавить в список уже запущенным —
                        // события о его старте не будет, а знать о нём надо.
                        shared.rescan("список изменён");
                        // И запреты должны знать о новом списке: добавили
                        // приложение при упавшем туннеле — запрет на него.
                        shared.refresh_killswitch();
                        // Запреты на время простоя службы — тоже по списку:
                        // новому приложению поставить, убранному снять.
                        Shared::refresh_standing(&shared, "список изменён");
                        // А путь B поднимается и гаснет ровно по этому списку.
                        Shared::refresh_engine(&shared, "список изменён");
                        // Свои подключения держатся, пока есть для кого, — и
                        // перехват должен знать, кого в какое вести.
                        shared.vpn.set_policy(&policy);
                        shared.refresh_lanes();
                        // Событие — последним. Подписчик по нему спрашивает
                        // состояние, и если разослать раньше, он увидит перехват,
                        // который ещё не поднялся: окно так и показывало
                        // «перехват не поднят» при работающем перехвате.
                        shared.broadcast(Event::PolicyChanged(policy));
                        Response::Ok
                    }
                    Err(e) => Response::Error(e),
                }
            }
            Request::Subscribe => {
                subscribe(connection, &shared, watch);
                return;
            }
            // Текст конфига дальше этой строки не идёт: ни в журнал, ни в
            // ответ. Что из него принято, запишет само подключение.
            Request::SetVpnConfig { name, config, key_password, login } => match shared.vpn.set_config(
                name.as_deref(),
                &config.0,
                crate::vpn::Secrets {
                    key_password: key_password.as_ref().map(|password| password.0.as_str()),
                    login: login
                        .as_ref()
                        .map(|login| (login.user.0.as_str(), login.password.0.as_str())),
                },
            ) {
                Ok(()) => Response::Ok,
                Err(e) => {
                    shared.store.log(&format!("своё подключение: конфиг не принят — {e}"));
                    Response::Error(e)
                }
            },
            Request::ClearVpnConfig { name } => match shared.vpn.clear_config(name.as_deref()) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e),
            },
            Request::VpnAction { name, action } => match shared.vpn.act(&name, action) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e),
            },
            Request::CheckUpdate => {
                if crate::update::check_now() {
                    Response::Ok
                } else {
                    Response::Error(
                        "эта копия обновлений не ищет: она не установлена установщиком или \
                         собрана для разработки"
                            .to_owned(),
                    )
                }
            }
            // Логин и пароль дальше этой строки не идут.
            Request::SetVpnLogin { name, login } => {
                match shared.vpn.set_login(&name, &login.user.0, &login.password.0) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            // Код дальше этой строки не идёт — ни в журнал, ни в ответ.
            Request::ConnectVpn { name, code } => match shared.vpn.connect(&name, &code.0) {
                Ok(()) => {
                    shared.store.log(&format!("подключение «{name}»: получен одноразовый код"));
                    Response::Ok
                }
                Err(e) => Response::Error(e),
            },
            Request::CheckKillswitch(app) => match Shared::check_killswitch(&shared, &app) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e),
            },
            Request::ProbeDivert { seconds } => {
                // Наблюдение идёт в этом же потоке клиента: ответ придёт,
                // когда оно закончится, и консоль сможет сразу показать
                // журнал. Остальным клиентам это не мешает — у каждого свой
                // поток.
                let seconds = seconds.clamp(1, 60);
                match crate::probe::run(&shared.store, seconds) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            Request::ProbeFlows { seconds } => {
                let seconds = seconds.clamp(1, 60);
                match crate::probe::run_flows(&shared.store, seconds) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            Request::ProbeDns { seconds } => {
                let seconds = seconds.clamp(1, 120);
                match crate::dnsprobe::run(&shared.store, seconds) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            Request::ProbeDnsRace { seconds } => {
                let seconds = seconds.clamp(1, 120);
                match crate::dnsprobe::race(&shared.store, seconds) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            Request::PathB { target, seconds } => {
                // Как и у остальных опытов, время ограничено: перехват не
                // бесплатен, и забытая ручка глотает пакеты.
                let seconds = seconds.clamp(1, 300);
                match Shared::path_b(&shared, &target, seconds) {
                    Ok(_) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            Request::ProbeUdp { seconds } => {
                let seconds = seconds.clamp(1, 300);
                match crate::udpprobe::run(&shared.store, seconds) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            Request::ProbeFlush { rounds } => {
                // Каждый запуск — до полутора секунд ожидания, настроек
                // несколько: без потолка клиент ждал бы минутами.
                let rounds = rounds.clamp(1, 20);
                match crate::flushprobe::run(&shared.store, rounds) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error(e),
                }
            }
            Request::CheckNoTunnel { seconds } => {
                // Время ограничено сверху: проверка оставляет выбранные
                // приложения без сети, и забыть её включённой нельзя.
                let seconds = seconds.clamp(1, 120);
                match shared.engine() {
                    Some(engine) => match engine.pretend_no_tunnel(seconds) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e),
                    },
                    None => Response::Error(
                        "путь B не поднят: проверять нечего. Добавь правило \
                         «приложение и все его потомки» (vpnsplit-svc addb ЦЕЛЬ)"
                            .to_owned(),
                    ),
                }
            }
            Request::Reroute { target, seconds } => {
                // Опыт перехвата живёт не дольше минуты и только на одном
                // адресе: ручка в рабочем режиме глотает пакеты, пока мы их
                // не отдадим, и забытая открытой она отрезала бы связь.
                let seconds = seconds.clamp(1, 60);
                match target.parse() {
                    Ok(target) => match crate::reroute::run(&shared.store, target, seconds) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e),
                    },
                    Err(_) => Response::Error(format!("«{target}» не адрес IPv4")),
                }
            }
        };
        if connection.send(&response).is_err() {
            return;
        }
    }
}

/// Можно ли принять эту политику от клиента на том конце.
///
/// Повышенному клиенту — любую. Обычному — если среди новых и изменённых
/// правил нет чужих программ (см. `rights`). Личность клиента спрашивается,
/// только когда есть что проверять: обычное сохранение списка из окна без
/// новых правил на `.exe` её не требует.
fn admit_policy(connection: &Connection, shared: &Shared, policy: &Policy) -> Result<(), String> {
    let current = shared.state.lock().unwrap_or_else(|e| e.into_inner()).policy.clone();
    let checked = crate::rights::fresh(policy, &current)
        .any(|rule| matches!(rule.target, vpnsplit_core::AppTarget::Executable(_)));
    if !checked {
        return Ok(());
    }
    let client = connection.client();
    if client.as_ref().is_some_and(|client| client.elevated) {
        return Ok(());
    }
    let sid = client.and_then(|client| client.sid);
    crate::rights::admit(policy, &current, &crate::rights::Places::current(), sid.as_deref()).map_err(|e| {
        shared.store.log(&format!("политика не принята: {e}"));
        e
    })
}

/// После подписки соединение только пишет. Поток спит в recv до следующего
/// события; отписка — клиент закрыл канал, и следующая запись не удастся.
/// Без событий поток изредка смотрит, жив ли канал (`SUBSCRIBER_PROBE`).
///
/// Записи — под сторожем: подписчика, который не читает, `broadcast`
/// выкидывает и просит сторожа прервать запись, на которой поток завис.
fn subscribe(mut connection: Connection, shared: &Shared, watch: &Watch) {
    if watch.guard(None, || connection.send(&Response::Ok)).is_err() {
        return;
    }
    // Первыми событиями — текущее состояние, чтобы подписчик начал не
    // вслепую: туннель, а за ним всё, что из списка уже работает. Подписчик
    // может открыться позже службы и иначе не узнал бы об этом никогда.
    //
    // Очередь ограничена: подписчик, который не читает, при переполнении
    // выпадает (см. `broadcast`). Место под начальные события — сверх
    // обычного запаса: их число известно здесь же.
    let (tx, rx) = {
        let state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
        let initial: Vec<Event> = std::iter::once(Event::TunnelChanged(state.tunnel.clone()))
            .chain(state.processes.iter().map(|(pid, running)| {
                if running.hooked {
                    Event::ProcessAttached { pid, target: running.target.clone() }
                } else {
                    Event::ProcessUnhooked { pid, image: running.image.clone() }
                }
            }))
            .collect();
        let (tx, rx) = sync_channel(SUBSCRIBER_QUEUE + initial.len());
        for event in initial {
            let _ = tx.try_send(event);
        }
        (tx, rx)
    };
    shared.subscribers.lock().unwrap_or_else(|e| e.into_inner()).push((tx, watch.remote()));

    loop {
        match rx.recv_timeout(SUBSCRIBER_PROBE) {
            Ok(event) => {
                if watch.guard(None, || connection.send(&event)).is_err() {
                    return;
                }
            }
            // Окно ушло молча — место его пользователя освобождается сейчас,
            // а не при следующем событии. Его отправитель выпадет из
            // `subscribers` при следующей рассылке.
            Err(RecvTimeoutError::Timeout) => {
                if connection.peer_gone() {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(sid: &str, elevated: bool) -> SeatKey {
        (Some(sid.to_owned()), elevated)
    }

    #[test]
    fn one_user_cannot_take_the_seats_of_another() {
        let mut seats = Seats::<()>::new();
        let greedy = user("S-1-5-21-1-2-3-1002", false);
        for _ in 0..PER_USER {
            assert!(seats.take(&greedy));
        }
        assert!(!seats.take(&greedy));
        // Другой пользователь и повышенный клиент того же — своим запасом.
        assert!(seats.take(&user("S-1-5-21-1-2-3-1001", false)));
        assert!(seats.take(&user("S-1-5-21-1-2-3-1002", true)));
        assert!(seats.take(&(None, false)));
        // Освободил место — снова можно.
        seats.leave(&greedy);
        assert!(seats.take(&greedy));
        assert!(!seats.take(&greedy));
    }

    #[test]
    fn leaving_frees_the_count_completely() {
        let mut seats = Seats::<()>::new();
        let key = user("S-1-5-18", true);
        assert!(seats.take(&key));
        seats.leave(&key);
        assert!(seats.users.is_empty());
        assert_eq!(seats.total, 0);
        // Лишний уход ничего не ломает.
        seats.leave(&key);
        assert_eq!(seats.total, 0);
    }

    #[test]
    fn the_total_limit_holds_across_users() {
        let mut seats = Seats::<()>::new();
        let mut taken = 0;
        for n in 0.. {
            let key = user(&format!("S-1-5-21-1-2-3-{n}"), false);
            if !(0..PER_USER).all(|_| seats.take(&key)) {
                break;
            }
            taken += PER_USER;
        }
        assert_eq!(taken, MAX_CLIENTS);
        assert_eq!(seats.total, MAX_CLIENTS);
    }

    #[test]
    fn a_new_connection_pushes_out_the_oldest_waiting_one() {
        let mut seats = Seats::<usize>::new();
        let silent = || Arc::new(AtomicBool::new(false));
        let ids: Vec<u64> = (0..MAX_WAITING).map(|n| {
            let (id, evicted) = seats.wait(n, silent());
            assert_eq!(evicted, None);
            id
        }).collect();
        let (_, evicted) = seats.wait(MAX_WAITING, silent());
        assert_eq!(evicted, Some(0));
        // Дождавшийся запроса из очереди уходит, и место есть снова.
        seats.served(ids[1]);
        assert_eq!(seats.wait(MAX_WAITING + 1, silent()).1, None);
        assert_eq!(seats.wait(MAX_WAITING + 2, silent()).1, Some(2));
        assert_eq!(seats.waiting.len(), MAX_WAITING);
    }

    #[test]
    fn a_connection_that_is_sending_outlives_silent_ones() {
        let mut seats = Seats::<usize>::new();
        let sending = Arc::new(AtomicBool::new(false));
        seats.wait(0, sending.clone());
        for n in 1..MAX_WAITING {
            seats.wait(n, Arc::new(AtomicBool::new(false)));
        }
        // Пошли байты длинного запроса: вытесняются молчащие, что за ним.
        sending.store(true, Ordering::Relaxed);
        for n in 0..MAX_WAITING * 2 {
            let (_, evicted) = seats.wait(MAX_WAITING + n, Arc::new(AtomicBool::new(false)));
            assert!(evicted.is_some_and(|evicted| evicted != 0), "{evicted:?}");
        }
        // Молчащих нет совсем — уходит самый старый, хоть он и говорит.
        let mut seats = Seats::<usize>::new();
        for n in 0..MAX_WAITING {
            seats.wait(n, Arc::new(AtomicBool::new(true)));
        }
        assert_eq!(seats.wait(MAX_WAITING, Arc::new(AtomicBool::new(true))).1, Some(0));
    }
}

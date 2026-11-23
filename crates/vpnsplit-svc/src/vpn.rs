//! Свои подключения: служба сама держит туннели OpenVPN.
//!
//! До 22.11.2026 туннель был чужой заботой: его поднимал VPN-клиент, а
//! vpnsplit только находил готовый интерфейс. Теперь пользователь выбирает
//! `.ovpn`, и служба запускает по нему `openvpn.exe` сама — при старте
//! Windows, пока подключение кому-то из списка нужно, и заново после
//! обрыва. С 23.11.2026 подключений может быть несколько, у каждого имя, и
//! приложению назначается одно из них: корпоративный VPN — одному,
//! зарубежный — другому.
//!
//! Что здесь важно:
//!
//! - **Конфиг до OpenVPN доходит очищенным** (`vpnsplit_core::ovpn`). Служба
//!   работает под SYSTEM, а конфиг присылает обычный пользователь.
//! - **Сеть машины OpenVPN не трогает.** Маршруты и DNS, которые велит
//!   поставить сервер, не принимаются (`--route-nopull`); вместо них на
//!   туннель ставится один маршрут по умолчанию с огромной метрикой. Он
//!   нужен пути B: пакет с адресом туннеля Windows отправит только туда,
//!   куда с этого интерфейса есть маршрут, — а обычный трафик он к себе не
//!   притягивает. Что сервер велел, служба читает из журнала OpenVPN и
//!   применяет сама и только к приложениям этого подключения (`lanes`).
//! - **У каждого подключения свой адаптер**, и назначает его служба
//!   (`--dev-node`): иначе не узнать, какой туннель чей.
//! - **Чужой туннель не перебиваем.** Пока туннель OpenVPN держит другая
//!   программа, свои подключения не начинаются: с тем же сертификатом они
//!   выбивали бы друг друга по очереди, а узнать, тот ли это сервер, нечем.
//! - **OpenVPN не переживает службу.** Он запущен в задании, которое
//!   закрывается вместе с нашим процессом: упавшая служба не оставит
//!   после себя туннель, о котором вернувшаяся ничего не знает.
//!
//! Опросов нет: поток подключения спит, пока его не разбудят — смена сети,
//! правка списка, новый конфиг или конец процесса OpenVPN. Часы идут только
//! в двух случаях: перед повтором после неудачи и пока туннель чужой.

use crate::lanes;
use crate::store::Store;
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use vpnsplit_core::{ovpn, Policy, Routing, VpnAction, VpnState};
use vpnsplit_net::iface;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent};

/// Список подключений: номера и имена. Сами конфиги лежат рядом, по файлу
/// на подключение, и читать их могут только SYSTEM и администраторы.
const INDEX_FILE: &str = "vpns.json";

/// Конфиг и пароль ключа единственного подключения, как их хранила первая
/// версия. Найденные, они становятся подключением «VPN».
const OLD_CONFIG: &str = "vpn.ovpn";
const OLD_PASS: &str = "vpn.pass";

/// Файлы холостого запуска, которым проверяется новый конфиг. Живут
/// секунды и убираются при любом исходе.
const PROBE_CONFIG: &str = "verify.ovpn";
const PROBE_PASS: &str = "verify.pass";
const PROBE_AUTH: &str = "verify.auth";
const PROBE_LOG: &str = "verify.log";

/// Сколько ждать от холостого запуска ответа. Ключ OpenVPN читает в первые
/// доли секунды; не вышел за это время и не сказал ничего — значит, принял.
const PROBE_PATIENCE: Duration = Duration::from_secs(4);
const PROBE_STEP: Duration = Duration::from_millis(100);

/// Строки журнала, после которых ясно: ключ прочитан, OpenVPN перешёл к
/// связи с сервером.
const PROBE_PASSED: [&str; 2] = ["link remote:", "Attempting to establish TCP connection"];

/// Так OpenVPN говорит о неверном пароле ключа.
const WRONG_PASSWORD: &str = "private key password verification failed";

/// А так — что сервер не принял логин и пароль.
const WRONG_LOGIN: &str = "AUTH_FAILED";

/// Что говорим мы, когда пароль перестал подходить уже после того, как
/// конфиг был принят.
const BAD_PASSWORD: &str = "пароль ключа не подходит — выбери конфиг заново и введи верный";

/// Логин проверить заранее нечем: его знает только сервер. Повторять с
/// теми же словами нельзя — за несколько неверных попыток учётную запись
/// на сервере могут закрыть.
const BAD_LOGIN: &str = "сервер не принял логин и пароль — выбери конфиг заново и введи верные; \
                         повторять с прежними служба не будет";

/// Сервер не принял вход подключения с одноразовым кодом. Что именно не
/// подошло, он не говорит.
const BAD_CODE: &str = "сервер не принял логин, пароль или одноразовый код";

/// Сколько живёт файл с одноразовым кодом. OpenVPN читает его при запуске,
/// до связи с сервером; дольше коду лежать на диске незачем.
const ONCE_LIFE: Duration = Duration::from_secs(20);

/// Метрика маршрута по умолчанию на туннеле. Маршрут должен быть, но
/// выигрывать у домашнего не должен никогда.
const ROUTE_METRIC: u32 = 5000;

/// Сколько ждать, пока OpenVPN выйдет сам, прежде чем гасить его силой.
const GRACE: Duration = Duration::from_secs(5);
const KILL_WAIT: Duration = Duration::from_secs(3);

/// Проработал столько — прежние неудачи забыты.
const STABLE: Duration = Duration::from_secs(60);

/// Паузы перед повтором, секунды; последняя повторяется.
const PAUSES: [u64; 5] = [2, 5, 15, 30, 60];

/// Пока туннель держит другая программа, о его падении нам скажет смена
/// сети. Это страховка на случай, если не скажет.
const FOREIGN_RECHECK: Duration = Duration::from_secs(30);

/// Длиннее имя подключения в окне не поместится.
const NAME_LIMIT: usize = 40;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Что сейчас с подключением.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Phase {
    /// Подключаться незачем.
    Idle,
    /// Туннель OpenVPN уже держит другая программа — вот этот.
    Foreign(String),
    /// OpenVPN запущен. Поднят ли туннель, видно не отсюда, а по сети.
    Running,
    /// Не вышло; ждём повтора.
    Waiting { why: String, until: Instant },
    /// Не выйдет, пока что-то не изменится: нет OpenVPN, не тот пароль.
    Unable(String),
    /// Сервер ждёт одноразовый код, а его может дать только человек.
    /// Внутри — чем кончилась прошлая попытка, если она была.
    NeedsCode(Option<String>),
    /// Отключено человеком. Поток такого состояния не ставит — оно
    /// показывается поверх любого другого, пока подключение выключено.
    Off,
}

struct Inner {
    /// Сервер из конфига.
    remote: String,
    /// Ключ под паролем: OpenVPN надо дать файл с ним.
    askpass: bool,
    /// Сервер спрашивает логин и пароль: файл с ними.
    auth: bool,
    /// К паролю сервер ждёт одноразовый код — при каждом подключении новый.
    by_code: bool,
    /// Код приписывается к паролю как есть, а не в обёртке `SCRV1`.
    concat: bool,
    /// Код, который дал человек и который ещё не израсходован.
    code: Option<String>,
    /// Отключено человеком: не подключаться, пока он же не включит.
    off: bool,
    /// Растёт с каждой сменой конфига: запущенный по прежнему — перезапустить.
    serial: u64,
    /// Подключение нужно кому-то из списка.
    wanted: bool,
    leaving: bool,
    /// Разбудили, пока не спал, — не засыпать.
    poked: bool,
    phase: Phase,
}

/// Общее для всех подключений: кто какой адаптер занял и кому сообщать о
/// переменах.
pub struct Hub {
    store: Store,
    claimed: Mutex<HashMap<u32, String>>,
    listener: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// Холостой запуск — по одному: файлы у него одни на всех.
    probing: Mutex<()>,
}

/// Адаптер, на котором OpenVPN умеет поднимать туннель без ускорителя.
fn is_tap(adapter: &iface::Adapter) -> bool {
    adapter.description.to_lowercase().contains("tap-windows adapter")
}

impl Hub {
    fn changed(&self) {
        if let Some(listener) = self.listener.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            listener();
        }
    }

    fn claimed(&self) -> MutexGuard<'_, HashMap<u32, String>> {
        self.claimed.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Адаптер для подключения: свободный, а если таких нет — новый.
    ///
    /// Свободный — значит не поднятый и не занятый другим нашим
    /// подключением. Поднятый чужой адаптер трогать нельзя: по нему идёт
    /// чья-то работа.
    fn claim(&self, id: u32) -> Result<String, String> {
        let mut created = false;
        loop {
            {
                let mut claimed = self.claimed();
                if let Some(name) = claimed.get(&id) {
                    return Ok(name.clone());
                }
                let adapters = iface::list()?;
                let free = adapters
                    .iter()
                    .find(|a| is_tap(a) && !a.up && !claimed.values().any(|taken| *taken == a.name));
                if let Some(adapter) = free {
                    claimed.insert(id, adapter.name.clone());
                    return Ok(adapter.name.clone());
                }
            }
            if created {
                return Err("нет свободного адаптера OpenVPN (TAP-Windows), и новый не появился".to_owned());
            }
            // Новый адаптер заводится без замка: это секунды, а про занятые
            // адаптеры спрашивают на каждый запрос состояния.
            create_adapter(&self.store, id)?;
            created = true;
        }
    }

    fn release(&self, id: u32) {
        self.claimed().remove(&id);
    }

    fn adapter_of(&self, id: u32) -> Option<String> {
        self.claimed().get(&id).cloned()
    }

    /// Туннель OpenVPN, который держим не мы: поднятый адаптер TAP с
    /// адресом, не занятый ни одним нашим подключением.
    pub fn foreign(&self) -> Option<String> {
        let claimed = self.claimed();
        iface::list()
            .ok()?
            .into_iter()
            .find(|a| is_tap(a) && a.usable() && !claimed.values().any(|taken| *taken == a.name))
            .map(|a| a.name)
    }
}

/// Заводит ещё один адаптер TAP — программой из состава OpenVPN.
fn create_adapter(store: &Store, id: u32) -> Result<(), String> {
    let Some(tool) = find_openvpn().map(|exe| exe.with_file_name("tapctl.exe")).filter(|p| p.is_file())
    else {
        return Err("свободных адаптеров OpenVPN нет, а завести новый нечем (нет tapctl.exe)".to_owned());
    };
    let name = format!("vpnsplit TAP {id}");
    let output = std::process::Command::new(&tool)
        .args(["create", "--hwid", "root\\tap0901", "--name", &name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("tapctl.exe не запустился: {e}"))?;
    if !output.status.success() {
        let said = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "новый адаптер OpenVPN не создан: {}",
            said.lines().rev().find(|line| !line.trim().is_empty()).unwrap_or("tapctl причину не назвал").trim()
        ));
    }
    store.log(&format!("свои подключения: свободных адаптеров не было — заведён «{name}»"));
    Ok(())
}

/// Имена файлов одного подключения в каталоге данных.
#[derive(Clone)]
struct Files {
    config: String,
    pass: String,
    auth: String,
    /// Логин и пароль с одноразовым кодом — на одно подключение.
    once: String,
    /// Пустой файл-пометка «отключено человеком»: служба должна помнить
    /// это и после перезапуска.
    off: String,
    log: String,
}

impl Files {
    fn of(id: u32) -> Files {
        Files {
            config: format!("vpn-{id}.ovpn"),
            pass: format!("vpn-{id}.pass"),
            auth: format!("vpn-{id}.auth"),
            once: format!("vpn-{id}.once"),
            off: format!("vpn-{id}.off"),
            log: format!("openvpn-{id}.log"),
        }
    }
}

/// Одно подключение и поток, который за ним присматривает.
pub struct Vpn {
    id: u32,
    name: String,
    files: Files,
    store: Store,
    hub: Arc<Hub>,
    inner: Mutex<Inner>,
    woken: Condvar,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// Хэндл Windows, который закроется сам.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Запущенный OpenVPN. Живёт только в потоке присмотра.
struct Running {
    /// Событие, по которому OpenVPN выходит сам: снимает маршруты и
    /// прощается с сервером.
    exit: Handle,
    /// Задание «умереть вместе с нами». Закрытие хэндла гасит всё, что в
    /// нём осталось.
    job: Handle,
    /// Код завершения придёт сюда.
    done: Receiver<i32>,
    since: Instant,
}

enum Failure {
    /// Повторять бессмысленно, пока что-то не изменится.
    Unable(String),
    Failed(String),
}

/// Пароль ключа и логин с паролем — то, что идёт к конфигу отдельно.
#[derive(Clone, Copy, Default)]
pub struct Secrets<'a> {
    pub key_password: Option<&'a str>,
    pub login: Option<(&'a str, &'a str)>,
}

impl Vpn {
    /// Подключение по уже лежащему на диске конфигу. `None` — конфиг не
    /// годится или к нему не хватает пароля; причина — в журнале.
    fn load(store: &Store, hub: &Arc<Hub>, id: u32, name: &str) -> Option<Arc<Vpn>> {
        let files = Files::of(id);
        let dismissed = |why: &str| {
            store.log(&format!("подключение «{name}»: {why} — не используется; выбери конфиг заново"));
            None
        };
        let Some(text) = store.load_text(&files.config) else {
            return dismissed("конфига на диске нет");
        };
        let config = match ovpn::sanitize(&text) {
            Ok(config) => config,
            Err(e) => return dismissed(&format!("сохранённый конфиг не годится ({e})")),
        };
        if config.needs_password && !store.dir().join(&files.pass).is_file() {
            return dismissed("ключ закрыт паролем, а пароля рядом нет");
        }
        if config.needs_login && !store.dir().join(&files.auth).is_file() {
            return dismissed("сервер спрашивает логин и пароль, а их рядом нет");
        }
        // Правила разбора могли стать строже с прошлого запуска: на диске
        // должно лежать то, что прошло бы их сегодня.
        if config.text != text {
            if let Err(e) = store.save_secret(&files.config, &config.text) {
                return dismissed(&format!("сохранённый конфиг не удалось переписать ({e})"));
            }
        }
        store.log(&format!("подключение «{name}»: конфиг есть, сервер {}", config.remote));
        let vpn = Vpn::new(store, hub, id, name, &config);
        vpn.lock().off = store.dir().join(&files.off).is_file();
        Some(vpn)
    }

    fn new(store: &Store, hub: &Arc<Hub>, id: u32, name: &str, config: &ovpn::Config) -> Arc<Vpn> {
        Arc::new(Vpn {
            id,
            name: name.to_owned(),
            files: Files::of(id),
            store: store.clone(),
            hub: hub.clone(),
            inner: Mutex::new(Inner {
                remote: config.remote.clone(),
                askpass: config.needs_password,
                auth: config.needs_login,
                by_code: config.needs_code,
                concat: config.code_concat,
                code: None,
                off: false,
                serial: 0,
                wanted: false,
                leaving: false,
                poked: false,
                phase: Phase::Idle,
            }),
            woken: Condvar::new(),
            thread: Mutex::new(None),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn say(&self, what: &str) {
        self.store.log(&format!("подключение «{}»: {what}", self.name));
    }

    /// Запускает поток присмотра.
    fn start(self: &Arc<Self>, wanted: bool) {
        self.lock().wanted = wanted;
        let vpn = self.clone();
        match std::thread::Builder::new().name("vpn".into()).spawn(move || vpn.run()) {
            Ok(thread) => *self.thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(thread),
            Err(e) => self.say(&format!("поток присмотра не завёлся ({e}) — подключаться некому")),
        }
    }

    /// Разбудить поток: в мире что-то изменилось.
    fn poke(&self) {
        self.lock().poked = true;
        self.woken.notify_all();
    }

    fn set_wanted(&self, wanted: bool) {
        let mut inner = self.lock();
        if inner.wanted == wanted {
            return;
        }
        inner.wanted = wanted;
        inner.poked = true;
        drop(inner);
        self.woken.notify_all();
    }

    /// Одноразовый код от человека: подключаться с ним сейчас.
    fn connect(&self, code: &str) -> Result<(), String> {
        ovpn::check_code(code)?;
        let mut inner = self.lock();
        if !inner.by_code {
            return Err(format!("подключению «{}» одноразовый код не нужен", self.name));
        }
        // Код живёт полминуты: принять его «на потом» значило бы молча
        // его потерять.
        if !inner.wanted {
            return Err(format!(
                "подключение «{}» пока не назначено ни одному приложению из списка — \
                 подключаться не для кого, код не израсходован",
                self.name
            ));
        }
        if matches!(inner.phase, Phase::Running) && !inner.off {
            return Err(format!("подключение «{}» уже подключается или работает", self.name));
        }
        // Код — это и есть «подключить»: отключённое человеком включается.
        if inner.off {
            inner.off = false;
            let _ = self.store.remove(&self.files.off);
        }
        inner.code = Some(code.to_owned());
        inner.poked = true;
        drop(inner);
        self.woken.notify_all();
        Ok(())
    }

    /// Человек отключил подключение или включил обратно. Помнится и после
    /// перезапуска службы: отключённое само не поднимется.
    fn switch(&self, on: bool) -> Result<(), String> {
        let saved = if on {
            self.store.remove(&self.files.off)
        } else {
            self.store.save_secret(&self.files.off, "")
        };
        saved.map_err(|e| format!("не удалось запомнить выбор: {e}"))?;
        let mut inner = self.lock();
        if inner.off == !on {
            return Ok(());
        }
        inner.off = !on;
        if !on {
            inner.code = None;
        }
        inner.poked = true;
        drop(inner);
        self.woken.notify_all();
        self.say(if on { "включено человеком" } else { "отключено человеком" });
        Ok(())
    }

    /// Сменить логин и пароль, не трогая конфиг. Подключение начинается
    /// заново: прежний отказ сервера к новым словам не относится.
    fn set_login(&self, user: &str, password: &str) -> Result<(), String> {
        ovpn::check_login(user, password)?;
        if !self.lock().auth {
            return Err(format!("подключение «{}» входит без логина и пароля", self.name));
        }
        self.store
            .save_secret(&self.files.auth, &format!("{user}\n{password}\n"))
            .map_err(|e| format!("не удалось сохранить логин и пароль: {e}"))?;
        let mut inner = self.lock();
        inner.code = None;
        inner.serial += 1;
        inner.poked = true;
        drop(inner);
        self.woken.notify_all();
        self.say("логин и пароль заменены");
        Ok(())
    }

    /// Сохранить проверенный конфиг и подключаться по нему.
    fn accept(&self, config: &ovpn::Config, secrets: Secrets, checked: bool) -> Result<(), String> {
        let saving = |e| format!("не удалось сохранить конфиг: {e}");
        // Пароли — раньше конфига: конфиг без своего пароля хуже, чем
        // пароль без конфига.
        match secrets.key_password.filter(|_| config.needs_password) {
            Some(password) => {
                self.store.save_secret(&self.files.pass, &format!("{password}\n")).map_err(saving)?
            }
            None => self.store.remove(&self.files.pass).map_err(saving)?,
        }
        match secrets.login.filter(|_| config.needs_login) {
            Some((user, password)) => self
                .store
                .save_secret(&self.files.auth, &format!("{user}\n{password}\n"))
                .map_err(saving)?,
            None => self.store.remove(&self.files.auth).map_err(saving)?,
        }
        self.store.save_secret(&self.files.config, &config.text).map_err(saving)?;
        let mut note = format!("принят конфиг, сервер {}", config.remote);
        if config.needs_password {
            note.push_str(", ключ под паролем");
        }
        if config.needs_login {
            note.push_str(", вход по логину и паролю");
        }
        if config.needs_code {
            note.push_str(", к ним одноразовый код при каждом подключении");
        }
        if config.needs_password || config.needs_login {
            note.push_str(" (сохранены рядом, под теми же правами)");
        }
        note.push_str(if checked {
            "; OpenVPN его принимает"
        } else {
            "; проверить нечем — OpenVPN не установлен"
        });
        if !config.dropped.is_empty() {
            // Директивы, не ключи: показывать можно.
            note.push_str(&format!("; из него не сработает: {}", config.dropped.join("; ")));
        }
        self.say(&note);
        let mut inner = self.lock();
        inner.remote = config.remote.clone();
        inner.askpass = config.needs_password;
        inner.auth = config.needs_login;
        inner.by_code = config.needs_code;
        inner.concat = config.code_concat;
        inner.code = None;
        inner.serial += 1;
        inner.poked = true;
        drop(inner);
        self.woken.notify_all();
        Ok(())
    }

    /// Опустить подключение, дождаться потока и убрать файлы.
    fn retire(&self) {
        self.shutdown();
        for name in
            [&self.files.config, &self.files.pass, &self.files.auth, &self.files.once, &self.files.off, &self.files.log]
        {
            if let Err(e) = self.store.remove(name) {
                self.say(&format!("файл {name} не убран: {e}"));
            }
        }
        self.say("забыто: конфиг и пароли убраны");
    }

    /// Адаптер, на котором сейчас работает наш OpenVPN.
    fn adapter(&self) -> Option<String> {
        matches!(self.lock().phase, Phase::Running).then(|| self.hub.adapter_of(self.id)).flatten()
    }

    /// Что сервер назначил подключению — из журнала OpenVPN.
    fn pushed(&self) -> lanes::Pushed {
        lanes::pushed(&read_log(&self.store.dir().join(&self.files.log)))
    }

    fn state(&self, address_of: &dyn Fn(&str) -> Option<Ipv4Addr>) -> VpnState {
        let address = self.adapter().and_then(|adapter| address_of(&adapter));
        let inner = self.lock();
        // «Отключено человеком» видно сразу, не дожидаясь потока.
        let phase = if inner.off { &Phase::Off } else { &inner.phase };
        VpnState {
            name: self.name.clone(),
            line: describe(&inner.remote, inner.wanted, phase, address.is_some(), Instant::now()),
            connected: address.is_some(),
            address,
            by_code: inner.by_code,
            off: inner.off,
            login: inner.auth,
        }
    }

    /// Служба уходит или подключение убирают: опустить и дождаться потока.
    fn shutdown(&self) {
        {
            let mut inner = self.lock();
            inner.leaving = true;
            inner.poked = true;
        }
        self.woken.notify_all();
        let thread = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }

    /// Спать, пока не разбудят или не выйдет время.
    fn wait(&self, patience: Option<Duration>) {
        let deadline = patience.map(|patience| Instant::now() + patience);
        let mut inner = self.lock();
        while !inner.poked {
            match deadline {
                None => inner = self.woken.wait(inner).unwrap_or_else(|e| e.into_inner()),
                Some(deadline) => {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else { break };
                    inner = self.woken.wait_timeout(inner, left).unwrap_or_else(|e| e.into_inner()).0;
                }
            }
        }
        inner.poked = false;
    }

    /// Правда — состояние действительно изменилось.
    fn set_phase(&self, phase: Phase) -> bool {
        {
            let mut inner = self.lock();
            if inner.phase == phase {
                return false;
            }
            inner.phase = phase;
        }
        self.hub.changed();
        true
    }

    /// OpenVPN больше не работает: адаптер свободен.
    fn gone(&self, running: Running, why: Option<&str>) {
        if let Some(why) = why {
            self.stop(running, why);
        }
        // Одноразовый код своё отслужил, каким бы ни был исход.
        let _ = self.store.remove(&self.files.once);
        self.hub.release(self.id);
    }

    fn run(self: Arc<Self>) {
        let mut child: Option<Running> = None;
        let mut failures = 0u32;
        let mut retry: Option<Instant> = None;
        // До какого времени лежит файл с одноразовым кодом.
        let mut once_until: Option<Instant> = None;
        // Конфиг, с которым пробовать бесполезно, пока его не сменят, — и
        // почему.
        let mut blocked: Option<(u64, &'static str)> = None;
        let mut seen = self.lock().serial;
        loop {
            // Умершего — забрать и сказать, от чего он умер.
            if let Some(code) = child.as_ref().and_then(|running| running.done.try_recv().ok()) {
                let lasted = match child.take() {
                    Some(running) => {
                        let lasted = running.since.elapsed();
                        self.gone(running, None);
                        lasted
                    }
                    None => Duration::ZERO,
                };
                if lasted >= STABLE {
                    failures = 0;
                }
                failures += 1;
                let pause = pause(failures);
                let log = read_log(&self.store.dir().join(&self.files.log));
                // Повторять незачем: те же слова не подойдут и через
                // минуту. Ждём нового конфига.
                let by_code = self.lock().by_code;
                let hopeless = if log.contains(WRONG_PASSWORD) {
                    Some(BAD_PASSWORD)
                } else if log.contains(WRONG_LOGIN) && !by_code {
                    Some(BAD_LOGIN)
                } else {
                    None
                };
                if let Some(why) = hopeless {
                    self.say(why);
                    blocked = Some((self.lock().serial, why));
                    continue;
                }
                let why = last_words(&log)
                    .unwrap_or_else(|| format!("OpenVPN завершился с кодом {code}"));
                if by_code {
                    // Повторять нечем: код одноразовый, новый даст только
                    // человек. Отказ сервера здесь — не приговор конфигу:
                    // чаще всего это опечатка в коде или код опоздал.
                    let why = if log.contains(WRONG_LOGIN) { BAD_CODE.to_owned() } else { why };
                    self.say(&format!(
                        "OpenVPN вышел через {} с (код {code}): {why}. Для нового подключения \
                         нужен новый одноразовый код",
                        lasted.as_secs()
                    ));
                    retry = None;
                    self.set_phase(Phase::NeedsCode(Some(why)));
                    continue;
                }
                self.say(&format!(
                    "OpenVPN вышел через {} с (код {code}): {why}. Повтор через {} с",
                    lasted.as_secs(),
                    pause.as_secs()
                ));
                let until = Instant::now() + pause;
                retry = Some(until);
                self.set_phase(Phase::Waiting { why, until });
            }

            let (leaving, want, off, serial) = {
                let inner = self.lock();
                (inner.leaving, inner.wanted && !inner.off, inner.off, inner.serial)
            };
            if leaving {
                if let Some(running) = child.take() {
                    self.gone(running, Some("подключение уходит"));
                }
                return;
            }
            if serial != seen {
                // Конфиг другой: прежние неудачи к нему не относятся, а
                // запущенный по старому должен уйти.
                seen = serial;
                failures = 0;
                retry = None;
                if let Some(running) = child.take() {
                    self.gone(running, Some("конфиг сменился"));
                }
            }
            if !want {
                if let Some(running) = child.take() {
                    let why =
                        if off { "отключено человеком" } else { "держать туннель больше не для кого" };
                    self.gone(running, Some(why));
                }
                failures = 0;
                retry = None;
                // Код, которым не успели воспользоваться, уже не годится.
                self.lock().code = None;
                self.set_phase(Phase::Idle);
                self.wait(None);
                continue;
            }
            if let Some((_, why)) = blocked.filter(|(at, _)| *at == serial) {
                // С этим конфигом не подключиться. Разбудит новый.
                self.set_phase(Phase::Unable(why.to_owned()));
                self.wait(None);
                continue;
            }
            if child.is_some() {
                // Работает. Разбудит либо его конец, либо перемена — а пока
                // лежит файл с одноразовым кодом, ещё и его срок.
                match once_until.and_then(|at| at.checked_duration_since(Instant::now())) {
                    Some(left) => self.wait(Some(left)),
                    None => {
                        if once_until.take().is_some() {
                            let _ = self.store.remove(&self.files.once);
                        }
                        self.wait(None);
                    }
                }
                continue;
            }
            if let Some(at) = retry {
                if let Some(left) = at.checked_duration_since(Instant::now()) {
                    self.wait(Some(left));
                    continue;
                }
                retry = None;
            }
            // Туннель OpenVPN есть, а держим его не мы. Подключение с тем
            // же сертификатом выбило бы его, тот вернулся бы и выбил наше,
            // и так по кругу; а тот ли это сервер, узнать нечем.
            if let Some(foreign) = self.hub.foreign() {
                if self.set_phase(Phase::Foreign(foreign.clone())) {
                    self.say(&format!(
                        "туннель «{foreign}» уже держит другая программа — не начинаю, пока она \
                         не отключится"
                    ));
                }
                self.wait(Some(FOREIGN_RECHECK));
                continue;
            }
            // Подключение по одноразовому коду без кода не начать, а дать
            // его может только человек.
            let (by_code, once) = {
                let mut inner = self.lock();
                (inner.by_code, inner.code.take())
            };
            if by_code && once.is_none() {
                // Чем кончилась прошлая попытка, остаётся на виду.
                let waiting = matches!(self.lock().phase, Phase::NeedsCode(_));
                if !waiting {
                    self.set_phase(Phase::NeedsCode(None));
                }
                self.wait(None);
                continue;
            }
            match self.launch(once.as_deref().filter(|_| by_code)) {
                Ok(running) => {
                    child = Some(running);
                    once_until = by_code.then(|| Instant::now() + ONCE_LIFE);
                    self.set_phase(Phase::Running);
                }
                Err(Failure::Failed(why)) if by_code => {
                    self.hub.release(self.id);
                    let _ = self.store.remove(&self.files.once);
                    self.say(&format!(
                        "OpenVPN не запустился — {why}. Для новой попытки нужен новый одноразовый код"
                    ));
                    self.set_phase(Phase::NeedsCode(Some(why)));
                }
                Err(Failure::Unable(why)) => {
                    self.hub.release(self.id);
                    if self.set_phase(Phase::Unable(why.clone())) {
                        self.say(&why);
                    }
                    self.wait(None);
                }
                Err(Failure::Failed(why)) => {
                    self.hub.release(self.id);
                    failures += 1;
                    let pause = pause(failures);
                    self.say(&format!("OpenVPN не запустился — {why}. Повтор через {} с", pause.as_secs()));
                    let until = Instant::now() + pause;
                    retry = Some(until);
                    self.set_phase(Phase::Waiting { why, until });
                }
            }
        }
    }

    /// `once` — одноразовый код, если подключение входит с ним.
    fn launch(self: &Arc<Self>, once: Option<&str>) -> Result<Running, Failure> {
        let Some(exe) = find_openvpn() else {
            return Err(Failure::Unable(
                "OpenVPN не установлен: в Program Files нет OpenVPN\\bin\\openvpn.exe".to_owned(),
            ));
        };
        let failed = |what: &str, e: std::io::Error| Failure::Failed(format!("{what}: {e}"));
        let adapter = self.hub.claim(self.id).map_err(Failure::Failed)?;

        // Имя события — с номером нашего процесса: OpenVPN прежней службы,
        // если он почему-то ещё жив, наше событие не услышит, и наоборот.
        let event_name = format!("vpnsplit-openvpn-exit-{}-{}", std::process::id(), self.id);
        let wide: Vec<u16> = event_name.encode_utf16().chain([0]).collect();
        let exit = Handle(unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) });
        if exit.0.is_null() {
            return Err(failed("событие остановки не создалось", std::io::Error::last_os_error()));
        }
        // Событие могло остаться поднятым от прошлого запуска, если тот
        // OpenVPN ещё не до конца ушёл.
        unsafe { ResetEvent(exit.0) };

        let dir = self.store.dir();
        let (askpass, auth, concat) = {
            let inner = self.lock();
            (inner.askpass.then(|| dir.join(&self.files.pass)), inner.auth, inner.concat)
        };
        let auth = match (auth, once) {
            (false, _) => None,
            (true, None) => Some(dir.join(&self.files.auth)),
            // С кодом OpenVPN получает свой файл на один раз: логин и
            // пароль, к которому код приложен так, как ждёт сервер.
            (true, Some(code)) => {
                let stored = self.store.load_text(&self.files.auth).unwrap_or_default();
                let mut lines = stored.lines();
                let (Some(user), Some(password)) = (lines.next(), lines.next()) else {
                    return Err(Failure::Unable(
                        "логин и пароль подключения пропали — выбери конфиг заново".to_owned(),
                    ));
                };
                let text = format!("{user}\n{}\n", ovpn::with_code(password, code, concat));
                self.store
                    .save_secret(&self.files.once, &text)
                    .map_err(|e| failed("файл с одноразовым кодом не записался", e))?;
                Some(dir.join(&self.files.once))
            }
        };
        let mut list = arguments(&dir.join(&self.files.config), askpass.as_deref(), auth.as_deref());
        list.extend(live_arguments(&event_name, &adapter));
        let log = dir.join(&self.files.log);
        let Spawned { mut child, job } = spawn(&exe, list, &log).map_err(Failure::Failed)?;
        let pid = child.id();

        let (tx, done) = channel();
        let vpn = self.clone();
        let waiter = std::thread::Builder::new().name("openvpn".into()).spawn(move || {
            let code = child.wait().ok().and_then(|status| status.code()).unwrap_or(-1);
            let _ = tx.send(code);
            vpn.poke();
        });
        if let Err(e) = waiter {
            // Процесс уже в задании: его конец — конец и процесса.
            unsafe { TerminateJobObject(job.0, 1) };
            return Err(failed("поток ожидания OpenVPN не завёлся", e));
        }
        self.say(&format!(
            "запущен OpenVPN (процесс {pid}) на адаптере «{adapter}», журнал — {}",
            log.display()
        ));
        Ok(Running { exit, job, done, since: Instant::now() })
    }

    fn stop(&self, running: Running, why: &str) {
        unsafe { SetEvent(running.exit.0) };
        let graceful = running.done.recv_timeout(GRACE).is_ok();
        if !graceful {
            unsafe { TerminateJobObject(running.job.0, 1) };
            let _ = running.done.recv_timeout(KILL_WAIT);
        }
        self.say(&format!(
            "OpenVPN остановлен ({why}){}",
            if graceful { "" } else { " — силой, сам за отведённое время не вышел" }
        ));
    }
}

/// Все свои подключения.
pub struct Vpns {
    store: Store,
    hub: Arc<Hub>,
    /// В порядке добавления; первое — подключение по умолчанию.
    list: Mutex<Vec<Arc<Vpn>>>,
    /// Какие подключения нужны списку приложений — чтобы новое подключение
    /// сразу знало, ждут ли его.
    policy: Mutex<Policy>,
    started: std::sync::atomic::AtomicBool,
}

impl Vpns {
    /// Читает сохранённые подключения. Потоки присмотра ещё не запущены.
    pub fn open(store: Store) -> Arc<Vpns> {
        let hub = Arc::new(Hub {
            store: store.clone(),
            claimed: Mutex::new(HashMap::new()),
            listener: Mutex::new(None),
            probing: Mutex::new(()),
        });
        let mut index = store.load_text(INDEX_FILE).and_then(|text| index_from_json(&text)).unwrap_or_default();
        // Конфиг первой версии, когда подключение было одно и без имени.
        if index.is_empty() && store.dir().join(OLD_CONFIG).is_file() {
            let files = Files::of(1);
            let dir = store.dir();
            let moved = std::fs::rename(dir.join(OLD_CONFIG), dir.join(&files.config)).is_ok();
            let _ = std::fs::rename(dir.join(OLD_PASS), dir.join(&files.pass));
            if moved {
                index.push((1, "VPN".to_owned()));
                store.log("свои подключения: прежнее безымянное подключение теперь называется «VPN»");
            }
        }
        let list: Vec<Arc<Vpn>> =
            index.iter().filter_map(|(id, name)| Vpn::load(&store, &hub, *id, name)).collect();
        let vpns = Arc::new(Vpns {
            store,
            hub,
            list: Mutex::new(list),
            policy: Mutex::new(Policy::default()),
            started: std::sync::atomic::AtomicBool::new(false),
        });
        // Что не загрузилось — из списка уходит: иначе имя висело бы
        // занятым, а подключения за ним не было бы.
        vpns.save_index();
        vpns
    }

    fn list(&self) -> MutexGuard<'_, Vec<Arc<Vpn>>> {
        self.list.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save_index(&self) {
        let index: Vec<(u32, String)> = self.list().iter().map(|vpn| (vpn.id, vpn.name.clone())).collect();
        let saved = if index.is_empty() {
            self.store.remove(INDEX_FILE)
        } else {
            let path = self.store.dir().join(INDEX_FILE);
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, index_to_json(&index)).and_then(|()| std::fs::rename(&tmp, &path))
        };
        if let Err(e) = saved {
            self.store.log(&format!(
                "свои подключения: список не записан ({e}) — после перезапуска службы их придётся \
                 задать заново"
            ));
        }
    }

    /// Кому сообщать о переменах. Вызывается без наших замков.
    pub fn listen(&self, listener: Box<dyn Fn() + Send + Sync>) {
        *self.hub.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(listener);
    }

    /// Запускает потоки присмотра. Один раз, при старте службы.
    pub fn start(&self, policy: &Policy) {
        *self.policy.lock().unwrap_or_else(|e| e.into_inner()) = policy.clone();
        self.started.store(true, std::sync::atomic::Ordering::Release);
        let list = self.list().clone();
        for (at, vpn) in list.iter().enumerate() {
            vpn.start(wanted(policy, &vpn.name, at == 0));
        }
    }

    /// Список приложений изменился: кому-то подключение стало нужно,
    /// кому-то перестало.
    pub fn set_policy(&self, policy: &Policy) {
        *self.policy.lock().unwrap_or_else(|e| e.into_inner()) = policy.clone();
        self.apply_policy();
    }

    fn apply_policy(&self) {
        let policy = self.policy.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let list = self.list().clone();
        for (at, vpn) in list.iter().enumerate() {
            vpn.set_wanted(wanted(&policy, &vpn.name, at == 0));
        }
    }

    /// Сеть изменилась: чужой туннель мог уйти — тогда пора поднимать свои.
    pub fn poke(&self) {
        for vpn in self.list().iter() {
            vpn.poke();
        }
    }

    /// Принять конфиг: очистить, проверить, сохранить, подключаться по нему.
    ///
    /// Проверяет его сам OpenVPN, запущенный вхолостую, — до того, как
    /// что-либо сохранено. Неверный пароль ключа иначе всплыл бы только
    /// при подключении: человек ушёл бы с уверенностью, что всё настроено,
    /// а приложения из списка остались бы без сети.
    ///
    /// Подключение с таким именем заменяется; без имени — заменяется
    /// первое, а если нет ни одного, заводится «VPN».
    pub fn set_config(&self, name: Option<&str>, source: &str, secrets: Secrets) -> Result<(), String> {
        let config = ovpn::sanitize(source)?;
        if config.needs_password {
            match secrets.key_password {
                None => return Err("ключ в конфиге закрыт паролем — нужен пароль ключа".to_owned()),
                Some(password) => ovpn::check_password(password)?,
            }
        }
        if config.needs_login {
            match secrets.login {
                None => return Err("сервер спрашивает логин и пароль — нужны они".to_owned()),
                Some((user, password)) => ovpn::check_login(user, password)?,
            }
        }
        let name = match name {
            Some(name) => check_name(name)?,
            None => self.list().first().map(|vpn| vpn.name.clone()).unwrap_or_else(|| "VPN".to_owned()),
        };
        let checked = {
            let _one = self.hub.probing.lock().unwrap_or_else(|e| e.into_inner());
            probe(&self.store, &config, secrets)?
        };

        let existing = self.list().iter().find(|vpn| same_name(&vpn.name, &name)).cloned();
        match existing {
            Some(vpn) => vpn.accept(&config, secrets, checked)?,
            None => {
                let id = self.list().iter().map(|vpn| vpn.id).max().unwrap_or(0) + 1;
                let vpn = Vpn::new(&self.store, &self.hub, id, &name, &config);
                vpn.accept(&config, secrets, checked)?;
                self.list().push(vpn.clone());
                self.save_index();
                if self.started.load(std::sync::atomic::Ordering::Acquire) {
                    vpn.start(false);
                }
                self.apply_policy();
            }
        }
        self.hub.changed();
        Ok(())
    }

    /// Подключить, отключить или сделать подключением по умолчанию.
    pub fn act(&self, name: &str, action: VpnAction) -> Result<(), String> {
        let Some(vpn) = self.list().iter().find(|vpn| same_name(&vpn.name, name)).cloned() else {
            return Err(format!("подключения «{name}» нет"));
        };
        match action {
            VpnAction::Connect => vpn.switch(true)?,
            VpnAction::Disconnect => vpn.switch(false)?,
            // «По умолчанию» — первое в списке; порядок и хранит выбор.
            VpnAction::MakeDefault => {
                {
                    let mut list = self.list();
                    if let Some(at) = list.iter().position(|other| other.id == vpn.id) {
                        let moved = list.remove(at);
                        list.insert(0, moved);
                    }
                }
                self.save_index();
                vpn.say("теперь подключение по умолчанию");
                // Нужным могло стать другое подключение.
                self.apply_policy();
            }
        }
        self.hub.changed();
        Ok(())
    }

    /// Сменить логин и пароль подключения.
    pub fn set_login(&self, name: &str, user: &str, password: &str) -> Result<(), String> {
        let Some(vpn) = self.list().iter().find(|vpn| same_name(&vpn.name, name)).cloned() else {
            return Err(format!("подключения «{name}» нет"));
        };
        vpn.set_login(user, password)?;
        self.hub.changed();
        Ok(())
    }

    /// Одноразовый код для подключения с таким именем.
    pub fn connect(&self, name: &str, code: &str) -> Result<(), String> {
        let vpn = self.list().iter().find(|vpn| same_name(&vpn.name, name)).cloned();
        match vpn {
            Some(vpn) => vpn.connect(code),
            None => Err(format!("подключения «{name}» нет")),
        }
    }

    /// Забыть подключение. Без имени — все.
    pub fn clear_config(&self, name: Option<&str>) -> Result<(), String> {
        let gone: Vec<Arc<Vpn>> = {
            let mut list = self.list();
            let (gone, kept) = std::mem::take(&mut *list)
                .into_iter()
                .partition(|vpn| name.is_none_or(|name| same_name(&vpn.name, name)));
            *list = kept;
            gone
        };
        if gone.is_empty() {
            return match name {
                Some(name) => Err(format!("подключения «{name}» нет")),
                None => Ok(()),
            };
        }
        self.save_index();
        // Опускаются без замка списка: остановка OpenVPN — это секунды.
        for vpn in &gone {
            vpn.retire();
        }
        // Первым могло стать другое подключение — и нужным тоже.
        self.apply_policy();
        self.hub.changed();
        Ok(())
    }

    /// Что с каждым подключением сейчас.
    pub fn states(&self) -> Vec<VpnState> {
        let list = self.list().clone();
        if list.is_empty() {
            return Vec::new();
        }
        let adapters = iface::list().unwrap_or_default();
        let address_of = |name: &str| {
            adapters.iter().find(|a| a.name == name && a.usable()).and_then(|a| a.ipv4)
        };
        list.iter().map(|vpn| vpn.state(&address_of)).collect()
    }

    /// Дорожки для перехвата: правило пути B → куда его вести.
    ///
    /// Без своих подключений указаний нет вовсе: всё идёт, как шло, в
    /// туннель, который найдётся. С ними: названное в правиле подключение —
    /// в его туннель, а пока он не поднят — никуда; правило без названия —
    /// в чужой туннель, пока тот есть, иначе в первое своё подключение.
    pub fn specs(&self, policy: &Policy) -> HashMap<String, lanes::Spec> {
        let list = self.list().clone();
        if list.is_empty() {
            return HashMap::new();
        }
        let own: Vec<(String, lanes::Spec)> = list
            .iter()
            .map(|vpn| {
                let spec = match vpn.adapter() {
                    Some(adapter) => {
                        let pushed = vpn.pushed();
                        lanes::Spec {
                            via: lanes::Via::Adapter(adapter),
                            resolver: pushed.dns.first().copied(),
                            inside: pushed.routes,
                        }
                    }
                    None => lanes::Spec { via: lanes::Via::Nowhere, ..lanes::Spec::default() },
                };
                (vpn.name.clone(), spec)
            })
            .collect();
        let nowhere = lanes::Spec { via: lanes::Via::Nowhere, ..lanes::Spec::default() };
        let unnamed = match self.hub.foreign() {
            Some(foreign) => lanes::Spec { via: lanes::Via::Adapter(foreign), ..lanes::Spec::default() },
            None => own.first().map(|(_, spec)| spec.clone()).unwrap_or_else(|| nowhere.clone()),
        };
        policy
            .rules
            .iter()
            .filter(|rule| rule.routing == Routing::Tunnel)
            .map(|rule| {
                let spec = match &rule.vpn {
                    None => unnamed.clone(),
                    Some(name) => own
                        .iter()
                        .find(|(own, _)| same_name(own, name))
                        .map(|(_, spec)| spec.clone())
                        .unwrap_or_else(|| nowhere.clone()),
                };
                (rule.target.key(), spec)
            })
            .collect()
    }

    /// Служба уходит: опустить подключения и дождаться потоков.
    pub fn shutdown(&self) {
        let list = self.list().clone();
        // Сначала сказать всем, потом ждать каждого: иначе остановка
        // трёх подключений шла бы втрое дольше.
        for vpn in &list {
            let mut inner = vpn.lock();
            inner.leaving = true;
            inner.poked = true;
            drop(inner);
            vpn.woken.notify_all();
        }
        for vpn in &list {
            vpn.shutdown();
        }
    }
}

/// Нужно ли подключение списку: его назвало правило «в VPN», или оно первое,
/// а в списке есть правило без названия.
fn wanted(policy: &Policy, name: &str, first: bool) -> bool {
    policy.rules.iter().filter(|rule| rule.routing == Routing::Tunnel).any(|rule| match &rule.vpn {
        Some(chosen) => same_name(chosen, name),
        None => first,
    })
}

/// Одно ли это имя. Регистр не различается: «Работа» и «работа» в меню —
/// одно и то же для человека, значит, и для нас.
fn same_name(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

/// Имя подключения, как оно будет записано, или почему оно не годится.
fn check_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("у подключения должно быть имя".to_owned());
    }
    if name.chars().count() > NAME_LIMIT || name.chars().any(char::is_control) {
        return Err(format!("имя подключения — одна строка не длиннее {NAME_LIMIT} знаков"));
    }
    Ok(name.to_owned())
}

fn index_to_json(index: &[(u32, String)]) -> String {
    let list: Vec<serde_json::Value> =
        index.iter().map(|(id, name)| serde_json::json!({ "id": id, "name": name })).collect();
    serde_json::Value::Array(list).to_string()
}

fn index_from_json(text: &str) -> Option<Vec<(u32, String)>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .as_array()?
        .iter()
        .map(|item| {
            Some((u32::try_from(item.get("id")?.as_u64()?).ok()?, item.get("name")?.as_str()?.to_owned()))
        })
        .collect()
}

/// Холостой запуск: принимает ли OpenVPN этот конфиг и подходит ли пароль
/// ключа.
///
/// Запускается настоящий `openvpn.exe` с тем же текстом, но сервером в нём
/// назван этот же компьютер: до настоящего сервера дело не доходит, адаптер
/// не открывается, маршруты не трогаются. Ключ OpenVPN читает до всякой
/// связи — если с ним или с конфигом что-то не так, он выходит сразу и
/// говорит что. Логин и пароль так не проверить: их знает только сервер.
///
/// Отдельно от службы затем, чтобы тем же самым мог проверить конфиг и
/// человек из консоли (`vpnsplit-svc vpn check`) — до того, как отдаст его
/// службе.
///
/// `Ok(false)` — проверить нечем: OpenVPN не установлен. Это не отказ: о
/// том, что его нет, скажет состояние подключения.
pub fn probe(store: &Store, config: &ovpn::Config, secrets: Secrets) -> Result<bool, String> {
    let Some(exe) = find_openvpn() else { return Ok(false) };
    let dir = store.dir();
    let outcome = (|| {
        let saving = |e| format!("не удалось подготовить проверку конфига: {e}");
        store.save_secret(PROBE_CONFIG, &config.probe).map_err(saving)?;
        let password = secrets.key_password.filter(|_| config.needs_password);
        if let Some(password) = password {
            store.save_secret(PROBE_PASS, &format!("{password}\n")).map_err(saving)?;
        }
        let login = secrets.login.filter(|_| config.needs_login);
        if let Some((user, password)) = login {
            store.save_secret(PROBE_AUTH, &format!("{user}\n{password}\n")).map_err(saving)?;
        }
        let askpass = password.map(|_| dir.join(PROBE_PASS));
        let auth = login.map(|_| dir.join(PROBE_AUTH));
        let log = dir.join(PROBE_LOG);
        let list = arguments(&dir.join(PROBE_CONFIG), askpass.as_deref(), auth.as_deref());
        let mut spawned = spawn(&exe, list, &log)?;
        let deadline = Instant::now() + PROBE_PATIENCE;
        loop {
            if let Ok(Some(_)) = spawned.child.try_wait() {
                // Вышел сам — значит, не принял. Причина в журнале.
                return Err(probe_failure(&read_log(&log)));
            }
            let said = read_log(&log);
            if PROBE_PASSED.iter().any(|mark| said.contains(mark)) || Instant::now() >= deadline {
                let _ = spawned.child.kill();
                let _ = spawned.child.wait();
                return Ok(true);
            }
            std::thread::sleep(PROBE_STEP);
        }
    })();
    // Ключ и пароли проверки не должны пережить проверку.
    for name in [PROBE_CONFIG, PROBE_PASS, PROBE_AUTH, PROBE_LOG] {
        let _ = store.remove(name);
    }
    outcome
}

/// Что сказать человеку, когда OpenVPN не принял конфиг.
fn probe_failure(log: &str) -> String {
    if log.contains(WRONG_PASSWORD) {
        return "пароль ключа не подошёл".to_owned();
    }
    match last_words(log) {
        Some(said) => format!("OpenVPN не принял конфиг: {said}"),
        None => "OpenVPN не принял конфиг и не сказал почему".to_owned(),
    }
}

/// Журнал читается как получится: в нём бывают сообщения Windows не в
/// UTF-8, и терять из-за них причину незачем.
fn read_log(path: &Path) -> String {
    std::fs::read(path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default()
}

/// Где лежит `openvpn.exe`. Только каталоги программ: туда пишет лишь
/// администратор, а запускать под SYSTEM то, что мог подложить
/// пользователь, нельзя.
fn find_openvpn() -> Option<PathBuf> {
    ["ProgramW6432", "ProgramFiles"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(|base| PathBuf::from(base).join("OpenVPN").join("bin").join("openvpn.exe"))
        .find(|path| path.is_file())
}

/// OpenVPN, запущенный в задании «умереть вместе с нами».
struct Spawned {
    child: std::process::Child,
    /// Закрытие хэндла гасит всё, что в задании осталось.
    job: Handle,
}

/// Запускает OpenVPN: без окна, с журналом в файл, в задании, которое
/// закроется вместе с нашим процессом, как бы тот ни завершился.
fn spawn(exe: &Path, arguments: Vec<OsString>, log: &Path) -> Result<Spawned, String> {
    let failed = |what: &str, e: std::io::Error| format!("{what}: {e}");
    let output = std::fs::File::create(log).map_err(|e| failed("журнал OpenVPN не открылся", e))?;
    let errors = output.try_clone().map_err(|e| failed("журнал OpenVPN не открылся", e))?;

    let job = Handle(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) });
    if job.0.is_null() {
        return Err(failed("задание не создалось", std::io::Error::last_os_error()));
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let set = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set == 0 {
        return Err(failed("задание не настроилось", std::io::Error::last_os_error()));
    }

    let mut child = std::process::Command::new(exe)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(output)
        .stderr(errors)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| failed("openvpn.exe не запустился", e))?;
    // Между запуском и этой строкой OpenVPN успевает разве что начать
    // читать конфиг; всё, что он запустит позже, окажется в задании.
    if unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) } == 0 {
        let error = std::io::Error::last_os_error();
        // Без задания он пережил бы службу — так не запускаем.
        let _ = child.kill();
        let _ = child.wait();
        return Err(failed("OpenVPN не вошёл в задание", error));
    }
    Ok(Spawned { child, job })
}

/// С чем OpenVPN запускается всегда — и вхолостую, и по-настоящему. Всё,
/// что конфигу запрещено решать самому, сказано здесь.
fn arguments(config: &Path, askpass: Option<&Path>, auth: Option<&Path>) -> Vec<OsString> {
    let mut list: Vec<OsString> = vec!["--config".into(), config.into()];
    if let Some(askpass) = askpass {
        // Пароль ключа — из файла: спросить его под службой не у кого.
        list.extend(["--askpass".into(), askpass.into()]);
    }
    if let Some(auth) = auth {
        // Логин и пароль — тоже. И без переспрашивания: не приняты —
        // OpenVPN выходит, а не ждёт у клавиатуры, которой нет.
        list.extend(["--auth-user-pass".into(), auth.into()]);
        list.extend(["--auth-retry", "none"].map(OsString::from));
    }
    let rest = [
        // Маршруты и DNS, которые велит поставить сервер, — мимо: иначе в
        // туннель ушла бы вся машина.
        "--route-nopull",
        // Ускоритель в ядре (DCO) — другой адаптер и другой путь пакетов;
        // перехват проверен на обычном TAP.
        "--disable-dco",
        // Чужих программ OpenVPN не запускает. Конфиг этого и не может
        // попросить, но пусть будет сказано и здесь.
        "--script-security",
        "1",
    ];
    list.extend(rest.into_iter().map(OsString::from));
    list
}

/// Что добавляется, когда подключение настоящее.
fn live_arguments(exit_event: &str, adapter: &str) -> Vec<OsString> {
    let metric = ROUTE_METRIC.to_string();
    [
        // Выйти по нашему событию, а не по Ctrl+C: консоли у него нет.
        "--service",
        exit_event,
        "0",
        // Адаптер назначаем мы: по нему служба знает, какой туннель чей.
        "--dev-node",
        adapter,
        // Один маршрут — свой: путь B шлёт пакеты с адресом туннеля, и
        // Windows выпустит их только туда, куда с этого интерфейса есть
        // маршрут. Метрика такая, что обычный трафик он не притягивает.
        "--route",
        "0.0.0.0",
        "0.0.0.0",
        "vpn_gateway",
        metric.as_str(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn pause(failures: u32) -> Duration {
    let index = (failures.max(1) as usize - 1).min(PAUSES.len() - 1);
    Duration::from_secs(PAUSES[index])
}

/// Последнее, что OpenVPN сказал по делу. Его последняя строка обычно
/// «Exiting due to fatal error», а причина — строкой выше.
fn last_words(log: &str) -> Option<String> {
    let lines: Vec<&str> = log.lines().map(unstamped).filter(|line| !line.is_empty()).collect();
    // Прощания и советы — не причина.
    let telling: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| {
            let low = line.to_lowercase();
            !low.contains("exiting due to fatal error") && !low.starts_with("use --help")
        })
        .collect();
    let said = telling
        .iter()
        .rev()
        .find(|line| line.to_lowercase().contains("error"))
        .or(telling.last())
        .or(lines.last())?;
    Some(said.chars().take(200).collect())
}

/// Строка журнала OpenVPN без отметки времени («2026-11-22 19:20:01 »).
fn unstamped(line: &str) -> &str {
    let line = line.trim();
    let bytes = line.as_bytes();
    let stamped = bytes.len() > 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[..4].iter().all(u8::is_ascii_digit);
    if stamped {
        line[20..].trim()
    } else {
        line
    }
}

fn describe(remote: &str, wanted: bool, phase: &Phase, tunnel_up: bool, now: Instant) -> String {
    let state = match phase {
        Phase::Idle if !wanted => "не подключаюсь: ни одному приложению из списка не назначено".to_owned(),
        Phase::Idle => "готовлюсь".to_owned(),
        Phase::Foreign(name) => {
            format!("не подключаюсь: туннель «{name}» уже держит другая программа")
        }
        Phase::Running if tunnel_up => "подключено".to_owned(),
        Phase::Running => "подключаюсь…".to_owned(),
        Phase::Waiting { why, until } => format!(
            "не подключено: {why}; повтор через {} с",
            until.saturating_duration_since(now).as_secs().max(1)
        ),
        Phase::Unable(why) => format!("не подключено: {why}"),
        Phase::Off => "отключено тобой: «VPN…» → «Подключить»".to_owned(),
        Phase::NeedsCode(None) => {
            "нужен одноразовый код: «VPN…» → «Подключить…»".to_owned()
        }
        Phase::NeedsCode(Some(why)) => format!(
            "не подключено: {why}. Нужен новый одноразовый код: «VPN…» → «Подключить…»"
        ),
    };
    format!("{remote} — {state}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpnsplit_core::{AppRule, AppTarget};

    fn words(list: Vec<OsString>) -> String {
        list.iter().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn openvpn_is_told_to_leave_the_machine_alone() {
        let line = words(arguments(Path::new(r"C:\ProgramData\vpnsplit\vpn-1.ovpn"), None, None));
        assert!(line.starts_with(r"--config C:\ProgramData\vpnsplit\vpn-1.ovpn "), "{line}");
        assert!(line.contains("--route-nopull"), "{line}");
        assert!(line.contains("--script-security 1"), "{line}");
        assert!(!line.contains("--askpass") && !line.contains("--auth-user-pass"), "{line}");
        // Вхолостую — ни события остановки, ни адаптера, ни маршрута: до
        // адаптера дело не доходит.
        assert!(!line.contains("--route ") && !line.contains("--service"), "{line}");
        assert!(!line.contains("--dev-node"), "{line}");
        // По-настоящему — на названном адаптере и с маршрутом по умолчанию
        // с метрикой, при которой он ничего не притягивает.
        let live = live_arguments("evt", "OpenVPN TAP-Windows6 #2");
        assert_eq!(
            words(live.clone()),
            "--service evt 0 --dev-node OpenVPN TAP-Windows6 #2 --route 0.0.0.0 0.0.0.0 vpn_gateway 5000"
        );
        // Имя адаптера с пробелами — одно слово.
        assert_eq!(live[4].to_string_lossy(), "OpenVPN TAP-Windows6 #2");
        // Конфиг и файлы паролей — отдельными словами, даже если в пути
        // пробелы; с логином OpenVPN не переспрашивает.
        let spaced = arguments(
            Path::new(r"C:\My Data\vpn.ovpn"),
            Some(Path::new(r"C:\My Data\vpn.pass")),
            Some(Path::new(r"C:\My Data\vpn.auth")),
        );
        assert_eq!(spaced[1].to_string_lossy(), r"C:\My Data\vpn.ovpn");
        assert_eq!(spaced[3].to_string_lossy(), r"C:\My Data\vpn.pass");
        assert_eq!(spaced[5].to_string_lossy(), r"C:\My Data\vpn.auth");
        assert!(words(spaced).contains("--auth-retry none"));
    }

    #[test]
    fn a_refused_config_is_explained_in_plain_words() {
        let wrong = "2026-11-23 00:34:15 OpenSSL: error:1C800064:Provider routines::bad decrypt:\n\
                     2026-11-23 00:34:15 Cannot load private key file [[INLINE]]\n\
                     2026-11-23 00:34:15 Error: private key password verification failed\n\
                     2026-11-23 00:34:15 Exiting due to fatal error\n";
        assert_eq!(probe_failure(wrong), "пароль ключа не подошёл");
        let option = "2026-11-23 00:34:15 Options error: Unrecognized option or missing parameter(s): ns-cert-type\n\
                      2026-11-23 00:34:15 Use --help for more information.\n";
        let said = probe_failure(option);
        assert!(said.starts_with("OpenVPN не принял конфиг: Options error"), "{said}");
        assert!(probe_failure("").contains("не сказал"));
    }

    #[test]
    fn pauses_grow_and_then_hold() {
        let seconds: Vec<u64> = (0..8).map(|n| pause(n).as_secs()).collect();
        assert_eq!(seconds, [2, 2, 5, 15, 30, 60, 60, 60]);
    }

    #[test]
    fn the_reason_is_the_line_above_the_farewell() {
        let log = "2026-11-22 19:20:01 OpenVPN 2.7.6 [git:release] Windows\n\
                   2026-11-22 19:20:01 Options error: Unrecognized option or missing parameter(s): bogus\n\
                   2026-11-22 19:20:01 Use --help for more information.\n";
        assert_eq!(
            last_words(log).as_deref(),
            Some("Options error: Unrecognized option or missing parameter(s): bogus")
        );
        let log = "2026-11-22 19:20:05 All tap-windows6 adapters on this system are currently in use or disabled.\n\
                   2026-11-22 19:20:05 Exiting due to fatal error\n";
        // Слова «error» в причине нет — но прощание причиной не становится.
        assert!(last_words(log).unwrap().starts_with("All tap-windows6 adapters"));
        // А если кроме прощания ничего нет — хотя бы оно.
        assert_eq!(
            last_words("2026-11-22 19:20:05 Exiting due to fatal error\n").as_deref(),
            Some("Exiting due to fatal error")
        );
        let log = "2026-11-22 19:20:05 TLS Error: TLS key negotiation failed to occur within 60 seconds\n\
                   2026-11-22 19:20:05 SIGTERM[soft,exit-with-notification] received, process exiting\n";
        assert!(last_words(log).unwrap().starts_with("TLS Error"));
        assert_eq!(last_words("\n\n"), None);
        // Строка без отметки времени остаётся как есть.
        assert_eq!(unstamped("  просто строка "), "просто строка");
    }

    #[test]
    fn the_state_says_what_a_person_needs_to_know() {
        let now = Instant::now();
        let say = |wanted, phase: Phase, up| describe("s:1 (udp)", wanted, &phase, up, now);
        assert!(say(false, Phase::Idle, false).contains("не назначено"));
        // Запущенный OpenVPN — ещё не туннель: «подключено» только когда
        // туннель виден в сети.
        assert_eq!(say(true, Phase::Running, false), "s:1 (udp) — подключаюсь…");
        assert_eq!(say(true, Phase::Running, true), "s:1 (udp) — подключено");
        let foreign = say(true, Phase::Foreign("TAP".to_owned()), true);
        assert!(foreign.contains("«TAP»") && foreign.contains("другая программа"), "{foreign}");
        let waiting = say(
            true,
            Phase::Waiting { why: "нет адаптера".to_owned(), until: now + Duration::from_secs(15) },
            false,
        );
        assert!(waiting.contains("нет адаптера") && waiting.contains("через 15 с"), "{waiting}");
        // Время вышло, а строку ещё не обновили — минуса и нуля не бывает.
        let late = describe(
            "s",
            true,
            &Phase::Waiting { why: "x".to_owned(), until: now },
            false,
            now + Duration::from_secs(9),
        );
        assert!(late.contains("через 1 с"), "{late}");
        // Подключение по коду говорит, чего ждёт и чем кончилось прошлое.
        let code = say(true, Phase::NeedsCode(None), false);
        assert!(code.contains("нужен одноразовый код") && code.contains("Подключить"), "{code}");
        let again = say(true, Phase::NeedsCode(Some(BAD_CODE.to_owned())), false);
        assert!(again.contains("не принял") && again.contains("новый одноразовый код"), "{again}");
    }

    #[test]
    fn a_connection_is_wanted_by_the_rules_that_name_it() {
        let rule = |target: &str, vpn: Option<&str>| AppRule {
            vpn: vpn.map(str::to_owned),
            ..AppRule::tunnel_family(AppTarget::Package(target.to_owned()))
        };
        let policy = |rules: Vec<AppRule>| Policy { rules, ..Policy::default() };
        // Правило без названия держит первое подключение — и только его.
        let unnamed = policy(vec![rule("chat", None)]);
        assert!(wanted(&unnamed, "Зарубежный", true));
        assert!(!wanted(&unnamed, "Работа", false));
        // Названное — своё, как бы ни было набрано имя и каким бы по счёту
        // оно ни стояло.
        let named = policy(vec![rule("firefox", Some("работа"))]);
        assert!(wanted(&named, "Работа", false));
        assert!(!wanted(&named, "Зарубежный", true));
        // Пустой список не держит ничего.
        assert!(!wanted(&policy(Vec::new()), "Работа", true));
        // Правило «напрямую» туннеля не просит.
        let mut direct = rule("x", Some("Работа"));
        direct.routing = Routing::Direct;
        assert!(!wanted(&policy(vec![direct]), "Работа", true));
    }

    #[test]
    fn names_are_one_line_and_the_list_survives_the_disk() {
        assert_eq!(check_name("  Работа ").as_deref(), Ok("Работа"));
        assert!(check_name("   ").is_err());
        assert!(check_name("a\nb").is_err());
        assert!(check_name(&"я".repeat(NAME_LIMIT)).is_ok());
        assert!(check_name(&"я".repeat(NAME_LIMIT + 1)).is_err());
        assert!(same_name("Работа", "РАБОТА") && !same_name("Работа", "Работа 2"));
        let index = vec![(1, "Зарубежный".to_owned()), (4, "Работа \"офис\"".to_owned())];
        assert_eq!(index_from_json(&index_to_json(&index)), Some(index));
        assert_eq!(index_from_json("{}"), None);
        assert_eq!(index_from_json(r#"[{"id":"один","name":"x"}]"#), None);
        assert_eq!(index_from_json("[]"), Some(Vec::new()));
    }

    #[test]
    fn connections_are_kept_between_starts_and_forgotten_by_name() {
        let dir = std::env::temp_dir().join(format!("vpnsplit-vpn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::scratch(dir.clone());
        let source = "client\ndev tun\nremote 203.0.113.7 3333\nredirect-gateway def1\n\
                      <ca>\nA\n</ca>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n";
        let locked = source.replace("<key>\nC\n", "<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nC\n");
        let login = format!("{source}auth-user-pass\n");
        let none = Secrets::default();

        let vpns = Vpns::open(store.clone());
        assert!(vpns.states().is_empty());
        assert!(vpns.set_config(Some("Работа"), "up evil.bat\n", none).is_err());
        // Без пароля ключа и без логина, когда они нужны, — отказ до всякой
        // проверки и без следов на диске.
        assert!(vpns.set_config(Some("Работа"), &locked, none).unwrap_err().contains("пароль"));
        assert!(vpns.set_config(Some("Работа"), &login, none).unwrap_err().contains("логин"));
        let empty = Secrets { key_password: Some(""), login: Some(("", "")) };
        assert!(vpns.set_config(Some("Работа"), &locked, empty).is_err());
        assert!(vpns.set_config(Some("  "), source, none).is_err());
        assert!(vpns.states().is_empty());
        // Там, где OpenVPN установлен, конфиг проверяет он сам — и «ключ»
        // из одной буквы не примет. Отвергнутое не сохраняется, а файлы
        // проверки её не переживают.
        if find_openvpn().is_some() {
            let error = vpns.set_config(Some("Работа"), source, none).unwrap_err();
            assert!(error.starts_with("OpenVPN не принял конфиг"), "{error}");
            assert!(vpns.states().is_empty(), "отвергнутое не сохраняется");
            for name in [PROBE_CONFIG, PROBE_PASS, PROBE_AUTH, PROBE_LOG] {
                assert!(!dir.join(name).exists(), "{name} пережил проверку");
            }
        }

        // Дальше — принятые конфиги, как если бы проверка прошла.
        let add = |vpns: &Vpns, id: u32, name: &str, text: &str, secrets: Secrets| {
            let config = ovpn::sanitize(text).unwrap();
            let vpn = Vpn::new(&vpns.store, &vpns.hub, id, name, &config);
            vpn.accept(&config, secrets, true).unwrap();
            vpns.list().push(vpn);
            vpns.save_index();
        };
        add(&vpns, 1, "Зарубежный", &locked, Secrets { key_password: Some("пароль"), login: None });
        add(&vpns, 2, "Работа", &login, Secrets { key_password: None, login: Some(("иван", "тайна")) });
        assert_eq!(store.load_text("vpn-1.pass").as_deref(), Some("пароль\n"));
        assert_eq!(store.load_text("vpn-2.auth").as_deref(), Some("иван\nтайна\n"));
        // На диске — очищенное, а не присланное; логин в конфиг не попал.
        let saved = store.load_text("vpn-2.ovpn").unwrap();
        // На диске — очищенное, а не присланное. Вход по логину в тексте
        // помечен: по нему служба после перезапуска знает, что OpenVPN
        // нужен файл с логином.
        assert!(!saved.contains("redirect-gateway") && saved.contains("auth-user-pass"), "{saved}");
        let states = vpns.states();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].name, "Зарубежный");
        // Потоки не запущены, приложений нет — подключаться не для кого.
        assert!(states[1].line.starts_with("203.0.113.7:3333 (udp) — не подключаюсь"), "{}", states[1].line);
        assert!(!states[0].connected && states[0].address.is_none());

        // Пока ничего не поднято, названному правилу некуда, а правилу без
        // названия — в первое подключение, то есть тоже пока некуда.
        let rule = |target: &str, vpn: Option<&str>| AppRule {
            vpn: vpn.map(str::to_owned),
            ..AppRule::tunnel_family(AppTarget::Package(target.to_owned()))
        };
        let policy = Policy {
            rules: vec![rule("chat", None), rule("fox", Some("работа")), rule("gone", Some("Нет такого"))],
            ..Policy::default()
        };
        let specs = vpns.specs(&policy);
        assert_eq!(specs.len(), 3);
        if vpns.hub.foreign().is_none() {
            assert!(specs.values().all(|spec| spec.via == lanes::Via::Nowhere), "{specs:?}");
        } else {
            // На машине, где туннель держит другая программа, правило без
            // названия идёт в него; названные — всё равно никуда.
            assert!(matches!(specs["pkg:chat"].via, lanes::Via::Adapter(_)));
            assert_eq!(specs["pkg:fox"].via, lanes::Via::Nowhere);
            assert_eq!(specs["pkg:gone"].via, lanes::Via::Nowhere);
        }

        // Следующий запуск службы находит оба сам, в том же порядке.
        let again = Vpns::open(store.clone());
        let names: Vec<String> = again.states().into_iter().map(|state| state.name).collect();
        assert_eq!(names, ["Зарубежный", "Работа"]);
        // И помнит, чем каждое входит: первое — паролем ключа, второе —
        // логином. Кода не просит ни одно, и подсунуть его нельзя.
        {
            let list = again.list();
            let how = |at: usize| {
                let inner = list[at].lock();
                (inner.askpass, inner.auth, inner.by_code)
            };
            assert_eq!(how(0), (true, false, false));
            assert_eq!(how(1), (false, true, false));
        }
        assert!(again.connect("Работа", "123456").unwrap_err().contains("не нужен"));
        assert!(again.connect("Нет такого", "123456").is_err());
        // Подключение по коду: без назначенного приложения код не берётся,
        // а назначенное ждёт именно его.
        let coded = format!("{login}static-challenge \"Enter OTP token:\" 1\n");
        add(&again, 3, "По коду", &coded, Secrets { key_password: None, login: Some(("иван", "тайна")) });
        assert!(again.states()[2].by_code && !again.states()[1].by_code);
        assert!(again.connect("по коду", "12 34").is_err(), "пробел в коде");
        assert!(again.connect("по коду", "123456").unwrap_err().contains("не назначено"));
        let reread = Vpns::open(store.clone());
        assert!(reread.list()[2].lock().by_code, "после перезапуска код всё так же нужен");
        // Порядок — это и есть «по умолчанию»: первое. Его меняют, и он
        // переживает перезапуск; как и «отключено человеком» и новый логин.
        reread.act("работа", VpnAction::MakeDefault).unwrap();
        reread.act("Зарубежный", VpnAction::Disconnect).unwrap();
        let states = reread.states();
        assert_eq!(states[0].name, "Работа");
        assert!(states[0].login && !states[1].login);
        assert!(states[1].off && states[1].line.contains("отключено тобой"), "{}", states[1].line);
        assert!(reread.act("Нет такого", VpnAction::Connect).is_err());
        reread.set_login("Работа", "пётр", "новый").unwrap();
        assert_eq!(store.load_text("vpn-2.auth").as_deref(), Some("пётр\nновый\n"));
        assert!(reread.set_login("Зарубежный", "a", "b").unwrap_err().contains("без логина"));
        assert!(reread.set_login("Работа", "", "b").is_err());
        let later = Vpns::open(store.clone());
        let states = later.states();
        assert_eq!((states[0].name.as_str(), states[1].name.as_str()), ("Работа", "Зарубежный"));
        assert!(states[1].off && !states[0].off);
        later.act("Зарубежный", VpnAction::Connect).unwrap();
        later.act("Зарубежный", VpnAction::MakeDefault).unwrap();
        let states = later.states();
        assert!(states[0].name == "Зарубежный" && !states[0].off);
        assert!(!dir.join("vpn-1.off").exists());
        later.clear_config(Some("По коду")).unwrap();
        // Пропал пароль — подключение не используется и из списка уходит.
        store.remove("vpn-1.pass").unwrap();
        let without = Vpns::open(store.clone());
        assert_eq!(without.states().len(), 1);
        assert_eq!(without.states()[0].name, "Работа");
        // Забыть по имени — файлов нет; того, чего нет, забыть нельзя.
        assert!(without.clear_config(Some("Зарубежный")).is_err());
        without.clear_config(Some("РАБОТА")).unwrap();
        assert!(without.states().is_empty());
        assert_eq!(store.load_text("vpn-2.ovpn"), None);
        assert_eq!(store.load_text("vpn-2.auth"), None);
        assert_eq!(store.load_text(INDEX_FILE), None);
        assert!(Vpns::open(store.clone()).states().is_empty());
        // Без своих подключений указаний перехвату нет вовсе.
        assert!(without.specs(&policy).is_empty());

        // Конфиг первой версии становится подключением «VPN».
        store.save_secret(OLD_CONFIG, &ovpn::sanitize(source).unwrap().text).unwrap();
        let old = Vpns::open(store.clone());
        assert_eq!(old.states().len(), 1);
        assert_eq!(old.states()[0].name, "VPN");
        assert!(store.load_text(OLD_CONFIG).is_none() && store.load_text("vpn-1.ovpn").is_some());
        old.clear_config(None).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

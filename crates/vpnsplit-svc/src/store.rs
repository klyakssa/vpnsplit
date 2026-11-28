//! Хранение списка приложений и журнал службы.
//!
//! Служба хранит данные в `%ProgramData%\vpnsplit`. Каталог создаётся с
//! защищённым ACL: SYSTEM и администраторы — полный доступ, пользователи —
//! только чтение. Иначе любая программа пользователя могла бы молча
//! дописать себя в список или вычеркнуть оттуда браузер. Каталог, который
//! уже был и открыт посторонним на запись, служба откладывает в сторону и
//! начинает новый (см. `guard_dir`).
//!
//! Консольный режим (`vpnsplit-svc run`) работает от обычного пользователя
//! и в такой каталог писать не может, поэтому у него свой каталог
//! `vpnsplit-data` рядом с исполняемым файлом.
//!
//! Почему не `%LOCALAPPDATA%`: процессы, запущенные из упакованного (MSIX)
//! приложения, видят эту папку через виртуализацию пакета, а запущенные
//! снаружи — настоящую. Два экземпляра консольной службы видели разные
//! файлы политики. Каталог рядом с exe одинаков для всех.

use crate::flows::Remembered;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use vpnsplit_core::Policy;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_READ, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorControl, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, MoveFileExW, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    READ_CONTROL,
};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

/// P — защищённый (без наследования от родителя), OICI — права переходят
/// на файлы и подкаталоги. FA — полный доступ, FR — чтение. BU — пользователи.
/// Тот же дескриптор ставит каталогу установщик (`vpnsplit-setup`, `note`),
/// если заводит его первым.
const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";

/// Предел журнала службы. Больше — он уходит в `service.log.1` (прежний
/// `.1` пропадает), и пишется новый. Строки пишутся и на запросы обычных
/// пользователей, так что без предела журнал рос бы, пока не кончится диск.
const LOG_LIMIT: u64 = 5 * 1024 * 1024;

/// Копии `Store` делят один замок журнала — именно поэтому он под `Arc`.
/// С отдельным замком у каждой копии строки в файле перемешивались бы.
#[derive(Clone)]
pub struct Store {
    dir: PathBuf,
    echo: bool,
    /// Каталог защищён ACL: писать в него могут только SYSTEM и
    /// администраторы. От этого зависит, можно ли верить файлу-разрешению
    /// из него (см. `diagnostics_open`).
    protected: bool,
    /// Файлы с ключами создаются со своими правами (см. `save_secret`). В
    /// службе — всегда.
    private: bool,
    log_lock: std::sync::Arc<Mutex<()>>,
}

/// Файл, которым администратор разрешает проверки и опыты всем вошедшим
/// пользователям. Содержимое не важно, важно существование.
const DIAGNOSTICS_FILE: &str = "diagnostics.allow";

impl Store {
    pub fn for_service() -> Result<Self, String> {
        let base = std::env::var_os("ProgramData").ok_or("не задана переменная ProgramData")?;
        let dir = PathBuf::from(base).join("vpnsplit");
        // Каталогу, которому верить нельзя, служба не доверяет и не
        // работает в нём вовсе: `guard_dir` либо даёт свой каталог, либо
        // ошибку, и тогда служба не запускается.
        let guard = guard_dir(&dir)?;
        let store = Store {
            dir,
            echo: false,
            protected: true,
            private: true,
            log_lock: std::sync::Arc::new(Mutex::new(())),
        };
        if let Guard::Moved { aside, carried, owner_trusted } = guard {
            let taken = match (owner_trusted, carried.is_empty()) {
                (true, false) => {
                    format!("перенесены файлы, которые писали сама служба или администратор: {}", carried.join(", "))
                }
                (true, true) => "переносить из него нечего".to_owned(),
                (false, _) => "из него не взято ничего: его завёл посторонний, и содержимому верить \
                               нельзя — список приложений и подключения, если были, придётся задать заново"
                    .to_owned(),
            };
            store.log(&format!(
                "каталог данных был открыт посторонним на запись (его завёл не SYSTEM и не \
                 администратор, права у него были от ProgramData, или на его месте была ссылка или \
                 файл): он целиком отложен в {} и заменён новым, с правильными правами; {taken}. \
                 Отложенный каталог службе больше не нужен, его можно удалить",
                aside.display()
            ));
        }
        Ok(store)
    }

    /// Разрешил ли администратор проверки и опыты всем вошедшим
    /// пользователям.
    ///
    /// По умолчанию — нет: команды, которые перехватывают пакеты или
    /// отрезают приложения от сети, принимаются только от процесса с
    /// повышенными правами. Но на машине, где программу разрабатывают и
    /// проверяют, это означало бы запускать каждый замер из окна
    /// администратора. Поэтому есть явный выключатель — файл в каталоге
    /// данных. Создать его может только администратор (каталог защищён),
    /// то есть само разрешение и есть решение администратора, принятое
    /// один раз и видимое глазами.
    ///
    /// Спрашивается при каждом запросе, а не при старте: убрал файл —
    /// разрешение кончилось сразу, без перезапуска службы.
    ///
    /// В консольном режиме каталог лежит рядом с исполняемым файлом и
    /// доступен на запись кому угодно, поэтому файлу оттуда веры нет.
    pub fn diagnostics_open(&self) -> bool {
        self.protected && self.dir.join(DIAGNOSTICS_FILE).exists()
    }

    pub fn for_console() -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| format!("не удалось определить свой путь: {e}"))?;
        let dir = exe.with_file_name("vpnsplit-data");
        std::fs::create_dir_all(&dir).map_err(|e| format!("не удалось создать {}: {e}", dir.display()))?;
        Ok(Store {
            dir,
            echo: true,
            protected: false,
            private: false,
            log_lock: std::sync::Arc::new(Mutex::new(())),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Хранилище в готовом каталоге, без особых прав и без вывода на
    /// экран: для разовой работы от имени самого пользователя (проверка
    /// конфига из консоли) и для тестов.
    pub fn scratch(dir: PathBuf) -> Self {
        Store { dir, echo: false, protected: false, private: false, log_lock: std::sync::Arc::new(Mutex::new(())) }
    }

    fn policy_path(&self) -> PathBuf {
        self.dir.join("policy.json")
    }

    /// Нет файла — пустая политика. Битый файл откладывается в сторону, а
    /// не затирается: пользователь сможет его посмотреть.
    pub fn load(&self) -> Policy {
        let path = self.policy_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Policy::default(),
            Err(e) => {
                self.log(&format!("не удалось прочитать {}: {e}", path.display()));
                return Policy::default();
            }
        };
        match serde_json::from_str(&text) {
            Ok(policy) => policy,
            Err(e) => {
                match set_aside(&path) {
                    Ok(aside) => self.log(&format!("битый {}: {e}; отложен в {}", path.display(), aside.display())),
                    Err(why) => self.log(&format!("битый {}: {e}; отложить не удалось ({why})", path.display())),
                }
                Policy::default()
            }
        }
    }

    /// Запись через временный файл и переименование: при сбое посреди
    /// записи старая политика остаётся целой.
    pub fn save(&self, policy: &Policy) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(policy).map_err(std::io::Error::other)?;
        replace_file(&self.policy_path(), text.as_bytes(), false)
    }

    fn family_path(&self) -> PathBuf {
        self.dir.join(FAMILY_FILE)
    }

    /// Записывает, кто был под присмотром пути B в момент остановки службы.
    ///
    /// Пустой список файл не оставляет: «никого» и «записи нет» при старте
    /// значат одно и то же, а лишний файл в каталоге данных — лишний
    /// вопрос.
    pub fn save_family(&self, members: &[Remembered]) -> std::io::Result<()> {
        let path = self.family_path();
        if members.is_empty() {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        replace_file(&path, family_to_json(members).as_bytes(), false)
    }

    /// Читает запись и **сразу удаляет её**: она верна только для того
    /// запуска, который идёт следом за остановкой. Оставь мы файл, служба
    /// после падения подняла бы запись недельной давности — безвредно
    /// (время создания не сошлось бы), но незачем.
    ///
    /// Битая или непонятная запись — то же, что её отсутствие: вернуть
    /// под присмотр некого, и программы покажут «не ведётся».
    pub fn take_family(&self) -> Vec<Remembered> {
        let path = self.family_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                self.log(&format!("не удалось прочитать {}: {e}", path.display()));
                return Vec::new();
            }
        };
        let _ = std::fs::remove_file(&path);
        match family_from_json(&text) {
            Some(members) => members,
            None => {
                self.log(&format!("запись {} не разобрана и отброшена", path.display()));
                Vec::new()
            }
        }
    }

    fn learned_path(&self) -> PathBuf {
        self.dir.join(LEARNED_FILE)
    }

    /// Какие программы служба видела под правилами пути B: имя правила →
    /// пути к образам. В отличие от записи о процессах, это знание не
    /// одноразовое: оно нужно при каждом старте, чтобы запреты на время
    /// простоя стояли и на тех программах, которых сейчас нет в памяти.
    ///
    /// Нет файла или он битый — пусто: запреты останутся только на самих
    /// целях правил, а остальное служба узнает заново.
    pub fn load_learned(&self) -> Learned {
        let path = self.learned_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Learned::new(),
            Err(e) => {
                self.log(&format!("не удалось прочитать {}: {e}", path.display()));
                return Learned::new();
            }
        };
        learned_from_json(&text).unwrap_or_else(|| {
            self.log(&format!("{} не разобран; программы под правилами узнаются заново", path.display()));
            Learned::new()
        })
    }

    pub fn save_learned(&self, learned: &Learned) -> std::io::Result<()> {
        replace_file(&self.learned_path(), learned_to_json(learned).as_bytes(), false)
    }

    fn alone_path(&self) -> PathBuf {
        self.dir.join(ALONE_FILE)
    }

    /// Программы, которые служба видела и под правилом, и запущенными сами
    /// по себе. Помнить это между запусками нужно затем же, зачем и
    /// виденные программы: иначе после перезапуска службы `git`, запущенный
    /// приложением из списка, снова получил бы запрет — до первого своего
    /// самостоятельного запуска, которого при остановленной службе уже
    /// никто не заметит.
    ///
    /// Нет файла или он битый — пусто: узнается заново.
    pub fn load_alone(&self) -> Alone {
        let path = self.alone_path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Alone::new(),
            Err(e) => {
                self.log(&format!("не удалось прочитать {}: {e}", path.display()));
                return Alone::new();
            }
        };
        alone_from_json(&text).unwrap_or_else(|| {
            self.log(&format!("{} не разобран; узнается заново", path.display()));
            Alone::new()
        })
    }

    pub fn save_alone(&self, alone: &Alone) -> std::io::Result<()> {
        replace_file(&self.alone_path(), alone_to_json(alone).as_bytes(), false)
    }

    /// Записывает файл, который нельзя читать пользователям: конфиг своего
    /// подключения с закрытым ключом.
    ///
    /// Каталог данных открыт пользователям на чтение — так задумано, в нём
    /// журнал. Поэтому у такого файла свои права, без наследования: SYSTEM
    /// и администраторы. Права ставятся при создании, а не после: файл,
    /// который хоть миг пролежал открытым, уже могли прочесть.
    ///
    /// В консольном режиме каталог лежит рядом с программой и принадлежит
    /// тому, кто её запустил, — там файл обычный: закрыть его от самого
    /// владельца значило бы не дать службе его прочесть.
    pub fn save_secret(&self, name: &str, text: &str) -> std::io::Result<()> {
        // Переименование права не меняет: они у файла свои, не от каталога.
        replace_file(&self.dir.join(name), text.as_bytes(), self.private)
    }

    /// Записывает обычный файл каталога данных целиком — через временный
    /// файл и переименование, как и всё остальное здесь.
    pub fn save_text(&self, name: &str, text: &str) -> std::io::Result<()> {
        replace_file(&self.dir.join(name), text.as_bytes(), false)
    }

    /// Текст файла из каталога данных; `None` — файла нет или он не
    /// читается (о втором — строка в журнале).
    pub fn load_text(&self, name: &str) -> Option<String> {
        let path = self.dir.join(name);
        match std::fs::read_to_string(&path) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.log(&format!("не удалось прочитать {}: {e}", path.display()));
                None
            }
        }
    }

    /// Убирает остатки записей, оборванных падением службы или сбоем
    /// питания: временные файлы каталога данных, кроме своих.
    ///
    /// Имена временных файлов у каждой записи свои (`temp_beside`), и
    /// остаток оборванной записи следующая запись уже не перепишет — а
    /// среди них бывают и `vpn-N.pass`, `.auth`, `.once` с паролем или
    /// одноразовым кодом. Зовётся при старте службы, когда канал уже занят
    /// ею: другого экземпляра, чья запись могла бы идти прямо сейчас, нет.
    /// Свои (с номером этого процесса) не трогаются: их запись может ещё
    /// идти.
    pub fn sweep_leftovers(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        let own = std::process::id();
        let mut removed = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Только обычные файлы: ссылку или каталог с таким именем
            // служба не заводила, и не ей их убирать.
            if !is_leftover(&name, own) || !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            match std::fs::remove_file(entry.path()) {
                Ok(()) => removed.push(name),
                Err(e) => self.log(&format!("остаток оборванной записи {name} не убран: {e}")),
            }
        }
        if !removed.is_empty() {
            removed.sort();
            self.log(&format!("убраны остатки оборванных записей: {}", removed.join(", ")));
        }
    }

    /// Убирает файл из каталога данных. Нет файла — не ошибка.
    pub fn remove(&self, name: &str) -> std::io::Result<()> {
        match std::fs::remove_file(self.dir.join(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    pub fn log(&self, message: &str) {
        let t = unsafe {
            let mut t = std::mem::zeroed();
            GetLocalTime(&mut t);
            t
        };
        let line = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}  {message}\n",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
        );
        if self.echo {
            eprint!("{line}");
        }
        let _guard = self.log_lock.lock();
        let path = self.dir.join("service.log");
        let Ok(mut file) = open_log(&path, false) else { return };
        if file.metadata().is_ok_and(|meta| meta.len() >= LOG_LIMIT) {
            drop(file);
            // Переименование заменяет прежний `.1`. Не вышло — пишем дальше
            // в тот же: потерять строку хуже, чем перерасти предел.
            let _ = std::fs::rename(&path, self.dir.join("service.log.1"));
            let Ok(again) = open_log(&path, false) else { return };
            file = again;
        }
        let _ = file.write_all(line.as_bytes());
    }
}

/// Имя временного файла рядом с `path`, своё у каждой записи.
///
/// Раньше оно было постоянным (`policy.json.tmp`, а у файлов подключения и
/// вовсе одно на всех — `vpn-1.tmp`), и две одновременные записи из разных
/// потоков писали в один файл: содержимое перемешивалось, а второе
/// переименование не находило файла. Номер процесса и счётчик делают имя
/// своим у каждой записи; окончание `.tmp` оставлено — по нему остатки не
/// переносятся в новый каталог данных (см. `worth_carrying`).
fn temp_beside(path: &Path) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = path.file_name().map(|name| name.to_os_string()).unwrap_or_default();
    name.push(format!(".{}.{serial}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Остаток ли это оборванной записи: временный файл (`.tmp`), кроме тех,
/// что `temp_beside` назвала номером процесса `own`. Старые постоянные
/// имена (`policy.json.tmp`, `vpn-1.tmp`) — тоже остатки.
fn is_leftover(name: &str, own: u32) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(stem) = lower.strip_suffix(".tmp") else { return false };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let pid = stem
        .rsplit_once('.')
        .filter(|(_, serial)| digits(serial))
        .and_then(|(rest, _)| rest.rsplit_once('.'))
        .filter(|(_, pid)| digits(pid))
        .and_then(|(_, pid)| pid.parse::<u32>().ok());
    pid != Some(own)
}

/// Заменяет файл целиком: пишет новый временный файл, сбрасывает его на
/// диск и переименовывает на место. При сбое посреди записи прежний файл
/// остаётся целым, а временный убирается.
///
/// Временный файл создаётся только новым: чужой с тем же именем — остаток
/// упавшего процесса с тем же номером — не открывается (у него могут быть
/// не те права), а берётся следующее имя. `private` — файл сразу с правами
/// `SECRET_SDDL`.
///
/// Сброс на диск до переименования нужен затем, что после сбоя питания
/// переименование могло бы оказаться на диске раньше содержимого, и на
/// месте списка приложений остался бы пустой файл.
fn replace_file(path: &Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    let mut attempts = 0;
    let (tmp, mut file) = loop {
        let tmp = temp_beside(path);
        let created = if private {
            create_private(&tmp)
        } else {
            std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
        };
        match created {
            Ok(file) => break (tmp, file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempts < 8 => attempts += 1,
            Err(e) => return Err(e),
        }
    };
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let outcome = written.and_then(|()| std::fs::rename(&tmp, path));
    if outcome.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}

/// Открывает журнал на запись: дописывать (`truncate == false`) или с
/// начала. Не идёт по ссылкам: служба пишет от SYSTEM, и журнал, который
/// кто-то подменил символической ссылкой, точкой соединения или жёсткой
/// ссылкой на чужой файл, привёл бы её запись в системный файл. Такой
/// журнал не открывается вовсе.
pub fn open_log(path: &Path, truncate: bool) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    let mut options = std::fs::OpenOptions::new();
    // Без усечения при открытии: усекать можно только после проверки, что
    // это наш файл, а не ссылка.
    options.create(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if truncate {
        options.write(true);
    } else {
        options.append(true);
    }
    let file = options.open(path)?;
    let info = file_info(file.as_raw_handle() as HANDLE).ok_or_else(std::io::Error::last_os_error)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks > 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{} — ссылка, а не обычный файл; писать в него не стану", path.display()),
        ));
    }
    if truncate {
        file.set_len(0)?;
    }
    Ok(file)
}

fn file_info(handle: HANDLE) -> Option<BY_HANDLE_FILE_INFORMATION> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    (unsafe { GetFileInformationByHandle(handle, &mut info) } != 0).then_some(info)
}

/// Кто был под присмотром пути B на момент остановки службы.
///
/// Верить этому файлу можно ровно настолько, насколько защищён каталог: в
/// службе писать в него могут только SYSTEM и администраторы. Но и
/// подложенная запись немногого стоит: она может назвать только правило,
/// которое уже есть в списке, а список и так правит любой вошедший
/// пользователь.
const FAMILY_FILE: &str = "family.json";

fn family_to_json(members: &[Remembered]) -> String {
    let list: Vec<serde_json::Value> = members
        .iter()
        .map(|m| serde_json::json!({ "pid": m.pid, "created": m.created, "rule": m.rule }))
        .collect();
    serde_json::Value::Array(list).to_string()
}

/// `None` — это не наша запись. Частично годной записи не бывает: если в
/// ней есть хоть одна непонятная строка, неизвестно, чему в ней верить.
fn family_from_json(text: &str) -> Option<Vec<Remembered>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .as_array()?
        .iter()
        .map(|item| {
            Some(Remembered {
                pid: u32::try_from(item.get("pid")?.as_u64()?).ok()?,
                created: item.get("created")?.as_u64()?,
                rule: item.get("rule")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

/// Программы, виденные под правилами пути B: имя правила → образы. Ключ
/// образа — путь со сложенным регистром, значение — путь как он есть.
pub type Learned = std::collections::BTreeMap<String, std::collections::BTreeMap<String, PathBuf>>;

const LEARNED_FILE: &str = "learned.json";

fn learned_to_json(learned: &Learned) -> String {
    let mut object = serde_json::Map::new();
    for (rule, images) in learned {
        let list: Vec<serde_json::Value> = images
            .values()
            .map(|path| serde_json::Value::String(path.to_string_lossy().into_owned()))
            .collect();
        object.insert(rule.clone(), serde_json::Value::Array(list));
    }
    serde_json::Value::Object(object).to_string()
}

fn learned_from_json(text: &str) -> Option<Learned> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut learned = Learned::new();
    for (rule, list) in value.as_object()? {
        let images = learned.entry(rule.clone()).or_default();
        for item in list.as_array()? {
            let path = PathBuf::from(item.as_str()?);
            images.insert(path.to_string_lossy().to_lowercase(), path);
        }
    }
    Some(learned)
}

/// Программы, которые запускаются и сами по себе, не только под правилом:
/// путь со сложенным регистром → путь как он есть. Сеть на время простоя
/// службы им не закрывается.
pub type Alone = std::collections::BTreeMap<String, PathBuf>;

const ALONE_FILE: &str = "alone.json";

fn alone_to_json(alone: &Alone) -> String {
    let list: Vec<serde_json::Value> = alone
        .values()
        .map(|path| serde_json::Value::String(path.to_string_lossy().into_owned()))
        .collect();
    serde_json::Value::Array(list).to_string()
}

fn alone_from_json(text: &str) -> Option<Alone> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut alone = Alone::new();
    for item in value.as_array()? {
        let path = PathBuf::from(item.as_str()?);
        alone.insert(path.to_string_lossy().to_lowercase(), path);
    }
    Some(alone)
}

/// Стоит ли запоминать программу, чтобы закрывать ей сеть на время простоя
/// службы.
///
/// Это первый из двух отсевов, по месту. Второй — по поведению: программа,
/// которую видели запущенной и вне правил (`Alone`), тоже не запоминается,
/// где бы она ни лежала. Каталогом Windows общие инструменты не кончаются:
/// приложение из Store запускало `git` и `wsl` из `Program Files`, и запрет
/// оставил бы их без сети у всех.
///
/// Запрет ставится на образ, а не на процесс: он коснётся **каждого**
/// запуска этой программы на машине, а не только тех, что шли под
/// правилом. Для браузера, запущенного значком, это то, что нужно. Для
/// `cmd.exe`, `powershell.exe` или `curl.exe`, которые приложение из
/// списка запустило по своим делам, — нет: без сети остались бы все
/// командные окна и сценарии машины. Поэтому программы из каталога Windows
/// не запоминаются. Цена названа честно: такие потомки на время простоя
/// службы остаются с домашним интернетом.
pub fn worth_remembering(image: &Path, system_root: &Path) -> bool {
    let image = image.to_string_lossy().to_lowercase();
    let root = system_root.to_string_lossy().to_lowercase();
    let root = root.trim_end_matches('\\');
    if root.is_empty() {
        return true;
    }
    !(image.starts_with(root) && image[root.len()..].starts_with('\\'))
}

/// Права файла с ключами: SYSTEM и администраторы, и ничего от каталога
/// (P), где пользователям разрешено чтение.
const SECRET_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Создаёт новый файл сразу с правами `SECRET_SDDL`. Существующий файл не
/// открывает: у того права уже есть, и они могут быть не те.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};

    let sddl: Vec<u16> = std::ffi::OsStr::new(SECRET_SDDL).encode_wide().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    // Ошибку взять до LocalFree: тот вправе её затереть.
    let error = std::io::Error::last_os_error();
    unsafe { LocalFree(descriptor as _) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(error);
    }
    Ok(unsafe { std::fs::File::from_raw_handle(handle as _) })
}

/// Что нашлось на месте каталога данных.
#[derive(Debug, PartialEq, Eq)]
enum Guard {
    /// Создан только что, сразу с нашими правами.
    Created,
    /// Уже был, его завёл SYSTEM или администратор, и права у него свои,
    /// не унаследованные от ProgramData. Права не трогаем: возможно,
    /// администратор настроил их сам.
    Trusted,
    /// Было что-то другое: каталог, который завёл посторонний или который
    /// унаследовал права ProgramData (где файлы создают и обычные
    /// пользователи), ссылка или файл. Оно целиком отложено в `aside`, а на
    /// его месте создан новый каталог с нашими правами. `carried` — что
    /// перенесено из отложенного (см. `carry`).
    Moved { aside: PathBuf, carried: Vec<String>, owner_trusted: bool },
}

/// Дескриптор безопасности из строки SDDL; освобождается сам.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn parse(sddl: &str) -> Result<Self, String> {
        let text: Vec<u16> = std::ffi::OsStr::new(sddl).encode_wide().chain([0]).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("не удалось собрать ACL (код {})", unsafe { GetLastError() }));
        }
        Ok(Descriptor(descriptor))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0 as _) };
    }
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// Файл или каталог как он есть: ссылка открывается сама, а не то, на что
/// она указывает.
fn open_entry(path: &Path, access: u32) -> Option<Owned> {
    let handle = unsafe {
        CreateFileW(
            wide_path(path).as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    (handle != INVALID_HANDLE_VALUE).then_some(Owned(handle))
}

/// Владелец — SYSTEM или администраторы; и защищены ли права от
/// наследования. `None` — права не прочитались.
fn owner_and_protection(handle: HANDLE) -> Option<(bool, bool)> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return None;
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    let protected = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
        && control & SE_DACL_PROTECTED != 0;
    let admins = !owner.is_null()
        && unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
        };
    unsafe { LocalFree(descriptor as _) };
    Some((admins, protected))
}

fn owned_by_admins(handle: HANDLE) -> bool {
    owner_and_protection(handle).is_some_and(|(admins, _)| admins)
}

/// Каталог данных с правами, которым можно верить.
///
/// Новый каталог создаётся сразу с нашими правами. С уже существующим
/// сложнее: в ProgramData обычные пользователи вправе заводить подкаталоги,
/// и кто-то мог создать `vpnsplit` до установки, чтобы потом писать в него
/// вместе со службой: подложить `diagnostics.allow` или политику, подменить
/// конфиг OpenVPN между проверкой и запуском, превратить каталог в ссылку,
/// по которой служба от SYSTEM запишет свой файл куда угодно.
///
/// Чинить такой каталог на месте нельзя. Его права можно сменить, но
/// ручка, открытая хозяином раньше, сохраняет прежний доступ; а обход
/// содержимого по именам идёт туда, куда в этот миг ведёт имя каталога.
/// Поэтому чужое целиком **откладывается в сторону** переименованием — оно
/// не идёт по ссылкам и не требует прав на сам каталог: SYSTEM может
/// удалять и переименовывать в ProgramData что угодно. На освободившемся
/// месте создаётся новый каталог, сразу с нашими правами, и обходить
/// содержимое прежнего на месте не нужно вовсе.
///
/// Не вышло отложить — служба не запускается: работать в каталоге, где
/// хозяйничает посторонний, хуже, чем не работать.
fn guard_dir(dir: &Path) -> Result<Guard, String> {
    if create_fresh(dir)? {
        return Ok(Guard::Created);
    }
    if trusted_dir(dir) {
        return Ok(Guard::Trusted);
    }
    let aside = move_aside(dir)?;
    if !create_fresh(dir)? {
        // Имя заняли снова, пока каталог переезжал: так бывает только
        // нарочно.
        return Err(format!(
            "{} занят снова сразу после того, как прежний отложен в {}; служба в нём работать не станет",
            dir.display(),
            aside.display()
        ));
    }
    let (owner_trusted, carried) = carry(&aside, dir, owned_by_admins);
    Ok(Guard::Moved { aside, carried, owner_trusted })
}

/// `Ok(true)` — каталог создан нами, с нашими правами; `Ok(false)` — на
/// этом месте уже что-то есть.
fn create_fresh(dir: &Path) -> Result<bool, String> {
    let descriptor = Descriptor::parse(DATA_DIR_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let created = unsafe { CreateDirectoryW(wide_path(dir).as_ptr(), &attributes) };
    let code = unsafe { GetLastError() };
    if created != 0 {
        return Ok(true);
    }
    if code != ERROR_ALREADY_EXISTS {
        return Err(format!("не удалось создать {} (код {code})", dir.display()));
    }
    Ok(false)
}

/// Настоящий каталог (не ссылка), владелец — SYSTEM или администраторы, и
/// права не унаследованы. Всё, что не открылось или не прочиталось, —
/// не наш каталог.
fn trusted_dir(dir: &Path) -> bool {
    let Some(handle) = open_entry(dir, READ_CONTROL) else { return false };
    let Some(info) = file_info(handle.0) else { return false };
    info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        && owner_and_protection(handle.0) == Some((true, true))
}

/// Переименовывает то, что лежит на месте каталога, в `<имя>.old-<время>`
/// рядом. Переименование берёт саму запись каталога, будь то ссылка или
/// файл, и никуда по ней не идёт.
///
/// Каталог, внутри которого кто-то держит открытый файл, Windows не
/// переименует. Поэтому несколько попыток: журнал мог читать человек.
fn move_aside(dir: &Path) -> Result<PathBuf, String> {
    let t = unsafe {
        let mut t = std::mem::zeroed();
        GetLocalTime(&mut t);
        t
    };
    let base = dir.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let stamp = format!(
        "{base}.old-{:04}{:02}{:02}-{:02}{:02}{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    );
    let source = wide_path(dir);
    let mut last = 0;
    for attempt in 0..5 {
        for n in 0..100 {
            let name = if n == 0 { stamp.clone() } else { format!("{stamp}-{n}") };
            let aside = dir.with_file_name(name);
            if unsafe { MoveFileExW(source.as_ptr(), wide_path(&aside).as_ptr(), 0) } != 0 {
                return Ok(aside);
            }
            last = unsafe { GetLastError() };
            if last != ERROR_ALREADY_EXISTS && last != ERROR_FILE_EXISTS {
                break;
            }
        }
        if attempt < 4 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    Err(format!(
        "каталог данных {} завёл не SYSTEM и не администратор (или права у него от ProgramData, или \
         на его месте ссылка), а отложить его в сторону не удалось (код {last}). В таком каталоге \
         служба работать не станет. Закрой программы, которые держат в нём файлы, или удали его \
         от имени администратора, и запусти службу снова",
        dir.display()
    ))
}

/// Сколько файлов и какого размера переносится из отложенного каталога.
/// Свои файлы службы — это килобайты; предел — от мусора, подложенного
/// нарочно.
const CARRY_FILES: usize = 512;
const CARRY_SIZE: u64 = 4 * 1024 * 1024;

/// Переносит из отложенного каталога то, что писали сама служба или
/// администратор, — чтобы обновление с прежней версии, где каталог
/// наследовал права ProgramData, не теряло список приложений и
/// подключения. Возвращает, вышло ли поверить отложенному, и что
/// перенесено.
///
/// Верить можно, только если **сам каталог** завели SYSTEM или
/// администраторы: в таком обычный пользователь только добавляет свои
/// файлы — и они его, — а файлы службы ему не по правам. Каталог, который
/// завёл посторонний, мог и права на файлы службы раздать какие угодно —
/// оттуда не берётся ничего. Из своего каталога берутся только обычные
/// файлы (не ссылки, не каталоги, с одним именем), чей владелец SYSTEM или
/// администраторы. Журналы и остатки записи не переносятся: журналы
/// начнутся заново, с правами нового каталога.
///
/// Содержимое читается по открытой ручке и пишется в новый каталог заново,
/// с правами только для SYSTEM и администраторов (`create_private`):
/// среди файлов есть ключи, а служба потом всё равно перепишет их сама.
fn carry(from: &Path, to: &Path, trusted_owner: fn(HANDLE) -> bool) -> (bool, Vec<String>) {
    use std::io::Read;
    use std::os::windows::io::FromRawHandle;

    let mut carried = Vec::new();
    let trusted = open_entry(from, READ_CONTROL).is_some_and(|handle| {
        file_info(handle.0).is_some_and(|info| {
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        }) && trusted_owner(handle.0)
    });
    if !trusted {
        return (false, carried);
    }
    let Ok(entries) = std::fs::read_dir(from) else { return (true, carried) };
    for entry in entries.take(CARRY_FILES) {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        if !worth_carrying(&name) {
            continue;
        }
        let Some(handle) = open_entry(&from.join(&name), GENERIC_READ) else { continue };
        let ordinary = file_info(handle.0).is_some_and(|info| {
            info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0
                && info.nNumberOfLinks == 1
                && ((info.nFileSizeHigh as u64) << 32 | info.nFileSizeLow as u64) <= CARRY_SIZE
        });
        if !ordinary || !trusted_owner(handle.0) {
            continue;
        }
        let file = unsafe { std::fs::File::from_raw_handle(handle.0 as _) };
        std::mem::forget(handle);
        let mut bytes = Vec::new();
        if file.take(CARRY_SIZE + 1).read_to_end(&mut bytes).is_err() || bytes.len() as u64 > CARRY_SIZE {
            continue;
        }
        let written = create_private(&to.join(&name)).and_then(|mut out| out.write_all(&bytes));
        if written.is_ok() {
            carried.push(name);
        } else {
            let _ = std::fs::remove_file(to.join(&name));
        }
    }
    carried.sort();
    (true, carried)
}

/// Откладывает испорченный файл рядом, под именем `<имя>.broken`, а если
/// такое уже есть — `<имя>.2.broken` и дальше. `rename` молча лёг бы
/// поверх прежней отложенной копии, а она могла быть единственной записью
/// о том, что в ней было. Окончание `.broken` держится ради
/// `worth_carrying`. Нет самого файла — `NotFound`.
pub fn set_aside(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| std::io::Error::other("у пути нет имени файла"))?;
    for n in 1..=100u32 {
        let mut candidate = name.to_os_string();
        if n > 1 {
            candidate.push(format!(".{n}"));
        }
        candidate.push(".broken");
        let aside = path.with_file_name(candidate);
        // Занятым считается и имя, о котором не удалось узнать: лучше
        // следующий номер, чем риск лечь поверх.
        match aside.symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return std::fs::rename(path, &aside).map(|()| aside);
            }
            _ => continue,
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "отложенных копий уже сотня"))
}

/// Журналы и остатки записи не переносятся.
fn worth_carrying(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let log = lower.ends_with(".log")
        || lower.rsplit_once(".log.").is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    !(log || lower.ends_with(".tmp") || lower.ends_with(".broken"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: u32, created: u64, rule: &str) -> Remembered {
        Remembered { pid, created, rule: rule.to_owned() }
    }

    /// Свой каталог на каждый тест: они идут одновременно.
    fn scratch(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("vpnsplit-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Store { dir, echo: false, protected: false, private: false, log_lock: std::sync::Arc::new(Mutex::new(())) }
    }

    #[test]
    fn the_record_survives_the_trip_to_text_and_back() {
        // Время создания — большое число: 22.11.2026 в единицах FILETIME
        // не помещается в 53 бита без потерь, если где-то по дороге оно
        // побывает дробным.
        let members = [
            record(18752, 134_082_018_170_000_001, r"exe:c:\users\klyaksa\desktop\firefox.exe"),
            record(4, u64::MAX, "pkg:some.package_8wekyb3d8bbwe"),
        ];
        let text = family_to_json(&members);
        assert_eq!(family_from_json(&text).as_deref(), Some(&members[..]));
    }

    #[test]
    fn a_record_that_is_not_ours_is_refused_whole() {
        assert_eq!(family_from_json("не json"), None);
        assert_eq!(family_from_json(r#"{"pid":1}"#), None);
        // Одна негодная строка — негодна вся запись.
        let mixed = r#"[{"pid":1,"created":2,"rule":"a"},{"pid":"два","created":2,"rule":"a"}]"#;
        assert_eq!(family_from_json(mixed), None);
        // Номер процесса больше, чем бывает.
        assert_eq!(family_from_json(r#"[{"pid":4294967296,"created":2,"rule":"a"}]"#), None);
        assert_eq!(family_from_json(r#"[{"pid":1,"created":-2,"rule":"a"}]"#), None);
        // А пустая запись — это запись: никого.
        assert_eq!(family_from_json("[]"), Some(Vec::new()));
    }

    #[test]
    fn system_tools_are_not_remembered_and_real_programs_are() {
        let root = Path::new(r"C:\Windows");
        // Потомки-инструменты: запрет на них задел бы всю машину.
        assert!(!worth_remembering(Path::new(r"C:\Windows\System32\cmd.exe"), root));
        assert!(!worth_remembering(Path::new(r"c:\windows\system32\CURL.EXE"), root));
        assert!(!worth_remembering(Path::new(r"C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"), root));
        // Настоящие программы — запоминаются.
        assert!(worth_remembering(Path::new(r"C:\Program Files\Mozilla Firefox\firefox.exe"), root));
        assert!(worth_remembering(Path::new(r"C:\Users\k\Desktop\Firefox.exe"), root));
        // Каталог, который только начинается так же, — не каталог Windows.
        assert!(worth_remembering(Path::new(r"C:\WindowsApps\tool.exe"), root));
        assert!(worth_remembering(Path::new(r"C:\Windows.old\System32\cmd.exe"), root));
        // Косая на конце в переменной окружения ничего не меняет.
        assert!(!worth_remembering(Path::new(r"C:\Windows\explorer.exe"), Path::new(r"C:\Windows\")));
    }

    #[test]
    fn learned_programs_survive_the_trip_to_text_and_back() {
        let mut learned = Learned::new();
        let firefox = PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe");
        learned
            .entry("exe:c:\\users\\k\\desktop\\firefox.exe".to_owned())
            .or_default()
            .insert(firefox.to_string_lossy().to_lowercase(), firefox.clone());
        let text = learned_to_json(&learned);
        assert_eq!(learned_from_json(&text), Some(learned));
        // Написание пути сохраняется как было: его увидит человек.
        assert!(text.contains("Mozilla Firefox"), "{text}");
        assert_eq!(learned_from_json("[]"), None);
        assert_eq!(learned_from_json(r#"{"правило":"не список"}"#), None);
        assert_eq!(learned_from_json(r#"{"правило":[1]}"#), None);
    }

    #[test]
    fn programs_that_run_on_their_own_are_kept_between_starts() {
        let store = scratch("alone");
        assert!(store.load_alone().is_empty());
        let mut alone = Alone::new();
        let git = PathBuf::from(r"C:\Program Files\Git\cmd\git.exe");
        alone.insert(git.to_string_lossy().to_lowercase(), git.clone());
        store.save_alone(&alone).unwrap();
        assert_eq!(store.load_alone(), alone);
        // Ключ — со сложенным регистром, значение — как было.
        assert_eq!(store.load_alone().get(r"c:\program files\git\cmd\git.exe"), Some(&git));
        // Чужое и битое — пусто, а не половина.
        assert_eq!(alone_from_json(r#"{"a":1}"#), None);
        assert_eq!(alone_from_json(r#"["a", 1]"#), None);
        std::fs::write(store.alone_path(), "мусор").unwrap();
        assert!(store.load_alone().is_empty());
    }

    #[test]
    fn learned_programs_are_kept_between_starts() {
        let store = scratch("learned");
        assert!(store.load_learned().is_empty());
        let mut learned = Learned::new();
        learned
            .entry("правило".to_owned())
            .or_default()
            .insert("c:\\a.exe".to_owned(), PathBuf::from(r"C:\a.exe"));
        store.save_learned(&learned).unwrap();
        // В отличие от записи о процессах, читается сколько угодно раз.
        assert_eq!(store.load_learned(), learned);
        assert_eq!(store.load_learned(), learned);
        std::fs::write(store.learned_path(), "мусор").unwrap();
        assert!(store.load_learned().is_empty());
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn a_secret_file_is_written_replaced_and_removed() {
        let store = scratch("secret");
        assert_eq!(store.load_text("vpn.ovpn"), None);
        store.save_secret("vpn.ovpn", "первый").unwrap();
        // Остаток прошлой неудачной записи новой не мешает.
        std::fs::write(store.dir().join("vpn.tmp"), "мусор").unwrap();
        store.save_secret("vpn.ovpn", "второй").unwrap();
        assert_eq!(store.load_text("vpn.ovpn").as_deref(), Some("второй"));
        // Своих временных файлов запись после себя не оставляет.
        let leftovers: Vec<String> = std::fs::read_dir(store.dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp") && name != "vpn.tmp")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        store.remove("vpn.ovpn").unwrap();
        store.remove("vpn.ovpn").unwrap();
        assert_eq!(store.load_text("vpn.ovpn"), None);
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn the_service_log_moves_aside_when_it_grows_too_big() {
        let store = scratch("rotate");
        let log = store.dir().join("service.log");
        std::fs::write(&log, vec![b'x'; LOG_LIMIT as usize]).unwrap();
        store.log("строка после предела");
        let old = std::fs::metadata(store.dir().join("service.log.1")).unwrap();
        assert_eq!(old.len(), LOG_LIMIT);
        let fresh = std::fs::read_to_string(&log).unwrap();
        assert!(fresh.contains("строка после предела") && fresh.len() < 200, "{fresh}");
        // Следующий переезд заменяет прежний `.1`, а не копит их.
        std::fs::write(&log, vec![b'y'; LOG_LIMIT as usize]).unwrap();
        store.log("ещё");
        assert_eq!(std::fs::read(store.dir().join("service.log.1")).unwrap()[0], b'y');
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn a_log_is_not_written_through_a_link() {
        let store = scratch("links");
        let victim = store.dir().join("victim.txt");
        std::fs::write(&victim, "чужой файл").unwrap();
        let log = store.dir().join("openvpn-1.log");
        std::fs::hard_link(&victim, &log).unwrap();
        assert!(open_log(&log, true).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "чужой файл");

        // Обычный журнал открывается, а с усечением начинается с нуля.
        let own = store.dir().join("verify.log");
        std::fs::write(&own, "прошлый запуск").unwrap();
        let mut file = open_log(&own, true).unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        assert_eq!(std::fs::read_to_string(&own).unwrap(), "new");
        let mut file = open_log(&own, false).unwrap();
        file.write_all(b"+").unwrap();
        drop(file);
        assert_eq!(std::fs::read_to_string(&own).unwrap(), "new+");
        let _ = std::fs::remove_dir_all(store.dir());
    }

    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|out| out.status.success())
    }

    #[test]
    fn a_fresh_data_dir_is_made_with_our_rights_and_a_foreign_one_is_moved_aside() {
        let base = std::env::temp_dir().join(format!("vpnsplit-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.join("vpnsplit");
        assert_eq!(guard_dir(&dir), Ok(Guard::Created));
        // Второй раз каталог уже есть. Тест работает не от SYSTEM: каталог
        // принадлежит ему самому, а владельцем SYSTEM его сделать нельзя.
        // Значит, либо каталогу верят (повышенный процесс — его владелец
        // группа администраторов), либо он отложен, и на его месте новый.
        match guard_dir(&dir).unwrap() {
            Guard::Trusted => {}
            Guard::Moved { aside, carried, owner_trusted } => {
                assert!(!owner_trusted && carried.is_empty(), "{carried:?}");
                assert!(aside.is_dir() && dir.is_dir(), "{}", aside.display());
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_link_or_a_file_in_place_of_the_data_dir_is_moved_aside_and_its_target_left_alone() {
        let base = std::env::temp_dir().join(format!("vpnsplit-guard-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let target = base.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("keep.txt"), "x").unwrap();

        // Файл на месте каталога — не повод службе не запускаться.
        let file = base.join("plain");
        std::fs::write(&file, "не каталог").unwrap();
        let Guard::Moved { aside, carried, owner_trusted } = guard_dir(&file).unwrap() else { panic!() };
        assert!(!owner_trusted && carried.is_empty());
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), "не каталог");
        assert!(std::fs::symlink_metadata(&file).unwrap().is_dir());

        let dir = base.join("vpnsplit");
        if !junction(&dir, &target) {
            eprintln!("mklink /J не сработал — проверка ссылки пропущена");
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        let guard = guard_dir(&dir).unwrap();
        let Guard::Moved { aside, carried, owner_trusted } = guard else { panic!("{guard:?}") };
        // Отложена сама ссылка; через неё ничего не взято и не тронуто.
        assert!(!owner_trusted && carried.is_empty());
        let meta = std::fs::symlink_metadata(&dir).unwrap();
        assert!(meta.is_dir() && !meta.file_type().is_symlink());
        assert!(target.join("keep.txt").exists());
        assert!(aside.join("keep.txt").exists(), "отложена ссылка, а не то, на что она указывает");
        let _ = std::fs::remove_dir(&aside);
        assert!(target.join("keep.txt").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn only_ordinary_files_of_trusted_owners_are_carried_over_and_links_are_never_followed() {
        let base = std::env::temp_dir().join(format!("vpnsplit-carry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("system.dat"), "важное").unwrap();
        let from = base.join("old");
        std::fs::create_dir_all(from.join("update")).unwrap();
        std::fs::write(from.join("update").join("setup.exe"), "подложено").unwrap();
        std::fs::write(from.join("policy.json"), "политика").unwrap();
        std::fs::write(from.join(DIAGNOSTICS_FILE), "").unwrap();
        for leftover in ["service.log", "service.log.1", "openvpn-1.log", "policy.json.tmp", "policy.json.broken"] {
            std::fs::write(from.join(leftover), "x").unwrap();
        }
        std::fs::hard_link(outside.join("system.dat"), from.join("vpns.json")).unwrap();
        let linked = junction(&from.join("logs"), &outside);

        // Владелец проверяется отдельно: тест не может завести файл от
        // имени SYSTEM, поэтому «верим всем» и «не верим никому».
        let to = base.join("new");
        std::fs::create_dir_all(&to).unwrap();
        let (trusted, carried) = carry(&from, &to, |_| true);
        assert!(trusted);
        assert_eq!(carried, [DIAGNOSTICS_FILE, "policy.json"], "linked: {linked}");
        // Перенесённое закрыто от обычных пользователей, а тест работает
        // обычно не от администратора: тогда сверяется хотя бы размер.
        match std::fs::read_to_string(to.join("policy.json")) {
            Ok(text) => assert_eq!(text, "политика"),
            Err(_) => assert_eq!(std::fs::metadata(to.join("policy.json")).unwrap().len(), "политика".len() as u64),
        }
        assert!(!to.join("vpns.json").exists() && !to.join("update").exists() && !to.join("logs").exists());
        // То, на что указывали ссылки, цело.
        assert_eq!(std::fs::read_to_string(outside.join("system.dat")).unwrap(), "важное");

        let none = base.join("none");
        std::fs::create_dir_all(&none).unwrap();
        assert_eq!(carry(&from, &none, |_| false), (false, Vec::new()));
        assert_eq!(std::fs::read_dir(&none).unwrap().count(), 0);
        if linked {
            let _ = std::fs::remove_dir(from.join("logs"));
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn logs_and_leftovers_are_not_worth_carrying() {
        for name in ["policy.json", "vpn-3.ovpn", "vpn-3.pass", "no-update", "learned.json", "service.logic"] {
            assert!(worth_carrying(name), "{name}");
        }
        for name in ["service.log", "SERVICE.LOG.1", "openvpn-2.log", "setup.log", "vpn-1.tmp", "policy.json.broken"] {
            assert!(!worth_carrying(name), "{name}");
        }
    }

    #[test]
    fn simultaneous_writes_of_one_file_do_not_mix_and_all_succeed() {
        // Раньше у всех записей одного файла был общий временный файл: две
        // одновременные перемешивали содержимое, и одна падала на
        // переименовании. Теперь каждая пишет своё и целиком.
        let store = scratch("simultaneous");
        let texts: Vec<String> = (0..8).map(|n| n.to_string().repeat(64 * 1024)).collect();
        std::thread::scope(|scope| {
            for text in &texts {
                let store = &store;
                scope.spawn(move || {
                    for _ in 0..10 {
                        store.save_secret("vpn-1.once", text).unwrap();
                        store.save_text("vpns.json", text).unwrap();
                    }
                });
            }
        });
        for name in ["vpn-1.once", "vpns.json"] {
            let found = store.load_text(name).unwrap();
            assert!(texts.contains(&found), "{name}: содержимое перемешалось");
        }
        let leftovers = std::fs::read_dir(store.dir())
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn only_foreign_and_old_temporary_files_count_as_leftovers() {
        let own = 4242;
        for name in ["vpn-1.pass.17.3.tmp", "policy.json.1.0.TMP", "policy.json.tmp", "vpn-1.tmp", "x.4242.tmp"] {
            assert!(is_leftover(name, own), "{name}");
        }
        for name in ["vpn-1.pass.4242.3.tmp", "policy.json", "vpn-1.pass", "service.log", "tmp", "a.tmp.bak"] {
            assert!(!is_leftover(name, own), "{name}");
        }
        // Имя, которое даёт `temp_beside` этому процессу, — своё.
        let mine = temp_beside(Path::new(r"C:\data\vpn-1.once"));
        assert!(!is_leftover(&mine.file_name().unwrap().to_string_lossy(), std::process::id()));
    }

    #[test]
    fn the_sweep_removes_leftovers_and_keeps_everything_else() {
        let store = scratch("sweep");
        let own = temp_beside(&store.dir().join("vpn-1.once"));
        let own_name = own.file_name().unwrap().to_string_lossy().into_owned();
        for name in ["vpn-1.pass.1.0.tmp", "vpn-1.tmp", "policy.json", "vpn-1.pass", own_name.as_str()] {
            std::fs::write(store.dir().join(name), "x").unwrap();
        }
        std::fs::create_dir(store.dir().join("dir.1.0.tmp")).unwrap();
        store.sweep_leftovers();
        let mut left: Vec<String> = std::fs::read_dir(store.dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "service.log")
            .collect();
        left.sort();
        let mut expected = vec!["dir.1.0.tmp".to_owned(), own_name, "policy.json".to_owned(), "vpn-1.pass".to_owned()];
        expected.sort();
        assert_eq!(left, expected);
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn a_temporary_name_is_new_each_time_and_still_ends_in_tmp() {
        let path = Path::new(r"C:\data\policy.json");
        let (a, b) = (temp_beside(path), temp_beside(path));
        assert_ne!(a, b);
        assert_eq!(a.parent(), path.parent());
        let name = a.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("policy.json.") && name.ends_with(".tmp"), "{name}");
        assert!(!worth_carrying(&name));
    }

    #[test]
    fn a_private_file_is_closed_to_ordinary_users_from_its_first_moment() {
        // Сами права проверяет Windows; здесь — что файл создаётся именно
        // новым и что описание прав она принимает. От обычного пользователя
        // такой файл после создания уже не прочесть — это и есть признак.
        let store = scratch("private");
        let path = store.dir().join("key.tmp");
        let mut file = create_private(&path).expect("описание прав принято, файл создан");
        file.write_all(b"x").unwrap();
        drop(file);
        // Второй раз тот же файл не создаётся: открыть существующий — значит
        // унаследовать чужие права.
        assert!(create_private(&path).is_err());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn the_record_is_read_once_and_then_gone() {
        let store = scratch("once");
        let members = [record(100, 5, "значок")];
        store.save_family(&members).unwrap();
        assert_eq!(store.take_family(), members);
        // Второй раз читать нечего: запись верна для одного запуска.
        assert!(store.take_family().is_empty());
        assert!(!store.family_path().exists());
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn saving_nobody_leaves_no_file_and_clears_an_old_one() {
        let store = scratch("nobody");
        store.save_family(&[record(100, 5, "значок")]).unwrap();
        store.save_family(&[]).unwrap();
        assert!(!store.family_path().exists());
        // И удалять нечего — тоже не ошибка.
        store.save_family(&[]).unwrap();
        assert!(store.take_family().is_empty());
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn a_broken_record_is_dropped_not_kept_for_next_time() {
        let store = scratch("broken");
        std::fs::write(store.family_path(), "мусор").unwrap();
        assert!(store.take_family().is_empty());
        assert!(!store.family_path().exists());
        let _ = std::fs::remove_dir_all(store.dir());
    }

    #[test]
    fn a_second_broken_copy_does_not_overwrite_the_first() {
        let store = scratch("aside");
        let path = store.dir().join("vpns.json");
        std::fs::write(&path, "первый").unwrap();
        assert_eq!(set_aside(&path).unwrap(), store.dir().join("vpns.json.broken"));
        std::fs::write(&path, "второй").unwrap();
        assert_eq!(set_aside(&path).unwrap(), store.dir().join("vpns.json.2.broken"));
        assert_eq!(std::fs::read_to_string(store.dir().join("vpns.json.broken")).unwrap(), "первый");
        assert_eq!(std::fs::read_to_string(store.dir().join("vpns.json.2.broken")).unwrap(), "второй");
        assert!(!worth_carrying("vpns.json.2.broken"));
        assert_eq!(set_aside(&path).unwrap_err().kind(), std::io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(store.dir());
    }
}

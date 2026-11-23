//! Хранение списка приложений и журнал службы.
//!
//! Служба хранит данные в `%ProgramData%\vpnsplit`. Каталог создаётся с
//! защищённым ACL: SYSTEM и администраторы — полный доступ, пользователи —
//! только чтение. Иначе любая программа пользователя могла бы молча
//! дописать себя в список или вычеркнуть оттуда браузер.
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
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

/// P — защищённый (без наследования от родителя), OICI — права переходят
/// на файлы и подкаталоги. FA — полный доступ, FR — чтение. BU — пользователи.
const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";

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
    log_lock: std::sync::Arc<Mutex<()>>,
}

/// Файл, которым администратор разрешает проверки и опыты всем вошедшим
/// пользователям. Содержимое не важно, важно существование.
const DIAGNOSTICS_FILE: &str = "diagnostics.allow";

impl Store {
    pub fn for_service() -> Result<Self, String> {
        let base = std::env::var_os("ProgramData").ok_or("не задана переменная ProgramData")?;
        let dir = PathBuf::from(base).join("vpnsplit");
        create_protected_dir(&dir)?;
        Ok(Store { dir, echo: false, protected: true, log_lock: std::sync::Arc::new(Mutex::new(())) })
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
        Ok(Store { dir, echo: true, protected: false, log_lock: std::sync::Arc::new(Mutex::new(())) })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Хранилище в готовом каталоге, без особых прав и без вывода на
    /// экран: для разовой работы от имени самого пользователя (проверка
    /// конфига из консоли) и для тестов.
    pub fn scratch(dir: PathBuf) -> Self {
        Store { dir, echo: false, protected: false, log_lock: std::sync::Arc::new(Mutex::new(())) }
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
                let aside = path.with_extension("json.broken");
                let _ = std::fs::rename(&path, &aside);
                self.log(&format!("битый {}: {e}; отложен в {}", path.display(), aside.display()));
                Policy::default()
            }
        }
    }

    /// Запись через временный файл и переименование: при сбое посреди
    /// записи старая политика остаётся целой.
    pub fn save(&self, policy: &Policy) -> std::io::Result<()> {
        let path = self.policy_path();
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(policy).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &path)
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
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, family_to_json(members))?;
        std::fs::rename(&tmp, &path)
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
        let path = self.learned_path();
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, learned_to_json(learned))?;
        std::fs::rename(&tmp, &path)
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
        let path = self.alone_path();
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, alone_to_json(alone))?;
        std::fs::rename(&tmp, &path)
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
        let path = self.dir.join(name);
        let tmp = path.with_extension("tmp");
        if !self.protected {
            std::fs::write(&tmp, text)?;
            return std::fs::rename(&tmp, &path);
        }
        // Остаток прошлой неудачной записи мешал бы создать файл заново, а
        // открыть существующий нельзя: права у него остались бы прежние.
        match std::fs::remove_file(&tmp) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut file = create_private(&tmp)?;
        file.write_all(text.as_bytes())?;
        drop(file);
        // Переименование права не меняет: они у файла свои, не от каталога.
        std::fs::rename(&tmp, &path)
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
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("service.log"))
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
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

/// ACL ставится только при создании каталога. Если каталог уже есть, его
/// права не трогаем: возможно, администратор настроил их сам.
fn create_protected_dir(dir: &Path) -> Result<(), String> {
    let sddl: Vec<u16> = std::ffi::OsStr::new(DATA_DIR_SDDL).encode_wide().chain([0]).collect();
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
        return Err(format!("не удалось собрать ACL каталога (код {})", unsafe { GetLastError() }));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let path: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    let created = unsafe { CreateDirectoryW(path.as_ptr(), &attributes) };
    let code = unsafe { GetLastError() };
    unsafe { LocalFree(descriptor as _) };
    if created == 0 && code != ERROR_ALREADY_EXISTS {
        return Err(format!("не удалось создать {} (код {code})", dir.display()));
    }
    Ok(())
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
        Store { dir, echo: false, protected: false, log_lock: std::sync::Arc::new(Mutex::new(())) }
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
        assert!(!store.dir().join("vpn.tmp").exists());
        store.remove("vpn.ovpn").unwrap();
        store.remove("vpn.ovpn").unwrap();
        assert_eq!(store.load_text("vpn.ovpn"), None);
        let _ = std::fs::remove_dir_all(store.dir());
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
}

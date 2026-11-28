//! vpnsplit-setup — установщик: один файл, который ставит, обновляет и
//! удаляет программу.
//!
//! Зачем он. Программа жила в папке сборки, и любая правка службы была
//! ручной пересборкой из окна администратора; всё это время приложения из
//! списка сидели без сети — запреты на время простоя службы для того и
//! стоят. Установщик делает то же за секунды: останавливает службу,
//! подменяет файлы и запускает её снова.
//!
//! Обновление — это тот же установщик поновее, запущенный поверх. Настройки
//! (`%ProgramData%\vpnsplit`: список приложений, свои подключения) он не
//! трогает ни при обновлении, ни при удалении.
//!
//! Служба при обновлении не создаётся заново: ей меняется только путь к
//! файлу. Удалить и создать — значит споткнуться о «служба помечена на
//! удаление», если у кого-нибудь открыта оснастка служб, и потерять её
//! настройки возврата после падения.

#![windows_subsystem = "windows"]

mod payload {
    include!(concat!(env!("OUT_DIR"), "/payload.rs"));
}

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SERVICE_DOES_NOT_EXIST, GetLastError, BOOL, HANDLE, HWND, LPARAM, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId,
    TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSQueryUserToken};
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_SZ,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
    QueryServiceConfigW, QueryServiceStatus, StartServiceW, QUERY_SERVICE_CONFIGW,
    SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP, SERVICE_NO_CHANGE,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS,
    SERVICE_STOP, SERVICE_STOPPED,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, STARTF_FORCEOFFFEEDBACK, STARTUPINFOW,
};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindow, GetWindowThreadProcessId, IsWindowVisible, MessageBoxW, GW_OWNER, IDOK,
    MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OKCANCEL, SW_SHOWNORMAL,
};

/// Имя службы — то же, что в `vpnsplit_core::SERVICE_NAME`. Вписано сюда,
/// чтобы установщик не тянул за собой остальную программу.
const SERVICE: &str = "vpnsplit";
const SVC: &str = "vpnsplit-svc.exe";
const UI: &str = "vpnsplit-ui.exe";
const SELF: &str = "vpnsplit-setup.exe";
const TITLE: &str = "vpnsplit — установка";
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\vpnsplit";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Журнал установщика: в каталоге данных, а если ему нельзя верить — в
/// папке установки (см. `note`).
const LOG: &str = "setup.log";

/// Ключ, с которым установщик запускает сам себя в сеансе пользователя:
/// «есть ли у этих процессов окно на виду» (см. `shown_in`). Ответ — код
/// выхода; коды необычные, чтобы ни сбой, ни чужой выход за ответ не сошли.
const SHOWN_FLAG: &str = "/shown";
const SHOWN: i32 = 0x5653_0001;
const HIDDEN: i32 = 0x5653_0000;
/// Сколько ждать этого ответа. Не дождались — окно считается спрятанным,
/// как и было до проверки.
const SHOWN_PATIENCE_MS: u32 = 5000;

/// Сколько ждать остановки службы: она сама ждёт, пока выйдет OpenVPN.
const STOP_PATIENCE: Duration = Duration::from_secs(45);

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn message(text: &str, flags: u32) -> i32 {
    unsafe { MessageBoxW(std::ptr::null_mut(), wide(text).as_ptr(), wide(TITLE).as_ptr(), flags) }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Мы же, запущенные из `shown_in` в сеансе пользователя: только ответить.
    // До проверки прав — ни установки, ни вопросов.
    if let Some(pids) = shown_pids(&args) {
        std::process::exit(if any_shown(&pids) { SHOWN } else { HIDDEN });
    }
    let quiet = args.iter().any(|a| a.eq_ignore_ascii_case("/quiet"));
    let removing = args.iter().any(|a| a.eq_ignore_ascii_case("/uninstall"));

    // Всё, что мы делаем, требует прав администратора. Спрашиваем их сами,
    // а не просим «запустить от администратора»: это один щелчок в окне
    // Windows вместо поиска нужного пункта в меню.
    if unsafe { IsUserAnAdmin() } == 0 {
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
        let started = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                wide("runas").as_ptr(),
                wide(&exe).as_ptr(),
                wide(&args.join(" ")).as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // Отказ в окне Windows — тоже ответ; повторять вопрос незачем.
        if started as usize <= 32 && !quiet {
            message("Без прав администратора установить программу нельзя: она ставит службу Windows.", MB_ICONERROR);
        }
        return;
    }

    let outcome = if removing { remove(quiet) } else { install(quiet) };
    match outcome {
        Ok(Some(text)) if !quiet => {
            message(&text, MB_ICONINFORMATION);
        }
        Ok(Some(text)) => note(&text),
        Ok(None) => {}
        // Неудача не проходит молча: человеку — окно, журналу — строка.
        Err(reason) => {
            note(&format!("не получилось: {reason}"));
            // Без человека окно показывать некому: под службой оно повисло
            // бы невидимым. Причина — в журнале.
            if !quiet {
                message(&format!("Не получилось: {reason}"), MB_ICONERROR);
            }
            std::process::exit(1);
        }
    }
}

fn install_dir() -> Result<PathBuf, String> {
    ["ProgramW6432", "ProgramFiles"]
        .into_iter()
        .find_map(std::env::var_os)
        .map(|base| PathBuf::from(base).join("vpnsplit"))
        .ok_or_else(|| "Windows не назвала папку Program Files".to_owned())
}

/// Что ставим — словами для вопроса.
fn version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    if payload::BUILT.is_empty() {
        version.to_owned()
    } else {
        format!("{version} (сборка {})", payload::BUILT)
    }
}

fn install(quiet: bool) -> Result<Option<String>, String> {
    if payload::PAYLOAD.is_empty() {
        return Err("этот установщик собран без содержимого. Собрать настоящий: \
                    scripts\\make-setup.ps1"
            .to_owned());
    }
    let dir = install_dir()?;
    let service = Service::open()?;
    let updating = service.is_some() || dir.join(SVC).is_file();
    if !quiet {
        let question = if updating {
            format!(
                "Обновить vpnsplit до {}?\n\nСлужба остановится на несколько секунд; на это время \
                 приложения из списка останутся без сети. Список приложений и свои подключения \
                 сохранятся. Подключения с одноразовым кодом после обновления надо подключить \
                 заново.",
                version()
            )
        } else {
            format!("Установить vpnsplit {} в папку\n{}?", version(), dir.display())
        };
        if message(&question, MB_OKCANCEL | MB_ICONQUESTION) != IDOK {
            return Ok(None);
        }
    }

    // Окно держит свои файлы открытыми и после обновления было бы прежним.
    // С человеком оно закрывается и в конце открывается от его имени. Без
    // человека (обновление ставит служба) — закрывается в тех сеансах, где
    // его удастся открыть заново от имени пользователя сеанса, и
    // открывается, когда установщик уходит (см. `Windows`). Само оно, увидев
    // службу новее себя, перезапустилось бы и так — но окна прежних сборок
    // до новой службы не достучатся.
    let _windows = if quiet {
        Windows::close(dir.join(UI))
    } else {
        stop_processes(UI);
        Windows::default()
    };
    // Как служба запускалась до нас — чтобы вернуть, если новая не поднимется.
    let before = match &service {
        Some(service) => Some(service.command()?),
        None => None,
    };
    if let Some(service) = &service {
        service.stop()?;
    }
    // С этого места служба остановлена. Любая неудача дальше — запись
    // файлов (антивирус держит библиотеку, кончилось место), путь службы,
    // её запуск — не должна оставить её так: приложения из списка сидели бы
    // без сети, причём молча, если обновление ставилось само, и поднять
    // службу было бы некому. Поэтому неудача любого шага ведёт к одному и
    // тому же откату.
    let mut kept = Vec::new();
    let exe = dir.join(SVC);
    let outcome = replace_files(&dir, &mut kept).and_then(|()| match &service {
        // Служба есть: ей нужен только новый путь — и запуск.
        Some(service) => {
            service.point_to(&exe)?;
            service.start().and_then(|()| service.wait_running())
        }
        // Службы нет: создаёт её она сама, как умеет, со всеми настройками.
        None => run(&exe, "install"),
    });
    if let Err(reason) = outcome {
        return Err(match &service {
            Some(service) => roll_back(service, &dir, &kept, before.as_deref(), &reason),
            // Возвращать нечего: прежней службы не было.
            None => reason,
        });
    }
    register(&dir);
    // Окно — от имени человека, а не администратора: проводник запускает
    // программы со своими правами, а не с нашими.
    if !quiet {
        let _ = std::process::Command::new("explorer.exe").arg(dir.join(UI)).spawn();
    }
    Ok(Some(if updating {
        format!("vpnsplit обновлён до {}. Служба запущена.", version())
    } else {
        "vpnsplit установлен, служба запущена. Окно программы открывается; дальше оно живёт в \
         области уведомлений."
            .to_owned()
    }))
}

/// Кладёт новые файлы на место; прежние сперва откладываются в `previous`
/// (их имена — в `kept`, даже если дальше что-то не вышло: по ним откат).
fn replace_files(dir: &Path, kept: &mut Vec<&'static str>) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("папка {} не создалась: {e}", dir.display()))?;
    sweep(dir);
    *kept = keep(dir);
    for (name, bytes) in payload::PAYLOAD {
        place(&dir.join(name), bytes)?;
    }
    // Сам установщик — туда же: он же и удаляет программу.
    if let Ok(me) = std::env::current_exe() {
        let there = dir.join(SELF);
        if !same_file(&me, &there) {
            match std::fs::read(&me) {
                Ok(bytes) => place(&there, &bytes)?,
                Err(e) => return Err(format!("установщик не прочитал сам себя: {e}")),
            }
        }
    }
    Ok(())
}

/// Обновление не встало: вернуть прежние файлы, прежнюю строку запуска и
/// запустить прежнюю службу. Возвращает текст ошибки — с тем, вернулась ли
/// она.
fn roll_back(service: &Service, dir: &Path, kept: &[&str], before: Option<&str>, reason: &str) -> String {
    let _ = service.stop();
    let restored = restore(dir, kept);
    if let Some(before) = before {
        let _ = service.set_command(before);
    }
    let back = service.start().and_then(|()| service.wait_running()).is_ok();
    format!(
        "обновление не встало ({reason}); прежняя служба {}",
        match (restored || kept.is_empty(), back) {
            (true, true) => "возвращена и работает",
            _ => "не вернулась — запусти её: Start-Service vpnsplit",
        }
    )
}

fn remove(quiet: bool) -> Result<Option<String>, String> {
    let dir = install_dir()?;
    if !quiet {
        let question = "Удалить vpnsplit?\n\nСлужба будет остановлена и удалена, запреты для \
                        приложений из списка сняты — они пойдут в сеть напрямую, мимо VPN.";
        if message(question, MB_OKCANCEL | MB_ICONQUESTION) != IDOK {
            return Ok(None);
        }
    }
    stop_processes(UI);
    // Служба удаляет себя сама: она же снимает запреты, которые иначе
    // пережили бы её и оставили приложения без сети навсегда.
    let exe = dir.join(SVC);
    if exe.is_file() {
        run(&exe, "uninstall")?;
    } else if Service::open()?.is_some() {
        return Err(format!(
            "служба есть, а её файла в {} нет — удали её командой vpnsplit-svc uninstall оттуда, \
             где она лежит",
            dir.display()
        ));
    }
    // Занятое (библиотеку хуков держат приложения, запущенные через
    // туннель, себя — мы сами) не удалить сейчас: это сделает Windows при
    // следующей загрузке. Порядок пометок важен — Windows выполняет их по
    // очереди, и папка удалится, только если к её очереди она уже пуста:
    // поэтому сначала файлы, потом вложенные папки, потом она сама.
    for (name, _) in payload::PAYLOAD {
        remove_or_later(&dir.join(name));
    }
    sweep(&dir);
    // Что `sweep` не смог убрать (отодвинутое прошлыми обновлениями и всё
    // ещё занятое), — тоже на загрузку.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if is_moved_aside(&entry.path()) {
                remove_or_later(&entry.path());
            }
        }
    }
    // Журнал, который `note` мог завести здесь вместо каталога данных.
    remove_or_later(&dir.join(LOG));
    for folder in ["previous", "update"] {
        remove_or_later(&dir.join(folder));
    }
    remove_or_later(&dir.join(SELF));
    // Саму папку — только если в ней не осталось чужого: того, что положили
    // туда не мы, удаление программы не касается.
    if std::fs::remove_dir(&dir).is_err() && dir.is_dir() {
        later(&dir);
    }
    unsafe {
        RegDeleteTreeW(HKEY_LOCAL_MACHINE, wide(UNINSTALL_KEY).as_ptr());
        // Автозапуск окна и ярлык в меню «Пуск» — у того, кто удаляет.
        RegDeleteKeyValueW(HKEY_CURRENT_USER, wide(RUN_KEY).as_ptr(), wide("vpnsplit").as_ptr());
    }
    if let Some(roaming) = std::env::var_os("APPDATA") {
        let link = PathBuf::from(roaming).join(r"Microsoft\Windows\Start Menu\Programs\vpnsplit.lnk");
        let _ = std::fs::remove_file(link);
    }
    Ok(Some(
        "vpnsplit удалён.\n\nНастройки оставлены в папке ProgramData\\vpnsplit: там список \
         приложений, журналы и сохранённые конфиги VPN с паролями. Если они больше не нужны — \
         удали эту папку."
            .to_owned(),
    ))
}

/// Запускает программу службы с одной командой и ждёт её.
fn run(exe: &Path, command: &str) -> Result<(), String> {
    let output = std::process::Command::new(exe)
        .arg(command)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{} не запустился: {e}", exe.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&output.stderr).into_owned()
        + &String::from_utf8_lossy(&output.stdout);
    let last = said.lines().rev().find(|line| !line.trim().is_empty()).unwrap_or("причину не назвал");
    Err(format!("vpnsplit-svc {command}: {}", last.trim()))
}

/// Кладёт файл на место. Занятый (библиотеку хуков держат запущенные через
/// неё приложения) переименовывается в сторону: Windows это позволяет, а
/// приложения доработают со старой.
fn place(path: &Path, bytes: &[u8]) -> Result<(), String> {
    // Тот же самый файл трогать незачем. Это не только бережливость:
    // драйвер WinDivert, пока он загружен, свой файл переписать не даёт.
    if std::fs::read(path).is_ok_and(|current| current == bytes) {
        return Ok(());
    }
    let mut error = None;
    // Служба остановлена, но её процесс отпускает файл не в тот же миг —
    // поэтому попыток несколько.
    for attempt in 0..8 {
        match std::fs::write(path, bytes) {
            Ok(()) => return Ok(()),
            Err(e) => error = Some(e),
        }
        // Работающую программу (окно, библиотеку хуков) переписать нельзя,
        // а переименовать можно: она доработает под новым именем.
        let aside = path.with_extension(format!("old-{}-{attempt}", std::process::id()));
        if std::fs::rename(path, &aside).is_ok() {
            if std::fs::write(path, bytes).is_ok() {
                // На удаление при загрузке — только когда замена удалась:
                // отменить такую пометку потом нечем.
                later(&aside);
                return Ok(());
            }
            // Не записалось и под освободившимся именем — прежний файл
            // возвращается на место: на месте файла не должно остаться
            // пустоты. Не вернулся — остаётся в стороне как есть (его
            // уберёт `sweep` следующей установки), а откат возьмёт копию
            // из `previous`.
            let _ = std::fs::remove_file(path);
            let _ = std::fs::rename(&aside, path);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!(
        "файл {} не записался: {}",
        path.display(),
        error.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Откладывает нынешние файлы в `previous` — на случай, если новая служба
/// не поднимется. Возвращает имена отложенного.
fn keep(dir: &Path) -> Vec<&'static str> {
    let previous = dir.join("previous");
    let _ = std::fs::create_dir_all(&previous);
    payload::PAYLOAD
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| std::fs::copy(dir.join(name), previous.join(name)).is_ok())
        .collect()
}

/// Возвращает отложенные файлы на место. Правда — вернулись все.
fn restore(dir: &Path, kept: &[&str]) -> bool {
    !kept.is_empty()
        && kept.iter().all(|name| {
            std::fs::read(dir.join("previous").join(name))
                .is_ok_and(|bytes| place(&dir.join(name), &bytes).is_ok())
        })
}

/// Права каталога данных — те же, что ставит служба (`store::DATA_DIR_SDDL`
/// в `vpnsplit-svc`): SYSTEM и администраторы — всё, пользователи — чтение.
const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)";

/// Строка в журнал установок: когда установщик работает без человека,
/// больше ему сказать некуда.
///
/// Пишется в каталог данных, если ему можно верить, — так же, как решает
/// служба: владелец SYSTEM или администраторы, права не унаследованы. Нет
/// каталога (первая установка не дошла до запуска службы) — установщик
/// заводит его сам, сразу с правами службы. Каталог, который завёл
/// посторонний или который остался от прежних версий с унаследованными
/// правами, служба при старте отложит в сторону; до тех пор строки в него
/// не пишутся: его хозяин мог бы подменить его ссылкой, и установщик с
/// правами администратора дописал бы строку в чужой файл. Тогда журнал
/// пишется в папку установки, пока программа там стоит: в Program Files
/// посторонний не пишет, а молчать нельзя — неудачное обновление без
/// человека иначе не оставило бы никакого следа. Журнал, который сам ссылка
/// или второе имя другого файла, не пишется нигде.
fn note(text: &str) {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let data = std::env::var_os("ProgramData").map(|data| PathBuf::from(data).join("vpnsplit"));
    let dir = match data {
        Some(dir) if data_dir_trusted(&dir) => dir,
        _ => match install_dir() {
            Ok(dir) if dir.join(SVC).is_file() => dir,
            _ => return,
        },
    };
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir.join(LOG));
    let Ok(mut log) = opened else { return };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ordinary = unsafe { GetFileInformationByHandle(log.as_raw_handle() as _, &mut info) } != 0
        && info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0
        && info.nNumberOfLinks == 1;
    if ordinary {
        let _ = writeln!(log, "{seconds}  сборка {}: {text}", payload::BUILT.trim());
    }
}

/// Каталог данных есть и ему можно верить — или его не было, и он создан
/// только что, с правами службы.
fn data_dir_trusted(dir: &Path) -> bool {
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorControl, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        READ_CONTROL,
    };

    let path = wide(&dir.to_string_lossy());
    unsafe {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(DATA_DIR_SDDL).as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return false;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let created = CreateDirectoryW(path.as_ptr(), &attributes) != 0;
        let code = GetLastError();
        LocalFree(descriptor as _);
        if created {
            return true;
        }
        if code != ERROR_ALREADY_EXISTS {
            return false;
        }

        // Сам каталог, а не то, куда он ведёт, если это ссылка.
        let handle = CreateFileW(
            path.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        let directory = GetFileInformationByHandle(handle, &mut info) != 0
            && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let mut owner: PSID = std::ptr::null_mut();
        let mut security: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let read = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut security,
        ) == 0;
        CloseHandle(handle);
        if !read {
            return false;
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        let protected =
            GetSecurityDescriptorControl(security, &mut control, &mut revision) != 0 && control & SE_DACL_PROTECTED != 0;
        let admins = !owner.is_null()
            && (IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0);
        LocalFree(security as _);
        directory && protected && admins
    }
}

/// Файл, который прошлое обновление отодвинуло в сторону (`*.old-…`).
fn is_moved_aside(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension.to_string_lossy().starts_with("old-"))
}

/// Убирает то, что прошлые обновления отодвинули в сторону.
fn sweep(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if is_moved_aside(&entry.path()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Убирает файл или папку со всем, что в ней; что не удаляется сейчас
/// (занято), помечается на удаление при загрузке — содержимое раньше
/// папки. Нет такого — ничего не делает.
fn remove_or_later(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return };
    // Ссылку убираем саму, не заходя туда, куда она ведёт.
    if meta.is_dir() && !meta.file_type().is_symlink() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                remove_or_later(&entry.path());
            }
        }
        if std::fs::remove_dir(path).is_err() {
            later(path);
        }
    } else if std::fs::remove_file(path).is_err() && std::fs::remove_dir(path).is_err() {
        // Занятый файл сначала отодвигаем под своё имя и уже его помечаем на
        // загрузку. Иначе пометка висит на прежнем имени, и если программу
        // поставят снова до перезагрузки, Windows при загрузке сотрёт файлы
        // новой установки. Занятый образ переименовать можно, удалить — нет.
        // Не отодвинулся (открыт без FILE_SHARE_DELETE) — оставляем на месте
        // без пометки, как было раньше: лишний файл лучше стёртой установки.
        if let Some(aside) = move_aside(path) {
            later(&aside);
        }
    }
}

/// Отодвигает файл под свободное имя `*.old-PID-N` рядом; None — не вышло.
fn move_aside(path: &Path) -> Option<PathBuf> {
    if is_moved_aside(path) {
        return Some(path.to_path_buf());
    }
    (0..100).find_map(|attempt| {
        let aside = path.with_extension(format!("old-{}-{attempt}", std::process::id()));
        (!aside.exists() && std::fs::rename(path, &aside).is_ok()).then_some(aside)
    })
}

/// Удалить при следующей загрузке Windows.
fn later(path: &Path) {
    unsafe {
        MoveFileExW(wide(&path.to_string_lossy()).as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT)
    };
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Номера процессов с таким именем файла, кроме нас самих.
fn processes(name: &str) -> Vec<u32> {
    let mut found = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot as isize == -1 {
            return found;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let length = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
            let image = String::from_utf16_lossy(&entry.szExeFile[..length]);
            if image.eq_ignore_ascii_case(name) && entry.th32ProcessID != std::process::id() {
                found.push(entry.th32ProcessID);
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    found
}

fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

/// Полный путь к файлу процесса по его хэндлу (нужно право
/// PROCESS_QUERY_LIMITED_INFORMATION); None — не узнать.
fn image_of(process: HANDLE) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut length) };
    (ok != 0).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize])))
}

/// Открытый хэндл процесса; закрывается сам.
struct Process(HANDLE);

impl Process {
    /// Открывает процесс, чтобы проверить его файл, завершить и дождаться.
    /// Пока хэндл открыт, номер процесса не достанется другому, даже если
    /// этот завершится: что проверено, то и завершается.
    fn open(pid: u32) -> Option<Self> {
        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE;
        let process = unsafe { OpenProcess(access, 0, pid) };
        (!process.is_null()).then_some(Process(process))
    }

    /// Завершает процесс и ждёт, пока он уйдёт.
    fn end(&self) {
        unsafe {
            TerminateProcess(self.0, 0);
            WaitForSingleObject(self.0, 3000);
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Один и тот же файл: пути в Windows сравниваются без учёта регистра, а
/// если записаны по-разному (короткое имя, ссылка), решает сама файловая
/// система.
fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase() || same_file(left, right)
}

/// Номера процессов после ключа [`SHOWN_FLAG`]; None — ключа нет, это
/// обычный запуск установщика.
fn shown_pids(args: &[String]) -> Option<Vec<u32>> {
    let (first, rest) = args.split_first()?;
    first
        .eq_ignore_ascii_case(SHOWN_FLAG)
        .then(|| rest.iter().filter_map(|pid| pid.parse().ok()).collect())
}

/// Есть ли у одного из процессов видимое окно верхнего уровня без
/// владельца — главное окно, а не подсказка или окно сообщения. Видны
/// только окна своего рабочего стола, поэтому работает это в сеансе
/// пользователя, а не там, где служба (см. `shown_in`).
fn any_shown(pids: &[u32]) -> bool {
    struct Search<'a> {
        pids: &'a [u32],
        found: bool,
    }
    unsafe extern "system" fn each(hwnd: HWND, data: LPARAM) -> BOOL {
        let search = &mut *(data as *mut Search);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if search.pids.contains(&pid) && IsWindowVisible(hwnd) != 0 && GetWindow(hwnd, GW_OWNER).is_null() {
            search.found = true;
            return 0;
        }
        1
    }
    if pids.is_empty() {
        return false;
    }
    let mut search = Search { pids, found: false };
    unsafe { EnumWindows(Some(each), &mut search as *mut Search as LPARAM) };
    search.found
}

/// Видно ли окно у этих процессов в сеансе `session`. Установщик без
/// человека работает от имени SYSTEM в сеансе служб, а окна чужого сеанса
/// оттуда не перечислить. Поэтому он запускает сам себя с [`SHOWN_FLAG`]
/// на рабочем столе того сеанса — под своим же токеном с другим номером
/// сеанса: от имени пользователя нельзя, файл установщика лежит в каталоге
/// данных, где пользователям дано только чтение, без запуска. Любая
/// неудача — «не видно»: окно уйдёт в трей, как и до этой проверки.
fn shown_in(session: u32, pids: &[u32]) -> bool {
    let Ok(me) = std::env::current_exe() else { return false };
    let mut command = format!("\"{}\" {SHOWN_FLAG}", me.display());
    for pid in pids {
        command.push_str(&format!(" {pid}"));
    }
    let mut command = wide(&command);
    let application = wide(&me.to_string_lossy());
    let mut desktop = wide(r"winsta0\default");
    unsafe {
        let mut own: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut own) == 0 {
            return false;
        }
        let mut token: HANDLE = std::ptr::null_mut();
        let duplicated = DuplicateTokenEx(
            own,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut token,
        ) != 0;
        CloseHandle(own);
        if !duplicated {
            return false;
        }
        let moved = SetTokenInformation(
            token,
            TokenSessionId,
            &session as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        ) != 0;
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        startup.lpDesktop = desktop.as_mut_ptr();
        // Без курсора «запускается программа» у человека: окна у нас нет.
        startup.dwFlags = STARTF_FORCEOFFFEEDBACK;
        let mut process: PROCESS_INFORMATION = std::mem::zeroed();
        let started = moved
            && CreateProcessAsUserW(
                token,
                application.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                std::ptr::null(),
                &startup,
                &mut process,
            ) != 0;
        CloseHandle(token);
        if !started {
            return false;
        }
        CloseHandle(process.hThread);
        let mut code = 0u32;
        let answered = WaitForSingleObject(process.hProcess, SHOWN_PATIENCE_MS) == WAIT_OBJECT_0
            && GetExitCodeProcess(process.hProcess, &mut code) != 0;
        if !answered {
            TerminateProcess(process.hProcess, 1);
        }
        CloseHandle(process.hProcess);
        answered && code == SHOWN as u32
    }
}

/// Окна, которые установщик без человека закрыл, чтобы открыть их заново из
/// нового файла, — по сеансу на окно, с токеном пользователя этого сеанса.
/// Открываются заново, когда установщик уходит (`Drop`), чем бы ни
/// кончилась установка: окно, которое закрыли и не вернули, хуже прежнего.
///
/// Зачем закрывать. Обычно окно, увидев службу новее себя, перезапускается
/// само. Но узнаёт оно это по каналу, а канал новой службы не пускает окна
/// прежних сборок: они открывают его с правом, которого обычным
/// пользователям больше не дают (см. `PIPE_SDDL` в `vpnsplit-net`). Такое
/// окно осталось бы с «нет связи со службой» до выхода из системы.
///
/// Открыть окно в чужом сеансе можно только от имени SYSTEM — так
/// установщик и запускается при обновлении, которое ставит служба. Если
/// токен сеанса не дали (установщик запущен иначе), окно в этом сеансе не
/// трогается вовсе.
#[derive(Default)]
struct Windows {
    sessions: Vec<Session>,
    exe: PathBuf,
}

/// Сеанс, где закрыто окно: токен его пользователя, закрытые процессы и
/// было ли окно на виду.
struct Session {
    id: u32,
    token: HANDLE,
    /// Номера и хэндлы процессов окна. Хэндлы держатся до завершения:
    /// проверка `shown_in` занимает секунды, и без них номер ушедшего за это
    /// время процесса мог бы достаться чужому — тот и был бы завершён.
    processes: Vec<(u32, Process)>,
    shown: bool,
}

impl Windows {
    /// Закрывает окна во всех сеансах, где потом сможет открыть их снова.
    ///
    /// Только установленные — файл которых и есть `exe`: копию из другой
    /// папки (окно из папки сборки у разработчика) обновление не касается,
    /// и подменять её установленной незачем.
    ///
    /// Окно, которое было на виду, откроется на виду, спрятанное в трей —
    /// в трее (см. `shown_in`). Процесс завершается, а не закрывается сам,
    /// поэтому свой значок в области уведомлений он не убирает: прежний
    /// значок висит рядом с новым, пока на него не наведут мышь, — тогда
    /// Windows видит, что хозяина нет, и убирает его. Это косметика, и с ней
    /// мирится: попросить окно чужого сеанса закрыться самому отсюда нечем,
    /// а окна прежних сборок ещё и не слушают новую службу.
    fn close(exe: PathBuf) -> Self {
        let mut windows = Windows { sessions: Vec::new(), exe };
        for pid in processes(UI) {
            // Сначала хэндл, потом проверки: номер, по которому смотрели файл
            // и сеанс, уже не сменит хозяина до завершения.
            let Some(process) = Process::open(pid) else { continue };
            if !image_of(process.0).is_some_and(|image| same_path(&image, &windows.exe)) {
                continue;
            }
            let Some(id) = session_of(pid).filter(|&session| session != 0) else { continue };
            if let Some(session) = windows.sessions.iter_mut().find(|session| session.id == id) {
                session.processes.push((pid, process));
                continue;
            }
            let mut token: HANDLE = std::ptr::null_mut();
            if unsafe { WTSQueryUserToken(id, &mut token) } == 0 {
                continue;
            }
            windows.sessions.push(Session { id, token, processes: vec![(pid, process)], shown: false });
        }
        // Пока окна живы: после завершения смотреть уже не на что.
        for session in &mut windows.sessions {
            let pids: Vec<u32> = session.processes.iter().map(|(pid, _)| *pid).collect();
            session.shown = shown_in(session.id, &pids);
        }
        // Завершаются те самые процессы, что проверены; хэндлы закрываются
        // сразу — заново окна открываются по токену, не по ним.
        for session in &mut windows.sessions {
            for (_, process) in session.processes.drain(..) {
                process.end();
            }
        }
        windows
    }
}

impl Drop for Windows {
    fn drop(&mut self) {
        for session in self.sessions.drain(..) {
            if let Err(code) = start_as(session.token, &self.exe, session.shown) {
                note(&format!("окно в сеансе {} заново не открылось (код {code})", session.id));
            }
            unsafe { CloseHandle(session.token) };
        }
    }
}

/// Строка запуска окна после обновления. `--after-update` — то же, с чем
/// окно перезапускается само: оно не станет перезапускаться ещё раз, увидев
/// службу новее себя. `--tray` — только если окно до обновления было
/// спрятано: так же решает и само окно при своём перезапуске.
fn window_command(exe: &Path, shown: bool) -> String {
    let tray = if shown { "" } else { " --tray" };
    format!("\"{}\" --after-update{tray}", exe.display())
}

/// Запускает окно от имени пользователя с этим токеном, на его рабочем
/// столе и с его переменными окружения; `shown` — на виду, иначе значком в
/// области уведомлений.
fn start_as(token: HANDLE, exe: &Path, shown: bool) -> Result<(), u32> {
    let mut environment: *mut std::ffi::c_void = std::ptr::null_mut();
    if unsafe { CreateEnvironmentBlock(&mut environment, token, 0) } == 0 {
        environment = std::ptr::null_mut();
    }
    let mut command = wide(&window_command(exe, shown));
    let mut desktop = wide(r"winsta0\default");
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = desktop.as_mut_ptr();
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let directory = exe.parent().map(|dir| wide(&dir.to_string_lossy()));
    let started = unsafe {
        CreateProcessAsUserW(
            token,
            std::ptr::null(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT,
            environment,
            directory.as_ref().map_or(std::ptr::null(), |dir| dir.as_ptr()),
            &startup,
            &mut process,
        )
    } != 0;
    let code = unsafe { GetLastError() };
    if !environment.is_null() {
        unsafe { DestroyEnvironmentBlock(environment) };
    }
    if !started {
        return Err(code);
    }
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    Ok(())
}

/// Завершает процессы и ждёт, пока они уйдут.
fn terminate(pids: &[u32]) -> bool {
    let mut found = false;
    for &pid in pids {
        unsafe {
            let process = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid);
            if !process.is_null() {
                found = true;
                TerminateProcess(process, 0);
                WaitForSingleObject(process, 3000);
                CloseHandle(process);
            }
        }
    }
    found
}

/// Завершает все процессы с таким именем файла. Возвращает, были ли они.
fn stop_processes(name: &str) -> bool {
    terminate(&processes(name))
}

/// Запись в «Программах и компонентах»: оттуда программу удаляют.
fn register(dir: &Path) {
    let uninstall = format!("\"{}\" /uninstall", dir.join(SELF).display());
    let size = payload::PAYLOAD.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() / 1024;
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        let opened = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(UNINSTALL_KEY).as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        );
        if opened != 0 {
            return;
        }
        let text = |name: &str, value: &str| {
            let value = wide(value);
            RegSetValueExW(
                key,
                wide(name).as_ptr(),
                0,
                REG_SZ,
                value.as_ptr() as *const u8,
                (value.len() * 2) as u32,
            );
        };
        text("DisplayName", "vpnsplit — раздельное туннелирование");
        text("DisplayVersion", env!("CARGO_PKG_VERSION"));
        text("Publisher", "vpnsplit");
        text("InstallLocation", &dir.display().to_string());
        text("DisplayIcon", &dir.join(UI).display().to_string());
        text("UninstallString", &uninstall);
        let number = |name: &str, value: u32| {
            RegSetValueExW(key, wide(name).as_ptr(), 0, REG_DWORD, &value as *const u32 as *const u8, 4);
        };
        number("NoModify", 1);
        number("NoRepair", 1);
        number("EstimatedSize", size as u32);
        RegCloseKey(key);
    }
}

/// Служба Windows, если она уже есть.
struct Service(*mut core::ffi::c_void);

impl Drop for Service {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

impl Service {
    /// `Ok(None)` — службы нет: ставимся впервые.
    fn open() -> Result<Option<Service>, String> {
        unsafe {
            let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if manager.is_null() {
                return Err(format!("нет доступа к диспетчеру служб (ошибка {})", GetLastError()));
            }
            let access = SERVICE_QUERY_STATUS
                | SERVICE_STOP
                | SERVICE_START
                | SERVICE_CHANGE_CONFIG
                | SERVICE_QUERY_CONFIG;
            let service = OpenServiceW(manager, wide(SERVICE).as_ptr(), access);
            let error = GetLastError();
            CloseServiceHandle(manager);
            if !service.is_null() {
                return Ok(Some(Service(service)));
            }
            if error == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(None);
            }
            Err(format!("служба vpnsplit не открылась (ошибка {error})"))
        }
    }

    fn stopped(&self) -> bool {
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        unsafe { QueryServiceStatus(self.0, &mut status) != 0 && status.dwCurrentState == SERVICE_STOPPED }
    }

    fn stop(&self) -> Result<(), String> {
        if self.stopped() {
            return Ok(());
        }
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        unsafe { ControlService(self.0, SERVICE_CONTROL_STOP, &mut status) };
        let deadline = Instant::now() + STOP_PATIENCE;
        while !self.stopped() {
            if Instant::now() >= deadline {
                return Err("служба vpnsplit не остановилась за отведённое время; файлы не тронуты, \
                            она продолжает работать по-старому"
                    .to_owned());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    }

    /// Ждёт, пока запущенная служба скажет, что работает.
    fn wait_running(&self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
            unsafe { QueryServiceStatus(self.0, &mut status) };
            match status.dwCurrentState {
                SERVICE_RUNNING => return Ok(()),
                SERVICE_STOPPED => return Err("служба запустилась и сразу остановилась".to_owned()),
                _ if Instant::now() >= deadline => {
                    return Err("служба не вышла в рабочее состояние за 30 с".to_owned())
                }
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    /// Меняет службе путь к файлу, оставляя всё остальное как было.
    fn point_to(&self, exe: &Path) -> Result<(), String> {
        let current = self.command()?;
        self.set_command(&format!("\"{}\"{}", exe.display(), arguments_of(&current)))
    }

    /// Строка, которой служба запускается сейчас.
    fn command(&self) -> Result<String, String> {
        unsafe {
            let mut needed = 0u32;
            QueryServiceConfigW(self.0, std::ptr::null_mut(), 0, &mut needed);
            // Выравнивание под структуру с указателями.
            let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
            let config = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
            if QueryServiceConfigW(self.0, config, needed, &mut needed) == 0 {
                return Err(format!("настройки службы не прочитались (ошибка {})", GetLastError()));
            }
            let mut length = 0;
            let line = (*config).lpBinaryPathName;
            while !line.is_null() && *line.add(length) != 0 {
                length += 1;
            }
            Ok(String::from_utf16_lossy(std::slice::from_raw_parts(line, length)))
        }
    }

    fn set_command(&self, fresh: &str) -> Result<(), String> {
        unsafe {
            let changed = ChangeServiceConfigW(
                self.0,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                wide(fresh).as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );
            if changed == 0 {
                return Err(format!("путь службы не записался (ошибка {})", GetLastError()));
            }
        }
        Ok(())
    }

    fn start(&self) -> Result<(), String> {
        if unsafe { StartServiceW(self.0, 0, std::ptr::null()) } == 0 {
            return Err(format!(
                "файлы обновлены, но служба не запустилась (ошибка {}). Запусти её: \
                 Start-Service vpnsplit",
                unsafe { GetLastError() }
            ));
        }
        Ok(())
    }
}

/// То, что в строке запуска службы стоит после пути к файлу, — вместе с
/// пробелом перед ним. Путь бывает в кавычках и без.
fn arguments_of(command: &str) -> &str {
    let command = command.trim_start();
    if let Some(rest) = command.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => &rest[end + 1..],
            None => "",
        };
    }
    // Без кавычек путь кончается на «.exe», за которым пробел или конец
    // строки, — пробелы в нём возможны, а «.exe» в середине имени папки
    // (`C:\tools.exec\…`) концом не считается. Ищем по байтам без смены
    // регистра: строчная форма не-ASCII букв бывает длиннее прописной, и
    // позиция из `to_lowercase()` в исходной строке указала бы не туда, а то
    // и в середину буквы. Срез после ASCII-байтов «.exe» — всегда на границе
    // символа.
    let bytes = command.as_bytes();
    let end = (0..bytes.len().saturating_sub(3)).find(|&at| {
        bytes[at..at + 4].eq_ignore_ascii_case(b".exe")
            && bytes.get(at + 4).copied().unwrap_or(b' ').is_ascii_whitespace()
    });
    match end {
        Some(end) => &command[end + 4..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_keeps_its_arguments_when_it_moves() {
        assert_eq!(arguments_of(r#""G:\src\target\debug\vpnsplit-svc.exe" service"#), " service");
        assert_eq!(arguments_of(r"C:\Program Files\vpnsplit\vpnsplit-svc.exe service"), " service");
        assert_eq!(arguments_of(r#""C:\a b\vpnsplit-svc.exe""#), "");
        assert_eq!(arguments_of(r"C:\x\VPNSPLIT-SVC.EXE"), "");
        assert_eq!(arguments_of(""), "");
        // Незакрытая кавычка — не повод выдумывать доводы.
        assert_eq!(arguments_of(r#""C:\a\vpnsplit-svc.exe service"#), "");
        // Буквы, у которых строчная форма длиннее прописной, позицию не сбивают.
        assert_eq!(arguments_of(r"C:\İş\Ⱥ\vpnsplit-svc.exe service"), " service");
        // «.exe» в имени папки — не конец пути.
        assert_eq!(arguments_of(r"C:\tools.exec\vpnsplit-svc.exe service"), " service");
        assert_eq!(arguments_of(r"C:\x.exe"), "");
        assert_eq!(arguments_of("C:\\x.exe\tservice"), "\tservice");
    }

    #[test]
    fn what_cannot_be_removed_now_is_left_for_the_reboot() {
        // Свободное удаляется сразу и целиком, с вложенными папками.
        let dir = std::env::temp_dir().join(format!("vpnsplit-setup-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("previous").join("inner")).unwrap();
        std::fs::write(dir.join("previous").join("a.bin"), b"x").unwrap();
        std::fs::write(dir.join("previous").join("inner").join("b.bin"), b"x").unwrap();
        std::fs::write(dir.join("vpnsplit_hook.old-1-0"), b"x").unwrap();
        remove_or_later(&dir.join("previous"));
        assert!(!dir.join("previous").exists());
        assert!(is_moved_aside(&dir.join("vpnsplit_hook.old-1-0")));
        assert!(!is_moved_aside(&dir.join("vpnsplit_hook.dll")));
        remove_or_later(&dir.join("vpnsplit_hook.old-1-0"));
        assert!(!dir.join("vpnsplit_hook.old-1-0").exists());
        // Того, чего нет, — нет и пометок.
        remove_or_later(&dir.join("нет такого"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn what_was_moved_aside_is_swept_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("vpnsplit-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vpnsplit_hook.old-123-0"), b"x").unwrap();
        // Отложенное возвращается на место; без отложенного возвращать нечего.
        assert!(!restore(&dir, &[]));
        std::fs::create_dir_all(dir.join("previous")).unwrap();
        std::fs::write(dir.join("previous").join("a.bin"), b"old").unwrap();
        std::fs::write(dir.join("a.bin"), b"broken").unwrap();
        assert!(restore(&dir, &["a.bin"]));
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), b"old");
        assert!(!restore(&dir, &["нет такого"]));
        std::fs::write(dir.join("vpnsplit_hook.old-123"), b"x").unwrap();
        std::fs::write(dir.join("vpnsplit_hook.dll"), b"x").unwrap();
        sweep(&dir);
        assert!(!dir.join("vpnsplit_hook.old-123").exists());
        assert!(!dir.join("vpnsplit_hook.old-123-0").exists());
        assert!(dir.join("vpnsplit_hook.dll").exists());
        // Запись поверх существующего файла — обычное обновление.
        place(&dir.join("vpnsplit_hook.dll"), b"new").unwrap();
        assert_eq!(std::fs::read(dir.join("vpnsplit_hook.dll")).unwrap(), b"new");
        assert!(same_file(&dir.join("vpnsplit_hook.dll"), &dir.join("vpnsplit_hook.dll")));
        assert!(!same_file(&dir.join("vpnsplit_hook.dll"), &dir.join("нет такого")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_the_installed_window_is_ours() {
        let installed = Path::new(r"C:\Program Files\vpnsplit\vpnsplit-ui.exe");
        assert!(same_path(Path::new(r"c:\program files\VPNSPLIT\vpnsplit-ui.exe"), installed));
        assert!(same_path(
            Path::new(r"C:\Программы\ВПН\vpnsplit-ui.exe"),
            Path::new(r"C:\программы\впн\VPNSPLIT-UI.EXE")
        ));
        assert!(!same_path(Path::new(r"G:\src\vpnsplit\target\release\vpnsplit-ui.exe"), installed));
    }

    #[test]
    fn the_window_comes_back_as_it_was() {
        let exe = Path::new(r"C:\Program Files\vpnsplit\vpnsplit-ui.exe");
        assert_eq!(window_command(exe, true), r#""C:\Program Files\vpnsplit\vpnsplit-ui.exe" --after-update"#);
        assert_eq!(
            window_command(exe, false),
            r#""C:\Program Files\vpnsplit\vpnsplit-ui.exe" --after-update --tray"#
        );
    }

    #[test]
    fn the_visibility_question_is_told_apart_from_an_install() {
        let args = |list: &[&str]| list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        assert_eq!(shown_pids(&args(&["/shown", "12", "345"])), Some(vec![12, 345]));
        assert_eq!(shown_pids(&args(&["/SHOWN", "x", "7"])), Some(vec![7]));
        assert_eq!(shown_pids(&args(&["/shown"])), Some(vec![]));
        assert_eq!(shown_pids(&args(&["/quiet"])), None);
        assert_eq!(shown_pids(&args(&["/quiet", "/shown"])), None);
        assert_eq!(shown_pids(&args(&[])), None);
        // Нет процессов — нет и окна; у несуществующего процесса — тоже.
        assert!(!any_shown(&[]));
        assert!(!any_shown(&[u32::MAX]));
        assert_ne!(SHOWN, HIDDEN);
    }

    #[test]
    fn without_a_payload_the_installer_says_so() {
        // Обычная сборка — без содержимого; настоящую делает сценарий.
        if payload::PAYLOAD.is_empty() {
            assert!(install(true).unwrap_err().contains("без содержимого"));
        } else {
            assert_eq!(payload::PAYLOAD.len(), 6);
        }
    }
}

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
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SERVICE_DOES_NOT_EXIST, GetLastError};
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
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDOK, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OKCANCEL,
    SW_SHOWNORMAL,
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
    // Без человека (обновление ставит служба) его не трогаем: запустить его
    // заново из-под системы нечем. Его файл подменяется на ходу, а само оно,
    // увидев службу новее себя, перезапускается.
    if !quiet {
        stop_processes(UI);
    }
    // Как служба запускалась до нас — чтобы вернуть, если новая не поднимется.
    let before = match &service {
        Some(service) => Some(service.command()?),
        None => None,
    };
    if let Some(service) = &service {
        service.stop()?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("папка {} не создалась: {e}", dir.display()))?;
    sweep(&dir);
    let kept = keep(&dir);
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

    let exe = dir.join(SVC);
    match &service {
        // Служба есть: ей нужен только новый путь — и запуск.
        Some(service) => {
            service.point_to(&exe)?;
            if let Err(reason) = service.start().and_then(|()| service.wait_running()) {
                // Новая служба не поднялась. Оставить так — значит оставить
                // приложения из списка без сети, причём молча, если
                // обновление ставилось само. Возвращаем прежнюю.
                let _ = service.stop();
                let restored = restore(&dir, &kept);
                if let Some(before) = &before {
                    let _ = service.set_command(before);
                }
                let back = service.start().and_then(|()| service.wait_running()).is_ok();
                return Err(format!(
                    "новая служба не запустилась ({reason}); прежняя {}",
                    match (restored || kept.is_empty(), back) {
                        (true, true) => "возвращена и работает",
                        _ => "не вернулась — запусти её: Start-Service vpnsplit",
                    }
                ));
            }
        }
        // Службы нет: создаёт её она сама, как умеет, со всеми настройками.
        None => run(&exe, "install")?,
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
    for (name, _) in payload::PAYLOAD {
        let _ = std::fs::remove_file(dir.join(name));
    }
    sweep(&dir);
    for folder in ["previous", "update"] {
        let _ = std::fs::remove_dir_all(dir.join(folder));
    }
    // Себя и папку, пока мы из неё работаем, не удалить: это сделает
    // Windows при следующей загрузке.
    for left in [dir.join(SELF), dir.clone()] {
        if std::fs::remove_file(&left).is_err() && std::fs::remove_dir(&left).is_err() {
            later(&left);
        }
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
            later(&aside);
            if std::fs::write(path, bytes).is_ok() {
                return Ok(());
            }
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

/// Строка в журнал установок: когда установщик работает без человека,
/// больше ему сказать некуда.
fn note(text: &str) {
    use std::io::Write;
    let Some(data) = std::env::var_os("ProgramData") else { return };
    let dir = PathBuf::from(data).join("vpnsplit");
    let _ = std::fs::create_dir_all(&dir);
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    if let Ok(mut log) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("setup.log")) {
        let _ = writeln!(log, "{seconds}  сборка {}: {text}", payload::BUILT.trim());
    }
}

/// Убирает то, что прошлые обновления отодвинули в сторону.
fn sweep(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let old = entry
            .path()
            .extension()
            .is_some_and(|extension| extension.to_string_lossy().starts_with("old-"));
        if old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
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

/// Завершает все процессы с таким именем файла. Возвращает, были ли они.
fn stop_processes(name: &str) -> bool {
    let mut found = false;
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot as isize == -1 {
            return false;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let length = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
            let image = String::from_utf16_lossy(&entry.szExeFile[..length]);
            if image.eq_ignore_ascii_case(name) && entry.th32ProcessID != std::process::id() {
                let process = OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, entry.th32ProcessID);
                if !process.is_null() {
                    found = true;
                    TerminateProcess(process, 0);
                    WaitForSingleObject(process, 3000);
                    CloseHandle(process);
                }
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    found
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
    // Без кавычек путь кончается на «.exe» — пробелы в нём возможны.
    match command.to_lowercase().find(".exe") {
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
    fn without_a_payload_the_installer_says_so() {
        // Обычная сборка — без содержимого; настоящую делает сценарий.
        if payload::PAYLOAD.is_empty() {
            assert!(install(true).unwrap_err().contains("без содержимого"));
        } else {
            assert_eq!(payload::PAYLOAD.len(), 6);
        }
    }
}

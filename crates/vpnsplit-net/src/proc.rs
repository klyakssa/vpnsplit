//! Что можно узнать о чужом процессе: путь к образу и список его модулей.
//!
//! Отсюда служба отвечает на единственный вопрос Этапа 7: это приложение из
//! списка идёт через туннель или мимо? Признак — загружена ли в нём
//! `vpnsplit_hook.dll`. Своего состояния hook.dll никуда не сообщает, и это
//! намеренно: он работает в чужих процессах, и чем меньше он там делает,
//! тем меньше шансов что-нибудь сломать.

use std::path::PathBuf;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BAD_LENGTH, FILETIME, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// Полный путь к образу процесса.
///
/// `PROCESS_QUERY_LIMITED_INFORMATION` — самое слабое право, которого хватает;
/// службе под SYSTEM его дают почти на всё, кроме защищённых процессов.
/// `None` означает «не наше дело»: процесс уже закрылся или недоступен.
pub fn image_path(pid: u32) -> Option<PathBuf> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut buffer = [0u16; 32768 / 2];
    let mut length = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) };
    unsafe { CloseHandle(process) };
    if ok == 0 {
        return None;
    }
    Some(PathBuf::from(from_wide(&buffer[..length as usize])))
}

/// Когда процесс создан — в единицах FILETIME (сотни наносекунд с 1601 года).
///
/// Нужно не время само по себе, а **личность процесса**. Номер процесса
/// Windows отдаёт следующему, как только прежний хозяин умер, и запись «был
/// такой-то номер» через минуту может указывать на постороннюю программу.
/// Номер вместе со временем создания называет процесс однозначно: двух
/// процессов с одним номером, созданных в один и тот же миг, не бывает.
///
/// `None` — процесса нет или он недоступен.
pub fn created(pid: u32) -> Option<u64> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut times: [FILETIME; 4] = unsafe { std::mem::zeroed() };
    let [creation, exit, kernel, user] = &mut times;
    let ok = unsafe { GetProcessTimes(process, creation, exit, kernel, user) };
    unsafe { CloseHandle(process) };
    if ok == 0 {
        return None;
    }
    let creation = &times[0];
    Some(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
}

/// Загружен ли в процессе модуль с таким именем. Сравнение без учёта регистра.
///
/// Снимок модулей у процесса, который ещё только поднимается, не делается:
/// Windows отвечает `ERROR_BAD_LENGTH`. Это не ошибка, а «спроси позже», и
/// отличать её важно — иначе приложение, запущенное лончером, будет
/// помечено как идущее мимо туннеля.
pub fn has_module(pid: u32, module: &str) -> Result<bool, Busy> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return if code == ERROR_BAD_LENGTH { Err(Busy) } else { Ok(false) };
    }

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut found = false;
    let mut more = unsafe { Module32FirstW(snapshot, &mut entry) };
    while more != 0 {
        if from_wide(&entry.szModule).eq_ignore_ascii_case(module) {
            found = true;
            break;
        }
        more = unsafe { Module32NextW(snapshot, &mut entry) };
    }
    unsafe { CloseHandle(snapshot) };
    Ok(found)
}

/// Имя семейства пакетов Store-приложения, если процесс ему принадлежит.
///
/// Для обычной программы Windows отвечает `APPMODEL_ERROR_NO_PACKAGE`, и
/// это не ошибка, а ответ «это не Store-приложение». Именно по этому имени
/// путь B и будет опознавать то, что путь A опознать не может: Store-
/// приложения живут в общих хост-процессах, и путь к образу у них общий.
pub fn package_family(pid: u32) -> Option<String> {
    const APPMODEL_ERROR_NO_PACKAGE: u32 = 15700;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut length = 0u32;
    // Первый вызов с нулевой длиной спрашивает размер.
    let code = unsafe { GetPackageFamilyName(process, &mut length, std::ptr::null_mut()) };
    if code == APPMODEL_ERROR_NO_PACKAGE || length == 0 {
        unsafe { CloseHandle(process) };
        return None;
    }
    let mut buffer = vec![0u16; length as usize];
    let code = unsafe { GetPackageFamilyName(process, &mut length, buffer.as_mut_ptr()) };
    unsafe { CloseHandle(process) };
    if code != 0 {
        return None;
    }
    Some(from_wide(&buffer))
}

/// Процесс ещё поднимается, спросить нечего — надо повторить позже.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Busy;

/// Все процессы системы с номером родителя: кто кого запустил.
///
/// Родитель нужен для правила «приложение и всё, что оно запускает»:
/// у дочернего процесса приложения из Store ни пути к образу приложения,
/// ни — как выяснилось — его принадлежности пакету может не быть, и
/// единственная связь с ним — родословная.
///
/// Номер родителя ненадёжен по своей природе: Windows переиспользует
/// номера, а родитель может умереть раньше ребёнка, и тогда номер уже
/// указывает на кого-то другого. Поэтому родословную надо вести по
/// событиям запуска, а не вычислять по снимку, — здесь это только для
/// осмотра.
pub fn parents() -> Vec<(u32, u32, String)> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) };
    while more != 0 {
        out.push((
            entry.th32ProcessID,
            entry.th32ParentProcessID,
            from_wide(&entry.szExeFile),
        ));
        more = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    unsafe { CloseHandle(snapshot) };
    out
}

/// Все процессы системы: номер и имя файла образа (без пути).
///
/// Полный путь здесь не берётся намеренно: он стоит открытия каждого
/// процесса, а нужен лишь для тех немногих, чьё имя совпало с правилом.
pub fn list() -> Vec<(u32, String)> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) };
    while more != 0 {
        out.push((entry.th32ProcessID, from_wide(&entry.szExeFile)));
        more = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    unsafe { CloseHandle(snapshot) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_image_path_is_found() {
        let pid = std::process::id();
        let path = image_path(pid).expect("свой процесс всегда открывается");
        assert!(path.to_string_lossy().to_lowercase().ends_with(".exe"), "{path:?}");
    }

    #[test]
    fn own_modules_contain_the_system_library() {
        // kernel32 загружен в любом процессе Windows — удобная проверка,
        // что перебор модулей вообще доходит до конца списка.
        let pid = std::process::id();
        assert_eq!(has_module(pid, "kernel32.dll"), Ok(true));
        assert_eq!(has_module(pid, "этого-модуля-нет.dll"), Ok(false));
    }

    #[test]
    fn creation_time_names_a_process_not_just_its_number() {
        let me = std::process::id();
        let mine = created(me).expect("свой процесс всегда открывается");
        // Одно и то же, сколько ни спрашивай: иначе сверять было бы не с чем.
        assert_eq!(created(me), Some(mine));
        // И это настоящее время, а не ноль: позже 2020 года в единицах
        // FILETIME.
        assert!(mine > 132_223_104_000_000_000, "{mine}");

        // Положительный контроль: другой процесс — другое время. Дочерний
        // создан позже нас, и это должно быть видно.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let theirs = created(child.id());
        let _ = child.wait();
        match theirs {
            Some(theirs) => assert!(theirs > mine, "ребёнок {theirs} не моложе нас {mine}"),
            // Успел выйти раньше, чем мы спросили, — судить не о чем.
            None => println!("ПРОВЕРКИ НЕ БЫЛО: дочерний процесс уже завершился"),
        }
        // Несуществующий номер ответа не даёт.
        assert_eq!(created(0xFFFF_FFF0), None);
    }

    #[test]
    fn process_list_contains_us() {
        let pid = std::process::id();
        assert!(list().iter().any(|(id, _)| *id == pid));
    }

    /// На этом держится kill-switch: когда туннель падает, его индекс
    /// становится невалидным, и привязка нового сокета должна не молча
    /// пройти мимо, а отказать. Если Windows когда-нибудь начнёт принимать
    /// несуществующий индекс, отказ придётся выдумывать самим.
    #[test]
    fn binding_to_a_missing_interface_is_refused() {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF};

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let handle = socket.as_raw_socket() as usize;
        // Такого интерфейса в системе быть не может.
        let dead = 0xFFFF_0000u32.to_be();
        let code = unsafe {
            setsockopt(
                handle,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &dead as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        assert_ne!(code, 0, "Windows приняла несуществующий индекс интерфейса");
    }
}

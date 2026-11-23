//! Запуск приложения с загрузкой vpnsplit_hook.dll.
//!
//! Процесс создаётся приостановленным, DLL внедряется общим крейтом
//! `vpnsplit-inject`, и только при успехе главный поток возобновляется.
//! Любой сбой завершает процесс: приложение, запущенное «через туннель»,
//! не должно молча пойти напрямую.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use vpnsplit_core::hook::INIT_EXPORT;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

pub struct Launched {
    process: HANDLE,
    pub pid: u32,
}

impl Launched {
    /// Ждёт завершения процесса и возвращает его код выхода.
    pub fn wait(self) -> u32 {
        let mut code = 0u32;
        unsafe {
            WaitForSingleObject(self.process, INFINITE);
            GetExitCodeProcess(self.process, &mut code);
        }
        code
    }
}

impl Drop for Launched {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.process) };
    }
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// Собирает командную строку по правилам разбора MSVCRT, иначе аргументы
/// с пробелами и кавычками доедут до программы искажёнными.
pub fn command_line(program: &str, args: &[String]) -> String {
    let mut out = quote(program);
    for arg in args {
        out.push(' ');
        out.push_str(&quote(arg));
    }
    out
}

fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(ch);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

pub fn launch(program: &str, args: &[String], dll: &Path, ifindex: u32) -> Result<Launched, String> {
    let init_offset = local_export_offset(dll)?;

    let mut cmdline: Vec<u16> = command_line(program, args)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // Стандартные потоки передаются явно. Консольное приложение и без этого
    // подцепится к консоли, а GUI-приложение (браузер) без этого останется
    // без stdout: всё, что оно печатает, уйдёт в никуда.
    startup.dwFlags = STARTF_USESTDHANDLES;
    unsafe {
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // наследовать хэндлы — иначе стандартные потоки не передать
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut info,
        )
    };
    if created == 0 {
        return Err(format!("не удалось запустить «{program}» (код {})", unsafe { GetLastError() }));
    }
    let main_thread = Handle(info.hThread);
    let launched = Launched { process: info.hProcess, pid: info.dwProcessId };

    match vpnsplit_inject::inject(launched.process, dll, init_offset, ifindex) {
        Ok(()) => {
            unsafe { ResumeThread(main_thread.0) };
            Ok(launched)
        }
        Err(err) => {
            unsafe { TerminateProcess(launched.process, 1) };
            Err(err.to_string())
        }
    }
}

/// Смещение экспорта инициализации от начала образа. Считается на локальной
/// копии DLL: DllMain в ней ничего не делает, поэтому загружать её безопасно.
fn local_export_offset(dll: &Path) -> Result<usize, String> {
    let module = unsafe { LoadLibraryW(wide(dll.as_os_str()).as_ptr()) };
    if module.is_null() {
        return Err(format!("не удалось загрузить {} локально", dll.display()));
    }
    let name = format!("{INIT_EXPORT}\0");
    let export = unsafe { GetProcAddress(module, name.as_ptr()) }
        .ok_or_else(|| format!("в DLL нет экспорта {INIT_EXPORT}"))?;
    Ok(export as usize - module as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_args_are_not_quoted() {
        assert_eq!(command_line("curl.exe", &["-s".into(), "http://x".into()]), "curl.exe -s http://x");
    }

    #[test]
    fn spaces_are_quoted() {
        assert_eq!(quote(r"C:\Program Files\app.exe"), r#""C:\Program Files\app.exe""#);
    }

    #[test]
    fn quotes_and_trailing_backslashes_survive() {
        assert_eq!(quote(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote(r"dir with space\"), r#""dir with space\\""#);
        assert_eq!(quote(""), r#""""#);
    }
}

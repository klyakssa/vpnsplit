//! Запуск приложения с загрузкой vpnsplit_hook.dll.
//!
//! Процесс создаётся приостановленным, DLL внедряется общим крейтом
//! `vpnsplit-inject`, и только при успехе главный поток возобновляется.
//! Любой сбой завершает процесс: приложение, запущенное «через туннель»,
//! не должно молча пойти напрямую.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetHandleInformation, GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileType, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_PIPE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
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

/// `detach_stdio` (`--detach-stdio`) — каналы (pipe) своих стандартных
/// потоков приложению не передавать, см. [`std_handle`].
pub fn launch(program: &str, args: &[String], dll: &Path, ifindex: u32, detach_stdio: bool) -> Result<Launched, String> {
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
    let mut nul = None;
    startup.hStdInput = std_handle(STD_INPUT_HANDLE, detach_stdio, &mut nul);
    startup.hStdOutput = std_handle(STD_OUTPUT_HANDLE, detach_stdio, &mut nul);
    startup.hStdError = std_handle(STD_ERROR_HANDLE, detach_stdio, &mut nul);
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

    // Своя копия NUL больше не нужна: у приложения — своя, унаследованная.
    drop(nul);

    match vpnsplit_inject::inject(launched.process, dll, ifindex) {
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

/// Стандартный поток для приложения.
///
/// Без `detach` передаём свой как есть: `vpnsplit-launch -- tool.exe | tee`
/// из консоли получает вывод приложения. С `detach` канал (pipe) не
/// передаём: его читает тот, кто запустил лончер (окно vpnsplit), и ждёт
/// конца данных. Пока копия пишущего конца живёт в приложении и всех его
/// потомках, конец не наступит — окно ждало бы закрытия браузера, а не
/// лончера. Вместо канала приложение получает NUL. Консоль и файл
/// передаются как обычно: они никого не держат. Поэтому подмена — только
/// по явной просьбе (`--detach-stdio`, его передаёт окно), а не при любом
/// `--no-wait`: иначе вывод в конвейер пропадал бы молча.
fn std_handle(which: STD_HANDLE, detach: bool, nul: &mut Option<Handle>) -> HANDLE {
    let own = unsafe { GetStdHandle(which) };
    if !detach || own.is_null() || own == INVALID_HANDLE_VALUE || unsafe { GetFileType(own) } != FILE_TYPE_PIPE {
        return own;
    }
    // Наследуются все наследуемые хэндлы, а не только указанные в
    // STARTUPINFO, — поэтому сам канал надо сделать ненаследуемым.
    unsafe { SetHandleInformation(own, HANDLE_FLAG_INHERIT, 0) };
    if nul.is_none() {
        *nul = Some(Handle(open_nul()));
    }
    nul.as_ref().map_or(std::ptr::null_mut(), |h| h.0)
}

/// Наследуемый хэндл NUL; при неудаче — пустой: приложение останется без
/// этого потока, что для GUI-приложения то же самое.
fn open_nul() -> HANDLE {
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let handle = unsafe {
        CreateFileW(
            wide("NUL".as_ref()).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attrs,
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        std::ptr::null_mut()
    } else {
        handle
    }
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

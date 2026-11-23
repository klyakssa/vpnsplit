//! Загрузка vpnsplit_hook.dll в приостановленный процесс.
//!
//! Используется в двух местах: лончером для запускаемого приложения и самой
//! hook.dll для дочерних процессов этого приложения. Поэтому здесь нет
//! ни выводов на экран, ни завершения процессов — только результат.
//!
//! Порядок:
//! 1. путь к DLL пишется в память процесса, удалённый поток вызывает LoadLibraryW;
//! 2. база модуля ищется через EnumProcessModulesEx — код возврата
//!    LoadLibraryW обрезан до 32 бит и об успехе не говорит;
//! 3. второй удалённый поток вызывает `vpnsplit_hook_init(индекс)`.

// `HANDLE` в windows-sys — сырой указатель, и clippy считает, что функция
// может его разыменовать. Здесь хэндлы только передаются системе как есть.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use vpnsplit_core::hook::status;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HMODULE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, IsWow64Process, WaitForSingleObject,
};

const REMOTE_TIMEOUT_MS: u32 = 15_000;

/// Почему DLL не встала. Отдельные варианты нужны, чтобы вызывающий мог
/// по-разному реагировать: лончер убивает процесс, hook.dll только пишет в лог.
#[derive(Debug)]
pub enum InjectError {
    /// Процесс 32-битный, а мы 64-битные — внедрить нельзя.
    Wow64,
    /// Системный вызов не удался.
    Os { what: &'static str, code: u32 },
    /// DLL не появилась в процессе. Типично для песочницы с урезанным токеном.
    NotLoaded,
    /// DLL загрузилась, но init вернул ошибку.
    Init(u32),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectError::Wow64 => write!(f, "32-битный процесс, внедрение не поддерживается"),
            InjectError::Os { what, code } => write!(f, "{what} не удался (код {code})"),
            InjectError::NotLoaded => {
                write!(f, "DLL не загрузилась в процесс (песочница или нет прав на чтение файла)")
            }
            InjectError::Init(code) => write!(f, "hook.dll: {} (код {code})", status::describe(*code)),
        }
    }
}

impl std::error::Error for InjectError {}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn last_error(what: &'static str) -> InjectError {
    InjectError::Os { what, code: unsafe { GetLastError() } }
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn is_wow64(process: HANDLE) -> bool {
    let mut wow64 = 0;
    unsafe { IsWow64Process(process, &mut wow64) };
    wow64 != 0
}

/// Внедряет DLL и запускает в ней инициализацию с указанным индексом
/// интерфейса. `init_offset` — смещение экспорта init от начала образа DLL.
pub fn inject(process: HANDLE, dll: &Path, init_offset: usize, ifindex: u32) -> Result<(), InjectError> {
    if is_wow64(process) {
        return Err(InjectError::Wow64);
    }
    load_library_remote(process, dll)?;
    let base = find_remote_module(process, dll)?;
    let code = run_remote(process, base as usize + init_offset, ifindex as usize as *const c_void)?;
    if code != status::OK {
        return Err(InjectError::Init(code));
    }
    Ok(())
}

/// Адрес LoadLibraryW совпадает с нашим: kernel32 грузится по одному адресу
/// во все 64-битные процессы в пределах одной загрузки системы.
fn load_library_remote(process: HANDLE, dll: &Path) -> Result<(), InjectError> {
    let path = wide(dll.as_os_str());
    let bytes = path.len() * 2;

    let remote = unsafe {
        VirtualAllocEx(process, std::ptr::null(), bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if remote.is_null() {
        return Err(last_error("VirtualAllocEx"));
    }

    let result = (|| {
        let written = unsafe {
            WriteProcessMemory(process, remote, path.as_ptr() as *const c_void, bytes, std::ptr::null_mut())
        };
        if written == 0 {
            return Err(last_error("WriteProcessMemory"));
        }
        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll".as_ref()).as_ptr()) };
        let load_library = unsafe { GetProcAddress(kernel32, c"LoadLibraryW".as_ptr() as *const u8) }
            .ok_or(InjectError::Os { what: "GetProcAddress(LoadLibraryW)", code: 0 })?;
        run_remote(process, load_library as usize, remote)?;
        Ok(())
    })();

    unsafe { VirtualFreeEx(process, remote, 0, MEM_RELEASE) };
    result
}

fn run_remote(process: HANDLE, start: usize, param: *const c_void) -> Result<u32, InjectError> {
    let routine: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(start) };
    let thread = unsafe {
        CreateRemoteThread(process, std::ptr::null(), 0, Some(routine), param, 0, std::ptr::null_mut())
    };
    if thread.is_null() {
        return Err(last_error("CreateRemoteThread"));
    }
    let thread = Handle(thread);
    if unsafe { WaitForSingleObject(thread.0, REMOTE_TIMEOUT_MS) } != WAIT_OBJECT_0 {
        return Err(InjectError::Os { what: "ожидание удалённого потока", code: 0 });
    }
    let mut code = 0u32;
    unsafe { GetExitCodeThread(thread.0, &mut code) };
    Ok(code)
}

fn find_remote_module(process: HANDLE, dll: &Path) -> Result<HMODULE, InjectError> {
    let wanted = dll
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mut modules: Vec<HMODULE> = vec![std::ptr::null_mut(); 1024];
    let mut needed = 0u32;
    let ok = unsafe {
        EnumProcessModulesEx(
            process,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
    };
    if ok == 0 {
        return Err(last_error("EnumProcessModulesEx"));
    }
    let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
    for &module in &modules[..count] {
        let mut name = [0u16; 512];
        let len = unsafe { GetModuleFileNameExW(process, module, name.as_mut_ptr(), name.len() as u32) };
        let path = String::from_utf16_lossy(&name[..len as usize]).to_lowercase();
        if path.ends_with(&wanted) {
            return Ok(module);
        }
    }
    Err(InjectError::NotLoaded)
}

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
//! 3. адрес `vpnsplit_hook_init` берётся из таблицы экспорта этого модуля,
//!    прочитанной через ReadProcessMemory. Смещение, посчитанное по своей
//!    копии DLL, не годится: после обновления под тем же именем лежит уже
//!    другая сборка, и старое смещение попадает в середину чужой функции;
//! 4. второй удалённый поток вызывает `vpnsplit_hook_init(индекс)`.

// `HANDLE` в windows-sys — сырой указатель, и clippy считает, что функция
// может его разыменовать. Здесь хэндлы только передаются системе как есть.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use vpnsplit_core::hook::{status, INIT_EXPORT, READY_EXPORT};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HMODULE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
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
    /// Удалённый поток не завершился вовремя — он, возможно, ещё работает.
    Timeout,
    /// Дождаться удалённого потока не удалось (WAIT_FAILED и т. п.), код —
    /// GetLastError. Как и при Timeout, поток, возможно, ещё работает.
    WaitFailed(u32),
    /// В загруженном модуле не нашёлся экспорт init: чужая или повреждённая DLL.
    NoExport,
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
            InjectError::Timeout => {
                write!(f, "удалённый поток не завершился за {} с", REMOTE_TIMEOUT_MS / 1000)
            }
            InjectError::WaitFailed(code) => {
                write!(f, "ожидание удалённого потока не удалось (код {code})")
            }
            InjectError::NoExport => write!(f, "в загруженной DLL нет экспорта {INIT_EXPORT}"),
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
/// интерфейса.
pub fn inject(process: HANDLE, dll: &Path, ifindex: u32) -> Result<(), InjectError> {
    if is_wow64(process) {
        return Err(InjectError::Wow64);
    }
    load_library_remote(process, dll)?;
    let base = find_remote_module(process, dll)? as usize;
    let rva = find_export(|rva, buf| read_remote(process, base, rva, buf), INIT_EXPORT)
        .ok_or(InjectError::NoExport)?;
    let code = run_remote(process, base + rva, ifindex as usize as *const c_void)?;
    if code != status::OK {
        return Err(InjectError::Init(code));
    }
    Ok(())
}

/// Что известно о хуках в процессе.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// hook.dll загружена, и её init прошёл: хуки стоят.
    Ready,
    /// hook.dll загружена, но init не сработал или ещё не закончился.
    NotReady,
    /// hook.dll в процессе нет.
    Absent,
    /// Узнать не удалось: нет прав на чтение памяти или загружена старая
    /// сборка hook.dll, у которой признака ещё нет.
    Unknown,
}

/// Поставила ли hook.dll свои хуки в процессе: читает её экспорт
/// `READY_EXPORT` через ReadProcessMemory. Ничего в процессе не запускает и
/// не меняет. `process` нужен с правами `PROCESS_QUERY_INFORMATION` и
/// `PROCESS_VM_READ`.
pub fn readiness(process: HANDLE, dll: &Path) -> Readiness {
    let base = match find_remote_module(process, dll) {
        Ok(base) => base as usize,
        Err(InjectError::NotLoaded) => return Readiness::Absent,
        Err(_) => return Readiness::Unknown,
    };
    let Some(rva) = find_export(|rva, buf| read_remote(process, base, rva, buf), READY_EXPORT) else {
        return Readiness::Unknown;
    };
    let mut value = [0u8; 4];
    if !read_remote(process, base, rva, &mut value) {
        return Readiness::Unknown;
    }
    if u32::from_le_bytes(value) != 0 {
        Readiness::Ready
    } else {
        Readiness::NotReady
    }
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

    // Если удалённый поток не дождались, LoadLibraryW в нём ещё может читать
    // строку пути (её не копируют). Освободить её сейчас — значит подсунуть
    // чужому процессу освобождённую страницу. Пусть лучше останутся лишние
    // несколько сотен байт.
    if !matches!(result, Err(InjectError::Timeout | InjectError::WaitFailed(_))) {
        unsafe { VirtualFreeEx(process, remote, 0, MEM_RELEASE) };
    }
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
    match unsafe { WaitForSingleObject(thread.0, REMOTE_TIMEOUT_MS) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => return Err(InjectError::Timeout),
        _ => return Err(InjectError::WaitFailed(unsafe { GetLastError() })),
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

/// Читает `buf.len()` байт по смещению `rva` от `base` в чужом процессе.
fn read_remote(process: HANDLE, base: usize, rva: usize, buf: &mut [u8]) -> bool {
    let Some(address) = base.checked_add(rva) else {
        return false;
    };
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(process, address as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut read)
    };
    ok != 0 && read == buf.len()
}

/// Больше имён и функций в экспорте не бывает (ординал 16-битный). Заодно
/// испорченный заголовок не раздует выделение в чужом процессе.
const MAX_EXPORTS: usize = 0x1_0000;

/// Ищет экспорт `name` в загруженном образе PE32+, читая его через
/// `read(rva, buf)`, и возвращает RVA функции. Каждое поле заголовка
/// проверяется на выход за пределы образа: модуль чужой, верить ему на
/// слово нельзя. Перенаправленный экспорт («dll.func») считается ненайденным.
fn find_export(mut read: impl FnMut(usize, &mut [u8]) -> bool, name: &str) -> Option<usize> {
    fn u16_at(buf: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([buf[at], buf[at + 1]])
    }
    fn u32_at(buf: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
    }

    // IMAGE_DOS_HEADER: e_magic по смещению 0, e_lfanew — 0x3C.
    let mut dos = [0u8; 0x40];
    if !read(0, &mut dos) || u16_at(&dos, 0) != 0x5A4D {
        return None;
    }
    let nt_at = u32_at(&dos, 0x3C) as usize;

    // IMAGE_NT_HEADERS64: подпись (4) + IMAGE_FILE_HEADER (20) + опциональный
    // заголовок до первого элемента DataDirectory включительно (112 + 8).
    const OPT: usize = 24;
    let mut nt = [0u8; OPT + 112 + 8];
    if !read(nt_at, &mut nt) || u32_at(&nt, 0) != 0x0000_4550 || u16_at(&nt, OPT) != 0x20B {
        return None;
    }
    let image_size = u32_at(&nt, OPT + 56) as usize;
    if nt_at.saturating_add(nt.len()) > image_size || u32_at(&nt, OPT + 108) == 0 {
        return None;
    }
    let dir_rva = u32_at(&nt, OPT + 112) as usize;
    let dir_size = u32_at(&nt, OPT + 116) as usize;
    let inside = |rva: usize, len: usize| rva.checked_add(len).is_some_and(|end| end <= image_size);
    if dir_rva == 0 || !inside(dir_rva, 40) {
        return None;
    }

    // IMAGE_EXPORT_DIRECTORY.
    let mut dir = [0u8; 40];
    if !read(dir_rva, &mut dir) {
        return None;
    }
    let functions = u32_at(&dir, 20) as usize;
    let names = u32_at(&dir, 24) as usize;
    let functions_rva = u32_at(&dir, 28) as usize;
    let names_rva = u32_at(&dir, 32) as usize;
    let ordinals_rva = u32_at(&dir, 36) as usize;
    if names > MAX_EXPORTS
        || functions > MAX_EXPORTS
        || !inside(names_rva, names * 4)
        || !inside(ordinals_rva, names * 2)
        || !inside(functions_rva, functions * 4)
    {
        return None;
    }

    let mut name_rvas = vec![0u8; names * 4];
    let mut ordinals = vec![0u8; names * 2];
    if !read(names_rva, &mut name_rvas) || !read(ordinals_rva, &mut ordinals) {
        return None;
    }

    // Имя сравниваем вместе с завершающим нулём, иначе «init» совпал бы
    // с «init_something».
    let wanted: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
    let mut candidate = vec![0u8; wanted.len()];
    for i in 0..names {
        let name_rva = u32_at(&name_rvas, i * 4) as usize;
        if !inside(name_rva, wanted.len()) || !read(name_rva, &mut candidate) || candidate != wanted {
            continue;
        }
        let ordinal = u16_at(&ordinals, i * 2) as usize;
        if ordinal >= functions {
            return None;
        }
        let mut entry = [0u8; 4];
        if !read(functions_rva + ordinal * 4, &mut entry) {
            return None;
        }
        let rva = u32_at(&entry, 0) as usize;
        let forwarded = rva >= dir_rva && rva < dir_rva.saturating_add(dir_size);
        if rva == 0 || forwarded || rva >= image_size {
            return None;
        }
        return Some(rva);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    fn put16(img: &mut [u8], at: usize, v: u16) {
        img[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(img: &mut [u8], at: usize, v: u32) {
        img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Минимальный образ PE32+ с двумя экспортами: «other_init» (ординал 0,
    /// RVA за пределами образа) и `export` (ординал 1, RVA `func_rva`).
    fn image(export: &str, func_rva: u32) -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        put16(&mut img, 0, 0x5A4D);
        put32(&mut img, 0x3C, 0x80);
        put32(&mut img, 0x80, 0x4550);
        let opt = 0x80 + 24;
        put16(&mut img, opt, 0x20B);
        put32(&mut img, opt + 56, 0x400); // SizeOfImage
        put32(&mut img, opt + 108, 16); // NumberOfRvaAndSizes
        put32(&mut img, opt + 112, 0x200); // каталог экспорта
        put32(&mut img, opt + 116, 0x100);
        let dir = 0x200;
        put32(&mut img, dir + 20, 2); // функций
        put32(&mut img, dir + 24, 2); // имён
        put32(&mut img, dir + 28, 0x340);
        put32(&mut img, dir + 32, 0x350);
        put32(&mut img, dir + 36, 0x360);
        put32(&mut img, 0x340, 0x1234);
        put32(&mut img, 0x344, func_rva);
        put32(&mut img, 0x350, 0x370);
        put32(&mut img, 0x354, 0x390);
        put16(&mut img, 0x360, 0);
        put16(&mut img, 0x362, 1);
        img[0x370..0x370 + 10].copy_from_slice(b"other_init");
        img[0x390..0x390 + export.len()].copy_from_slice(export.as_bytes());
        img
    }

    fn reader(img: &[u8]) -> impl FnMut(usize, &mut [u8]) -> bool + '_ {
        move |rva, buf| match rva.checked_add(buf.len()).and_then(|end| img.get(rva..end)) {
            Some(src) => {
                buf.copy_from_slice(src);
                true
            }
            None => false,
        }
    }

    #[test]
    fn finds_export_by_exact_name() {
        let img = image("vpnsplit_hook_init", 0x300);
        assert_eq!(find_export(reader(&img), "vpnsplit_hook_init"), Some(0x300));
        assert_eq!(find_export(reader(&img), "vpnsplit_hook"), None);
        assert_eq!(find_export(reader(&img), "vpnsplit_hook_init_x"), None);
        // RVA функции за пределами образа.
        assert_eq!(find_export(reader(&img), "other_init"), None);
    }

    #[test]
    fn rejects_forwarders_and_garbage() {
        // RVA внутри каталога экспорта — это строка перенаправления.
        let img = image("vpnsplit_hook_init", 0x210);
        assert_eq!(find_export(reader(&img), "vpnsplit_hook_init"), None);

        let mut img = image("vpnsplit_hook_init", 0x300);
        img[0] = 0; // не MZ
        assert_eq!(find_export(reader(&img), "vpnsplit_hook_init"), None);

        let mut img = image("vpnsplit_hook_init", 0x300);
        put32(&mut img, 0x200 + 24, u32::MAX); // имён «очень много»
        assert_eq!(find_export(reader(&img), "vpnsplit_hook_init"), None);

        let mut img = image("vpnsplit_hook_init", 0x300);
        put32(&mut img, 0x3C, 0x7FFF_FFF0); // e_lfanew мимо образа
        assert_eq!(find_export(reader(&img), "vpnsplit_hook_init"), None);

        let mut img = image("vpnsplit_hook_init", 0x300);
        put16(&mut img, 0x362, 7); // ординал больше числа функций
        assert_eq!(find_export(reader(&img), "vpnsplit_hook_init"), None);
    }

    /// Тот же путь, что для потомка, но на своём процессе: чтение через
    /// ReadProcessMemory и сверка с GetProcAddress.
    #[test]
    fn matches_get_proc_address_on_real_module() {
        let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll".as_ref()).as_ptr()) };
        assert!(!kernel32.is_null());
        let expected = unsafe { GetProcAddress(kernel32, c"LoadLibraryW".as_ptr() as *const u8) }
            .expect("LoadLibraryW") as usize;
        let base = kernel32 as usize;
        let process = unsafe { GetCurrentProcess() };
        let rva = find_export(|rva, buf| read_remote(process, base, rva, buf), "LoadLibraryW")
            .expect("экспорт найден");
        assert_eq!(base + rva, expected);
        assert_eq!(find_export(|rva, buf| read_remote(process, base, rva, buf), "NoSuchExport"), None);
    }

    /// Признак хуков на своём процессе: hook.dll в нём нет, а у модуля без
    /// признака (старая сборка) ответ — «не известно», а не «не стоят».
    #[test]
    fn readiness_tells_absent_from_unknown() {
        let process = unsafe { GetCurrentProcess() };
        assert_eq!(readiness(process, Path::new(vpnsplit_core::hook::DLL_NAME)), Readiness::Absent);
        assert_eq!(readiness(process, Path::new("kernel32.dll")), Readiness::Unknown);
    }
}

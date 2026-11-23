//! Библиотека, загружаемая в процесс, запущенный через лончер.
//!
//! Две обязанности:
//! 1. Каждому сокету IPv4/IPv6 ставит `IP_UNICAST_IF` (и `IPV6_UNICAST_IF`)
//!    с индексом интерфейса туннеля. Сокеты, которые биндятся или
//!    подключаются к локальным адресам (loopback и домашняя сеть), от
//!    привязки освобождаются: программы общаются сами с собой через
//!    127.0.0.1 и ходят к роутеру, а привязанный к туннелю сокет туда
//!    не достаёт.
//! 2. Перехватывает создание процессов и внедряет себя в потомков —
//!    у браузеров сеть живёт не в главном процессе.
//!
//! Правила, которые здесь нарушать нельзя:
//! - ни одной паники наружу: весь наш код идёт под `catch_unwind`, иначе
//!   упадёт приложение пользователя;
//! - результат и код ошибки оригинальной функции не трогаем;
//! - в DllMain ничего не делаем: хуки ставит экспорт `vpnsplit_hook_init`.

mod dns;
mod hooks;
mod log;

use std::ffi::c_void;
use std::panic::catch_unwind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::OnceLock;
use vpnsplit_core::hook::{status, IFINDEX_ENV};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};

/// Индекс интерфейса туннеля. Ноль — хуки не установлены, ничего не делаем.
static IFINDEX: AtomicU32 = AtomicU32::new(0);
/// Сколько сокетов привязано. Для журнала и будущей статистики.
static BOUND: AtomicU32 = AtomicU32::new(0);
/// Путь к самой себе и смещение init — нужны для внедрения в потомков.
static SELF_PATH: OnceLock<PathBuf> = OnceLock::new();
static INIT_OFFSET: AtomicUsize = AtomicUsize::new(0);

/// Версия ABI. 2 — индекс передаётся параметром init.
#[no_mangle]
pub extern "system" fn vpnsplit_hook_abi_version() -> u32 {
    2
}

/// Сколько сокетов уже привязано к туннелю в этом процессе.
#[no_mangle]
pub extern "system" fn vpnsplit_hook_bound_count() -> u32 {
    BOUND.load(Ordering::Relaxed)
}

/// Точка входа для удалённого потока. Сигнатура — `LPTHREAD_START_ROUTINE`,
/// параметр — индекс интерфейса (не указатель), код возврата — `hook::status`.
#[no_mangle]
pub extern "system" fn vpnsplit_hook_init(param: *mut c_void) -> u32 {
    catch_unwind(|| init(param as usize as u32)).unwrap_or(status::PANIC)
}

fn init(param: u32) -> u32 {
    // Повторный вызов в том же процессе — не ошибка.
    if IFINDEX.load(Ordering::SeqCst) != 0 {
        return status::OK;
    }

    let index = if param != 0 {
        param
    } else {
        let Ok(raw) = std::env::var(IFINDEX_ENV) else {
            return status::NO_ENV;
        };
        match raw.trim().parse() {
            Ok(value) if value != 0 => value,
            _ => return status::BAD_ENV,
        }
    };

    remember_self();
    log::open();

    let code = hooks::install(index);
    log::write(&format!(
        "init: индекс {index}, {} (код {code})",
        status::describe(code)
    ));
    code
}

/// Запоминает собственный путь и смещение init — по ним hook.dll внедряет
/// себя в потомков ровно так же, как лончер внедрил её сюда.
fn remember_self() {
    let anchor = vpnsplit_hook_init as *const u16;
    let mut module = std::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            anchor,
            &mut module,
        )
    };
    if ok == 0 {
        return;
    }
    INIT_OFFSET.store(
        vpnsplit_hook_init as *const () as usize - module as usize,
        Ordering::SeqCst,
    );

    let mut buf = [0u16; 1024];
    let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len > 0 && len < buf.len() {
        let _ = SELF_PATH.set(PathBuf::from(String::from_utf16_lossy(&buf[..len])));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn abi_version_is_stable() {
        assert_eq!(super::vpnsplit_hook_abi_version(), 2);
    }

    #[test]
    fn init_without_param_and_env_reports_it() {
        std::env::remove_var(vpnsplit_core::hook::IFINDEX_ENV);
        assert_eq!(super::init(0), vpnsplit_core::hook::status::NO_ENV);
    }
}

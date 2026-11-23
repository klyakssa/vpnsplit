//! Журнал hook.dll. Включается переменной `VPNSPLIT_LOG` с путём к файлу.
//!
//! Без переменной не делает ничего и не стоит ничего. Ошибки записи
//! молча игнорируются: процесс в песочнице писать файлы не может, и это
//! не повод мешать приложению.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use vpnsplit_core::hook::LOG_ENV;

static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
static LOCK: Mutex<()> = Mutex::new(());

pub fn open() {
    PATH.get_or_init(|| std::env::var_os(LOG_ENV).map(PathBuf::from));
}

pub fn write(message: &str) {
    let Some(Some(path)) = PATH.get() else {
        return;
    };
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();
    let line = format!("pid {:>6} {exe:<16} {message}\n", std::process::id());

    // Несколько процессов пишут в один файл: каждая строка — одна запись
    // в режиме append, так строки не перемешиваются.
    let _guard = LOCK.lock();
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes());
    }
}

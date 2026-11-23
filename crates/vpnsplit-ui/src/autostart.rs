//! Запуск окна вместе с Windows.
//!
//! Речь только об окне и значке в трее. Служба, которая и ведёт приложения
//! в туннель, запускается с Windows сама — она установлена с автозапуском и
//! от этой галочки не зависит. Галочка отвечает на другой вопрос: видеть ли
//! значок сразу после входа, не открывая программу руками.
//!
//! Способ — самый обычный: строка в `HKCU\…\CurrentVersion\Run`. Прав
//! администратора не нужно, запись видна в «Автозагрузке» диспетчера задач
//! и там же выключается, и касается она только этого пользователя. Задача
//! планировщика или служба для окна были бы тяжелее и ничего не добавили.
//!
//! Окно при таком запуске не показывается (`--tray`): выскакивающее при
//! каждом входе окно — это то, из-за чего автозапуск выключают.

use crate::win::{from_wide, wide};
use std::path::Path;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE: &str = "vpnsplit";

/// Ключ, с которым окно запускается при входе: значок есть, окна нет.
pub const TRAY_FLAG: &str = "--tray";

/// Запущены ли мы автозапуском — то есть показывать ли окно сразу.
pub fn wants_tray(args: &[String]) -> bool {
    args.iter().any(|argument| argument == TRAY_FLAG)
}

/// Строка автозапуска для этого файла. Путь в кавычках: без них пробел в
/// пути превращает его начало в имя программы.
pub fn command(exe: &Path) -> String {
    format!("\"{}\" {TRAY_FLAG}", exe.display())
}

/// Наша ли это строка — та, что запустит именно этот файл.
///
/// Сравнение без учёта регистра: путь один, а записать его Windows может
/// по-разному. Строка, ведущая к другому файлу (программу перенесли, а
/// запись осталась), нашей не считается: галочка тогда снята, и поставить
/// её — значит переписать запись на нынешнее место.
pub fn points_here(stored: &str, exe: &Path) -> bool {
    stored.trim().to_lowercase() == command(exe).to_lowercase()
}

fn me() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("не найден свой путь: {e}"))
}

/// Что сейчас записано в автозапуске под нашим именем.
fn stored() -> Option<String> {
    let mut buffer = [0u16; 1024];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    let code = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            wide(RUN_KEY).as_ptr(),
            wide(VALUE).as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut _,
            &mut size,
        )
    };
    (code == ERROR_SUCCESS).then(|| from_wide(&buffer))
}

/// Включён ли автозапуск этого самого файла.
pub fn enabled() -> bool {
    match (stored(), me()) {
        (Some(line), Ok(exe)) => points_here(&line, &exe),
        _ => false,
    }
}

/// Запись автозапуска есть, но ведёт к этой же программе в другом месте:
/// её перенесли (установили из папки сборки), а запись осталась.
fn left_behind(stored: &str, exe: &Path) -> bool {
    !points_here(stored, exe) && stored.to_lowercase().contains("vpnsplit-ui.exe")
}

/// Перевести на себя автозапуск, оставшийся от прежнего места. Зовёт это
/// только установленная копия: иначе окно из папки сборки, запущенное для
/// проверки, утащило бы автозапуск к себе. Выключенный автозапуск не
/// включается — это решение человека.
pub fn adopt() {
    if let (Some(line), Ok(exe)) = (stored(), me()) {
        if left_behind(&line, &exe) {
            let _ = set(true);
        }
    }
}

fn open_run_key() -> Result<HKEY, String> {
    let mut key: HKEY = std::ptr::null_mut();
    let code = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide(RUN_KEY).as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(format!("раздел автозапуска не открылся (код {code})"));
    }
    Ok(key)
}

/// Включить или выключить. Выключение записи, которой и так нет, — успех.
pub fn set(on: bool) -> Result<(), String> {
    let key = open_run_key()?;
    let code = if on {
        match me() {
            Ok(exe) => {
                let line = wide(&command(&exe));
                unsafe {
                    RegSetValueExW(
                        key,
                        wide(VALUE).as_ptr(),
                        0,
                        REG_SZ,
                        line.as_ptr() as *const u8,
                        (line.len() * 2) as u32,
                    )
                }
            }
            Err(reason) => {
                unsafe { RegCloseKey(key) };
                return Err(reason);
            }
        }
    } else {
        match unsafe { RegDeleteValueW(key, wide(VALUE).as_ptr()) } {
            ERROR_FILE_NOT_FOUND => ERROR_SUCCESS,
            other => other,
        }
    };
    unsafe { RegCloseKey(key) };
    if code != ERROR_SUCCESS {
        return Err(format!("запись автозапуска не изменилась (код {code})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{command, points_here, wants_tray};
    use std::path::Path;

    #[test]
    fn the_path_is_quoted_so_a_space_does_not_cut_it() {
        assert_eq!(
            command(Path::new(r"C:\Program Files\vpnsplit\vpnsplit-ui.exe")),
            "\"C:\\Program Files\\vpnsplit\\vpnsplit-ui.exe\" --tray"
        );
    }

    #[test]
    fn our_line_is_known_however_windows_spells_the_path() {
        let exe = Path::new(r"G:\Проекты\vpnsplit\vpnsplit-ui.exe");
        assert!(points_here(&command(exe), exe));
        assert!(points_here("\"g:\\проекты\\VPNSPLIT\\vpnsplit-ui.exe\" --tray ", exe));
    }

    #[test]
    fn a_line_left_from_another_place_is_not_ours() {
        let exe = Path::new(r"C:\new\vpnsplit-ui.exe");
        assert!(!points_here("\"C:\\old\\vpnsplit-ui.exe\" --tray", exe));
        // Та же программа, но без ключа: она открывала бы окно при входе.
        assert!(!points_here("\"C:\\new\\vpnsplit-ui.exe\"", exe));
        assert!(!points_here("", exe));
    }

    #[test]
    fn an_entry_left_at_the_old_place_is_told_from_ours_and_from_strangers() {
        let here = Path::new(r"C:\Program Files\vpnsplit\vpnsplit-ui.exe");
        let old = r#""G:\src\vpnsplit\target\debug\vpnsplit-ui.exe" --tray"#;
        assert!(super::left_behind(old, here));
        assert!(!super::left_behind(&command(here), here), "своя запись — не чужая");
        assert!(!super::left_behind(r#""C:\Other\other.exe" --tray"#, here), "чужую программу не трогаем");
    }

    #[test]
    fn the_window_stays_hidden_only_when_asked() {
        let args = |list: &[&str]| list.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert!(wants_tray(&args(&["--tray"])));
        assert!(!wants_tray(&args(&[])));
        assert!(!wants_tray(&args(&["--run", "C:\\a.exe"])));
    }
}

//! Ярлык на рабочем столе, запускающий приложение через туннель.
//!
//! Ярлык указывает не на лончер, а на само окно vpnsplit с ключом `--run`.
//! Причина простая: лончер — консольная программа, и ярлык на него мигал бы
//! чёрным окном при каждом запуске. Окно же — обычное приложение Windows,
//! оно запускает лончер скрытно и сразу завершается.
//!
//! COM-интерфейсы объявлены здесь вручную: в `windows-sys` их нет вовсе, а
//! тянуть ради одного ярлыка большой крейт незачем. Порядок методов в
//! таблице менять нельзя — вызов идёт по смещению.

use crate::win::{from_wide, wide};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use windows_sys::core::{GUID, HRESULT, PWSTR};
use windows_sys::Win32::Foundation::{S_FALSE, S_OK};
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_Desktop, FOLDERID_Programs};

const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);
const IID_ISHELL_LINK_W: GUID = GUID::from_u128(0x000214f9_0000_0000_c000_000000000046);
const IID_IPERSIST_FILE: GUID = GUID::from_u128(0x0000010b_0000_0000_c000_000000000046);

type Unknown = *mut c_void;

/// Таблица методов `IShellLinkW`. Три первых — от `IUnknown`, дальше порядок
/// объявлен в `shobjidl_core.h` и менялся последний раз никогда.
#[repr(C)]
struct ShellLinkVtbl {
    query_interface: unsafe extern "system" fn(Unknown, *const GUID, *mut Unknown) -> HRESULT,
    add_ref: unsafe extern "system" fn(Unknown) -> u32,
    release: unsafe extern "system" fn(Unknown) -> u32,
    get_path: unsafe extern "system" fn(Unknown, PWSTR, i32, *mut c_void, u32) -> HRESULT,
    get_id_list: unsafe extern "system" fn(Unknown, *mut *mut c_void) -> HRESULT,
    set_id_list: unsafe extern "system" fn(Unknown, *const c_void) -> HRESULT,
    get_description: unsafe extern "system" fn(Unknown, PWSTR, i32) -> HRESULT,
    set_description: unsafe extern "system" fn(Unknown, *const u16) -> HRESULT,
    get_working_directory: unsafe extern "system" fn(Unknown, PWSTR, i32) -> HRESULT,
    set_working_directory: unsafe extern "system" fn(Unknown, *const u16) -> HRESULT,
    get_arguments: unsafe extern "system" fn(Unknown, PWSTR, i32) -> HRESULT,
    set_arguments: unsafe extern "system" fn(Unknown, *const u16) -> HRESULT,
    get_hotkey: unsafe extern "system" fn(Unknown, *mut u16) -> HRESULT,
    set_hotkey: unsafe extern "system" fn(Unknown, u16) -> HRESULT,
    get_show_cmd: unsafe extern "system" fn(Unknown, *mut i32) -> HRESULT,
    set_show_cmd: unsafe extern "system" fn(Unknown, i32) -> HRESULT,
    get_icon_location: unsafe extern "system" fn(Unknown, PWSTR, i32, *mut i32) -> HRESULT,
    set_icon_location: unsafe extern "system" fn(Unknown, *const u16, i32) -> HRESULT,
    set_relative_path: unsafe extern "system" fn(Unknown, *const u16, u32) -> HRESULT,
    resolve: unsafe extern "system" fn(Unknown, *mut c_void, u32) -> HRESULT,
    set_path: unsafe extern "system" fn(Unknown, *const u16) -> HRESULT,
}

/// `IPersistFile`: наследует `IPersist`, отсюда `get_class_id` перед своими.
#[repr(C)]
struct PersistFileVtbl {
    query_interface: unsafe extern "system" fn(Unknown, *const GUID, *mut Unknown) -> HRESULT,
    add_ref: unsafe extern "system" fn(Unknown) -> u32,
    release: unsafe extern "system" fn(Unknown) -> u32,
    get_class_id: unsafe extern "system" fn(Unknown, *mut GUID) -> HRESULT,
    is_dirty: unsafe extern "system" fn(Unknown) -> HRESULT,
    load: unsafe extern "system" fn(Unknown, *const u16, u32) -> HRESULT,
    save: unsafe extern "system" fn(Unknown, *const u16, i32) -> HRESULT,
    save_completed: unsafe extern "system" fn(Unknown, *const u16) -> HRESULT,
    get_cur_file: unsafe extern "system" fn(Unknown, *mut PWSTR) -> HRESULT,
}

unsafe fn vtable<T>(object: Unknown) -> *const T {
    *(object as *const *const T)
}

/// COM на время одного вызова. `S_FALSE` значит «уже было инициализировано
/// на этом потоке» — тогда закрывать не нам.
pub(crate) struct Com {
    close: bool,
}

impl Com {
    pub(crate) fn open() -> Result<Com, String> {
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        match hr {
            S_OK => Ok(Com { close: true }),
            S_FALSE => Ok(Com { close: false }),
            other => Err(format!("CoInitializeEx вернул 0x{other:08X}")),
        }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.close {
            unsafe { CoUninitialize() };
        }
    }
}

/// Путь к рабочему столу. Через известную папку, а не через `%USERPROFILE%`:
/// рабочий стол бывает перенесён в OneDrive, и тогда второй путь ведёт не
/// туда, где пользователь увидит ярлык.
fn desktop() -> Result<PathBuf, String> {
    known_folder(&FOLDERID_Desktop, "рабочий стол")
}

/// Известная папка Windows по её номеру.
fn known_folder(id: &windows_sys::core::GUID, what: &str) -> Result<PathBuf, String> {
    let mut raw: PWSTR = std::ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut raw) };
    if hr != S_OK || raw.is_null() {
        return Err(format!("не удалось найти {what}"));
    }
    let mut length = 0;
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    let path = from_wide(unsafe { std::slice::from_raw_parts(raw, length + 1) });
    unsafe { CoTaskMemFree(raw as *const c_void) };
    Ok(PathBuf::from(path))
}

/// Создаёт на рабочем столе ярлык, запускающий приложение через туннель.
/// Возвращает путь к ярлыку.
pub fn create(app: &Path) -> Result<PathBuf, String> {
    let me = std::env::current_exe().map_err(|e| format!("не найден свой путь: {e}"))?;
    let name = app
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .ok_or("у приложения нет имени файла")?;
    let target = desktop()?.join(format!("{name} (VPN).lnk"));

    // Кавычки обязательны: в пути к приложению бывают пробелы.
    let arguments = format!("--run \"{}\"", app.display());
    // Значок берётся у самого приложения — ярлык выглядит как привычный.
    make(&me, &arguments, app, "Запуск через VPN (vpnsplit)", app.parent(), &target)?;
    Ok(target)
}

/// Ярлык самой программы в меню «Пуск» этого человека — если его там ещё
/// нет. Заводит его установленная копия при запуске: меню у каждого своё,
/// а установщик работает от имени администратора.
pub fn ensure_start_menu() -> Result<(), String> {
    let me = std::env::current_exe().map_err(|e| format!("не найден свой путь: {e}"))?;
    let target = known_folder(&FOLDERID_Programs, "меню «Пуск»")?.join("vpnsplit.lnk");
    if target.is_file() {
        return Ok(());
    }
    make(&me, "", &me, "vpnsplit — раздельное туннелирование", me.parent(), &target)
}

/// Записывает ярлык: что запускать, с чем, чей значок и где лежать.
fn make(
    exe: &Path,
    arguments: &str,
    icon: &Path,
    description: &str,
    folder: Option<&Path>,
    target: &Path,
) -> Result<(), String> {
    let _com = Com::open()?;
    let mut link: Unknown = std::ptr::null_mut();
    let hr = unsafe {
        CoCreateInstance(
            &CLSID_SHELL_LINK,
            std::ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_ISHELL_LINK_W,
            &mut link,
        )
    };
    if hr != S_OK || link.is_null() {
        return Err(format!("не удалось создать объект ярлыка (0x{hr:08X})"));
    }

    let result = unsafe { fill_and_save(link, exe, arguments, icon, description, folder, target) };
    unsafe { ((*vtable::<ShellLinkVtbl>(link)).release)(link) };
    result
}

unsafe fn fill_and_save(
    link: Unknown,
    exe: &Path,
    arguments: &str,
    icon: &Path,
    description: &str,
    folder: Option<&Path>,
    target: &Path,
) -> Result<(), String> {
    let table = vtable::<ShellLinkVtbl>(link);

    (table.read().set_path)(link, wide(&exe.to_string_lossy()).as_ptr());
    (table.read().set_arguments)(link, wide(arguments).as_ptr());
    (table.read().set_icon_location)(link, wide(&icon.to_string_lossy()).as_ptr(), 0);
    (table.read().set_description)(link, wide(description).as_ptr());
    if let Some(folder) = folder {
        (table.read().set_working_directory)(link, wide(&folder.to_string_lossy()).as_ptr());
    }

    let mut file: Unknown = std::ptr::null_mut();
    let hr = (table.read().query_interface)(link, &IID_IPERSIST_FILE, &mut file);
    if hr != S_OK || file.is_null() {
        return Err(format!("ярлык не умеет сохраняться (0x{hr:08X})"));
    }
    let persist = vtable::<PersistFileVtbl>(file);
    let hr = (persist.read().save)(file, wide(&target.to_string_lossy()).as_ptr(), 1);
    (persist.read().release)(file);
    if hr != S_OK {
        return Err(format!("не удалось записать ярлык (0x{hr:08X})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_match_the_system_ones() {
        // Если перепутать байты в GUID, CoCreateInstance просто вернёт
        // ошибку, и причину искать будет долго.
        assert_eq!(CLSID_SHELL_LINK.data1, 0x0002_1401);
        assert_eq!(CLSID_SHELL_LINK.data4, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
        assert_eq!(IID_ISHELL_LINK_W.data1, 0x0002_14f9);
        assert_eq!(IID_IPERSIST_FILE.data1, 0x0000_010b);
    }

    #[test]
    fn shortcut_lands_on_the_desktop_with_a_readable_name() {
        // Сам ярлык здесь не создаётся: проверяется только имя файла.
        let app = Path::new(r"C:\Program Files\Thing\thing.exe");
        let name = app.file_stem().unwrap().to_string_lossy().into_owned();
        assert_eq!(format!("{name} (VPN).lnk"), "thing (VPN).lnk");
    }

    #[test]
    fn arguments_quote_the_path() {
        let app = Path::new(r"C:\Program Files\A B\app.exe");
        let arguments = format!("--run \"{}\"", app.display());
        assert_eq!(arguments, "--run \"C:\\Program Files\\A B\\app.exe\"");
    }
}

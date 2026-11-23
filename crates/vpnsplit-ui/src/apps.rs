//! Приложения из Store, установленные у пользователя: имя, под которым их
//! знает человек, и семейство пакета, по которому пишется правило.
//!
//! Источник — папка «Приложения» оболочки (`shell:AppsFolder`), та же, из
//! которой собрано меню «Пуск». В ней ровно то, что человек может открыть
//! сам: без библиотек и служебных пакетов, которых в списке установленных
//! пакетов больше половины, и сразу с настоящими названиями — «ChatGPT», а
//! не `OpenAI.Codex_2p2nqsd0c76g0`.
//!
//! COM-интерфейсы, как и в `shortcut`, объявлены вручную: в `windows-sys`
//! их нет. Порядок методов в таблицах менять нельзя.

use crate::shortcut::Com;
use crate::win::wide;
use std::ffi::c_void;
use windows_sys::core::{GUID, HRESULT, PWSTR};
use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::SHCreateItemFromParsingName;

const IID_ISHELL_ITEM: GUID = GUID::from_u128(0x43826d1e_e718_42ee_bc55_a1e261c37bfe);
const IID_IENUM_SHELL_ITEMS: GUID = GUID::from_u128(0x70629033_e363_4a28_a567_0db78006e6d7);
/// «Дай перечислитель того, что в этой папке».
const BHID_ENUM_ITEMS: GUID = GUID::from_u128(0x94f60519_2850_4924_aa5a_d15e84868039);

/// Название, как его показывает оболочка.
const SIGDN_NORMALDISPLAY: u32 = 0;
/// Имя внутри папки. Для приложения это его идентификатор (AUMID):
/// у пакетов — `Семейство!Приложение`.
const SIGDN_PARENTRELATIVEPARSING: u32 = 0x8001_8001;

type Unknown = *mut c_void;

/// `IShellItem`: три метода `IUnknown`, дальше как в `shobjidl_core.h`.
#[repr(C)]
struct ShellItemVtbl {
    query_interface: unsafe extern "system" fn(Unknown, *const GUID, *mut Unknown) -> HRESULT,
    add_ref: unsafe extern "system" fn(Unknown) -> u32,
    release: unsafe extern "system" fn(Unknown) -> u32,
    bind_to_handler:
        unsafe extern "system" fn(Unknown, Unknown, *const GUID, *const GUID, *mut Unknown) -> HRESULT,
    get_parent: unsafe extern "system" fn(Unknown, *mut Unknown) -> HRESULT,
    get_display_name: unsafe extern "system" fn(Unknown, u32, *mut PWSTR) -> HRESULT,
    get_attributes: unsafe extern "system" fn(Unknown, u32, *mut u32) -> HRESULT,
    compare: unsafe extern "system" fn(Unknown, Unknown, u32, *mut i32) -> HRESULT,
}

/// `IEnumShellItems`.
#[repr(C)]
struct EnumShellItemsVtbl {
    query_interface: unsafe extern "system" fn(Unknown, *const GUID, *mut Unknown) -> HRESULT,
    add_ref: unsafe extern "system" fn(Unknown) -> u32,
    release: unsafe extern "system" fn(Unknown) -> u32,
    next: unsafe extern "system" fn(Unknown, u32, *mut Unknown, *mut u32) -> HRESULT,
    skip: unsafe extern "system" fn(Unknown, u32) -> HRESULT,
    reset: unsafe extern "system" fn(Unknown) -> HRESULT,
    clone: unsafe extern "system" fn(Unknown, *mut Unknown) -> HRESULT,
}

unsafe fn item(object: Unknown) -> &'static ShellItemVtbl {
    &**(object as *const *const ShellItemVtbl)
}

/// Имя элемента в нужном виде; строку оболочки освобождаем мы.
unsafe fn name_of(object: Unknown, form: u32) -> Option<String> {
    let mut raw: PWSTR = std::ptr::null_mut();
    if (item(object).get_display_name)(object, form, &mut raw) != S_OK || raw.is_null() {
        return None;
    }
    let mut length = 0;
    while *raw.add(length) != 0 {
        length += 1;
    }
    let text = String::from_utf16_lossy(std::slice::from_raw_parts(raw, length));
    CoTaskMemFree(raw as *const c_void);
    Some(text)
}

/// Установленные приложения-пакеты: название и семейство пакета. У пакета
/// бывает несколько приложений (Почта и Календарь) — тогда строк несколько,
/// с одним семейством.
///
/// Пусто — и когда пакетов нет, и когда оболочка не ответила: меню тогда
/// покажет хотя бы то, что запущено.
pub fn installed() -> Vec<(String, String)> {
    let Ok(_com) = Com::open() else { return Vec::new() };
    let mut found = Vec::new();
    unsafe {
        let mut folder: Unknown = std::ptr::null_mut();
        let hr = SHCreateItemFromParsingName(
            wide("shell:AppsFolder").as_ptr(),
            std::ptr::null_mut(),
            &IID_ISHELL_ITEM,
            &mut folder,
        );
        if hr != S_OK || folder.is_null() {
            return found;
        }
        let mut items: Unknown = std::ptr::null_mut();
        let hr = (item(folder).bind_to_handler)(
            folder,
            std::ptr::null_mut(),
            &BHID_ENUM_ITEMS,
            &IID_IENUM_SHELL_ITEMS,
            &mut items,
        );
        (item(folder).release)(folder);
        if hr != S_OK || items.is_null() {
            return found;
        }
        let list = &**(items as *const *const EnumShellItemsVtbl);
        loop {
            let mut one: Unknown = std::ptr::null_mut();
            let mut fetched = 0u32;
            if (list.next)(items, 1, &mut one, &mut fetched) != S_OK || one.is_null() {
                break;
            }
            let title = name_of(one, SIGDN_NORMALDISPLAY);
            let id = name_of(one, SIGDN_PARENTRELATIVEPARSING);
            (item(one).release)(one);
            if let (Some(title), Some(family)) = (title, id.as_deref().and_then(family_of)) {
                found.push((title, family));
            }
        }
        (list.release)(items);
    }
    found
}

/// Семейство пакета из идентификатора приложения.
///
/// У приложения-пакета он выглядит как `Имя.Пакета_издатель!Приложение`,
/// издатель — всегда тринадцать букв и цифр. У обычных программ в той же
/// папке идентификаторы другие — путь, имя или код папки, — и правило по
/// семейству для них не пишется.
fn family_of(id: &str) -> Option<String> {
    let (family, app) = id.split_once('!')?;
    let (name, publisher) = family.rsplit_once('_')?;
    let packaged = !name.is_empty()
        && !app.is_empty()
        && publisher.len() == 13
        && publisher.bytes().all(|b| b.is_ascii_alphanumeric());
    packaged.then(|| family.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_family_is_read_from_a_packaged_app_and_from_nothing_else() {
        assert_eq!(family_of("OpenAI.Codex_2p2nqsd0c76g0!App").as_deref(), Some("OpenAI.Codex_2p2nqsd0c76g0"));
        assert_eq!(
            family_of("Microsoft.WindowsCalculator_8wekyb3d8bbwe!App").as_deref(),
            Some("Microsoft.WindowsCalculator_8wekyb3d8bbwe")
        );
        // Обычные программы той же папки.
        assert_eq!(family_of(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe"), None);
        assert_eq!(family_of("Microsoft.Windows.Explorer"), None);
        assert_eq!(family_of("Chrome"), None);
        // Похоже, но не оно.
        assert_eq!(family_of("Some_thing!App"), None);
        assert_eq!(family_of("_8wekyb3d8bbwe!App"), None);
        assert_eq!(family_of("Name_8wekyb3d8bbwe!"), None);
    }

    #[test]
    fn identifiers_match_the_system_ones() {
        assert_eq!(IID_ISHELL_ITEM.data1, 0x4382_6d1e);
        assert_eq!(IID_IENUM_SHELL_ITEMS.data1, 0x7062_9033);
        assert_eq!(BHID_ENUM_ITEMS.data1, 0x94f6_0519);
        assert_eq!(BHID_ENUM_ITEMS.data4, [0xaa, 0x5a, 0xd1, 0x5e, 0x84, 0x86, 0x80, 0x39]);
    }

    /// Живая проверка на этой машине: `cargo test -p vpnsplit-ui -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn show_what_is_installed_here() {
        let started = std::time::Instant::now();
        let apps = installed();
        println!("за {} мс найдено {}:", started.elapsed().as_millis(), apps.len());
        for (title, family) in &apps {
            println!("  {title}  —  {family}");
        }
        assert!(!apps.is_empty());
    }
}

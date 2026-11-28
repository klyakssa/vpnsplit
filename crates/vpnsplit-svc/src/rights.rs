//! Чьи программы вправе ставить в список обычный пользователь.
//!
//! Список у службы общий на всю машину: правило на `.exe` действует на
//! каждый запуск этой программы, чей бы он ни был, а kill-switch и
//! запреты на время простоя закрывают ей сеть у всех. Окно работает без
//! повышения прав, и правка списка без прав остаётся. Но без прав нельзя
//! ставить правила на программы, которые заведомо не только твои:
//! системные (каталог Windows), приложения Store из общего
//! `Program Files\WindowsApps` и всё, что лежит в профилях других
//! пользователей. Иначе любая программа обычного пользователя могла бы,
//! например, закрыть сеть `svchost.exe` — то есть всей машине, и даже
//! после остановки службы.
//!
//! Правила, которые уже были в списке и не изменились, проходят: список
//! мог составить администратор, и окно без прав должно уметь сохранить его,
//! поменяв что-то своё.
//!
//! Системными считаются не только программы из каталога Windows, но и
//! части Windows в `Program Files\Windows …` и `ProgramData\Microsoft`:
//! там, например, живёт служба Защитника. Чего этот список не знает —
//! служб сторонних программ из `Program Files` и `ProgramData`, которые тоже
//! работают от SYSTEM. Их без прав в список поставить можно, как и любую
//! общую программу (браузер из `Program Files` тоже общий для всех); это
//! известный остаток, а не недосмотр.
//!
//! Принятое правило проверяется ещё раз там, где на программу ставится
//! фильтр (`vet`): путь к ней мог стать ссылкой уже после проверки.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use vpnsplit_core::{AppRule, AppTarget, Policy};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    RRF_RT_REG_SZ,
};

const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// Каталоги, программы из которых без прав в список не ставятся. Все пути —
/// в нормальном виде (`normalize`).
#[derive(Clone, Debug, Default)]
pub struct Places {
    pub system_root: Option<String>,
    /// Другие каталоги Windows вне `system_root` (`ProgramData\Microsoft`).
    pub system_dirs: Vec<String>,
    /// Каталоги `Program Files`: части Windows в них — подкаталоги, имя
    /// которых начинается с `windows` (`Windows Defender`, `Windows NT`…).
    pub program_files: Vec<String>,
    pub windows_apps: Vec<String>,
    /// Общий каталог профилей (`C:\Users`).
    pub profiles_root: Option<String>,
    /// Профили по SID пользователя.
    pub profiles: Vec<(String, String)>,
}

impl Places {
    /// Как они есть на этой машине сейчас.
    pub fn current() -> Self {
        let from_env = |name: &str| std::env::var_os(name).and_then(|value| normalize(Path::new(&value)));
        let system_root = from_env("SystemRoot").or_else(|| from_env("windir"));
        let mut program_files: Vec<String> =
            ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"].into_iter().filter_map(from_env).collect();
        program_files.sort();
        program_files.dedup();
        let windows_apps = program_files.iter().map(|base| format!(r"{base}\windowsapps")).collect();
        let system_dirs = from_env("ProgramData").map(|base| format!(r"{base}\microsoft")).into_iter().collect();
        let profiles_root =
            reg_string(HKEY_LOCAL_MACHINE, PROFILE_LIST, "ProfilesDirectory").and_then(|dir| normalize(Path::new(&dir)));
        Places { system_root, system_dirs, program_files, windows_apps, profiles_root, profiles: profiles() }
    }
}

/// Почему правило не принято от обычного пользователя.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Foreign {
    /// Путь не полный: служба искала бы такой файл от своего имени, в
    /// своём каталоге (`System32`).
    NotAbsolute,
    System,
    Store,
    OtherUser,
}

impl Foreign {
    fn why(self) -> &'static str {
        match self {
            Foreign::NotAbsolute => "путь не полный — нужен путь с буквой диска",
            Foreign::System => "это системная программа Windows, она общая для всех пользователей",
            Foreign::Store => {
                "это программа из общего каталога приложений Store (WindowsApps), она общая для всех пользователей"
            }
            Foreign::OtherUser => "программа лежит в профиле другого пользователя",
        }
    }
}

/// Принять ли политику от клиента без повышенных прав. `sid` — его SID;
/// `None` — не узнали, и тогда чужими считаются все профили.
///
/// Проверяются только новые и изменённые правила на `.exe`. Пакеты Store
/// опознаются по имени семейства, и пути у них нет.
pub fn admit(new: &Policy, current: &Policy, places: &Places, sid: Option<&str>) -> Result<(), String> {
    for rule in fresh(new, current) {
        let AppTarget::Executable(path) = &rule.target else { continue };
        if let Some(foreign) = foreign(path, places, sid) {
            return Err(format!(
                "без прав администратора «{}» в список не добавить: {}. Путь: {}. \
                 Добавь её из окна, запущенного от имени администратора",
                rule.target.display_name(),
                foreign.why(),
                path.display()
            ));
        }
    }
    Ok(())
}

/// Правила, которых в текущей политике нет в точности такими же.
pub fn fresh<'a>(new: &'a Policy, current: &'a Policy) -> impl Iterator<Item = &'a AppRule> + 'a {
    new.rules.iter().filter(move |rule| !current.rules.contains(rule))
}

/// Чья это программа, если не только того, кто просит.
///
/// Путь проверяется дважды: как написан и, если файл есть, как он лежит
/// на самом деле. Второе ловит обходы через точку соединения в своём
/// профиле, короткие имена 8.3 и прочие написания одного файла: Windows
/// запрет на программу ставит по настоящему файлу, а не по строке.
pub fn foreign(path: &Path, places: &Places, sid: Option<&str>) -> Option<Foreign> {
    let Some(written) = normalize(path) else { return Some(Foreign::NotAbsolute) };
    if let Some(foreign) = classify(&written, places, sid) {
        return Some(foreign);
    }
    // Сетевые пути служба не открывает: от имени SYSTEM она представилась
    // бы чужому серверу учётной записью машины.
    if written.starts_with(r"\\") {
        return None;
    }
    let real = std::fs::canonicalize(path).ok().and_then(|real| normalize(&real))?;
    classify(&real, places, sid)
}

/// Проверка там, где на программу ставится фильтр (см. `wfp::vet_apps`):
/// `written` — путь из правила, `real` — файл, который нашла по нему
/// Windows.
///
/// Кто ставил правило, здесь уже неизвестно, поэтому отказ — только когда
/// путь **ведёт через ссылку** туда, куда написанный не ведёт: в каталог
/// Windows, в общий каталог Store или из своего профиля в чужой. Правило
/// администратора на системную программу, написанное прямо, проходит.
pub fn vet(written: &Path, real: &Path) -> Result<(), String> {
    let Some(normal) = normalize(written) else {
        // Неполный путь служба искала бы в своём каталоге — `System32`.
        return Err(Foreign::NotAbsolute.why().to_owned());
    };
    // Обычный случай — путь и есть файл; реестр профилей тогда не нужен.
    if normalize(real).is_some_and(|real| real == normal) {
        return Ok(());
    }
    match redirected(written, real, &Places::current()) {
        None => Ok(()),
        Some(foreign) => Err(format!(
            "путь ведёт через ссылку в {}: {}. Фильтр на неё не ставлю",
            real.display(),
            foreign.why()
        )),
    }
}

/// Куда ведёт путь на самом деле, если это чужое место, а написанный путь
/// туда не ведёт. `None` — всё в порядке.
pub fn redirected(written: &Path, real: &Path, places: &Places) -> Option<Foreign> {
    let Some(written) = normalize(written) else { return Some(Foreign::NotAbsolute) };
    let real = normalize(real)?;
    if real == written {
        return None;
    }
    let (from, to) = (zone(&written, places), zone(&real, places));
    if from == to {
        return None;
    }
    match to {
        Zone::System => Some(Foreign::System),
        Zone::Store => Some(Foreign::Store),
        // Из своего профиля — в чужой. Ссылка с другого диска в профиль
        // ничего не выдаёт: чей это профиль, здесь всё равно не узнать.
        Zone::Profile(_) | Zone::Profiles if matches!(from, Zone::Profile(_)) => Some(Foreign::OtherUser),
        _ => None,
    }
}

/// Чьё это место — без учёта того, кто спрашивает.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Zone {
    Ordinary,
    System,
    Store,
    /// Профиль под этим номером в `Places::profiles`.
    Profile(usize),
    /// Каталог профилей, но не известный профиль (Public, Default).
    Profiles,
}

fn zone(path: &str, places: &Places) -> Zone {
    if system(path, places) {
        return Zone::System;
    }
    if places.windows_apps.iter().any(|dir| under(path, dir)) {
        return Zone::Store;
    }
    if let Some(index) = places.profiles.iter().position(|(_, dir)| under(path, dir)) {
        return Zone::Profile(index);
    }
    if places.profiles_root.as_deref().is_some_and(|root| under(path, root)) {
        return Zone::Profiles;
    }
    Zone::Ordinary
}

/// Каталог Windows и части Windows за его пределами.
fn system(path: &str, places: &Places) -> bool {
    if places.system_root.as_deref().is_some_and(|root| under(path, root)) {
        return true;
    }
    if places.system_dirs.iter().any(|dir| under(path, dir)) {
        return true;
    }
    // `Program Files\Windows Defender\…`, но не `WindowsApps` — это Store,
    // о нём отдельно.
    places.program_files.iter().any(|base| {
        under(path, base)
            && path[base.trim_end_matches('\\').len() + 1..]
                .split('\\')
                .next()
                .is_some_and(|first| first.starts_with("windows") && first != "windowsapps")
    })
}

fn classify(path: &str, places: &Places, sid: Option<&str>) -> Option<Foreign> {
    if system(path, places) {
        return Some(Foreign::System);
    }
    if places.windows_apps.iter().any(|dir| under(path, dir)) {
        return Some(Foreign::Store);
    }
    let own = |profile_sid: &str| sid.is_some_and(|sid| sid.eq_ignore_ascii_case(profile_sid));
    // Сначала свой профиль: тот же каталог бывает записан и за другим SID —
    // прежней учётной записью после переноса профиля или смены домена. Раз
    // каталог числится за тобой, программа в нём твоя.
    if places.profiles.iter().any(|(profile_sid, dir)| own(profile_sid) && under(path, dir)) {
        return None;
    }
    if places.profiles.iter().any(|(_, dir)| under(path, dir)) {
        return Some(Foreign::OtherUser);
    }
    // Каталог профилей, но ни в одном известном своём профиле: Public,
    // Default, профиль, которого нет в списке, — не только твоё.
    if places.profiles_root.as_deref().is_some_and(|root| under(path, root)) {
        return Some(Foreign::OtherUser);
    }
    None
}

/// Лежит ли `path` внутри `dir` (оба в нормальном виде).
fn under(path: &str, dir: &str) -> bool {
    let dir = dir.trim_end_matches('\\');
    !dir.is_empty() && path.len() > dir.len() && path.starts_with(dir) && path[dir.len()..].starts_with('\\')
}

/// Путь в одном написании: строчные буквы, обратная косая черта, без
/// `\\?\`, без `.` и `..`, без точек и пробелов в конце частей (Windows их
/// отбрасывает сама). `None` — путь не полный: ни буквы диска, ни `\\сервер`.
pub fn normalize(path: &Path) -> Option<String> {
    let text = path.to_string_lossy().replace('/', "\\");
    let text = text.to_lowercase();
    let (root, rest) = if let Some(rest) = text.strip_prefix(r"\\?\unc\") {
        (String::from(r"\\"), rest.to_owned())
    } else if let Some(rest) = text.strip_prefix(r"\\?\").or_else(|| text.strip_prefix(r"\\.\")).or_else(|| text.strip_prefix(r"\??\")) {
        drive(rest)?
    } else if let Some(rest) = text.strip_prefix(r"\\") {
        (String::from(r"\\"), rest.to_owned())
    } else {
        drive(&text)?
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        if part == ".." {
            parts.pop();
            continue;
        }
        // Остальное из одних точек и пробелов («.», «...») Windows сводит к
        // пустому месту.
        let part = part.trim_end_matches(&['.', ' '][..]);
        if !part.is_empty() {
            parts.push(part);
        }
    }
    // У сетевого пути сервер и общая папка — часть корня: `..` их не съест.
    if root == r"\\" && parts.len() < 2 {
        return None;
    }
    Some(format!("{root}{}", parts.join("\\")))
}

/// `c:\…` → корень `c:\` и остаток.
fn drive(text: &str) -> Option<(String, String)> {
    let mut chars = text.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() || chars.next()? != ':' {
        return None;
    }
    let rest = &text[2..];
    // `c:file.exe` — путь относительно текущего каталога диска.
    if !rest.starts_with('\\') {
        return None;
    }
    Some((format!("{letter}:\\"), rest.to_owned()))
}

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect()
}

/// Строковое значение из реестра; переменные окружения в нём раскрыты.
fn reg_string(key: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey = wide(subkey);
    let value = wide(value);
    let mut size = 0u32;
    let code = unsafe {
        RegGetValueW(
            key,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    // Путь к профилю не бывает длиннее нескольких сотен знаков.
    if code != 0 || size == 0 || size > 64 * 1024 {
        return None;
    }
    let mut buffer = vec![0u16; size as usize / 2 + 1];
    let mut size = (buffer.len() * 2) as u32;
    let code = unsafe {
        RegGetValueW(
            key,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut _,
            &mut size,
        )
    };
    if code != 0 {
        return None;
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16(&buffer[..len]).ok()
}

/// Профили пользователей машины: SID → каталог.
fn profiles() -> Vec<(String, String)> {
    let mut list = Vec::new();
    let mut key: HKEY = std::ptr::null_mut();
    let path = wide(PROFILE_LIST);
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
        return list;
    }
    // Предел — от зацикливания, а не от числа пользователей.
    for index in 0..4096 {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        let code = unsafe {
            RegEnumKeyExW(
                key,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if code != 0 {
            break;
        }
        let Ok(sid) = String::from_utf16(&name[..len as usize]) else { continue };
        // `S-…-1001.bak` — запасная запись, которую Windows оставляет при
        // сбое загрузки профиля; каталог у неё тот же, что у настоящей.
        if is_backup_entry(&sid) {
            continue;
        }
        let dir = reg_string(key, &sid, "ProfileImagePath").and_then(|dir| normalize(Path::new(&dir)));
        if let Some(dir) = dir {
            list.push((sid, dir));
        }
    }
    unsafe { RegCloseKey(key) };
    list
}

/// Запасная запись ProfileList (`S-1-5-21-…-1001.bak`).
fn is_backup_entry(name: &str) -> bool {
    name.len() > 4 && name.is_char_boundary(name.len() - 4) && name[name.len() - 4..].eq_ignore_ascii_case(".bak")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use vpnsplit_core::AppRule;

    const ME: &str = "S-1-5-21-1-2-3-1001";
    const OTHER: &str = "S-1-5-21-1-2-3-1002";

    fn places() -> Places {
        Places {
            system_root: Some(r"c:\windows".to_owned()),
            system_dirs: vec![r"c:\programdata\microsoft".to_owned()],
            program_files: vec![r"c:\program files".to_owned(), r"c:\program files (x86)".to_owned()],
            windows_apps: vec![r"c:\program files\windowsapps".to_owned()],
            profiles_root: Some(r"c:\users".to_owned()),
            profiles: vec![
                (ME.to_owned(), r"c:\users\klyaksa".to_owned()),
                (OTHER.to_owned(), r"c:\users\other".to_owned()),
                ("S-1-5-18".to_owned(), r"c:\windows\system32\config\systemprofile".to_owned()),
            ],
        }
    }

    fn check(path: &str) -> Option<Foreign> {
        // Несуществующий диск: проверка по настоящему файлу здесь ничего не
        // найдёт, и тест не зависит от того, что лежит на машине.
        classify(&normalize(Path::new(path))?, &places(), Some(ME))
    }

    #[test]
    fn one_path_has_one_spelling() {
        let same = [
            r"C:\Windows\System32\svchost.exe",
            r"c:/windows/system32/SVCHOST.EXE",
            r"\\?\C:\Windows\System32\svchost.exe",
            r"C:\Program Files\..\Windows\.\System32\\svchost.exe",
            r"C:\Windows.\System32 \svchost.exe",
        ];
        for path in same {
            assert_eq!(
                normalize(Path::new(path)).as_deref(),
                Some(r"c:\windows\system32\svchost.exe"),
                "{path}"
            );
        }
        assert_eq!(normalize(Path::new(r"C:\..\..\Windows\notepad.exe")).as_deref(), Some(r"c:\windows\notepad.exe"));
        assert_eq!(normalize(Path::new(r"\\server\share\..\..\x.exe")), None);
        assert_eq!(normalize(Path::new(r"\\?\UNC\server\share\app.exe")).as_deref(), Some(r"\\server\share\app.exe"));
    }

    #[test]
    fn a_path_without_a_drive_is_not_a_path_of_a_program() {
        for path in ["svchost.exe", r"System32\svchost.exe", r"C:svchost.exe", r"\Windows\svchost.exe"] {
            assert_eq!(normalize(Path::new(path)), None, "{path}");
            assert_eq!(foreign(Path::new(path), &places(), Some(ME)), Some(Foreign::NotAbsolute), "{path}");
        }
    }

    #[test]
    fn programs_of_everybody_are_refused() {
        assert_eq!(check(r"C:\Windows\System32\svchost.exe"), Some(Foreign::System));
        assert_eq!(check(r"C:\Windows\..\Windows\System32\svchost.exe"), Some(Foreign::System));
        assert_eq!(check(r"C:\Program Files\WindowsApps\Some.App_1.0_x64__abc\app.exe"), Some(Foreign::Store));
        assert_eq!(check(r"C:\Users\Other\AppData\Local\app.exe"), Some(Foreign::OtherUser));
        assert_eq!(check(r"C:\Users\Public\app.exe"), Some(Foreign::OtherUser));
        assert_eq!(check(r"C:\Users\klyaksa\..\Other\app.exe"), Some(Foreign::OtherUser));
        // Части Windows вне её каталога: служба Защитника и прочие.
        let defender = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe";
        assert_eq!(check(defender), Some(Foreign::System));
        assert_eq!(check(r"C:\Program Files\Windows Defender\MsMpEng.exe"), Some(Foreign::System));
        assert_eq!(check(r"C:\Program Files (x86)\Windows NT\Accessories\wordpad.exe"), Some(Foreign::System));
    }

    #[test]
    fn a_path_that_turned_into_a_link_is_caught_where_the_filter_is_set() {
        let places = places();
        let redirected = |written: &str, real: &str| redirected(Path::new(written), Path::new(real), &places);
        // Своя папка стала точкой соединения на System32.
        assert_eq!(
            redirected(r"C:\Users\klyaksa\j\svchost.exe", r"C:\Windows\System32\svchost.exe"),
            Some(Foreign::System)
        );
        assert_eq!(
            redirected(r"D:\x\app.exe", r"C:\Program Files\WindowsApps\A_1.0_x64__abc\app.exe"),
            Some(Foreign::Store)
        );
        assert_eq!(redirected(r"C:\Users\klyaksa\j\app.exe", r"C:\Users\Other\app.exe"), Some(Foreign::OtherUser));
        assert_eq!(redirected(r"C:\Users\klyaksa\j\app.exe", r"C:\Users\Public\app.exe"), Some(Foreign::OtherUser));
        // Без ссылки — как написано, так и есть: правило администратора на
        // системную программу работает. Внутри одного места — тоже.
        assert_eq!(redirected(r"C:\Windows\System32\curl.exe", r"c:\windows\system32\curl.exe"), None);
        assert_eq!(redirected(r"C:\Windows\System32\x.exe", r"C:\Windows\SysWOW64\x.exe"), None);
        // Ссылка в обычное место — не обход.
        assert_eq!(redirected(r"C:\Users\klyaksa\j\app.exe", r"D:\Games\app.exe"), None);
        assert_eq!(redirected(r"D:\Games\app.exe", r"C:\Users\klyaksa\app.exe"), None);
        // Короткое имя 8.3 строкой с системным каталогом не совпадает и
        // считается ссылкой: администратору достаточно написать путь полностью.
        assert_eq!(
            redirected(r"C:\PROGRA~1\Windows Defender\x.exe", r"C:\Program Files\Windows Defender\x.exe"),
            Some(Foreign::System)
        );
        // Неполный путь Windows искала бы в каталоге службы.
        assert_eq!(redirected("svchost.exe", r"C:\Windows\System32\svchost.exe"), Some(Foreign::NotAbsolute));
        assert!(vet(Path::new("svchost.exe"), Path::new(r"C:\Windows\System32\svchost.exe")).is_err());
        assert_eq!(vet(Path::new(r"C:\Windows\notepad.exe"), Path::new(r"c:\windows\NOTEPAD.EXE")), Ok(()));
    }

    #[test]
    fn own_and_shared_programs_pass() {
        assert_eq!(check(r"C:\Users\klyaksa\AppData\Local\Programs\app\app.exe"), None);
        assert_eq!(check(r"C:\Program Files\Mozilla Firefox\firefox.exe"), None);
        assert_eq!(check(r"D:\Games\game.exe"), None);
        // Каталог, имя которого только начинается так же, — другой каталог.
        assert_eq!(check(r"C:\WindowsTools\tool.exe"), None);
        assert_eq!(check(r"C:\Users\klyaksa2\app.exe"), Some(Foreign::OtherUser));
    }

    #[test]
    fn own_profile_stays_own_when_another_entry_shares_its_folder() {
        // Прежняя учётная запись после переноса профиля и запасная `.bak`
        // указывают на тот же каталог, причём стоят раньше своей записи.
        let mut places = places();
        places.profiles.insert(0, ("S-1-5-21-9-9-9-1001".to_owned(), r"c:\users\klyaksa".to_owned()));
        places.profiles.insert(0, (format!("{ME}.bak"), r"c:\users\klyaksa".to_owned()));
        let path = normalize(Path::new(r"C:\Users\klyaksa\AppData\Local\app.exe")).unwrap();
        assert_eq!(classify(&path, &places, Some(ME)), None);
        // Для другого пользователя этот каталог по-прежнему чужой, а чужой
        // профиль — по-прежнему чужой для тебя.
        assert_eq!(classify(&path, &places, Some(OTHER)), Some(Foreign::OtherUser));
        let other = normalize(Path::new(r"C:\Users\Other\app.exe")).unwrap();
        assert_eq!(classify(&other, &places, Some(ME)), Some(Foreign::OtherUser));
    }

    #[test]
    fn backup_entries_of_the_profile_list_are_recognised() {
        assert!(is_backup_entry("S-1-5-21-1-2-3-1001.bak"));
        assert!(is_backup_entry("S-1-5-21-1-2-3-1001.BAK"));
        assert!(!is_backup_entry("S-1-5-21-1-2-3-1001"));
        assert!(!is_backup_entry(".bak"));
    }

    #[test]
    fn without_a_known_user_every_profile_is_foreign() {
        let path = normalize(Path::new(r"C:\Users\klyaksa\app.exe")).unwrap();
        assert_eq!(classify(&path, &places(), None), Some(Foreign::OtherUser));
    }

    #[test]
    fn rules_the_admin_made_survive_a_save_without_rights() {
        let system = AppRule::tunnel(AppTarget::Executable(PathBuf::from(r"C:\Windows\System32\curl.exe")));
        let mine = AppRule::tunnel(AppTarget::Executable(PathBuf::from(r"C:\Users\klyaksa\app.exe")));
        let current = Policy { rules: vec![system.clone()], ..Policy::default() };
        // Своё добавил, админское не тронул — принято.
        let new = Policy { rules: vec![system.clone(), mine.clone()], ..Policy::default() };
        assert_eq!(admit(&new, &current, &places(), Some(ME)), Ok(()));
        // Админское убрал — тоже можно: убрать правило значит вернуть
        // программе обычную сеть.
        let new = Policy { rules: vec![mine.clone()], ..Policy::default() };
        assert_eq!(admit(&new, &current, &places(), Some(ME)), Ok(()));
        // А изменить админское правило или добавить новое системное — нет.
        let mut changed = system.clone();
        changed.vpn = Some("Работа".to_owned());
        let new = Policy { rules: vec![changed, mine.clone()], ..Policy::default() };
        let refused = admit(&new, &current, &places(), Some(ME)).unwrap_err();
        assert!(refused.contains("curl.exe") && refused.contains("администратора"), "{refused}");
        // Пакеты Store опознаются по имени, а не по пути, и проходят.
        let package = AppRule::tunnel(AppTarget::Package("Some.App_abc".to_owned()));
        let new = Policy { rules: vec![package], ..Policy::default() };
        assert_eq!(admit(&new, &Policy::default(), &places(), Some(ME)), Ok(()));
    }

    #[test]
    fn this_machine_has_the_usual_places() {
        let places = Places::current();
        assert!(places.system_root.is_some());
        assert!(!places.system_dirs.is_empty() && !places.program_files.is_empty());
        assert!(!places.windows_apps.is_empty());
        assert!(places.profiles_root.is_some());
        assert!(places.profiles.iter().any(|(sid, _)| sid == "S-1-5-18"), "{:?}", places.profiles);
    }
}

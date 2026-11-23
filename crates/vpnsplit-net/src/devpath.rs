//! Путь ядра → привычный путь: `\Device\HarddiskVolume3\a.exe` → `C:\a.exe`.
//!
//! Событие о запуске процесса называет образ так, как его знает ядро, а
//! правила пользователя записаны с буквой диска. Сравнить одно с другим
//! можно, только зная, какой том под какой буквой стоит. Это знание
//! спрашивается у системы (`QueryDosDeviceW`), а не выводится из номера
//! тома: номера раздаются при загрузке и к буквам отношения не имеют.
//!
//! Нужно это ради процессов, которых уже нет: у живого путь проще
//! спросить у него самого.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows_sys::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};

/// Том ядра и его буква: (`\Device\HarddiskVolume3`, `C:`).
type Volumes = Vec<(String, String)>;

struct Cache {
    volumes: Volumes,
    loaded: Option<Instant>,
}

static CACHE: Mutex<Cache> = Mutex::new(Cache { volumes: Vec::new(), loaded: None });

/// Как часто можно переспрашивать систему, если путь не узнан. Том могли
/// подключить после нас — тогда переспросить надо; но путь может быть и
/// вовсе без буквы (сетевой), и опрашивать диски на каждый такой незачем.
const RELOAD_EVERY: Duration = Duration::from_secs(5);

/// Привычный путь по пути ядра. `None` — буквы у этого тома нет или путь
/// не похож на путь ядра; придумывать ответ в обоих случаях нельзя.
pub fn to_dos(kernel_path: &str) -> Option<PathBuf> {
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.loaded.is_none() {
        cache.volumes = volumes();
        cache.loaded = Some(Instant::now());
    }
    if let Some(found) = translate(kernel_path, &cache.volumes) {
        return Some(PathBuf::from(found));
    }
    if cache.loaded.is_some_and(|at| at.elapsed() < RELOAD_EVERY) {
        return None;
    }
    cache.volumes = volumes();
    cache.loaded = Some(Instant::now());
    translate(kernel_path, &cache.volumes).map(PathBuf::from)
}

/// Сама подстановка, без обращений к системе.
///
/// Том должен совпасть целиком, до разделителя: иначе `HarddiskVolume1`
/// подошёл бы к пути на `HarddiskVolume10`, и файл нашёлся бы на чужом
/// диске.
fn translate(kernel_path: &str, volumes: &[(String, String)]) -> Option<String> {
    volumes.iter().find_map(|(device, letter)| {
        let head = kernel_path.get(..device.len())?;
        let rest = kernel_path.get(device.len()..)?;
        (head.eq_ignore_ascii_case(device) && rest.starts_with('\\'))
            .then(|| format!("{letter}{rest}"))
    })
}

/// Какие тома под какими буквами стоят сейчас.
fn volumes() -> Volumes {
    let mask = unsafe { GetLogicalDrives() };
    let mut found = Vec::new();
    for index in 0..26u32 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let letter = format!("{}:", (b'A' + index as u8) as char);
        let name: Vec<u16> = letter.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buffer = [0u16; 512];
        let length =
            unsafe { QueryDosDeviceW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            continue;
        }
        // Ответ — список строк; первая и есть нынешнее назначение буквы.
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(0);
        let device = String::from_utf16_lossy(&buffer[..end]);
        if !device.is_empty() {
            found.push((device, letter));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Volumes {
        vec![
            (r"\Device\HarddiskVolume1".to_owned(), "E:".to_owned()),
            (r"\Device\HarddiskVolume10".to_owned(), "G:".to_owned()),
            (r"\Device\HarddiskVolume3".to_owned(), "C:".to_owned()),
        ]
    }

    #[test]
    fn the_volume_becomes_its_letter() {
        assert_eq!(
            translate(r"\Device\HarddiskVolume3\Users\klyaksa\Desktop\Firefox.exe", &sample()),
            Some(r"C:\Users\klyaksa\Desktop\Firefox.exe".to_owned())
        );
    }

    #[test]
    fn a_volume_is_matched_whole_not_by_its_beginning() {
        // Том 10 не должен сойти за том 1 с хвостом «0\…».
        assert_eq!(
            translate(r"\Device\HarddiskVolume10\a.exe", &sample()),
            Some(r"G:\a.exe".to_owned())
        );
        assert_eq!(translate(r"\Device\HarddiskVolume12\a.exe", &sample()), None);
    }

    #[test]
    fn letter_case_of_the_volume_does_not_matter() {
        assert_eq!(
            translate(r"\device\harddiskvolume3\a.exe", &sample()),
            Some(r"C:\a.exe".to_owned())
        );
    }

    #[test]
    fn what_has_no_letter_gets_no_answer() {
        assert_eq!(translate(r"\Device\Mup\server\share\a.exe", &sample()), None);
        assert_eq!(translate(r"C:\Windows\notepad.exe", &sample()), None);
        assert_eq!(translate(r"\Device\HarddiskVolume3", &sample()), None);
        assert_eq!(translate("", &sample()), None);
        // Не-ASCII на границе тома не должно ронять разбор.
        assert_eq!(translate("\\Device\\HarddiskVolumeé\\a.exe", &sample()), None);
    }

    /// Проверка на живой системе: системный диск обязан найтись, и путь
    /// ядра к собственному образу теста должен вернуться в привычный вид.
    #[test]
    fn the_running_system_knows_its_own_volumes() {
        let found = volumes();
        println!("тома: {found:?}");
        assert!(!found.is_empty(), "ни одной буквы диска — такого не бывает");
        let me = std::env::current_exe().unwrap();
        let text = me.to_string_lossy().to_string();
        let letter = &text[..2];
        // Положительный контроль: туда и обратно через найденный том.
        match found.iter().find(|(_, l)| l.eq_ignore_ascii_case(letter)) {
            Some((device, _)) => {
                let kernel = format!("{device}{}", &text[2..]);
                assert_eq!(to_dos(&kernel), Some(me), "{kernel}");
            }
            // Диск подставной (subst) или сетевой: буква есть, тома нет.
            None => println!("ПРОВЕРКИ НЕ БЫЛО: у буквы {letter} нет своего тома"),
        }
    }
}

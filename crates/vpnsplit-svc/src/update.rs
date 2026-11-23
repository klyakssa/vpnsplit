//! Обновление: служба сама находит новый выпуск, проверяет его и ставит.
//!
//! Решение пользователя от 23.11.2026: обновление приходит всем, кто
//! поставил программу, без вопросов и щелчков. Значит, служба скачивает
//! файл из сети и запускает его с правами системы — и всё здесь устроено
//! вокруг одного вопроса: **чей это файл**.
//!
//! - Выпуск лежит на GitHub (`releases/latest/download/…`): установщик,
//!   короткое описание к нему и подпись описания.
//! - **Подпись** делается ключом, которого на GitHub нет: он лежит у
//!   автора, а в программу вшита только открытая половина. Украденной
//!   учётной записи GitHub мало, чтобы подсунуть свой файл: без ключа
//!   подпись не подделать, а без подписи служба ничего не запустит.
//! - В описании — номер сборки, размер и SHA-256 установщика. Ставится
//!   только сборка **новее** нынешней: старый выпуск с настоящей подписью
//!   подсунуть нельзя.
//! - Скачанное кладётся в `Program Files\vpnsplit\update`: туда пишут
//!   только система и администраторы, так что между проверкой и запуском
//!   файл никто не подменит.
//!
//! Обновляется только установленная копия и только выпускная сборка: у
//! сборки из папки разработчика номера нет, и она ничего не ищет.
//! Отказаться можно, положив файл `no-update` в `%ProgramData%\vpnsplit`.
//!
//! Сам установщик останавливает службу, меняет файлы и запускает её снова;
//! если новая не поднимется, он возвращает прежнюю.

use crate::store::Store;
use crate::update_key::MODULUS;
use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use vpnsplit_core::BUILD;
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
    WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptHash, BCryptImportKeyPair,
    BCryptOpenAlgorithmProvider, BCryptVerifySignature, BCRYPT_PAD_PKCS1,
    BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSAPUBLIC_MAGIC,
    BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
};

/// Откуда берутся выпуски.
const HOST: &str = "github.com";
const BASE: &str = "/klyakssa/vpnsplit/releases/latest/download/";
const SETUP: &str = "vpnsplit-setup.exe";
const MANIFEST: &str = "vpnsplit-setup.manifest";
const SIGNATURE: &str = "vpnsplit-setup.manifest.sig";

/// Первая строка описания выпуска: по ней видно, что это оно и какого вида.
const MANIFEST_HEAD: &str = "vpnsplit-update 1";

/// Файл-отказ в каталоге данных: пока он есть, обновления не ищутся.
const OPT_OUT: &str = "no-update";

/// Первая проверка — не сразу: при запуске Windows сеть ещё поднимается, а
/// службе есть чем заняться.
const FIRST_CHECK: Duration = Duration::from_secs(180);
const PERIOD: Duration = Duration::from_secs(6 * 3600);

const MANIFEST_LIMIT: usize = 16 * 1024;
const SIGNATURE_LIMIT: usize = 4 * 1024;
const SETUP_LIMIT: usize = 64 * 1024 * 1024;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Описание выпуска.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    pub build: u64,
    pub version: String,
    pub size: usize,
    pub sha256: [u8; 32],
}

impl Manifest {
    /// Разбирает описание. Всё, чего не понял, — отказ: описание подписано,
    /// и непонятное в нём значит, что его писала другая версия правил.
    pub fn parse(bytes: &[u8]) -> Result<Manifest, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "описание выпуска — не текст".to_owned())?;
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        if lines.next() != Some(MANIFEST_HEAD) {
            return Err("описание выпуска неизвестного вида".to_owned());
        }
        let (mut build, mut version, mut size, mut sha256) = (None, None, None, None);
        for line in lines {
            let Some((name, value)) = line.split_once('=') else {
                return Err(format!("непонятная строка в описании выпуска: {line}"));
            };
            match name {
                "build" => build = value.parse::<u64>().ok(),
                "version" => version = Some(value.to_owned()),
                "size" => size = value.parse::<usize>().ok(),
                "sha256" => sha256 = unhex(value).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()),
                _ => return Err(format!("непонятная строка в описании выпуска: {line}")),
            }
        }
        match (build, version, size, sha256) {
            (Some(build), Some(version), Some(size), Some(sha256)) if build > 0 => {
                Ok(Manifest { build, version, size, sha256 })
            }
            _ => Err("в описании выпуска не хватает номера сборки, версии, размера или SHA-256".to_owned()),
        }
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok()).collect()
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// SHA-256 средствами Windows.
pub fn sha256(data: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    unsafe {
        let mut algorithm = std::ptr::null_mut();
        if BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, std::ptr::null(), 0) != 0 {
            return None;
        }
        let status = BCryptHash(
            algorithm,
            std::ptr::null(),
            0,
            data.as_ptr(),
            data.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
        );
        BCryptCloseAlgorithmProvider(algorithm, 0);
        (status == 0).then_some(out)
    }
}

/// Сходится ли подпись RSA (PKCS#1 v1.5, SHA-256) с данными. `modulus_hex`
/// — открытый ключ: модуль шестнадцатеричной записью; показатель — 65537.
///
/// Любая неудача — «не сходится»: причины здесь не различаются намеренно,
/// потому что ответ на все один — не запускать.
pub fn verify(data: &[u8], signature: &[u8], modulus_hex: &str) -> bool {
    let Some(mut modulus) = unhex(modulus_hex) else { return false };
    // Ведущие нули в записи модуля — не часть числа.
    while modulus.first() == Some(&0) {
        modulus.remove(0);
    }
    // Ключи короче 2048 бит подписью не считаем.
    if modulus.len() < 256 || signature.len() != modulus.len() {
        return false;
    }
    let Some(hash) = sha256(data) else { return false };
    let exponent = [1u8, 0, 1];
    let mut blob = Vec::with_capacity(24 + exponent.len() + modulus.len());
    for field in [
        BCRYPT_RSAPUBLIC_MAGIC,
        (modulus.len() * 8) as u32,
        exponent.len() as u32,
        modulus.len() as u32,
        0,
        0,
    ] {
        blob.extend(field.to_le_bytes());
    }
    blob.extend(exponent);
    blob.extend(&modulus);
    unsafe {
        let mut algorithm = std::ptr::null_mut();
        if BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_RSA_ALGORITHM, std::ptr::null(), 0) != 0 {
            return false;
        }
        let mut key = std::ptr::null_mut();
        let imported = BCryptImportKeyPair(
            algorithm,
            std::ptr::null_mut(),
            BCRYPT_RSAPUBLIC_BLOB,
            &mut key,
            blob.as_ptr(),
            blob.len() as u32,
            0,
        );
        let mut good = false;
        if imported == 0 {
            let padding = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM };
            good = BCryptVerifySignature(
                key,
                &padding as *const _ as *const c_void,
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                BCRYPT_PAD_PKCS1,
            ) == 0;
            BCryptDestroyKey(key);
        }
        BCryptCloseAlgorithmProvider(algorithm, 0);
        good
    }
}

/// Ручка WinHTTP, которая закроется сама.
struct Net(*mut c_void);

impl Drop for Net {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

/// Скачивает файл выпуска. Только HTTPS; перенаправления GitHub (на его
/// хранилище) WinHTTP проходит сам и с HTTPS на HTTP не уходит.
fn fetch(name: &str, limit: usize) -> Result<Vec<u8>, String> {
    let failed = |what: &str| format!("{name}: {what} ({})", std::io::Error::last_os_error());
    unsafe {
        let session = Net(WinHttpOpen(
            wide("vpnsplit-update").as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        ));
        if session.0.is_null() {
            return Err(failed("сеть не открылась"));
        }
        WinHttpSetTimeouts(session.0, 15_000, 15_000, 30_000, 60_000);
        let connection = Net(WinHttpConnect(session.0, wide(HOST).as_ptr(), 443, 0));
        if connection.0.is_null() {
            return Err(failed("нет соединения"));
        }
        let path = format!("{BASE}{name}");
        let request = Net(WinHttpOpenRequest(
            connection.0,
            wide("GET").as_ptr(),
            wide(&path).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null() {
            return Err(failed("запрос не составился"));
        }
        if WinHttpSendRequest(request.0, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) == 0
            || WinHttpReceiveResponse(request.0, std::ptr::null_mut()) == 0
        {
            return Err(failed("сервер не ответил"));
        }
        let mut status = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            std::ptr::null(),
            &mut status as *mut u32 as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
        );
        if status != 200 {
            return Err(format!("{name}: сервер ответил {status}"));
        }
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let mut got = 0u32;
            if WinHttpReadData(request.0, chunk.as_mut_ptr() as *mut c_void, chunk.len() as u32, &mut got) == 0 {
                return Err(failed("скачивание оборвалось"));
            }
            if got == 0 {
                return Ok(body);
            }
            body.extend_from_slice(&chunk[..got as usize]);
            if body.len() > limit {
                return Err(format!("{name}: файл больше, чем бывает ({limit} байт)"));
            }
        }
    }
}

/// Каталог установленной копии — тот, где рядом со службой лежит
/// установщик. `None` — мы запущены из папки сборки.
fn installed() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.with_file_name(SETUP).is_file().then(|| exe.parent().map(Path::to_owned)).flatten()
}

/// Что служба думает об обновлениях — одной строкой.
pub fn describe(store: &Store) -> String {
    if BUILD == 0 {
        return "сборка без номера (для разработки) — обновления не ищутся".to_owned();
    }
    let state = if MODULUS.is_empty() {
        "ключ выпусков в программу не вшит — обновления не ищутся"
    } else if installed().is_none() {
        "копия не установлена установщиком — обновления не ищутся"
    } else if store.dir().join(OPT_OUT).is_file() {
        "обновления выключены файлом no-update"
    } else {
        "обновления ищутся сами, раз в шесть часов"
    };
    format!("сборка {BUILD}; {state}")
}

/// Запускает поиск обновлений в своём потоке.
pub fn start(store: Store) {
    store.log(&format!("обновления: {}", describe(&store)));
    let Some(dir) = installed() else { return };
    if BUILD == 0 || MODULUS.is_empty() {
        return;
    }
    // Что осталось от прошлого обновления — своё оно отслужило.
    let _ = std::fs::remove_dir_all(dir.join("update"));
    let spawned = std::thread::Builder::new().name("update".into()).spawn(move || {
        std::thread::sleep(FIRST_CHECK);
        // Одно и то же «не вышло» раз в шесть часов журналу ни к чему.
        let mut last_trouble = String::new();
        loop {
            if !store.dir().join(OPT_OUT).is_file() {
                match check(&store, &dir) {
                    Ok(()) => last_trouble.clear(),
                    Err(reason) => {
                        if reason != last_trouble {
                            store.log(&format!("обновления: {reason}"));
                            last_trouble = reason;
                        }
                    }
                }
            }
            std::thread::sleep(PERIOD);
        }
    });
    if let Err(e) = spawned {
        // Без обновлений программа работает как работала.
        eprintln!("поток обновлений не завёлся: {e}");
    }
}

/// Новее ли сборка нашей.
fn newer(build: u64) -> bool {
    build > BUILD
}

/// Одна проверка: есть ли выпуск новее, и если есть — поставить.
fn check(store: &Store, dir: &Path) -> Result<(), String> {
    let manifest = fetch(MANIFEST, MANIFEST_LIMIT)?;
    let signature = fetch(SIGNATURE, SIGNATURE_LIMIT)?;
    if !verify(&manifest, &signature, MODULUS) {
        return Err("подпись выпуска не сходится — он не от автора программы, не ставлю".to_owned());
    }
    let release = Manifest::parse(&manifest)?;
    if !newer(release.build) {
        return Ok(());
    }
    store.log(&format!(
        "обновления: есть сборка {} (версия {}), у нас {BUILD} — скачиваю",
        release.build, release.version
    ));
    let setup = fetch(SETUP, SETUP_LIMIT)?;
    if setup.len() != release.size || sha256(&setup) != Some(release.sha256) {
        return Err("скачанный установщик не тот, что описан в выпуске, — не ставлю".to_owned());
    }
    let folder = dir.join("update");
    std::fs::create_dir_all(&folder).map_err(|e| format!("папка обновления не создалась: {e}"))?;
    let path = folder.join(format!("vpnsplit-setup-{}.exe", release.build));
    std::fs::write(&path, &setup).map_err(|e| format!("установщик не записался: {e}"))?;
    // Перечитываем то, что легло на диск: запускается оно, а не то, что
    // было в памяти.
    let written = std::fs::read(&path).map_err(|e| format!("установщик не перечитался: {e}"))?;
    if sha256(&written) != Some(release.sha256) {
        return Err("установщик на диске не совпал со скачанным — не ставлю".to_owned());
    }
    store.log(&format!(
        "обновления: сборка {} проверена, запускаю установщик; служба сейчас остановится и \
         вернётся новой",
        release.build
    ));
    std::process::Command::new(&path)
        .arg("/quiet")
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("установщик не запустился: {e}"))?;
    Ok(())
}

/// `vpnsplit-svc update …` — посмотреть и проверить без службы.
pub fn command(store: &Store, first: Option<&String>, second: Option<&String>, third: Option<&String>) -> Result<(), String> {
    match (first.map(String::as_str), second, third) {
        (None, ..) => {
            println!("{}", describe(store));
            Ok(())
        }
        // Проверка подписи выпуска тем же кодом, каким её проверит служба.
        (Some("verify"), Some(manifest), Some(signature)) => {
            let data = std::fs::read(manifest).map_err(|e| format!("{manifest}: {e}"))?;
            let signed = std::fs::read(signature).map_err(|e| format!("{signature}: {e}"))?;
            if MODULUS.is_empty() {
                return Err("ключ выпусков в программу не вшит".to_owned());
            }
            if !verify(&data, &signed, MODULUS) {
                return Err("подпись НЕ сходится".to_owned());
            }
            let release = Manifest::parse(&data)?;
            println!("подпись сходится: сборка {}, версия {}, установщик {} байт", release.build, release.version, release.size);
            if let Some(setup) = Path::new(manifest).parent().map(|dir| dir.join(SETUP)).filter(|p| p.is_file()) {
                let bytes = std::fs::read(&setup).map_err(|e| format!("{}: {e}", setup.display()))?;
                if bytes.len() == release.size && sha256(&bytes) == Some(release.sha256) {
                    println!("установщик рядом — тот самый");
                } else {
                    return Err("установщик рядом НЕ тот, что описан".to_owned());
                }
            }
            Ok(())
        }
        // Спросить GitHub прямо сейчас, ничего не ставя.
        (Some("look"), ..) => {
            let manifest = fetch(MANIFEST, MANIFEST_LIMIT)?;
            let signature = fetch(SIGNATURE, SIGNATURE_LIMIT)?;
            let good = !MODULUS.is_empty() && verify(&manifest, &signature, MODULUS);
            let release = Manifest::parse(&manifest)?;
            println!(
                "на GitHub сборка {} (версия {}), у нас {BUILD}; подпись {}",
                release.build,
                release.version,
                if good { "сходится" } else { "НЕ сходится" }
            );
            Ok(())
        }
        _ => Err("update | update look | update verify ОПИСАНИЕ ПОДПИСЬ".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn a_release_is_described_by_four_lines_and_nothing_else() {
        let text = format!("vpnsplit-update 1\nbuild=202611231200\nversion=0.1.0\nsize=2887168\nsha256={SHA}\n");
        let release = Manifest::parse(text.as_bytes()).unwrap();
        assert_eq!(release.build, 202_611_231_200);
        assert_eq!(release.version, "0.1.0");
        assert_eq!(release.size, 2_887_168);
        assert_eq!(release.sha256[..2], [0xe3, 0xb0]);
        // Строки Windows и пустые строки — не помеха.
        assert!(Manifest::parse(text.replace('\n', "\r\n\r\n").as_bytes()).is_ok());
        // А всё остальное — отказ.
        assert!(Manifest::parse(b"vpnsplit-update 2\nbuild=1\n").is_err());
        assert!(Manifest::parse(text.replace("build=202611231200\n", "").as_bytes()).is_err());
        assert!(Manifest::parse(text.replace("build=202611231200", "build=0").as_bytes()).is_err());
        assert!(Manifest::parse(text.replace(SHA, "abcd").as_bytes()).is_err());
        assert!(Manifest::parse(format!("{text}run=calc.exe\n").as_bytes()).is_err());
        assert!(Manifest::parse(&[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn the_hash_is_the_real_sha256() {
        // Известные значения: пустая строка и «abc».
        let hex = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(sha256(b"").unwrap()), SHA);
        assert_eq!(
            hex(sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(unhex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("abc"), None);
    }

    #[test]
    fn a_signature_that_is_not_ours_is_never_accepted() {
        // Настоящую подпись проверяет `update verify` на настоящем выпуске;
        // здесь — что всё, кроме неё, отвергается.
        let key = "c3".repeat(384);
        assert!(!verify(b"data", &[0u8; 384], &key));
        assert!(!verify(b"data", &[0u8; 10], &key), "подпись не той длины");
        assert!(!verify(b"data", &[0u8; 128], &"c3".repeat(128)), "ключ слишком короткий");
        assert!(!verify(b"data", &[0u8; 384], ""), "ключа нет");
        assert!(!verify(b"data", &[0u8; 384], "это не ключ"));
    }
}

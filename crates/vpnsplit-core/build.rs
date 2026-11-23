//! Номер сборки. Его называет переменная `VPNSPLIT_BUILD` (ставит сценарий
//! выпуска: дата и время цифрами подряд); без неё номер — ноль, «сборка для
//! разработки». По номеру служба решает, новее ли выпуск на GitHub, а окно
//! — новее ли его самого служба.

fn main() {
    println!("cargo:rerun-if-env-changed=VPNSPLIT_BUILD");
    let build = std::env::var("VPNSPLIT_BUILD").unwrap_or_else(|_| "0".to_owned());
    let good = !build.is_empty() && build.len() <= 18 && build.bytes().all(|b| b.is_ascii_digit());
    if !good {
        panic!("VPNSPLIT_BUILD должно быть числом, а там «{build}»");
    }
    println!("cargo:rustc-env=VPNSPLIT_BUILD_NUMBER={build}");
}

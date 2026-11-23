//! Манифест вшивается в exe линкером MSVC: `/MANIFESTINPUT`. Без него
//! Windows даёт окну общие элементы управления версии 5 (вид из 1999 года)
//! и считает программу не знающей о DPI. Отдельного крейта для ресурсов не
//! нужно — rustc передаёт эти ключи линкеру как есть.

fn main() {
    println!("cargo:rerun-if-changed=vpnsplit-ui.manifest");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest = std::path::Path::new(&dir).join("vpnsplit-ui.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", manifest.display());
}

//! Вшивает в установщик то, что он ставит.
//!
//! Каталог с готовыми файлами называет переменная `VPNSPLIT_PAYLOAD` — её
//! ставит `scripts\make-setup.ps1` после выпускной сборки остального. Без
//! неё установщик собирается пустым: так обычная `cargo build --workspace`
//! не требует выпускной сборки всего подряд, а пустой установщик при
//! запуске честно говорит, что ставить ему нечего.

use std::path::PathBuf;

/// Что ставится. Порядок — порядок записи на диск.
const FILES: [&str; 6] = [
    "vpnsplit-svc.exe",
    "vpnsplit-ui.exe",
    "vpnsplit-launch.exe",
    "vpnsplit_hook.dll",
    "WinDivert.dll",
    "WinDivert64.sys",
];

fn main() {
    println!("cargo:rerun-if-env-changed=VPNSPLIT_PAYLOAD");
    println!("cargo:rerun-if-env-changed=VPNSPLIT_BUILT");
    let mut code = String::from("pub const PAYLOAD: &[(&str, &[u8])] = &[\n");
    if let Ok(dir) = std::env::var("VPNSPLIT_PAYLOAD") {
        for name in FILES {
            let path = PathBuf::from(&dir).join(name);
            if !path.is_file() {
                panic!("в каталоге содержимого нет файла {name}: {}", path.display());
            }
            println!("cargo:rerun-if-changed={}", path.display());
            code.push_str(&format!(
                "    ({name:?}, include_bytes!({:?})),\n",
                path.display().to_string()
            ));
        }
    }
    code.push_str("];\n");
    // Когда собрано — чтобы человек видел, что именно он ставит.
    let built = std::env::var("VPNSPLIT_BUILT").unwrap_or_default();
    code.push_str(&format!("pub const BUILT: &str = {built:?};\n"));
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("payload.rs");
    std::fs::write(out, code).expect("payload.rs");
}

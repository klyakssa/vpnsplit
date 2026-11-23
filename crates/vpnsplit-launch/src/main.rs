//! Лончер: запускает приложение так, чтобы его трафик шёл через туннель.
//!
//!   vpnsplit-launch --list
//!   vpnsplit-launch [--adapter ТЕКСТ] [--no-wait] -- программа [аргументы...]

mod inject;

use std::path::PathBuf;
use std::process::ExitCode;
use vpnsplit_core::hook::{DLL_NAME, IFINDEX_ENV, LOG_ENV};
use vpnsplit_core::{Request, Response, TunnelInfo, TunnelState};
use vpnsplit_net::iface;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code.min(255) as u8),
        Err(err) => {
            eprintln!("vpnsplit-launch: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<u32, String> {
    let mut adapter_filter: Option<String> = None;
    let mut wait = true;
    let mut rest: &[String] = &[];

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--list" => return list().map(|_| 0),
            "--help" | "-h" => {
                print_help();
                return Ok(0);
            }
            "--adapter" => {
                i += 1;
                adapter_filter = Some(args.get(i).ok_or("после --adapter нужно имя")?.clone());
            }
            "--no-wait" => wait = false,
            "--log" => {
                i += 1;
                let path = args.get(i).ok_or("после --log нужен путь к файлу")?;
                // Через окружение лог доходит и до DLL, и до её потомков.
                std::env::set_var(LOG_ENV, path);
            }
            "--" => {
                rest = &args[i + 1..];
                break;
            }
            other => {
                // Разрешаем и без "--": первое неопциональное слово — программа.
                if other.starts_with("--") {
                    return Err(format!("неизвестный параметр {other}"));
                }
                rest = &args[i..];
                break;
            }
        }
        i += 1;
    }

    let (program, program_args) = rest.split_first().ok_or("не указана программа. --help")?;

    let tunnel = choose_tunnel(adapter_filter.as_deref())?;
    eprintln!("туннель: {}", TunnelState::Up(tunnel.clone()).describe());

    let dll = dll_path()?;
    std::env::set_var(IFINDEX_ENV, tunnel.index.to_string());

    let launched = inject::launch(program, program_args, &dll, tunnel.index)?;
    eprintln!("запущен {program}, pid {}, хуки установлены", launched.pid);

    if wait {
        Ok(launched.wait())
    } else {
        Ok(0)
    }
}

/// Откуда брать туннель:
/// - явный `--adapter` — ищем сами, служба не нужна;
/// - служба отвечает — верим ей: она следит за переподключениями;
/// - служба сообщает, что туннель опущен, — отказ. Запустить напрямую
///   значило бы молча пустить приложение мимо VPN;
/// - службы нет — ищем сами, как раньше.
fn choose_tunnel(filter: Option<&str>) -> Result<TunnelInfo, String> {
    if let Some(filter) = filter {
        return iface::find_tunnel(Some(filter)).map(|a| a.to_info());
    }
    match vpnsplit_net::pipe::request(&Request::GetStatus) {
        Ok(Response::Status(status)) => match status.tunnel {
            TunnelState::Up(info) => Ok(info),
            TunnelState::Down => Err(
                "служба сообщает: туннель не поднят. Подключи OpenVPN и повтори — \
                 запускать напрямую не буду, иначе приложение молча пойдёт мимо VPN"
                    .to_owned(),
            ),
        },
        Ok(other) => Err(format!("служба ответила неожиданно: {other:?}")),
        Err(_) => {
            eprintln!("служба vpnsplit не отвечает — ищу туннель сам");
            iface::find_tunnel(None).map(|a| a.to_info())
        }
    }
}

fn dll_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("не удалось определить свой путь: {e}"))?;
    let dll = exe.with_file_name(DLL_NAME);
    if !dll.exists() {
        return Err(format!("рядом с лончером нет {DLL_NAME}: {}", dll.display()));
    }
    Ok(dll)
}

fn list() -> Result<(), String> {
    println!("{:>6}  {:<5} {:<16} {:<34} описание", "индекс", "сост", "IPv4", "имя");
    for a in iface::list()? {
        let mark = if a.looks_like_tunnel() { "*" } else { " " };
        println!(
            "{:>6}{} {:<5} {:<16} {:<34} {}",
            a.index.get(),
            mark,
            if a.up { "up" } else { "down" },
            a.ipv4.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
            a.name,
            a.description
        );
    }
    println!();
    println!("* — похоже на туннель; без --adapter берётся первый такой, поднятый и с адресом.");
    Ok(())
}

fn print_help() {
    println!("vpnsplit-launch {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  --list                         список адаптеров");
    println!("  [--adapter ТЕКСТ] -- прог арг  запустить через туннель");
    println!("  --no-wait                      не ждать завершения программы");
    println!("  --log ФАЙЛ                     журнал hook.dll: какие процессы получили хуки");
}

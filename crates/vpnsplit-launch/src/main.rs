//! Лончер: запускает приложение так, чтобы его трафик шёл через туннель.
//!
//!   vpnsplit-launch --list
//!   vpnsplit-launch [--adapter ТЕКСТ] [--no-wait] [--detach-stdio] -- программа [аргументы...]

mod inject;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use vpnsplit_core::hook::{DLL_NAME, DNS_ENV, IFINDEX_ENV, LOG_ENV};
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
    let mut detach_stdio = false;
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
            "--detach-stdio" => detach_stdio = true,
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
    // DNS подключения — hook.dll спросит его первым (через туннель). Уже
    // заданные серверы остаются, но после него: значение могло достаться
    // по наследству от прошлого запуска через другой VPN, и тогда каждое
    // имя ждало бы мёртвый сервер; а без DNS VPN на VPN, режущем порт 53
    // к чужим резолверам, имён не было бы вовсе.
    let existing = std::env::var_os(DNS_ENV);
    if let Some(list) = dns_list(&tunnel.dns, existing.as_deref().and_then(|raw| raw.to_str())) {
        eprintln!("DNS для приложения: {list}");
        std::env::set_var(DNS_ENV, list);
    }

    let launched = inject::launch(program, program_args, &dll, tunnel.index, detach_stdio)?;
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
        let mut info = iface::find_tunnel(Some(filter)).map(|a| a.to_info())?;
        // DNS подключения знает только служба (OpenVPN на TAP его к адаптеру
        // не применяет). Спрашиваем её, но не требуем: адаптер выбран явно.
        info.dns = service_dns(info.index);
        return Ok(info);
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

/// DNS, который служба знает для туннеля с этим индексом. Пусто — служба
/// не ответила или туннель у неё другой.
fn service_dns(index: u32) -> Vec<Ipv4Addr> {
    match vpnsplit_net::pipe::request(&Request::GetStatus) {
        Ok(Response::Status(status)) => match status.tunnel {
            TunnelState::Up(info) if info.index == index => info.dns,
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Значение `VPNSPLIT_DNS`: адреса через запятую, как их разбирает
/// hook.dll, — сначала DNS подключения, затем уже заданные (`existing`),
/// без повторов. `None` — DNS подключения нет, переменную не трогаем.
fn dns_list(pushed: &[Ipv4Addr], existing: Option<&str>) -> Option<String> {
    if pushed.iter().all(|a| a.is_unspecified()) {
        return None;
    }
    let existing = existing.unwrap_or_default().split(',').filter_map(|part| part.trim().parse::<Ipv4Addr>().ok());
    let mut list: Vec<Ipv4Addr> = Vec::new();
    for address in pushed.iter().copied().chain(existing) {
        if !address.is_unspecified() && !list.contains(&address) {
            list.push(address);
        }
    }
    Some(list.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(","))
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
    println!("  --detach-stdio                 не передавать программе каналы (pipe) своих stdin,");
    println!("                                 stdout и stderr — вместо них NUL; консоль и файл");
    println!("                                 передаются как есть. Так запускает окно vpnsplit:");
    println!("                                 иначе оно ждало бы закрытия программы, а не лончера");
    println!("  --log ФАЙЛ                     журнал hook.dll: какие процессы получили хуки");
    println!();
    println!("  Имена приложение спрашивает через туннель: сначала DNS, который назначил VPN,");
    println!("  потом DNS адаптера туннеля, потом 1.1.1.1 и 8.8.8.8. Свои серверы можно задать");
    println!("  переменной VPNSPLIT_DNS (адреса через запятую) — они спрашиваются сразу после DNS");
    println!("  VPN. Назначенный VPN DNS знает только служба: если она не отвечает, его не будет.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_goes_to_the_hook_as_a_comma_list() {
        assert_eq!(dns_list(&[], None), None);
        assert_eq!(dns_list(&[Ipv4Addr::UNSPECIFIED], None), None);
        let pushed = [Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 8, 0, 2)];
        assert_eq!(dns_list(&pushed, None).as_deref(), Some("10.8.0.1,10.8.0.2"));
        // Без DNS подключения заданное пользователем не переписываем.
        assert_eq!(dns_list(&[], Some("9.9.9.9")), None);
    }

    #[test]
    fn vpn_dns_goes_before_what_was_already_set() {
        let pushed = [Ipv4Addr::new(10, 8, 0, 1)];
        // Свой сервер пользователя остаётся, но после DNS VPN.
        assert_eq!(dns_list(&pushed, Some("9.9.9.9")).as_deref(), Some("10.8.0.1,9.9.9.9"));
        // Унаследованное от прошлого запуска — без повторов, мусор
        // отбрасывается.
        assert_eq!(
            dns_list(&pushed, Some(" 10.8.0.1 , мусор,10.9.0.1,,")).as_deref(),
            Some("10.8.0.1,10.9.0.1")
        );
    }
}

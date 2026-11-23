//! Подъём собственного туннеля WireGuardNT. Сейчас не используется —
//! транспортом служит уже настроенный OpenVPN, — но код рабочий и
//! протестированный: появится WireGuard-сервер, и он понадобится.
//!
//! Команда: `vpnsplit-svc wg-up [путь к .conf]`.

use crate::net;
use crate::wg;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use vpnsplit_core::WG_ROUTE_METRIC;
use wg::TunnelConfig;

/// Метрика маршрута до endpoint'а через физику. Маленькая: он обязан
/// выигрывать у чего угодно, иначе handshake уйдёт внутрь туннеля.
const ENDPOINT_ROUTE_METRIC: u32 = 1;

pub fn config_path(args: &[String]) -> PathBuf {
    args.get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config").join("vpnsplit.conf"))
}

fn dll_path() -> PathBuf {
    // Сначала рядом с бинарём, потом из vendor — так удобно на этапе разработки.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    if let Some(dir) = exe_dir {
        let beside = dir.join("wireguard.dll");
        if beside.exists() {
            return beside;
        }
    }
    PathBuf::from("vendor")
        .join("wireguard-nt")
        .join("wireguard-nt")
        .join("bin")
        .join("amd64")
        .join("wireguard.dll")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("wireguard.dll"))
}

pub fn cmd_up(config_file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = TunnelConfig::from_file(&config_file).map_err(|e| {
        format!("{e}\n  файл: {}", config_file.display())
    })?;
    println!("конфиг:     {}", config_file.display());
    println!("endpoint:   {} -> {}", config.peer.endpoint_raw, config.peer.endpoint);

    // Шаг 1. Путь до endpoint'а снимается ДО подъёма туннеля.
    let physical = net::routes::find_physical_path(config.peer.endpoint)?;
    println!("физический интерфейс: индекс {}", physical.interface_index);

    // Шаг 2. Драйвер и адаптер.
    let dll = dll_path();
    let driver = wg::Driver::load(&dll)?;
    println!("wireguard.dll: {}", dll.display());

    let adapter = driver.create_adapter()?;
    let luid = adapter.luid();
    let index = adapter.interface_index()?;
    println!(
        "адаптер «{}»: индекс {}, версия драйвера {:#x}",
        wg::ADAPTER_NAME,
        index.get(),
        driver.running_version()
    );

    // Шаг 3. Конфигурация и подъём.
    adapter.apply(&config)?;
    adapter.set_state(true)?;

    // Шаг 4. Адреса и параметры интерфейса.
    let mut has_v4 = false;
    let mut has_v6 = false;
    for addr in &config.addresses {
        net::routes::add_address(luid, addr.addr, addr.cidr)?;
        match addr.addr {
            IpAddr::V4(_) => has_v4 = true,
            IpAddr::V6(_) => has_v6 = true,
        }
        println!("адрес:      {}/{}", addr.addr, addr.cidr);
    }
    if has_v4 {
        net::routes::configure_interface(
            luid,
            net::routes::family_of(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            config.mtu,
            WG_ROUTE_METRIC,
        )?;
    }
    if has_v6 {
        net::routes::configure_interface(
            luid,
            net::routes::family_of(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
            config.mtu,
            WG_ROUTE_METRIC,
        )?;
    }
    println!("MTU:        {}", config.mtu);

    // Шаг 5. Host-маршрут до endpoint'а мимо туннеля.
    let endpoint_ip = config.peer.endpoint.ip();
    let endpoint_cidr = if endpoint_ip.is_ipv4() { 32 } else { 128 };
    net::routes::add_route(
        "до endpoint",
        physical.interface_luid,
        endpoint_ip,
        endpoint_cidr,
        Some(physical.next_hop),
        ENDPOINT_ROUTE_METRIC,
    )?;
    println!("маршрут:    {endpoint_ip}/{endpoint_cidr} через физику, метрика {ENDPOINT_ROUTE_METRIC}");

    // Шаг 6. Маршруты туннеля с огромной метрикой.
    if has_v4 {
        net::routes::add_route(
            "0.0.0.0/0",
            luid,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
            None,
            WG_ROUTE_METRIC,
        )?;
        println!("маршрут:    0.0.0.0/0 через WG, метрика {WG_ROUTE_METRIC}");
    }
    if has_v6 {
        net::routes::add_route(
            "::/0",
            luid,
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            0,
            None,
            WG_ROUTE_METRIC,
        )?;
        println!("маршрут:    ::/0 через WG, метрика {WG_ROUTE_METRIC}");
    }

    println!();
    println!("Туннель поднят. Индекс интерфейса для IP_UNICAST_IF: {}", index.get());
    println!("Проверка: обычный браузер должен показывать прежний адрес.");
    println!("Enter — опустить туннель.");

    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();

    // Снятие. Маршруты на адаптере уходят вместе с ним, а вот маршрут до
    // endpoint'а живёт на физическом интерфейсе и убирается вручную.
    net::routes::delete_route(
        physical.interface_luid,
        endpoint_ip,
        endpoint_cidr,
        Some(physical.next_hop),
    )?;
    adapter.set_state(false)?;
    drop(adapter);
    println!("Туннель опущен.");
    Ok(())
}

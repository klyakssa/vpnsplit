//! vpnsplit-svc — служба раздельного туннелирования и её консольный клиент.

mod daemon;
mod dnsprobe;
mod flows;
mod flushprobe;
mod lanes;
mod net;
mod probe;
mod procs;
mod redirect;
mod reroute;
mod service;
mod store;
mod udpprobe;
mod update;
mod update_key;
mod vpn;
mod wg;
mod wgcli;

use std::path::PathBuf;
use std::process::ExitCode;
use vpnsplit_core::{AppRule, AppTarget, Event, Request, Response, TunnelState};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");

    let result: Result<(), String> = match command {
        "service" => service::run_dispatcher(),
        "run" => run_console(),
        "install" => service::install(),
        "uninstall" => service::uninstall(),
        "unblock" => unblock(),
        "status" => status(),
        "watch" => watch(),
        "policy" => show_policy(),
        "add" => edit_policy(args.get(1), true, false),
        "addb" => edit_policy(args.get(1), true, true),
        "remove" => edit_policy(args.get(1), false, false),
        "vpn" => own_vpn(args.get(1), args.get(2), args.get(3)),
        "update" => store::Store::for_console()
            .and_then(|store| update::command(&store, args.get(1), args.get(2), args.get(3))),
        "killswitch" => check_killswitch(args.get(1)),
        "notunnel" => check_no_tunnel(args.get(1)),
        "divert" => probe_divert(args.get(1)),
        "flows" => probe_flows(args.get(1)),
        "reroute" => reroute(args.get(1), args.get(2)),
        "filter-limit" => filter_limit(),
        "tree" => show_tree(args.get(1)),
        "pathb" => path_b(args.get(1), args.get(2)),
        "dns" => probe_dns(args.get(1), args.get(2)),
        "udp" => probe_udp(args.get(1)),
        "flush" => probe_flush(args.get(1)),
        "wg-up" => wgcli::cmd_up(wgcli::config_path(&args)).map_err(|e| e.to_string()),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("неизвестная команда «{other}». vpnsplit-svc help")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ошибка: {err}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("vpnsplit-svc {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Служба:");
    println!("  install          установить и запустить службу (нужен администратор)");
    println!("  uninstall        остановить и удалить службу (нужен администратор)");
    println!("  run              работать в консоли — тот же код, без установки");
    println!("  unblock          снять запреты на время простоя (нужен администратор).");
    println!("                   Пока служба не работает, приложениям из списка закрыт");
    println!("                   интернет; эта команда открывает его без службы — до её");
    println!("                   следующего запуска, который поставит запреты снова");
    println!();
    println!("Клиент:");
    println!("  status           состояние туннеля и число правил");
    println!("  watch            печатать события по мере появления");
    println!("  policy           список приложений");
    println!("  add ПУТЬ.exe     добавить приложение в туннель (путь A, через лончер)");
    println!("  addb ЦЕЛЬ        добавить приложение и всех его потомков (путь B,");
    println!("                   лончер не нужен). ЦЕЛЬ — путь к .exe или имя пакета");
    println!("  remove ЦЕЛЬ      убрать приложение");
    println!("  vpn ФАЙЛ [ИМЯ]   своё подключение: служба сама держит туннель OpenVPN по");
    println!("                   этому .ovpn, пока оно нужно приложениям из списка. Подключений");
    println!("                   может быть несколько; без имени берётся имя файла");
    println!("  vpn use ЦЕЛЬ ИМЯ вести приложение из списка через подключение ИМЯ (путь B);");
    println!("                   «-» вместо имени — через то, что по умолчанию (первое)");
    println!("  vpn code ИМЯ     ввести одноразовый код и подключиться — для подключения, сервер");
    println!("                   которого ждёт код при каждом входе");
    println!("  vpn connect ИМЯ  подключаться снова; vpn disconnect ИМЯ — опустить и не поднимать,");
    println!("                   пока не скажут (конфиг остаётся)");
    println!("  vpn default ИМЯ  вести через него приложения, которым подключение не выбрано");
    println!("  vpn login ИМЯ    сменить логин и пароль подключения");
    println!("  vpn off [ИМЯ]    забыть подключение и опустить его; без имени — все");
    println!("  vpn check ФАЙЛ   ничего не меняя: что из конфига дойдёт до OpenVPN, примет ли он");
    println!("                   его и подходит ли пароль ключа (сервер при этом не тревожится)");
    println!("  vpn              что со своими подключениями сейчас");
    println!("  update           что с обновлениями; update look — что сейчас лежит на GitHub;");
    println!("                   update verify ОПИСАНИЕ ПОДПИСЬ — проверить подпись выпуска");
    println!("  killswitch ПУТЬ  проверка: закрыть приложению сеть на 12 секунд");
    println!("  notunnel [СЕК]   проверка: путь B делает вид, что туннеля нет");
    println!("  divert [СЕК]     путь B: послушать, кто открывает соединения");
    println!("  flows [СЕК]      путь B: открытие и закрытие потоков с пятёркой");
    println!("  pathb ЦЕЛЬ [СЕК] путь B, опыт на время: цель задаётся подстрокой");
    println!("  tree [ЧАСТЬ]     родословная процессов и принадлежность пакету");
    println!("  dns [СЕК]        кто спрашивает имена");
    println!("  dns race [СЕК]   успевает ли привязка к процессу раньше запроса");
    println!("  udp [СЕК]        сколько исходящего UDP и успевают ли события о потоках");
    println!("  flush [ЧИСЛО]    с каким опозданием доходят события о запуске процессов");
    println!("  filter-limit     сколько потоков влезает в один фильтр WinDivert");
    println!("  reroute АДРЕС [СЕК]");
    println!("                   путь B, опыт: увести обмен с этим адресом в туннель");
    println!();
    println!("Проверки и опыты (killswitch, notunnel, divert, flows, pathb, dns, udp,");
    println!("flush, reroute) служба принимает только из окна с правами администратора: они");
    println!("перехватывают чужие пакеты или отрезают приложения от сети. Состояние и");
    println!("список доступны без прав.");
    println!();
    println!("Запас:");
    println!("  wg-up [.conf]    поднять собственный туннель WireGuardNT");
}

fn run_console() -> Result<(), String> {
    let store = store::Store::for_console()?;
    let _daemon = daemon::start(store)?;
    eprintln!("служба работает в консоли. Ctrl+C — выход.");
    // Главный поток просто спит: вся работа — в обработчиках и потоке канала.
    loop {
        std::thread::park();
    }
}

fn ask(request: &Request) -> Result<Response, String> {
    vpnsplit_net::pipe::request(request).map_err(|e| format!("{e}. Служба запущена? (vpnsplit-svc run или install)"))
}

fn describe(tunnel: &TunnelState) -> String {
    tunnel.describe()
}

fn status() -> Result<(), String> {
    match ask(&Request::GetStatus)? {
        Response::Status(s) => {
            println!("туннель:   {}", describe(&s.tunnel));
            for (at, line) in own_vpn_lines(&s).iter().enumerate() {
                println!("{}  {line}", if at == 0 { "своё VPN:" } else { "         " });
            }
            println!("правил:    {}", s.rules);
            println!("в туннеле: {} приложений запущено через лончер", s.attached_processes);
            match &s.divert {
                Some(line) => {
                    println!("путь B:    {line}");
                    // Поднятый перехват ещё не значит, что приложение
                    // ведётся: под правилом может не быть ни одного процесса.
                    println!("ведутся:   {}", names(&s.supervised));
                    // Не «перехват поднят», а что он сделал: сколько
                    // соединений процессы правила открыли и сколько из них
                    // увели. Расхождение — соединения мимо службы.
                    for rule in &s.traffic {
                        println!(
                            "           {}: процессов с сетью {}, {}",
                            rule.target.display_name(),
                            rule.processes,
                            rule.describe()
                        );
                    }
                    // Пояснение — один раз и только когда есть к чему:
                    // без него «не дошло» читается то как утечка, то как
                    // пустяк, а это ни то ни другое.
                    if s.traffic.iter().any(|rule| rule.unseen() > 0) {
                        println!(
                            "           «до службы не дошло»: начало соединения забрала другая \
                             программа перехвата, стоящая раньше службы, или соединение не \
                             состоялось. С домашнего адреса пакет приложения не уходил, но куда \
                             соединение пошло дальше, служба не видит и за него не ручается."
                        );
                    }
                }
                None => println!("путь B:    не поднят (правил «приложение и потомки» нет)"),
            }
            if s.standing.is_empty() {
                println!("без службы: запретов нет — без службы приложения из списка пойдут мимо VPN");
            } else {
                println!(
                    "без службы: закрыт интернет {} приложениям (локальная сеть остаётся):",
                    s.standing.len()
                );
                for app in &s.standing {
                    println!("             {}", app.display());
                }
            }
            if !s.alone.is_empty() {
                println!(
                    "            не закрыт {} — они запускаются и сами по себе, запрет оставил бы \
                     без сети всех, кто ими пользуется:",
                    s.alone.len()
                );
                for app in &s.alone {
                    println!("             {}", app.display());
                }
            }
            println!(
                "kill-switch: {}",
                if s.killswitch {
                    "запреты стоят — приложениям из списка сеть закрыта"
                } else if s.is_up() {
                    "не нужен, туннель поднят"
                } else {
                    "ЗАПРЕТОВ НЕТ, хотя туннеля тоже нет"
                }
            );
            Ok(())
        }
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

fn watch() -> Result<(), String> {
    let events = vpnsplit_net::pipe::subscribe().map_err(|e| format!("{e}. Служба запущена?"))?;
    eprintln!("жду событий, Ctrl+C — выход");
    for event in events {
        let event = event.map_err(|e| e.to_string())?;
        let text = match &event {
            Event::TunnelChanged(t) => format!("туннель: {}", describe(t)),
            Event::PolicyChanged(p) => format!("политика: правил {}", p.rules.len()),
            Event::ProcessAttached { pid, target } => {
                format!("процесс {} ({pid}) идёт через туннель", target.display_name())
            }
            Event::ProcessUnhooked { pid, image } => format!(
                "процесс {} ({pid}) работает МИМО туннеля — запущен не лончером",
                image
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| image.display().to_string())
            ),
            Event::ProcessGone { pid } => format!("процесс {pid} завершился"),
            Event::SupervisedChanged(targets) => format!("путь B ведёт: {}", names(targets)),
            Event::VpnChanged(vpns) if vpns.is_empty() => "свои подключения: ни одного".to_owned(),
            Event::VpnChanged(vpns) => format!(
                "свои подключения: {}",
                vpns.iter().map(vpn_line).collect::<Vec<_>>().join("; ")
            ),
        };
        println!("{}  {text}", clock());
    }
    eprintln!("служба закрыла канал");
    Ok(())
}

fn vpn_line(vpn: &vpnsplit_core::VpnState) -> String {
    match vpn.address {
        Some(address) => format!("«{}»: {}, адрес {address}", vpn.name, vpn.line),
        None => format!("«{}»: {}", vpn.name, vpn.line),
    }
}

/// Свои подключения, по строке на каждое; первое — то, куда идут правила
/// без названного подключения.
fn own_vpn_lines(status: &vpnsplit_core::Status) -> Vec<String> {
    if status.vpns.is_empty() {
        return vec![
            "ни одного — туннель поднимает другая программа (задать: vpnsplit-svc vpn ФАЙЛ.ovpn)"
                .to_owned(),
        ];
    }
    // Первое — то, куда идут приложения без выбранного подключения.
    status
        .vpns
        .iter()
        .enumerate()
        .map(|(at, vpn)| {
            let mark = if at == 0 && status.vpns.len() > 1 { " (по умолчанию)" } else { "" };
            format!("{}{mark}", vpn_line(vpn))
        })
        .collect()
}

/// Текст конфига из файла. Блокнот Windows любит UTF-16 и метку порядка
/// байтов; служба ждёт обычный текст.
fn read_config(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    vpnsplit_core::ovpn::decode(bytes).map_err(|e| format!("{path}: {e}"))
}

/// Строка с клавиатуры, которую не видно, пока её набирают. Если ввод —
/// не клавиатура (файл, другая программа), читается как есть.
fn read_secret(prompt: &str) -> Result<String, String> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };
    eprint!("{prompt}");
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    let keyboard = unsafe { GetConsoleMode(input, &mut mode) } != 0;
    if keyboard {
        unsafe { SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT) };
    }
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if keyboard {
        unsafe { SetConsoleMode(input, mode) };
        // Перевод строки, набранный человеком, на экран не попал.
        eprintln!();
    }
    read.map_err(|e| format!("пароль не прочитан: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Что из конфига дойдёт до OpenVPN — словами, без самого текста: в нём
/// ключи, и печатать его незачем даже владельцу.
fn report_config(config: &vpnsplit_core::ovpn::Config) {
    println!("сервер: {}", config.remote);
    if config.needs_password {
        println!("закрытый ключ защищён паролем");
    }
    if config.needs_login {
        println!("сервер спрашивает логин и пароль");
    }
    if config.needs_code {
        println!("и одноразовый код при каждом подключении — само такое подключение не поднимется");
    }
    if config.dropped.is_empty() {
        println!("из конфига принято всё");
    } else {
        println!("не сработает из конфига (маршруты и DNS всей машины служба не трогает):");
        for line in &config.dropped {
            println!("  {line}");
        }
    }
}

/// Спрашивает пароль ключа, если конфигу он нужен.
fn ask_key_password(config: &vpnsplit_core::ovpn::Config) -> Result<Option<String>, String> {
    if !config.needs_password {
        return Ok(None);
    }
    let password = read_secret("пароль ключа: ")?;
    vpnsplit_core::ovpn::check_password(&password)?;
    Ok(Some(password))
}

/// Спрашивает логин и пароль, если их ждёт сервер.
fn ask_login(config: &vpnsplit_core::ovpn::Config) -> Result<Option<(String, String)>, String> {
    if !config.needs_login {
        return Ok(None);
    }
    eprint!("логин: ");
    let mut user = String::new();
    std::io::stdin().read_line(&mut user).map_err(|e| format!("логин не прочитан: {e}"))?;
    let user = user.trim().to_owned();
    let password = read_secret("пароль: ")?;
    vpnsplit_core::ovpn::check_login(&user, &password)?;
    Ok(Some((user, password)))
}

/// Тот же холостой запуск OpenVPN, каким конфиг проверит служба, — но
/// здесь, от имени самого человека и ничего не сохраняя: узнать, годится
/// ли конфиг и подходит ли пароль, до того как отдавать их службе.
fn check_with_openvpn(config: &vpnsplit_core::ovpn::Config) -> Result<(), String> {
    let password = ask_key_password(config)?;
    let dir = std::env::temp_dir().join(format!("vpnsplit-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // Логин вхолостую не проверить — его знает только сервер; для проверки
    // хватит любого, лишь бы OpenVPN было что прочитать.
    let secrets = vpn::Secrets {
        key_password: password.as_deref(),
        login: config.needs_login.then_some(("check", "check")),
    };
    let outcome = vpn::probe(&store::Store::scratch(dir.clone()), config, secrets);
    let _ = std::fs::remove_dir_all(&dir);
    match outcome? {
        true if config.needs_password => println!("OpenVPN конфиг принимает, пароль ключа подходит"),
        true if config.needs_login => {
            println!("OpenVPN конфиг принимает; логин и пароль проверит только сам сервер")
        }
        true => println!("OpenVPN конфиг принимает"),
        false => println!("проверить нечем: OpenVPN не установлен (нет Program Files\\OpenVPN\\bin\\openvpn.exe)"),
    }
    Ok(())
}

/// Своё подключение: задать конфиг, убрать, проверить, посмотреть.
fn own_vpn(first: Option<&String>, second: Option<&String>, third: Option<&String>) -> Result<(), String> {
    match (first.map(String::as_str), second) {
        (None, _) => match ask(&Request::GetStatus)? {
            Response::Status(s) => {
                for line in own_vpn_lines(&s) {
                    println!("{line}");
                }
                println!("туннель: {}", describe(&s.tunnel));
                Ok(())
            }
            other => Err(format!("неожиданный ответ: {other:?}")),
        },
        (Some("off"), name) => match ask(&Request::ClearVpnConfig { name: name.cloned() })? {
            Response::Ok => {
                match name {
                    Some(name) => println!("подключение «{name}» забыто и опускается."),
                    None => println!("свои подключения забыты и опускаются."),
                }
                println!("Приложения, которым оно было назначено, наружу не ходят, пока им не");
                println!("назначат другое или туннель не поднимет другая программа.");
                Ok(())
            }
            Response::Error(e) => Err(e),
            other => Err(format!("неожиданный ответ: {other:?}")),
        },
        (Some("use"), Some(what)) => use_vpn(what, third),
        (Some("use"), None) => Err("нужны приложение из списка и имя подключения".to_owned()),
        (Some(word @ ("connect" | "disconnect" | "default")), Some(name)) => {
            let action = match word {
                "connect" => vpnsplit_core::VpnAction::Connect,
                "disconnect" => vpnsplit_core::VpnAction::Disconnect,
                _ => vpnsplit_core::VpnAction::MakeDefault,
            };
            match ask(&Request::VpnAction { name: name.clone(), action })? {
                Response::Ok => {
                    println!("сделано. Состояние: vpnsplit-svc vpn");
                    Ok(())
                }
                Response::Error(e) => Err(e),
                other => Err(format!("неожиданный ответ: {other:?}")),
            }
        }
        (Some("login"), Some(name)) => {
            eprint!("логин: ");
            let mut user = String::new();
            std::io::stdin().read_line(&mut user).map_err(|e| format!("логин не прочитан: {e}"))?;
            let user = user.trim().to_owned();
            let password = read_secret("пароль: ")?;
            vpnsplit_core::ovpn::check_login(&user, &password)?;
            let login = vpnsplit_core::Login {
                user: vpnsplit_core::Secret(user),
                password: vpnsplit_core::Secret(password),
            };
            match ask(&Request::SetVpnLogin { name: name.clone(), login })? {
                Response::Ok => {
                    println!("логин и пароль «{name}» заменены, подключение начинается заново");
                    Ok(())
                }
                Response::Error(e) => Err(e),
                other => Err(format!("неожиданный ответ: {other:?}")),
            }
        }
        (Some("connect" | "disconnect" | "default" | "login"), None) => {
            Err("нужно имя подключения".to_owned())
        }
        (Some("code"), Some(name)) => {
            let code = read_secret("одноразовый код: ")?;
            let code = code.trim().to_owned();
            vpnsplit_core::ovpn::check_code(&code)?;
            let request =
                Request::ConnectVpn { name: name.clone(), code: vpnsplit_core::Secret(code) };
            match ask(&request)? {
                Response::Ok => {
                    println!("код принят службой, «{name}» подключается. Состояние: vpnsplit-svc vpn");
                    Ok(())
                }
                Response::Error(e) => Err(e),
                other => Err(format!("неожиданный ответ: {other:?}")),
            }
        }
        (Some("code"), None) => Err("нужно имя подключения".to_owned()),
        (Some("check"), Some(path)) => {
            let config = vpnsplit_core::ovpn::sanitize(&read_config(path)?)?;
            report_config(&config);
            // Очищенную копию — только по прямой просьбе и только туда,
            // куда сказано.
            if let Some(out) = third {
                std::fs::write(out, &config.text).map_err(|e| format!("{out}: {e}"))?;
                println!("очищенная копия записана в {out} — в ней ключи, не оставляй её лежать");
            }
            check_with_openvpn(&config)
        }
        (Some("check"), None) => Err("нужен путь к .ovpn".to_owned()),
        (Some(path), _) => {
            let source = read_config(path)?;
            // Разбор здесь — ради понятного отчёта и чтобы знать, нужен ли
            // пароль; решает всё равно служба.
            let config = vpnsplit_core::ovpn::sanitize(&source)?;
            if config.needs_password {
                println!("Закрытый ключ в конфиге защищён паролем. Служба сохранит пароль рядом с");
                println!("конфигом (читать их могут только система и администраторы): подключаться");
                println!("ей придётся и тогда, когда спросить его не у кого.");
            }
            if config.needs_login {
                println!("Сервер спрашивает логин и пароль. Служба сохранит их рядом с конфигом на");
                println!("тех же правах. Проверить их заранее нечем: подойдут ли, скажет сервер.");
            }
            let key_password = ask_key_password(&config)?.map(vpnsplit_core::Secret);
            let login = ask_login(&config)?.map(|(user, password)| vpnsplit_core::Login {
                user: vpnsplit_core::Secret(user),
                password: vpnsplit_core::Secret(password),
            });
            // Имя — второе слово, а без него — имя файла.
            let name = second.cloned().or_else(|| {
                std::path::Path::new(path).file_stem().map(|stem| stem.to_string_lossy().into_owned())
            });
            println!("проверяю конфиг самим OpenVPN (вхолостую, сервер не тревожится)…");
            let request = Request::SetVpnConfig {
                name,
                config: vpnsplit_core::Secret(source),
                key_password,
                login,
            };
            match ask(&request)? {
                Response::Ok => {
                    println!("конфиг принят.");
                    report_config(&config);
                    println!("Служба подключается сама, пока подключение нужно приложениям из списка,");
                    println!("и не начинает, пока туннель держит другая программа.");
                    println!("Кого через него вести: vpnsplit-svc vpn use ЦЕЛЬ ИМЯ.");
                    if config.needs_code {
                        println!("Сервер ждёт одноразовый код при каждом входе: когда подключение");
                        println!("назначено приложению, подключай его сам — vpnsplit-svc vpn code ИМЯ.");
                    }
                    println!("Состояние: vpnsplit-svc vpn. Журналы OpenVPN: %ProgramData%\\vpnsplit\\openvpn-N.log");
                    Ok(())
                }
                Response::Error(e) => Err(e),
                other => Err(format!("неожиданный ответ: {other:?}")),
            }
        }
    }
}

/// Назначить приложению из списка подключение. Выбор подключения есть
/// только у пути B, поэтому правило пути A при этом становится правилом
/// пути B.
fn use_vpn(what: &str, name: Option<&String>) -> Result<(), String> {
    let name = name.ok_or("нужно имя подключения («-» — то, что по умолчанию)")?;
    let target = target_from(what);
    let mut policy = match ask(&Request::GetPolicy)? {
        Response::Policy(p) => p,
        other => return Err(format!("неожиданный ответ: {other:?}")),
    };
    let Some(rule) = policy.rules.iter_mut().find(|rule| rule.target.key() == target.key()) else {
        return Err(format!("{} нет в списке", target.display_name()));
    };
    rule.vpn = (name != "-").then(|| name.clone());
    if rule.vpn.is_some() {
        rule.mechanism = Some(vpnsplit_core::Mechanism::Divert);
    }
    match ask(&Request::SetPolicy(policy))? {
        Response::Ok => {
            match name.as_str() {
                "-" => println!("{}: через подключение по умолчанию", target.display_name()),
                name => println!("{}: через подключение «{name}»", target.display_name()),
            }
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Аварийный выход: снять постоянные запреты без участия службы.
fn unblock() -> Result<(), String> {
    let apps = service::unblock()?;
    println!("запреты на время простоя сняты с приложений: {apps}");
    println!("Теперь, пока служба не работает, приложения из списка ходят в интернет");
    println!("напрямую, мимо VPN. Служба при следующем запуске поставит запреты снова.");
    Ok(())
}

/// Правила, под которыми сейчас есть процессы, — через запятую.
fn names(targets: &[AppTarget]) -> String {
    if targets.is_empty() {
        return "никто — под правилами пути B сейчас нет ни одного процесса".to_owned();
    }
    targets.iter().map(AppTarget::display_name).collect::<Vec<_>>().join(", ")
}

fn clock() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Время UTC без зависимостей; для журнала событий этого достаточно.
    format!("{:02}:{:02}:{:02}Z", secs / 3600 % 24, secs / 60 % 60, secs % 60)
}

fn show_policy() -> Result<(), String> {
    match ask(&Request::GetPolicy)? {
        Response::Policy(p) => {
            if p.rules.is_empty() {
                println!("список пуст");
            }
            for rule in &p.rules {
                println!(
                    "{:?}  {:<8}  {}{}",
                    rule.routing,
                    rule.mechanism().short(),
                    rule.target.display_name(),
                    match &rule.vpn {
                        Some(name) => format!("  → «{name}»"),
                        None => String::new(),
                    }
                );
            }
            if !p.rules.is_empty() {
                println!();
                for mechanism in [vpnsplit_core::Mechanism::Inject, vpnsplit_core::Mechanism::Divert] {
                    println!("{}: {}", mechanism.short(), mechanism.describe());
                }
            }
            Ok(())
        }
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Проверка kill-switch при живом туннеле: приложению закрывается сеть на
/// несколько секунд. Иначе убедиться, что защита работает, можно было бы
/// только в момент, когда она уже понадобилась.
fn check_killswitch(path: Option<&String>) -> Result<(), String> {
    let path = PathBuf::from(path.ok_or("нужен путь к .exe")?);
    match ask(&Request::CheckKillswitch(path.clone()))? {
        Response::Ok => {
            println!("{} на несколько секунд отрезан от сети.", path.display());
            println!("Запусти его прямо сейчас — он не должен достучаться наружу.");
            println!("Локальная сеть при этом остаётся доступной: так же, как при");
            println!("настоящем kill-switch.");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// События запуска процессов: с каким опозданием они доходят и какая
/// настройка доставки его сокращает. Ничего не перехватывает.
fn probe_flush(rounds: Option<&String>) -> Result<(), String> {
    let rounds: u32 = rounds.map(|s| s.parse().unwrap_or(8)).unwrap_or(8);
    println!("меряю опоздание событий запуска, по {rounds} запусков на настройку…");
    match ask(&Request::ProbeFlush { rounds })? {
        Response::Ok => {
            println!("готово. Что получилось — в журнале службы:");
            println!("  %ProgramData%\\vpnsplit\\service.log");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// UDP: успевает ли событие о новом потоке раньше его первого пакета и
/// сколько на машине исходящего UDP. Только чтение.
fn probe_udp(seconds: Option<&String>) -> Result<(), String> {
    let seconds: u32 = seconds.map(|s| s.parse().unwrap_or(30)).unwrap_or(30);
    println!("слушаю UDP {seconds} с…");
    match ask(&Request::ProbeUdp { seconds })? {
        Response::Ok => {
            println!("готово. Что получилось — в журнале службы:");
            println!("  %ProgramData%\\vpnsplit\\service.log");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Проверка отказа без туннеля. Отключать VPN ради этого не надо — и
/// нельзя, если по нему же идёт работа: движок просто делает вид, что
/// туннеля нет.
fn check_no_tunnel(seconds: Option<&String>) -> Result<(), String> {
    let seconds: u32 = seconds.map(|s| s.parse().unwrap_or(20)).unwrap_or(20);
    match ask(&Request::CheckNoTunnel { seconds })? {
        Response::Ok => {
            println!("{seconds} с путь B считает, что туннеля нет.");
            println!("Выбранные приложения сейчас не должны достучаться наружу —");
            println!("ни через туннель, ни через домашний интернет. Остальной");
            println!("трафик машины при этом работает как обычно.");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Путь B, наблюдение: несколько секунд слушать события сокетов из ядра.
/// Только чтение; результат ложится в журнал службы.
fn probe_divert(seconds: Option<&String>) -> Result<(), String> {
    let seconds: u32 = seconds.map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
    println!("слушаю события сокетов {seconds} с…");
    match ask(&Request::ProbeDivert { seconds })? {
        Response::Ok => {
            println!("готово. Что увидено — в журнале службы:");
            println!("  %ProgramData%\\vpnsplit\\service.log");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Путь B, наблюдение за потоками: открытие и закрытие соединений с полной
/// пятёркой. Только чтение.
fn probe_flows(seconds: Option<&String>) -> Result<(), String> {
    let seconds: u32 = seconds.map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
    println!("слушаю открытие и закрытие потоков {seconds} с…");
    match ask(&Request::ProbeFlows { seconds })? {
        Response::Ok => {
            println!("готово. Что увидено — в журнале службы:");
            println!("  %ProgramData%\\vpnsplit\\service.log");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Кто спрашивает имена: события провайдера DNS-Client с номером процесса.
fn probe_dns(first: Option<&String>, second: Option<&String>) -> Result<(), String> {
    // `dns race [СЕК]` — замер опережения, `dns [СЕК]` — просто наблюдение.
    let race = first.map(|s| s == "race").unwrap_or(false);
    let seconds = if race { second } else { first };
    let seconds: u32 = seconds.map(|s| s.parse().unwrap_or(20)).unwrap_or(20);
    let request = if race {
        println!("замеряю, что раньше — привязка к процессу или запрос на проводе, {seconds} с…");
        Request::ProbeDnsRace { seconds }
    } else {
        println!("слушаю события разрешения имён {seconds} с…");
        Request::ProbeDns { seconds }
    };
    match ask(&request)? {
        Response::Ok => {
            println!("готово. Что увидено — в журнале службы:");
            println!("  %ProgramData%\\vpnsplit\\service.log");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Путь B целиком: приложение и всё, что оно запускает, в туннель.
fn path_b(target: Option<&String>, seconds: Option<&String>) -> Result<(), String> {
    let target = target.ok_or(
        "нужна цель — часть пути к образу или имени пакета, например: \
         pathb winget 60",
    )?;
    let seconds: u32 = seconds.map(|s| s.parse().unwrap_or(60)).unwrap_or(60);
    println!("путь B на «{target}», {seconds} с. Что происходит — в журнале службы.");
    match ask(&Request::PathB { target: target.clone(), seconds })? {
        Response::Ok => {
            println!("готово. Итог — последняя строка журнала:");
            println!("  %ProgramData%\\vpnsplit\\service.log");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Родословная процессов и принадлежность пакету.
///
/// Отвечает на вопрос, от которого зависит правило «приложение и всё, что
/// оно запускает»: передаётся ли принадлежность пакету детям. Если да, то
/// для приложения из Store достаточно одного правила по имени пакета. Если
/// нет — связь с приложением придётся вести по родословной.
fn show_tree(needle: Option<&String>) -> Result<(), String> {
    use std::collections::HashMap;
    let all = vpnsplit_net::proc::parents();
    let by_pid: HashMap<u32, &(u32, u32, String)> = all.iter().map(|e| (e.0, e)).collect();
    let needle = needle.map(|s| s.to_lowercase());

    println!("{:>7} {:>7}  {:<28} {}", "процесс", "родитель", "образ", "пакет");
    let mut shown = 0usize;
    for (pid, parent, name) in &all {
        // Показываем либо то, что просили, либо всё, у чего есть пакет, и
        // детей таких процессов: именно там и виден ответ.
        let parent_name = by_pid.get(parent).map(|e| e.2.to_lowercase());
        let interesting = match &needle {
            Some(n) => {
                name.to_lowercase().contains(n)
                    || parent_name.as_deref().map(|p| p.contains(n)).unwrap_or(false)
            }
            None => vpnsplit_net::proc::package_family(*pid).is_some(),
        };
        if !interesting {
            continue;
        }
        shown += 1;
        let package = vpnsplit_net::proc::package_family(*pid)
            .unwrap_or_else(|| "— нет пакета".to_owned());
        println!(
            "{pid:>7} {parent:>7}  {:<28} {package}",
            name.chars().take(28).collect::<String>()
        );
    }
    if shown == 0 {
        println!("ничего не нашлось");
    }
    Ok(())
}

/// Сколько потоков влезает в один фильтр WinDivert.
///
/// Работает здесь же, в клиенте, и службу не трогает: проверка фильтра идёт
/// целиком в пользовательском режиме — ни драйвера, ни прав администратора
/// она не требует. От этого числа зависит устройство перенаправления:
/// фильтр перечисляет нынешние потоки, и если их больше, чем влезает,
/// часть придётся оставлять без перехвата.
fn filter_limit() -> Result<(), String> {
    use std::net::Ipv4Addr;
    let make = |count: usize| {
        let mut table = flows::Table::default();
        for i in 0..count {
            table.opened(
                flows::Key {
                    protocol: 6,
                    local_port: 40000 + i as u16,
                    // Адреса тоже разные: одинаковые могли бы сложиться в
                    // более короткую программу, и замер вышел бы радужнее
                    // настоящего.
                    remote: Ipv4Addr::new(104, 26, (i / 256) as u8, (i % 256) as u8),
                    remote_port: 443,
                },
                1,
            );
        }
        table.filter_up_to(usize::MAX).unwrap_or_default()
    };

    // Сначала убедимся, что сама проверка работает: заведомо плохой фильтр
    // должен быть отвергнут, заведомо хороший — принят.
    if vpnsplit_net::divert::check_filter("это не фильтр", 0).is_ok() {
        return Err("проверка фильтра принимает мусор — верить ей нельзя".to_owned());
    }
    vpnsplit_net::divert::check_filter("outbound and tcp", 0)
        .map_err(|e| format!("простейший фильтр не принят: {e}"))?;
    println!("проверка фильтра работает: мусор отвергнут, простой фильтр принят");

    let mut last_good = 0usize;
    let mut last_error = String::new();
    for count in 1..=512 {
        let filter = make(count);
        match vpnsplit_net::divert::check_filter(&filter, 0) {
            Ok(()) => last_good = count,
            Err(e) => {
                last_error = e;
                println!(
                    "потоков {count}: отказ, длина строки {} байт — {last_error}",
                    filter.len()
                );
                break;
            }
        }
    }
    if last_good == 0 {
        return Err(format!("не принят даже один поток: {last_error}"));
    }
    let filter = make(last_good);
    println!(
        "влезает потоков: {last_good}, это {} байт строки ({} байт на поток)",
        filter.len(),
        filter.len() / last_good
    );
    if last_good != flows::MAX_IN_FILTER {
        println!(
            "в flows.rs стоит предел {} — измерено {last_good}",
            flows::MAX_IN_FILTER
        );
    }

    // Сколько дала бы более короткая запись: без обёртки по протоколу и без
    // удалённого порта. Это не предложение так сделать, а цена точности —
    // такое условие поймало бы и чужое соединение с тем же местным портом.
    let compact = |count: usize| {
        (0..count)
            .map(|i| {
                format!(
                    "(outbound and tcp.SrcPort == {p} and ip.DstAddr == 104.26.{a}.{b}) or \
                     (inbound and tcp.DstPort == {p} and ip.SrcAddr == 104.26.{a}.{b})",
                    p = 40000 + i,
                    a = i / 256,
                    b = i % 256
                )
            })
            .collect::<Vec<_>>()
            .join(" or ")
    };
    let mut compact_good = 0usize;
    for count in 1..=512 {
        if vpnsplit_net::divert::check_filter(&compact(count), 0).is_ok() {
            compact_good = count;
        } else {
            break;
        }
    }
    println!("короткой записью влезло бы {compact_good} потоков — ценой точности");
    Ok(())
}

/// Путь B, опыт перенаправления: увести обмен с одним адресом в туннель.
/// Трогает только этот адрес и только на заданное число секунд.
fn reroute(target: Option<&String>, seconds: Option<&String>) -> Result<(), String> {
    let target = target.ok_or("нужен адрес IPv4, например: reroute 1.1.1.1 15")?;
    let seconds: u32 = seconds.map(|s| s.parse().unwrap_or(15)).unwrap_or(15);
    println!("перехватываю обмен с {target} на {seconds} с…");
    match ask(&Request::Reroute { target: target.clone(), seconds })? {
        Response::Ok => {
            println!("готово. Что получилось — в журнале службы:");
            println!("  %ProgramData%\\vpnsplit\\service.log");
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

/// Цель из командной строки. Путь к файлу узнаётся по разделителям или по
/// расширению; всё остальное — имя семейства пакета, у них ни того, ни
/// другого не бывает.
fn target_from(text: &str) -> AppTarget {
    let path_like = text.contains('\\') || text.contains('/') || text.to_lowercase().ends_with(".exe");
    if path_like {
        AppTarget::Executable(PathBuf::from(text))
    } else {
        AppTarget::Package(text.to_owned())
    }
}

/// `family` — правило «приложение и все его потомки» (путь B). Иначе
/// обычное правило пути A, которое работает через лончер.
fn edit_policy(what: Option<&String>, add: bool, family: bool) -> Result<(), String> {
    let what = what.ok_or("нужен путь к .exe или имя семейства пакета")?;
    let target = target_from(what);
    let mut policy = match ask(&Request::GetPolicy)? {
        Response::Policy(p) => p,
        other => return Err(format!("неожиданный ответ: {other:?}")),
    };
    let before = policy.rules.len();
    // Одно правило на приложение: добавить второй раз — значит заменить,
    // в том числе сменить путь A на путь B.
    policy.rules.retain(|r| r.target != target);
    if add {
        policy.rules.push(if family {
            AppRule::tunnel_family(target.clone())
        } else {
            AppRule::tunnel(target.clone())
        });
    } else if policy.rules.len() == before {
        return Err(format!("{} нет в списке", target.display_name()));
    }
    match ask(&Request::SetPolicy(policy))? {
        Response::Ok => {
            let how = if add && family { " (приложение и все его потомки)" } else { "" };
            println!(
                "{} {}{how}",
                if add { "добавлено:" } else { "убрано:" },
                target.display_name()
            );
            if add && family {
                println!("Служба поднимает перехват сама; что происходит — в журнале.");
            }
            Ok(())
        }
        Response::Error(e) => Err(e),
        other => Err(format!("неожиданный ответ: {other:?}")),
    }
}

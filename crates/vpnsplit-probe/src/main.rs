//! Проверка фундамента всей схемы.
//!
//! Создаёт TCP-сокет, ставит на него `IP_UNICAST_IF` с указанным индексом
//! интерфейса и спрашивает у сервиса свой внешний адрес. Если с индексом
//! туннеля виден адрес сервера, а без него — домашний, значит раздельное
//! туннелирование по приложениям работает и остальные этапы имеют смысл.
//!
//! Если не работает — пересматривать надо всю архитектуру, и лучше узнать
//! об этом здесь, на двухстах строках, чем на десятом этапе.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::windows::io::FromRawSocket;
use std::process::ExitCode;
use std::time::Duration;
use vpnsplit_core::InterfaceIndex;
use windows_sys::Win32::Networking::WinSock::{
    closesocket, connect, setsockopt, socket, WSACleanup, WSAGetLastError, WSAStartup, AF_INET,
    INVALID_SOCKET, IPPROTO_IP, IPPROTO_TCP, IP_UNICAST_IF, SOCKADDR, SOCKADDR_IN, SOCK_STREAM,
    SOCKET, SOCKET_ERROR, WSADATA,
};

/// Сервис отдаёт внешний адрес простым текстом по обычному HTTP.
/// Без TLS намеренно: проверяется маршрутизация, а не умение ходить в https.
const HOST: &str = "api.ipify.org";
const PORT: u16 = 80;
const TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    let index: u32 = match arg.as_deref() {
        None | Some("--help") | Some("-h") => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some(text) => match text.parse() {
            Ok(value) => value,
            Err(_) => {
                eprintln!("«{text}» не похоже на индекс интерфейса");
                print_help();
                return ExitCode::from(2);
            }
        },
    };

    match run(InterfaceIndex::new(index)) {
        Ok(address) => {
            println!();
            println!("внешний адрес: {address}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("ошибка: {err}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!("vpnsplit-probe {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  vpnsplit-probe 0    без привязки — как ходит обычное приложение");
    println!("  vpnsplit-probe 8    привязать сокет к интерфейсу с индексом 8");
    println!();
    println!("Индексы интерфейсов: Get-NetIPInterface -AddressFamily IPv4");
}

fn run(iface: InterfaceIndex) -> Result<String, String> {
    let endpoint = resolve()?;
    if iface.get() == 0 {
        println!("привязка:   нет (обычное поведение приложения)");
    } else {
        println!(
            "привязка:   индекс {}, значение опции 0x{:08x}",
            iface.get(),
            iface.ipv4_sockopt_value()
        );
    }
    println!("назначение: {HOST} -> {endpoint}");

    let _winsock = Winsock::start()?;
    let mut stream = open(endpoint, iface)?;

    let request = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\nUser-Agent: vpnsplit-probe\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("не удалось отправить запрос: {e}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("не удалось прочитать ответ: {e}"))?;

    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.trim().to_owned())
        .filter(|body| !body.is_empty())
        .ok_or_else(|| format!("ответ без тела:\n{response}"))
}

fn resolve() -> Result<SocketAddr, String> {
    (HOST, PORT)
        .to_socket_addrs()
        .map_err(|e| format!("не удалось разрешить {HOST}: {e}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| format!("у {HOST} нет адреса IPv4"))
}

/// Сокет создаётся вручную, потому что опцию надо поставить ДО connect:
/// после установления соединения менять интерфейс уже поздно.
fn open(endpoint: SocketAddr, iface: InterfaceIndex) -> Result<TcpStream, String> {
    let SocketAddr::V4(v4) = endpoint else {
        return Err("ожидался адрес IPv4".to_owned());
    };

    let handle: SOCKET = unsafe { socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
    if handle == INVALID_SOCKET {
        return Err(format!("socket() не удался, WSA {}", unsafe { WSAGetLastError() }));
    }
    let guard = SocketGuard(handle);

    if iface.get() != 0 {
        // Вот она, главная ловушка: значение передаётся в сетевом порядке байт.
        let value = iface.ipv4_sockopt_value();
        let result = unsafe {
            setsockopt(
                handle,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if result == SOCKET_ERROR {
            return Err(format!(
                "setsockopt(IP_UNICAST_IF) не удался, WSA {}",
                unsafe { WSAGetLastError() }
            ));
        }
    }

    let mut addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    addr.sin_family = AF_INET;
    addr.sin_port = v4.port().to_be();
    addr.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.ip().octets());

    let result = unsafe {
        connect(
            handle,
            &addr as *const SOCKADDR_IN as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(format!(
            "connect() не удался, WSA {} (если привязка указывает на интерфейс без маршрута, это ожидаемо)",
            unsafe { WSAGetLastError() }
        ));
    }

    // Сокет передаётся во владение TcpStream, поэтому guard разоружается.
    let raw = guard.release();
    let stream = unsafe { TcpStream::from_raw_socket(raw as std::os::windows::raw::SOCKET) };
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    Ok(stream)
}

/// Закрывает сокет, если владение не было передано дальше.
struct SocketGuard(SOCKET);

impl SocketGuard {
    fn release(self) -> SOCKET {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        unsafe { closesocket(self.0) };
    }
}

struct Winsock;

impl Winsock {
    fn start() -> Result<Self, String> {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        let code = unsafe { WSAStartup(0x0202, &mut data) };
        if code != 0 {
            return Err(format!("WSAStartup вернул {code}"));
        }
        Ok(Winsock)
    }
}

impl Drop for Winsock {
    fn drop(&mut self) {
        unsafe { WSACleanup() };
    }
}

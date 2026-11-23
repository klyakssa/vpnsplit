//! Чьё это соединение: таблица TCP с номерами процессов.
//!
//! На слое пакетов WinDivert номера процесса нет вовсе — там только адреса
//! и порты. А решение «в туннель или нет» принимается по приложению.
//! Мостик между тем и другим — таблица соединений ядра: по местному порту
//! она отдаёт номер процесса-владельца.
//!
//! Слой FLOW отдаёт то же самое и сразу, но только для потоков, открытых
//! при живом наблюдении. Для первого пакета соединения, которое началось
//! раньше нашей ручки, остаётся только эта таблица.
//!
//! Прав администратора не требует: обычный пользователь видит владельцев
//! всех соединений.

use std::net::Ipv4Addr;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
use windows_sys::Win32::Networking::WinSock::AF_INET;

/// Строка таблицы: соединение и его хозяин.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    pub local: Ipv4Addr,
    pub local_port: u16,
    pub remote: Ipv4Addr,
    pub remote_port: u16,
    pub pid: u32,
}

/// `MIB_TCPROW_OWNER_PID`. Порты лежат в младших двух байтах двойного
/// слова и **в сетевом порядке** — отсюда разбор через `to_ne_bytes`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Row {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    pid: u32,
}

/// Все соединения TCP над IPv4 с номерами процессов.
pub fn connections() -> Vec<Connection> {
    let mut size = 0u32;
    // Первый вызов спрашивает размер: таблица меняется, запас не поможет.
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if size == 0 {
        return Vec::new();
    }
    let mut buffer = vec![0u8; size as usize];
    let code = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if code != 0 {
        return Vec::new();
    }
    parse(&buffer)
}

/// Разбор буфера: число строк, за ним сами строки. Вынесено отдельно,
/// чтобы раскладку можно было проверить, не обращаясь к системе.
fn parse(buffer: &[u8]) -> Vec<Connection> {
    if buffer.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let rows = buffer.len().saturating_sub(4) / std::mem::size_of::<Row>();
    let count = count.min(rows);
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let at = 4 + i * std::mem::size_of::<Row>();
        // Строки идут вплотную и выровнены по 4 байта, как и само число.
        let row: Row = unsafe { std::ptr::read_unaligned(buffer[at..].as_ptr() as *const Row) };
        let _ = row.state;
        result.push(Connection {
            local: Ipv4Addr::from(row.local_addr.to_ne_bytes()),
            local_port: port(row.local_port),
            remote: Ipv4Addr::from(row.remote_addr.to_ne_bytes()),
            remote_port: port(row.remote_port),
            pid: row.pid,
        });
    }
    result
}

/// Порт из двойного слова: значащие два байта — первые, в сетевом порядке.
fn port(value: u32) -> u16 {
    let bytes = value.to_ne_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

/// Кому принадлежит соединение с этим местным портом и этим собеседником.
/// Порт без собеседника неоднозначен: один и тот же номер может быть занят
/// слушающим сокетом и исходящим соединением другого процесса.
pub fn owner(local_port: u16, remote: Ipv4Addr, remote_port: u16) -> Option<u32> {
    connections()
        .into_iter()
        .find(|c| c.local_port == local_port && c.remote == remote && c.remote_port == remote_port)
        .map(|c| c.pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_not_empty_and_has_sane_rows() {
        let all = connections();
        assert!(!all.is_empty(), "в системе всегда есть соединения TCP");
        // Хотя бы одна строка должна быть осмысленной: порт не нулевой,
        // номер процесса не нулевой.
        assert!(all.iter().any(|c| c.local_port != 0 && c.pid != 0));
    }

    /// Главная проверка: открываем настоящее соединение и ищем себя.
    /// Если разбор раскладки или порядок байт в порту неверны, найти себя
    /// не удастся — а это ровно та ошибка, которая на пути B выглядела бы
    /// как «приложение не опознано».
    #[test]
    fn our_own_connection_points_back_at_us() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").expect("слушатель");
        let address = listener.local_addr().expect("адрес слушателя");
        let mut client = TcpStream::connect(address).expect("соединение");
        let (mut accepted, _) = listener.accept().expect("приём");
        // Данные нужны, чтобы соединение точно оказалось установленным.
        client.write_all(b"x").expect("запись");
        accepted.flush().ok();

        let local = client.local_addr().expect("местный адрес");
        let me = std::process::id();
        let found = owner(
            local.port(),
            Ipv4Addr::LOCALHOST,
            address.port(),
        );
        assert_eq!(found, Some(me), "своё же соединение должно указывать на нас");
    }

    #[test]
    fn ports_are_read_from_the_leading_bytes_in_network_order() {
        // 443 в сетевом порядке — 0x01BB → байты 0x01, 0xBB.
        let value = u32::from_ne_bytes([0x01, 0xBB, 0, 0]);
        assert_eq!(port(value), 443);
        assert_eq!(port(u32::from_ne_bytes([0, 80, 0, 0])), 80);
    }

    #[test]
    fn a_truncated_buffer_does_not_panic() {
        assert!(parse(&[]).is_empty());
        assert!(parse(&[1, 0, 0]).is_empty());
        // Заявлено сто строк, а байтов нет: берём столько, сколько влезло.
        let mut buffer = vec![0u8; 4];
        buffer[0] = 100;
        assert!(parse(&buffer).is_empty());
    }
}

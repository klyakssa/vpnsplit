//! Чей это порт UDP: таблица сокетов ядра с номерами процессов.
//!
//! У UDP нет соединения, поэтому хозяин ищется по одному только местному
//! порту. Отсюда и отличие от таблицы TCP: порт может быть занят сразу
//! несколькими сокетами (разные местные адреса, общий доступ к порту), и
//! ответ здесь — список, а не один номер. Что с ним делать, решает
//! вызывающий: путь B считает порт своим, если своим оказался хоть один из
//! хозяев, — увести лишнее в туннель лучше, чем выпустить своё домой.
//!
//! Сокеты двойного режима (один сокет IPv6, через который ходят и в IPv4, —
//! так делают .NET и Java) в таблице IPv4 видны: проверено 22.11.2026
//! скриптом `dualstack.ps1`. Поэтому таблица IPv6 здесь не читается.

use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedUdpTable, UDP_TABLE_OWNER_PID};
use windows_sys::Win32::Networking::WinSock::AF_INET;

/// `MIB_UDPROW_OWNER_PID`. Порт — в младших двух байтах двойного слова и в
/// сетевом порядке, как и в таблице TCP.
#[repr(C)]
#[derive(Clone, Copy)]
struct Row {
    local_addr: u32,
    local_port: u32,
    pid: u32,
}

/// Все сокеты UDP над IPv4: местный порт и номер процесса.
pub fn sockets() -> Vec<(u16, u32)> {
    let mut size = 0u32;
    // Первый вызов спрашивает размер: таблица меняется, запас не поможет.
    unsafe {
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    };
    if size == 0 {
        return Vec::new();
    }
    // Между двумя вызовами таблица могла вырасти — берём с запасом, иначе
    // второй вызов вернёт «мало места», и мы решили бы, что порт ничей.
    size += 512;
    let mut buffer = vec![0u8; size as usize];
    let code = unsafe {
        GetExtendedUdpTable(
            buffer.as_mut_ptr() as *mut _,
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if code != 0 {
        return Vec::new();
    }
    parse(&buffer)
}

/// Разбор буфера: число строк, за ним сами строки.
fn parse(buffer: &[u8]) -> Vec<(u16, u32)> {
    if buffer.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let rows = buffer.len().saturating_sub(4) / std::mem::size_of::<Row>();
    let count = count.min(rows);
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let at = 4 + i * std::mem::size_of::<Row>();
        let row: Row = unsafe { std::ptr::read_unaligned(buffer[at..].as_ptr() as *const Row) };
        let _ = row.local_addr;
        let bytes = row.local_port.to_ne_bytes();
        result.push((u16::from_be_bytes([bytes[0], bytes[1]]), row.pid));
    }
    result
}

/// Все процессы, у которых открыт сокет UDP на этом местном порту.
pub fn owners(local_port: u16) -> Vec<u32> {
    sockets()
        .into_iter()
        .filter(|(port, _)| *port == local_port)
        .map(|(_, pid)| pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Главная проверка: открываем настоящий сокет и ищем себя. Если
    /// раскладка строки или порядок байт в порту разобраны неверно, найти
    /// себя не удастся — на пути B это выглядело бы как «порт ничей», то
    /// есть как утечка.
    #[test]
    fn we_find_our_own_socket_by_its_port() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let found = owners(port);
        assert!(found.contains(&std::process::id()), "порт {port}: {found:?}");
    }

    #[test]
    fn a_port_nobody_holds_has_no_owners() {
        // Занять порт, запомнить номер, отпустить: теперь он точно ничей.
        let port = {
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.local_addr().unwrap().port()
        };
        assert!(!owners(port).contains(&std::process::id()));
    }

    #[test]
    fn a_short_buffer_is_not_read_past_its_end() {
        assert!(parse(&[]).is_empty());
        // Заявлено сто строк, а места на одну: берём одну.
        let mut buffer = 100u32.to_ne_bytes().to_vec();
        buffer.extend_from_slice(&0u32.to_ne_bytes());
        buffer.extend_from_slice(&u32::from_ne_bytes([0x13, 0x88, 0, 0]).to_ne_bytes());
        buffer.extend_from_slice(&77u32.to_ne_bytes());
        assert_eq!(parse(&buffer), vec![(5000, 77)]);
    }

    /// Цена одного обращения. Это не проверка, а замер: путь B платит её
    /// за пакет UDP, хозяин которого ещё не известен, и число надо знать.
    #[test]
    fn one_lookup_costs_this_much() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let started = std::time::Instant::now();
        const TIMES: u32 = 200;
        for _ in 0..TIMES {
            assert!(!owners(port).is_empty());
        }
        let each = started.elapsed().as_micros() / TIMES as u128;
        println!("обращение к таблице UDP: {each} мкс, сокетов в таблице {}", sockets().len());
    }
}

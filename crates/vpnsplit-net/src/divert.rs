//! WinDivert: кто именно открывает соединение — и куда уходит его трафик.
//!
//! Путь A (внедрение DLL) не берёт Store-приложения: они живут в общих
//! хост-процессах, и внедряться туда нельзя. Путь B смотрит на соединения
//! со стороны ядра, где видно и номер процесса, и его принадлежность
//! пакету, — независимо от того, как приложение запустили.
//!
//! Ручку можно открыть тремя способами, и разница между ними существенна:
//!
//! - `sniff_sockets` и `sniff_flows` — только чтение (`SNIFF | RECV_ONLY`):
//!   ни задержать, ни изменить, ни уронить пакет нельзя даже по ошибке.
//! - `intercept_network` — рабочий режим: пакет приходит нам и **исчезает
//!   из сети**, пока мы не отправим его обратно. Забыть отправить — значит
//!   молча оборвать связь всему, что попало под фильтр. Поэтому фильтр
//!   держим узким, а время жизни ручки — ограниченным.
//!
//! **Драйвер мы не ставим.** Флаг `NO_INSTALL` означает «открой уже
//! загруженный». На этой машине WinDivert 2.2 уже работает: его держат
//! `zapret` и `VpnClient`. Ставить свою копию поверх чужой службы с тем же
//! именем — верный способ сломать обе.
//!
//! Библиотека грузится вручную, а не линкуется: без неё служба должна
//! спокойно работать дальше, а не отказываться запускаться.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

/// Слои WinDivert. На NETWORK ходят сами пакеты, на FLOW и SOCKET — только
/// сведения о соединениях.
pub const LAYER_NETWORK: u8 = 0;
pub const LAYER_FLOW: u8 = 2;
pub const LAYER_SOCKET: u8 = 3;

const FLAG_SNIFF: u64 = 0x0001;
const FLAG_RECV_ONLY: u64 = 0x0004;
const FLAG_NO_INSTALL: u64 = 0x0010;

/// События слоёв FLOW и SOCKET.
const EVENT_ESTABLISHED: u8 = 1;
const EVENT_DELETED: u8 = 2;
const EVENT_BIND: u8 = 3;
const EVENT_CONNECT: u8 = 4;
const EVENT_LISTEN: u8 = 5;
const EVENT_ACCEPT: u8 = 6;
const EVENT_CLOSE: u8 = 7;

/// Как закрывать ручку — значения `WINDIVERT_SHUTDOWN`: 1 приём, 2
/// отправка, 3 оба.
///
/// Разница существенная, и ошибка в ней не видна на глаз. Сначала здесь
/// стояло 2 — «закрыть отправку», — и поток, висящий в `recv`, от этого не
/// просыпался вовсе. На занятом фильтре это незаметно: следующий же пакет
/// выводит цикл из ожидания, и всё выглядит рабочим. Поймалось на адресе,
/// с которым после опыта больше никто не разговаривал: поток остался ждать
/// навсегда, а клиент — ответа службы.
const SHUTDOWN_RECV: u32 = 1;
const SHUTDOWN_BOTH: u32 = 3;

/// Наибольший пакет, который может прийти. С учётом сборки крупных кадров
/// сетевой картой пакет бывает больше обычных 1500 байт.
pub const MAX_PACKET: usize = 0xFFFF;

type OpenFn = unsafe extern "system" fn(*const u8, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "system" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "system" fn(HANDLE, u32) -> i32;
type ChecksumFn = unsafe extern "system" fn(*mut c_void, u32, *const Address, u64) -> i32;
type CompileFn = unsafe extern "system" fn(
    *const u8,
    u32,
    *mut u8,
    u32,
    *mut *const u8,
    *mut u32,
) -> i32;

static OPEN: AtomicUsize = AtomicUsize::new(0);
static RECV: AtomicUsize = AtomicUsize::new(0);
static SEND: AtomicUsize = AtomicUsize::new(0);
static SHUTDOWN: AtomicUsize = AtomicUsize::new(0);
static CHECKSUM: AtomicUsize = AtomicUsize::new(0);
static COMPILE: AtomicUsize = AtomicUsize::new(0);

/// `WINDIVERT_ADDRESS`. Первые два поля — время и упакованные биты, дальше
/// объединение на 64 байта: какой его вариант осмыслен, говорит `layer`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    /// Слой (8 бит), событие (8 бит), дальше флаги по одному биту.
    bits: u32,
    _reserved: u32,
    payload: Payload,
}

#[repr(C)]
#[derive(Clone, Copy)]
union Payload {
    socket: SocketData,
    network: NetworkData,
    /// Задаёт размер объединения: 64 байта, как в заголовке.
    _bytes: [u8; 64],
}

/// `WINDIVERT_DATA_SOCKET` и `WINDIVERT_DATA_FLOW` — одна и та же форма.
///
/// Адреса драйвер кладёт в сетевом порядке байт, а **порты — в порядке
/// узла**. Это легко перепутать: порядок разный внутри одной структуры.
/// Проверено наблюдением: обращение к веб-серверу приходит как 80, к
/// службе имён — как 53, без всякой перестановки байт.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SocketData {
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

/// `WINDIVERT_DATA_NETWORK` — через какой интерфейс пришёл или уйдёт пакет.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkData {
    pub interface_index: u32,
    pub sub_interface_index: u32,
}

impl Address {
    pub fn layer(&self) -> u8 {
        (self.bits & 0xFF) as u8
    }

    pub fn event(&self) -> u8 {
        ((self.bits >> 8) & 0xFF) as u8
    }

    pub fn outbound(&self) -> bool {
        self.bits >> 17 & 1 == 1
    }

    pub fn loopback(&self) -> bool {
        self.bits >> 18 & 1 == 1
    }

    /// Пакет подсунут кем-то через WinDivert, а не пришёл из сети. Наш
    /// собственный реинжект возвращается именно таким, и это главный
    /// признак, по которому можно не обработать его второй раз.
    pub fn impostor(&self) -> bool {
        self.bits >> 19 & 1 == 1
    }

    pub fn ipv6(&self) -> bool {
        self.bits >> 20 & 1 == 1
    }

    /// Сведения о соединении — только для слоёв, где они есть. Вариант
    /// объединения выбирает поле `layer`, а не догадка вызывающего.
    pub fn socket(&self) -> Option<&SocketData> {
        matches!(self.layer(), LAYER_SOCKET | LAYER_FLOW).then(|| unsafe { &self.payload.socket })
    }

    /// Интерфейс — только для слоя пакетов.
    pub fn interface(&self) -> Option<NetworkData> {
        (self.layer() == LAYER_NETWORK).then(|| unsafe { self.payload.network })
    }

    /// Куда отправить пакет обратно. Для входящего пакета это существенно:
    /// при строгой модели узла пакет, отданный не на тот интерфейс, будет
    /// отброшен стеком.
    pub fn set_interface(&mut self, index: u32, sub_index: u32) {
        self.payload.network = NetworkData {
            interface_index: index,
            sub_interface_index: sub_index,
        };
    }

    /// Записать сведения о соединении может только драйвер; в тестах —
    /// проверка разбора, поэтому доступ к записи есть, но только там.
    #[cfg(test)]
    fn socket_mut(&mut self) -> &mut SocketData {
        unsafe { &mut self.payload.socket }
    }

    /// Удалённый адрес соединения. Для IPv4 драйвер кладёт его в первое
    /// слово четвёрки, в сетевом порядке байт.
    pub fn remote(&self) -> IpAddr {
        let Some(socket) = self.socket() else {
            return IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        };
        words_to_address(&socket.remote_addr, self.ipv6())
    }

    /// Местный адрес соединения.
    pub fn local(&self) -> IpAddr {
        let Some(socket) = self.socket() else {
            return IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        };
        words_to_address(&socket.local_addr, self.ipv6())
    }
}

fn words_to_address(words: &[u32; 4], ipv6: bool) -> IpAddr {
    if ipv6 {
        let mut octets = [0u8; 16];
        for (i, word) in words.iter().enumerate() {
            octets[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        IpAddr::V4(Ipv4Addr::from(words[0].to_be_bytes()))
    }
}

/// Сколько отсчётов `Address::timestamp` в секунде.
///
/// Драйвер ставит метку счётчиком высокого разрешения в момент события в
/// ядре — то есть до того, как событие попало в очередь к нам. Сравнивать
/// два события по этим меткам честнее, чем по времени, когда их прочитал
/// наш поток: второе зависит от планировщика.
pub fn ticks_per_second() -> i64 {
    let mut frequency = 0i64;
    unsafe {
        windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency);
    }
    frequency.max(1)
}

pub fn describe_event(event: u8) -> &'static str {
    match event {
        EVENT_ESTABLISHED => "поток открыт",
        EVENT_DELETED => "поток закрыт",
        EVENT_BIND => "bind",
        EVENT_CONNECT => "connect",
        EVENT_LISTEN => "listen",
        EVENT_ACCEPT => "accept",
        EVENT_CLOSE => "close",
        _ => "?",
    }
}

pub fn describe_protocol(protocol: u8) -> &'static str {
    match protocol {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "?",
    }
}

/// Загружает `WinDivert.dll` рядом с собой. Повторный вызов ничего не делает.
fn load() -> Result<(), String> {
    if OPEN.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| format!("не найден свой путь: {e}"))?;
    let dll = exe.with_file_name("WinDivert.dll");
    if !dll.exists() {
        return Err(format!("рядом нет WinDivert.dll: {}", dll.display()));
    }
    let wide: Vec<u16> = wide(&dll);
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    if module.is_null() {
        return Err(format!("WinDivert.dll не загрузилась (код {})", unsafe {
            GetLastError()
        }));
    }
    for (name, slot) in [
        (c"WinDivertOpen", &OPEN),
        (c"WinDivertRecv", &RECV),
        (c"WinDivertSend", &SEND),
        (c"WinDivertShutdown", &SHUTDOWN),
        (c"WinDivertHelperCalcChecksums", &CHECKSUM),
        (c"WinDivertHelperCompileFilter", &COMPILE),
    ] {
        let Some(address) = (unsafe { GetProcAddress(module, name.as_ptr() as *const u8) }) else {
            return Err(format!("в WinDivert.dll нет {name:?}"));
        };
        slot.store(address as usize, Ordering::Release);
    }
    Ok(())
}

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Открытая ручка WinDivert.
pub struct Handle {
    handle: HANDLE,
    /// Рабочий режим: пакет, который не отправить обратно, пропадёт.
    intercepting: bool,
}

// Ручка — обычный хэндл ядра, её можно отдать другому потоку.
unsafe impl Send for Handle {}
// И разделить между потоками тоже: разбудить висящий `recv` вызовом
// `shutdown` из соседнего потока — это документированный способ закончить
// наблюдение, а не самодеятельность.
unsafe impl Sync for Handle {}

impl Handle {
    /// Только чтение событий сокетов.
    pub fn sniff_sockets(filter: &str) -> Result<Handle, String> {
        Self::open(filter, LAYER_SOCKET, FLAG_SNIFF | FLAG_RECV_ONLY | FLAG_NO_INSTALL)
    }

    /// Только чтение событий потоков: открытие и закрытие, с полной
    /// пятёркой и номером процесса.
    pub fn sniff_flows(filter: &str) -> Result<Handle, String> {
        Self::open(filter, LAYER_FLOW, FLAG_SNIFF | FLAG_RECV_ONLY | FLAG_NO_INSTALL)
    }

    /// Только чтение пакетов: копии приходят нам, а сами пакеты идут своей
    /// дорогой. Для замеров это единственный безопасный способ смотреть на
    /// слой пакетов — забыть отправить обратно здесь нечего.
    pub fn sniff_network(filter: &str) -> Result<Handle, String> {
        Self::open(filter, LAYER_NETWORK, FLAG_SNIFF | FLAG_RECV_ONLY | FLAG_NO_INSTALL)
    }

    /// Рабочий режим на слое пакетов: что пришло — исчезло из сети, пока не
    /// отправлено обратно. Фильтр должен быть узким.
    pub fn intercept_network(filter: &str) -> Result<Handle, String> {
        Self::open(filter, LAYER_NETWORK, FLAG_NO_INSTALL)
    }

    fn open(filter: &str, layer: u8, flags: u64) -> Result<Handle, String> {
        load()?;
        let open: OpenFn = unsafe { std::mem::transmute(OPEN.load(Ordering::Acquire)) };
        let filter = std::ffi::CString::new(filter).map_err(|_| "фильтр с нулём внутри")?;
        let handle = unsafe { open(filter.as_ptr() as *const u8, layer as u32, 0, flags) };
        if handle == INVALID_HANDLE_VALUE {
            let code = unsafe { GetLastError() };
            return Err(describe_open(code));
        }
        Ok(Handle {
            handle,
            intercepting: flags & FLAG_SNIFF == 0,
        })
    }

    /// Следующее событие без пакета — для слоёв FLOW и SOCKET.
    /// Блокируется, пока событие не придёт или пока ручку не закроют.
    /// `Err` несёт код ошибки: 232 (`ERROR_NO_DATA`) — это нормальный
    /// конец, ручку закрыли.
    pub fn next(&self) -> Result<Address, u32> {
        let recv: RecvFn = unsafe { std::mem::transmute(RECV.load(Ordering::Acquire)) };
        let mut address: Address = unsafe { std::mem::zeroed() };
        let mut length = 0u32;
        let ok = unsafe {
            recv(
                self.handle,
                std::ptr::null_mut(),
                0,
                &mut length,
                &mut address,
            )
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok(address)
    }

    /// Следующий пакет. Возвращает его длину в переданном буфере.
    pub fn next_packet(&self, buffer: &mut [u8]) -> Result<(usize, Address), u32> {
        let recv: RecvFn = unsafe { std::mem::transmute(RECV.load(Ordering::Acquire)) };
        let mut address: Address = unsafe { std::mem::zeroed() };
        let mut length = 0u32;
        let ok = unsafe {
            recv(
                self.handle,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut length,
                &mut address,
            )
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok((length as usize, address))
    }

    /// Отправляет пакет обратно в сеть. Для перехваченного пакета это
    /// обязательно: иначе он просто не дойдёт.
    pub fn send(&self, packet: &[u8], address: &Address) -> Result<(), u32> {
        let send: SendFn = unsafe { std::mem::transmute(SEND.load(Ordering::Acquire)) };
        let mut sent = 0u32;
        let ok = unsafe {
            send(
                self.handle,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                &mut sent,
                address,
            )
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        Ok(())
    }

    /// Закрывает приём и будит поток, висящий в `next`. Отправка остаётся
    /// живой: перехваченный пакет, который мы ещё держим в руках, надо
    /// успеть вернуть в сеть, иначе он пропадёт.
    pub fn stop(&self) {
        self.shutdown(SHUTDOWN_RECV);
    }

    /// Закрывает и приём, и отправку. Нужно только как последнее средство:
    /// пакеты, не отправленные к этому моменту, пропадут.
    pub fn stop_hard(&self) {
        self.shutdown(SHUTDOWN_BOTH);
    }

    fn shutdown(&self, how: u32) {
        let shutdown: ShutdownFn = unsafe { std::mem::transmute(SHUTDOWN.load(Ordering::Acquire)) };
        unsafe { shutdown(self.handle, how) };
    }

    /// Рабочая ли это ручка. Нужно одному: не дать перехватывающей ручке
    /// незаметно проглотить пакет.
    pub fn intercepting(&self) -> bool {
        self.intercepting
    }
}

/// Примет ли WinDivert такой фильтр. Проверка идёт целиком в
/// пользовательском режиме: драйвер не нужен, права администратора не
/// нужны, ручка не открывается.
///
/// Нужна для перенаправления: фильтр там перечисляет нынешние потоки, и
/// знать, сколько их влезет, надо до того, как от этого числа начнёт
/// зависеть работа.
pub fn check_filter(filter: &str, layer: u8) -> Result<(), String> {
    load()?;
    let compile: CompileFn = unsafe { std::mem::transmute(COMPILE.load(Ordering::Acquire)) };
    let text = std::ffi::CString::new(filter).map_err(|_| "фильтр с нулём внутри")?;
    let mut message: *const u8 = std::ptr::null();
    let mut position = 0u32;
    let ok = unsafe {
        compile(
            text.as_ptr() as *const u8,
            layer as u32,
            std::ptr::null_mut(),
            0,
            &mut message,
            &mut position,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let reason = if message.is_null() {
        "причина не названа".to_owned()
    } else {
        let bytes = unsafe { std::ffi::CStr::from_ptr(message as *const i8) };
        bytes.to_string_lossy().into_owned()
    };
    Err(format!("{reason} (знак {position})"))
}

/// Пересчитывает контрольные суммы после правки заголовков. Своей
/// арифметики тут нет намеренно: в библиотеке она уже есть и проверена.
pub fn fix_checksums(packet: &mut [u8], address: &Address) -> bool {
    let calc: ChecksumFn = unsafe { std::mem::transmute(CHECKSUM.load(Ordering::Acquire)) };
    if calc as usize == 0 {
        return false;
    }
    let ok = unsafe {
        calc(
            packet.as_mut_ptr() as *mut c_void,
            packet.len() as u32,
            address,
            0,
        )
    };
    ok != 0
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.stop();
        unsafe { CloseHandle(self.handle) };
    }
}

fn describe_open(code: u32) -> String {
    match code {
        2 => "драйвер WinDivert не загружен. Своей копии мы не ставим: \
              открываем только уже работающий"
            .to_owned(),
        5 => "отказано в доступе — WinDivert открывается только из-под SYSTEM \
              или администратора"
            .to_owned(),
        87 => "WinDivert не принял фильтр".to_owned(),
        577 => "подпись драйвера отклонена (так выглядит отказ при включённой \
                проверке целостности памяти)"
            .to_owned(),
        other => format!("WinDivertOpen вернул код {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_layout_matches_the_header() {
        // WINDIVERT_ADDRESS: 8 байт времени, 4 байта флагов, 4 байта запаса
        // и объединение на 64 байта. Если размер уедет, драйвер запишет
        // событие мимо наших полей.
        assert_eq!(std::mem::size_of::<Address>(), 80);
        assert_eq!(std::mem::size_of::<Payload>(), 64);
        assert_eq!(std::mem::align_of::<Address>(), 8);
    }

    #[test]
    fn bits_are_unpacked_in_the_right_order() {
        let mut address: Address = unsafe { std::mem::zeroed() };
        // слой 3 (SOCKET), событие 4 (CONNECT), outbound
        address.bits = 3 | (4 << 8) | (1 << 17);
        assert_eq!(address.layer(), LAYER_SOCKET);
        assert_eq!(address.event(), EVENT_CONNECT);
        assert!(address.outbound());
        assert!(!address.loopback());
        assert!(!address.impostor());
        assert!(!address.ipv6());
    }

    #[test]
    fn impostor_marks_our_own_reinjected_packet() {
        let mut address: Address = unsafe { std::mem::zeroed() };
        address.bits = (1 << 19) | (1 << 17);
        assert!(address.impostor());
    }

    #[test]
    fn the_layer_decides_which_variant_is_readable() {
        let mut address: Address = unsafe { std::mem::zeroed() };
        address.bits = LAYER_NETWORK as u32;
        address.set_interface(8, 1);
        // На слое пакетов читается интерфейс и не читается соединение.
        assert_eq!(
            address.interface(),
            Some(NetworkData { interface_index: 8, sub_interface_index: 1 })
        );
        assert!(address.socket().is_none());

        let mut address: Address = unsafe { std::mem::zeroed() };
        address.bits = LAYER_FLOW as u32;
        assert!(address.socket().is_some());
        assert!(address.interface().is_none());
    }

    #[test]
    fn ipv4_is_read_from_the_first_word() {
        let mut address: Address = unsafe { std::mem::zeroed() };
        address.bits = LAYER_SOCKET as u32;
        address.socket_mut().remote_addr[0] = u32::from_be_bytes([93, 184, 216, 34]);
        address.socket_mut().local_addr[0] = u32::from_be_bytes([10, 5, 5, 2]);
        assert_eq!(address.remote(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(address.local(), IpAddr::V4(Ipv4Addr::new(10, 5, 5, 2)));
    }

    #[test]
    fn ipv6_is_collected_from_four_words() {
        let mut address: Address = unsafe { std::mem::zeroed() };
        address.bits = LAYER_SOCKET as u32 | (1 << 20); // ipv6
        let expected: Ipv6Addr = "2001:db8::1".parse().unwrap();
        for (i, chunk) in expected.octets().chunks(4).enumerate() {
            address.socket_mut().remote_addr[i] =
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        assert_eq!(address.remote(), IpAddr::V6(expected));
    }

    #[test]
    fn events_and_protocols_have_names() {
        assert_eq!(describe_event(EVENT_CONNECT), "connect");
        assert_eq!(describe_event(EVENT_ESTABLISHED), "поток открыт");
        assert_eq!(describe_protocol(6), "tcp");
        assert_eq!(describe_protocol(200), "?");
    }

    #[test]
    fn open_errors_are_explained() {
        assert!(describe_open(5).contains("SYSTEM"));
        assert!(describe_open(577).contains("целостности"));
        assert!(describe_open(12345).contains("12345"));
    }
}

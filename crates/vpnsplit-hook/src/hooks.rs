//! Перехваты: сокеты, имена и создание процессов.

use crate::{dns, hosts, log, BOUND, IFINDEX, SELF_PATH};
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use vpnsplit_core::hook::status;
use vpnsplit_core::InterfaceIndex;
use windows_sys::Win32::Foundation::{
    GetLastError, SetLastError, DNS_ERROR_RCODE_NAME_ERROR, DNS_INFO_NO_RECORDS, ERROR_OUTOFMEMORY,
    ERROR_TIMEOUT, HANDLE,
};
use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_ACP};
use windows_sys::Win32::NetworkManagement::Dns::{
    DnsCharSetAnsi, DnsCharSetUnicode, DnsCharSetUtf8, DnsSectionAnswer, DNS_QUERY_NO_HOSTS_FILE,
    DNS_QUERY_NO_WIRE_QUERY, DNS_RECORDW, DNS_RECORDW_0, DNS_TYPE_A, DNS_TYPE_AAAA,
};
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, WSASetLastError, ADDRINFOA, ADDRINFOEX2A, ADDRINFOEX2W,
    ADDRINFOEX3, ADDRINFOEX4, ADDRINFOEX5, ADDRINFOEX6, ADDRINFOEXA, ADDRINFOEXW,
    ADDRINFOEX_VERSION_2, ADDRINFOEX_VERSION_3, ADDRINFOEX_VERSION_4, ADDRINFOEX_VERSION_5,
    ADDRINFOEX_VERSION_6, ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC, AI_CANONNAME, AI_EXTENDED,
    AI_FQDN, AI_NUMERICHOST, AI_V4MAPPED, HOSTENT, INVALID_SOCKET, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
    IP_UNICAST_IF, NS_ALL, NS_DNS, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET, SOCKET_ERROR,
    WSAENETUNREACH, WSAHOST_NOT_FOUND, WSANO_DATA, WSAPROTOCOL_INFOW, WSATRY_AGAIN,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Threading::{
    ResumeThread, CREATE_SUSPENDED, DEBUG_ONLY_THIS_PROCESS, DEBUG_PROCESS, PROCESS_INFORMATION,
};

static ORIG_WSASOCKETW: AtomicUsize = AtomicUsize::new(0);
static ORIG_SOCKET: AtomicUsize = AtomicUsize::new(0);
static ORIG_BIND: AtomicUsize = AtomicUsize::new(0);
static ORIG_CONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSACONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_PROCESS: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETADDRINFOW: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETADDRINFOA: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETADDRINFOEXW: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETADDRINFOEXA: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETHOSTBYNAME: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSACONNECTBYNAMEW: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSACONNECTBYNAMEA: AtomicUsize = AtomicUsize::new(0);
static ORIG_DNSQUERY_W: AtomicUsize = AtomicUsize::new(0);
static ORIG_DNSQUERY_A: AtomicUsize = AtomicUsize::new(0);
static ORIG_DNSQUERY_UTF8: AtomicUsize = AtomicUsize::new(0);

type WsaSocketWFn = unsafe extern "system" fn(i32, i32, i32, *const WSAPROTOCOL_INFOW, u32, u32) -> SOCKET;
type SocketFn = unsafe extern "system" fn(i32, i32, i32) -> SOCKET;
/// Общая сигнатура `bind` и `connect`.
type AddrFn = unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;
/// `WSAConnect`. QoS и данные вызова объявлены сырыми указателями: мы их
/// не читаем, а по ABI это то же самое.
type WsaConnectFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const c_void,
    *mut c_void,
    *const c_void,
    *const c_void,
) -> i32;

type GetAddrInfoWFn = unsafe extern "system" fn(
    *const u16,
    *const u16,
    *const ADDRINFOW,
    *mut *mut ADDRINFOW,
) -> i32;
type GetAddrInfoAFn = unsafe extern "system" fn(
    *const u8,
    *const u8,
    *const ADDRINFOA,
    *mut *mut ADDRINFOA,
) -> i32;
/// `GetAddrInfoExW`. Пространство имён, OVERLAPPED, время ожидания и
/// процедура завершения объявлены сырыми указателями: по ABI это то же самое.
type GetAddrInfoExWFn = unsafe extern "system" fn(
    *const u16,
    *const u16,
    u32,
    *const c_void,
    *const ADDRINFOEXW,
    *mut *mut ADDRINFOEXW,
    *const c_void,
    *const c_void,
    *const c_void,
    *mut HANDLE,
) -> i32;
type GetAddrInfoExAFn = unsafe extern "system" fn(
    *const u8,
    *const u8,
    u32,
    *const c_void,
    *const ADDRINFOEXA,
    *mut *mut ADDRINFOEXA,
    *const c_void,
    *const c_void,
    *const c_void,
    *mut HANDLE,
) -> i32;
type GetHostByNameFn = unsafe extern "system" fn(*const u8) -> *mut HOSTENT;
type WsaConnectByNameWFn = unsafe extern "system" fn(
    SOCKET,
    *const u16,
    *const u16,
    *mut u32,
    *mut SOCKADDR,
    *mut u32,
    *mut SOCKADDR,
    *const c_void,
    *const c_void,
) -> i32;
type WsaConnectByNameAFn = unsafe extern "system" fn(
    SOCKET,
    *const u8,
    *const u8,
    *mut u32,
    *mut SOCKADDR,
    *mut u32,
    *mut SOCKADDR,
    *const c_void,
    *const c_void,
) -> i32;
/// `DnsQuery_W`. Результат — список `DNS_RECORD`, здесь просто указатель.
type DnsQueryWFn =
    unsafe extern "system" fn(*const u16, u16, u32, *mut c_void, *mut *mut c_void, *mut *mut c_void) -> u32;
/// `DnsQuery_A` и `DnsQuery_UTF8`: отличаются только кодировкой строк.
type DnsQueryAFn =
    unsafe extern "system" fn(*const u8, u16, u32, *mut c_void, *mut *mut c_void, *mut *mut c_void) -> u32;

/// `CreateProcessInternalW` из kernelbase. Не документирована, но сигнатура
/// стабильна с Windows XP: через неё проходят и `CreateProcessW`, и
/// `CreateProcessAsUserW`, которой Chromium создаёт процессы-песочницы.
type CreateProcessInternalWFn = unsafe extern "system" fn(
    token: HANDLE,
    application: *const u16,
    command_line: *mut u16,
    process_attrs: *const c_void,
    thread_attrs: *const c_void,
    inherit_handles: i32,
    flags: u32,
    environment: *const c_void,
    current_dir: *const u16,
    startup_info: *const c_void,
    process_info: *mut PROCESS_INFORMATION,
    restricted_token: *mut HANDLE,
) -> i32;

fn proc_addr(module: *mut c_void, name: &std::ffi::CStr) -> Option<*mut c_void> {
    unsafe { GetProcAddress(module, name.as_ptr() as *const u8) }.map(|f| f as *mut c_void)
}

unsafe fn hook(target: *mut c_void, detour: *mut c_void, slot: &AtomicUsize) -> bool {
    match minhook::MinHook::create_hook(target, detour) {
        Ok(original) => {
            slot.store(original as usize, Ordering::SeqCst);
            true
        }
        Err(_) => false,
    }
}

/// Ставит все хуки. Вызывается из отдельного потока, а не из DllMain,
/// поэтому загрузка библиотек здесь безопасна.
pub fn install(index: u32) -> u32 {
    let ws2 = unsafe { LoadLibraryA(c"ws2_32.dll".as_ptr() as *const u8) };
    if ws2.is_null() {
        return status::NO_WS2;
    }
    let sockets = [
        (c"WSASocketW", hook_wsasocketw as *mut c_void, &ORIG_WSASOCKETW),
        // socket() может вызывать WSASocketW внутри, а может и нет. Ставить
        // опцию дважды безвредно, поэтому хукаем обе.
        (c"socket", hook_socket as *mut c_void, &ORIG_SOCKET),
        (c"bind", hook_bind as *mut c_void, &ORIG_BIND),
        (c"connect", hook_connect as *mut c_void, &ORIG_CONNECT),
        (c"WSAConnect", hook_wsaconnect as *mut c_void, &ORIG_WSACONNECT),
        // Имена: без этого приложение идёт через VPN, а резолвит через
        // домашний роутер. ANSI-вариант хукается отдельно, потому что
        // внутрь него мы не заглядываем и полагаться на то, что он зовёт
        // широкий, не хотим.
        (c"GetAddrInfoW", hook_getaddrinfow as *mut c_void, &ORIG_GETADDRINFOW),
        (c"getaddrinfo", hook_getaddrinfoa as *mut c_void, &ORIG_GETADDRINFOA),
    ];
    let mut targets = Vec::with_capacity(sockets.len());
    for (name, detour, slot) in sockets {
        let Some(target) = proc_addr(ws2, name) else {
            return status::NO_EXPORT;
        };
        targets.push((target, detour, slot));
    }

    // Индекс публикуется до включения хуков: первый же перехваченный вызов
    // должен его увидеть.
    IFINDEX.store(index, Ordering::SeqCst);

    let mut mandatory = Vec::with_capacity(targets.len());
    for (target, detour, slot) in targets {
        if !unsafe { hook(target, detour, slot) } {
            IFINDEX.store(0, Ordering::SeqCst);
            return status::CREATE_HOOK;
        }
        mandatory.push(target);
    }

    let mut optional = Vec::new();
    install_names(ws2, &mut optional);

    // Потомки — не обязательная часть: без неё однопроцессные приложения
    // всё равно работают, поэтому сбой здесь только пишется в журнал.
    let kernelbase = unsafe { LoadLibraryA(c"kernelbase.dll".as_ptr() as *const u8) };
    match (!kernelbase.is_null()).then(|| proc_addr(kernelbase, c"CreateProcessInternalW")).flatten() {
        Some(target) => {
            if unsafe { hook(target, hook_create_process as *mut c_void, &ORIG_CREATE_PROCESS) } {
                optional.push((target, "потомки: kernelbase!CreateProcessInternalW".to_owned()));
            } else {
                log::write("потомки: не удалось перехватить CreateProcessInternalW");
            }
        }
        None => log::write("потомки: в kernelbase нет CreateProcessInternalW"),
    }

    // Обязательные хуки включаются разом и отдельно от необязательных:
    // сбой включения любого из необязательных не должен выключать привязку
    // сокетов и kill-switch для всего процесса.
    let queued = mandatory.iter().all(|&target| unsafe { minhook::MinHook::queue_enable_hook(target) }.is_ok());
    if !queued || unsafe { minhook::MinHook::apply_queued() }.is_err() {
        IFINDEX.store(0, Ordering::SeqCst);
        return status::ENABLE_HOOK;
    }
    for (target, what) in optional {
        if unsafe { minhook::MinHook::enable_hook(target) }.is_err() {
            log::write(&format!("{what}: перехват не включился — этот путь идёт мимо нас"));
        }
    }
    status::OK
}

/// Остальные способы разрешить имя: без них .NET (`GetAddrInfoExW`),
/// старые программы (`gethostbyname`), `WSAConnectByName` и `DnsQuery_*`
/// спрашивали бы службу DNS Client, а та — домашний роутер, и kill-switch
/// для имён на них не действовал бы. Каждый перехват здесь необязателен:
/// если функции нет или перехват не встал, это пишется в журнал, а
/// остальная защита работает. Созданные перехваты складываются в
/// `optional` и включаются по одному.
///
/// Чего здесь нет, и почему:
/// - `DnsQueryEx`. Её асинхронный вызов пришлось бы завершать самим —
///   вызвать процедуру завершения до возврата из `DnsQueryEx`, — а
///   `DNS_QUERY_REQUEST3` устроена иначе, чем запрос версий 1 и 2. Ошибка
///   здесь ломает приложению разрешение имён целиком, поэтому пока это
///   честно пишется в журнал, а не перехватывается наполовину.
/// - DNS «руками»: UDP через `sendto`/`WSASendTo` без `connect` и TCP через
///   `ConnectEx`. Такие сокеты привязаны к туннелю, как все, но запрос к
///   DNS-серверу своей сети отклоняется только на `connect`/`WSAConnect`.
fn install_names(ws2: *mut c_void, optional: &mut Vec<(*mut c_void, String)>) {
    log::write(
        "dns: не перехвачены DnsQueryEx, DnsQuery_* с типами кроме A/AAAA или с pExtra, \
         DNS через sendto/WSASendTo и ConnectEx — имена через них идут мимо туннеля",
    );

    // Настройки DNS адаптера туннеля (зоны VPN и его серверы) читаются
    // через iphlpapi. Без неё внутренние имена VPN не разрешатся, а
    // остальное работает.
    let iphlpapi = unsafe { LoadLibraryA(c"iphlpapi.dll".as_ptr() as *const u8) };
    match (!iphlpapi.is_null()).then(|| proc_addr(iphlpapi, c"GetAdaptersAddresses")).flatten() {
        Some(function) => dns::GET_ADAPTERS.store(function as usize, Ordering::Release),
        None => log::write("dns: нет GetAdaptersAddresses — внутренние зоны VPN разрешаться не будут"),
    }

    // Перевод международных имён в punycode. Без него такие имена
    // получают «нет такого имени» — но к системе всё равно не уходят.
    let idn = [c"kernel32.dll", c"normaliz.dll"].iter().find_map(|dll| {
        let module = unsafe { LoadLibraryA(dll.as_ptr() as *const u8) };
        (!module.is_null()).then(|| proc_addr(module, c"IdnToAscii")).flatten()
    });
    match idn {
        Some(function) => IDN_TO_ASCII.store(function as usize, Ordering::Release),
        None => log::write("dns: нет IdnToAscii — международные имена разрешаться не будут"),
    }

    let names = [
        (c"GetAddrInfoExW", hook_getaddrinfoexw as *mut c_void, &ORIG_GETADDRINFOEXW),
        (c"GetAddrInfoExA", hook_getaddrinfoexa as *mut c_void, &ORIG_GETADDRINFOEXA),
        (c"gethostbyname", hook_gethostbyname as *mut c_void, &ORIG_GETHOSTBYNAME),
        (c"WSAConnectByNameW", hook_wsaconnectbynamew as *mut c_void, &ORIG_WSACONNECTBYNAMEW),
        (c"WSAConnectByNameA", hook_wsaconnectbynamea as *mut c_void, &ORIG_WSACONNECTBYNAMEA),
    ];
    hook_optional(ws2, "ws2_32", &names, optional);

    // dnsapi грузим сами: так перехват стоит, даже если приложение подгрузит
    // её позже. Это системная библиотека, и при разрешении имён Winsock
    // обычно загружает её и сам.
    let dnsapi = unsafe { LoadLibraryA(c"dnsapi.dll".as_ptr() as *const u8) };
    if dnsapi.is_null() {
        log::write("dns: dnsapi.dll не загрузилась — DnsQuery не перехвачен");
        return;
    }
    // Без функции копирования отдать приложению запись, которую оно сможет
    // освободить, нечем — и тогда DnsQuery не перехватываем вовсе.
    let Some(copy) = proc_addr(dnsapi, c"DnsRecordSetCopyEx") else {
        log::write("dns: в dnsapi нет DnsRecordSetCopyEx — DnsQuery не перехвачен");
        return;
    };
    DNS_COPY.store(copy as usize, Ordering::Release);
    // DnsQueryEx не перехватывается — почему, сказано в описании функции.
    let queries = [
        (c"DnsQuery_W", hook_dnsquery_w as *mut c_void, &ORIG_DNSQUERY_W),
        (c"DnsQuery_A", hook_dnsquery_a as *mut c_void, &ORIG_DNSQUERY_A),
        (c"DnsQuery_UTF8", hook_dnsquery_utf8 as *mut c_void, &ORIG_DNSQUERY_UTF8),
    ];
    hook_optional(dnsapi, "dnsapi", &queries, optional);
}

fn hook_optional(
    module: *mut c_void,
    dll: &str,
    list: &[(&std::ffi::CStr, *mut c_void, &AtomicUsize)],
    optional: &mut Vec<(*mut c_void, String)>,
) {
    for &(name, detour, slot) in list {
        let name_text = name.to_string_lossy();
        match proc_addr(module, name) {
            Some(target) => {
                if unsafe { hook(target, detour, slot) } {
                    optional.push((target, format!("dns: {dll}!{name_text}")));
                } else {
                    log::write(&format!("dns: не удалось перехватить {dll}!{name_text} — имена через неё идут мимо туннеля"));
                }
            }
            None => log::write(&format!("dns: в {dll} нет {name_text}")),
        }
    }
}

// ---------- создание процессов ----------

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_create_process(
    token: HANDLE,
    application: *const u16,
    command_line: *mut u16,
    process_attrs: *const c_void,
    thread_attrs: *const c_void,
    inherit_handles: i32,
    flags: u32,
    environment: *const c_void,
    current_dir: *const u16,
    startup_info: *const c_void,
    process_info: *mut PROCESS_INFORMATION,
    restricted_token: *mut HANDLE,
) -> i32 {
    let original: CreateProcessInternalWFn =
        std::mem::transmute(ORIG_CREATE_PROCESS.load(Ordering::Acquire));

    // Процесс с отдельным токеном — это песочница (так Chromium создаёт
    // процессы отрисовки, GPU и прочие) или процесс другого пользователя.
    // DLL в него не загрузится из-за прав, а сама попытка опасна: удалённый
    // поток запускает инициализацию процесса раньше, чем песочница успевает
    // его настроить, и процесс падает. Такие процессы не трогаем вовсе.
    //
    // Отлаживаемый процесс (DEBUG_PROCESS / DEBUG_ONLY_THIS_PROCESS) тоже:
    // его события отладки — создание удалённого потока, загрузка DLL —
    // доставляются этому же потоку, а он сам ждал бы удалённый LoadLibraryW.
    // Взаимная блокировка до таймаута, а потом падение потомка.
    let debugged = flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS) != 0;
    if !token.is_null() || debugged {
        let ok = original(
            token,
            application,
            command_line,
            process_attrs,
            thread_attrs,
            inherit_handles,
            flags,
            environment,
            current_dir,
            startup_info,
            process_info,
            restricted_token,
        );
        if ok != 0 && !process_info.is_null() {
            let saved_error = GetLastError();
            let why = if debugged { "запущен под отладчиком" } else { "отдельный токен (песочница)" };
            log::write(&format!("потомок pid {}: пропущен — {why}", (*process_info).dwProcessId));
            SetLastError(saved_error);
        }
        return ok;
    }

    // Ребёнок всегда создаётся приостановленным, чтобы успеть поставить хуки
    // до его первого сокета. Если вызывающий сам просил suspended (так делает
    // песочница Chromium), возобновлять не нам.
    let caller_wants_suspended = flags & CREATE_SUSPENDED != 0;
    let ok = original(
        token,
        application,
        command_line,
        process_attrs,
        thread_attrs,
        inherit_handles,
        flags | CREATE_SUSPENDED,
        environment,
        current_dir,
        startup_info,
        process_info,
        restricted_token,
    );
    if ok == 0 || process_info.is_null() {
        return ok;
    }

    let saved_error = GetLastError();
    let info = &*process_info;
    let _ = catch_unwind(AssertUnwindSafe(|| attach_child(info)));
    if !caller_wants_suspended {
        ResumeThread(info.hThread);
    }
    SetLastError(saved_error);
    ok
}

/// Внедряет hook.dll в ребёнка. При неудаче ребёнок всё равно запускается:
/// убить, например, процесс отрисовки браузера значит сломать браузер
/// целиком. Это осознанный «отказ в открытую» — закрывается kill-switch'ем
/// на Этапе 9.
fn attach_child(info: &PROCESS_INFORMATION) {
    let index = IFINDEX.load(Ordering::Relaxed);
    let Some(dll) = SELF_PATH.get() else {
        log::write("потомки: свой путь неизвестен, внедрение невозможно");
        return;
    };
    match vpnsplit_inject::inject(info.hProcess, dll, index) {
        Ok(()) => log::write(&format!("потомок pid {}: хуки установлены", info.dwProcessId)),
        Err(err) => log::write(&format!("потомок pid {}: НЕ внедрено — {err}", info.dwProcessId)),
    }
}

// ---------- имена ----------

/// Чем ответить приложению, если адреса нет.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// Такого имени нет: NXDOMAIN или имя, которое нельзя записать в DNS.
    NoName,
    /// Имя есть, адресов нужного семейства нет.
    NoData,
    /// Ответа нет: серверы молчат или туннеля больше нет. Отдать имя
    /// системе значит отправить его домашнему роутеру, поэтому приложение
    /// получает «попробуйте позже», а не утечку.
    TryAgain,
}

impl Failure {
    /// Код для `getaddrinfo`, `gethostbyname` и `WSAConnectByName`.
    fn wsa(self) -> i32 {
        match self {
            Failure::NoName => WSAHOST_NOT_FOUND,
            Failure::NoData => WSANO_DATA,
            Failure::TryAgain => WSATRY_AGAIN,
        }
    }

    /// Код для `DnsQuery_*`.
    fn dns(self) -> u32 {
        match self {
            Failure::NoName => DNS_ERROR_RCODE_NAME_ERROR,
            Failure::NoData => DNS_INFO_NO_RECORDS as u32,
            Failure::TryAgain => ERROR_TIMEOUT,
        }
    }
}

/// Как поступить с запросом имени.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Не наше дело — зовём оригинал как есть.
    PassThrough,
    /// Разрешили сами (через туннель или из hosts), подставляем адрес.
    Replace(IpAddr),
    /// Отвечаем сами, что адреса нет. К системе имя не попадает.
    Fail(Failure),
}

/// Имя, которое разрешаем сами, или `None` — его отдаём системе.
///
/// Системе остаются только имена, которые публичному резолверу всё равно
/// неизвестны и живут в своей сети: без точки (NetBIOS, суффиксы
/// домена), `.local` и прочие домашние суффиксы, домен Active Directory.
/// И то, что именем не является: числовые адреса.
fn tunnel_name(host: &str, family: i32, numeric: bool) -> Option<&str> {
    // Приложение само сказало «это число» — значит, имени здесь и нет.
    if numeric {
        return None;
    }
    // Не IP (Bluetooth, Hyper-V…): DNS тут ни при чём.
    if family != AF_UNSPEC as i32 && family != AF_INET as i32 && family != AF_INET6 as i32 {
        return None;
    }
    let name = host.trim();
    if name.is_empty() {
        return None;
    }
    // Уже адрес — разрешать нечего.
    if name.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return None;
    }
    let bare = name.trim_end_matches('.');
    if !bare.contains('.') {
        return None;
    }
    // Последняя метка — число: это адрес в нестандартной записи вроде
    // `127.1` или `0x7f.1`. Таких доменов верхнего уровня не бывает, а
    // система разберёт число сама, без сети.
    let last = bare.rsplit('.').next().unwrap_or("");
    let hex = last.get(..2).is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"));
    if hex || (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    if dns::is_local_name(name) {
        return None;
    }
    Some(name)
}

/// Имя из домена пользователя (Active Directory). Такие имена сначала
/// спрашиваются через туннель: домен AD нередко совпадает с публичным
/// доменом компании (`acme.com`), и отдать их системе целиком значило бы
/// слить мимо туннеля всё `*.acme.com`. Системе — только если ни один
/// сервер туннеля имени не знает (`dns::Mode::Unanimous`).
fn in_user_domain(name: &str, domain: Option<&str>) -> bool {
    domain.is_some_and(|domain| dns::is_under(name, domain))
}

/// DNS-домен пользователя: имена в нём разрешает контроллер домена.
fn user_domain() -> Option<&'static str> {
    static DOMAIN: OnceLock<Option<String>> = OnceLock::new();
    DOMAIN
        .get_or_init(|| {
            std::env::var("USERDNSDOMAIN")
                .ok()
                .map(|domain| domain.trim().to_owned())
                .filter(|domain| !domain.is_empty())
        })
        .as_deref()
}

/// Точки, которые IDN приравнивает к обычной: «。» (U+3002), «．» (U+FF0E)
/// и «｡» (U+FF61). Без замены «例え。テスト» выглядело бы именем без точки и
/// ушло бы системе, а та сама превратила бы их в точки и спросила роутер.
fn ascii_dots(host: &str) -> std::borrow::Cow<'_, str> {
    let is_dot = |c: char| matches!(c, '\u{3002}' | '\u{FF0E}' | '\u{FF61}');
    if host.contains(is_dot) {
        std::borrow::Cow::Owned(host.replace(is_dot, "."))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

/// Приложение просит AF_INET6, но согласно получить IPv4 в виде
/// `::ffff:a.b.c.d` (`AI_V4MAPPED`) — так работают двухрежимные сокеты.
fn wants_v4_mapped(family: i32, flags: i32) -> bool {
    family == AF_INET6 as i32 && flags as u32 & AI_V4MAPPED != 0
}

/// Какую запись спрашивать первой и какую — если первой у имени нет.
///
/// IPv6 спрашиваем первым, только если его прямо попросили: на этой
/// машине он не маршрутизируется, и адрес AAAA приложению обычно ничего
/// не даст. Но при AF_UNSPEC имя, у которого есть только AAAA, — всё
/// равно существующее имя. А при AF_INET6 с `AI_V4MAPPED` (и `AI_ALL`)
/// имя с одной лишь записью A должно найтись, как нашла бы его система.
fn query_order(family: i32, v4mapped: bool) -> (u16, Option<u16>) {
    if family == AF_INET6 as i32 {
        (dns::TYPE_AAAA, v4mapped.then_some(dns::TYPE_A))
    } else if family == AF_UNSPEC as i32 {
        (dns::TYPE_A, Some(dns::TYPE_AAAA))
    } else {
        (dns::TYPE_A, None)
    }
}

/// Адрес в том виде, в каком его ждёт приложение: при AF_INET6 адрес IPv4
/// возможен только сопоставленным. Оригинал получит `::ffff:a.b.c.d`
/// числом и построит из него `sockaddr_in6` сам.
fn shaped(address: IpAddr, family: i32) -> IpAddr {
    match address {
        IpAddr::V4(v4) if family == AF_INET6 as i32 => IpAddr::V6(v4.to_ipv6_mapped()),
        other => other,
    }
}

/// Поиск в hosts: сначала в punycode, затем как написано. При
/// `AI_V4MAPPED` имя, у которого в hosts только IPv4, тоже находится.
fn hosts_lookup(table: &hosts::Table, ascii: &str, name: &str, family: i32, v4mapped: bool) -> hosts::Hit {
    let find = |family: i32| {
        let hit = table.lookup(ascii, family);
        if hit == hosts::Hit::Miss && ascii != name {
            table.lookup(name, family)
        } else {
            hit
        }
    };
    match find(family) {
        hosts::Hit::OtherFamily if v4mapped => match find(AF_INET as i32) {
            hosts::Hit::Address(address) => hosts::Hit::Address(address),
            _ => hosts::Hit::OtherFamily,
        },
        hit => hit,
    }
}

/// Ответ туннельного резолвера в терминах приложения.
fn verdict(outcome: &dns::Outcome) -> Result<IpAddr, Failure> {
    match outcome {
        dns::Outcome::Found(answer) => Ok(answer.address),
        dns::Outcome::NoName => Err(Failure::NoName),
        dns::Outcome::NoData => Err(Failure::NoData),
        // Раньше здесь имя отдавалось системе. Теперь — нет: молчание
        // всех серверов туннеля (и DNS VPN, и публичных) — не повод
        // спрашивать роутер.
        dns::Outcome::Unavailable | dns::Outcome::TunnelGone => Err(Failure::TryAgain),
    }
}

/// Решает, брать ли имя на себя, и если да — разрешает его: сначала по
/// hosts, затем через туннель.
///
/// Результат отдаётся не структурой `addrinfo`, а адресом: структуру
/// построит сама Windows, когда мы позовём оригинал с этим адресом и
/// флагом `AI_NUMERICHOST`. Иначе её пришлось бы выделять нам, а
/// освобождал бы её `FreeAddrInfoW` — чужим аллокатором по чужим правилам.
/// Поэтому `FreeAddrInfoW`, `FreeAddrInfoExW` и `freeaddrinfo` не
/// перехватываются: всё, что получает приложение, выделила Windows. Цена
/// решения в том, что приложение получает один адрес вместо списка; за
/// ней мы следим, но менять владение памятью в чужом процессе ради второго
/// адреса — плохой размен.
///
/// `flags` — `ai_flags` из подсказок (для остальных API ноль).
fn decide(host: Option<&str>, family: i32, flags: i32, use_hosts: bool) -> Plan {
    let index = IFINDEX.load(Ordering::Relaxed);
    if index == 0 {
        return Plan::PassThrough;
    }
    let Some(host) = host else {
        return Plan::PassThrough;
    };
    let host = ascii_dots(host);
    let Some(name) = tunnel_name(&host, family, is_numeric(flags)) else {
        return Plan::PassThrough;
    };
    let v4mapped = wants_v4_mapped(family, flags);

    // Международное имя (почта.рф) спрашиваем в punycode, как спросила бы
    // и система. Раньше такие имена уходили системе целиком.
    let ascii = if name.is_ascii() {
        name.to_owned()
    } else {
        match to_ascii_name(name) {
            Some(ascii) => ascii,
            None => {
                log::write(&format!("dns: {name} не разрешено — имя не переводится в punycode"));
                return Plan::Fail(Failure::NoName);
            }
        }
    };

    if use_hosts {
        if let Some(table) = hosts::current() {
            match hosts_lookup(&table, &ascii, name, family, v4mapped) {
                hosts::Hit::Address(address) => {
                    let address = shaped(address, family);
                    log::write(&format!("dns: {name} -> {address} (из hosts)"));
                    return Plan::Replace(address);
                }
                hosts::Hit::OtherFamily => {
                    log::write(&format!("dns: {name} есть в hosts, но адреса нужного семейства нет"));
                    return Plan::Fail(Failure::NoData);
                }
                hosts::Hit::Miss => {}
            }
        }
    }

    // Сначала DNS самого VPN, потом публичные — всё через туннель (порядок
    // и что считается окончательным — в описании `dns`). Публичный сервер
    // внутренних имён VPN не знает, а система спросила бы домашний роутер.
    let servers = dns::lookup_servers(index);
    let domain = in_user_domain(&ascii, user_domain());
    let mode = if domain { dns::Mode::Unanimous } else { dns::Mode::First };

    let (first, fallback) = query_order(family, v4mapped);
    let mut outcome = dns::resolve_via(&ascii, first, index, &servers, mode);
    let first_said_no_name = matches!(outcome, dns::Outcome::NoName);
    if let Some(second) = fallback {
        if matches!(outcome, dns::Outcome::NoData) {
            outcome = dns::resolve_via(&ascii, second, index, &servers, mode);
        }
    }

    // Имя домена пользователя, которого не знает DNS туннеля (см.
    // `dns::Mode::Unanimous`), живёт только во внутренней сети домена: его
    // разрешит контроллер домена через систему. Только по первому запросу:
    // если на него было «нет адресов», имя существует, и второй ответ «нет
    // такого» — несогласованность серверов, а не повод идти мимо туннеля.
    if domain && first_said_no_name {
        log::write(&format!("dns: {name} — домен пользователя, DNS туннеля его не знает, отдаём системе"));
        return Plan::PassThrough;
    }

    match (&outcome, verdict(&outcome)) {
        (dns::Outcome::Found(answer), _) => {
            let address = shaped(answer.address, family);
            log::write(&format!(
                "dns: {name} -> {address} (с адреса {}, сервер {}, {} мс)",
                answer.source.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
                answer.server,
                answer.millis
            ));
            Plan::Replace(address)
        }
        (dns::Outcome::TunnelGone, Err(failure)) => {
            log::write(&format!("dns: {name} не разрешено — туннеля нет"));
            Plan::Fail(failure)
        }
        (dns::Outcome::Unavailable, Err(failure)) => {
            log::write(&format!("dns: {name} не разрешено — серверы не ответили, системе не отдаём"));
            Plan::Fail(failure)
        }
        (_, Err(failure)) => {
            log::write(&format!("dns: {name} — адреса нет ({failure:?}), системе не отдаём"));
            Plan::Fail(failure)
        }
        // Found уже разобран выше, а verdict даёт Ok только для него.
        (_, Ok(address)) => Plan::Replace(shaped(address, family)),
    }
}

/// Флаги для вызова оригинала с готовым адресом.
fn numeric_flags(flags: i32) -> i32 {
    // Канонического имени у числа нет, а просьба его вернуть сделала бы
    // ещё один запрос — уже системный.
    (flags | AI_NUMERICHOST as i32) & !(AI_CANONNAME as i32 | AI_FQDN as i32)
}

fn is_numeric(flags: i32) -> bool {
    flags & AI_NUMERICHOST as i32 != 0
}

fn wide_address(address: IpAddr) -> Vec<u16> {
    address.to_string().encode_utf16().chain(std::iter::once(0)).collect()
}

fn narrow_address(address: IpAddr) -> Vec<u8> {
    address.to_string().bytes().chain(std::iter::once(0)).collect()
}

/// Ответ «адреса нет» для семейства getaddrinfo. Код дублируется в
/// `WSAGetLastError`, как это делает сама Windows.
unsafe fn fail_addrinfo<T>(failure: Failure, result: *mut *mut T) -> i32 {
    if !result.is_null() {
        *result = std::ptr::null_mut();
    }
    let code = failure.wsa();
    WSASetLastError(code);
    code
}

// ----- строки из чужого процесса -----

/// Длина строки, если она не длиннее разумного. Имя в DNS не бывает
/// длиннее 253 знаков, так что 1024 — с большим запасом.
unsafe fn bounded_len<T: Copy + PartialEq + Default>(text: *const T) -> Option<usize> {
    if text.is_null() {
        return None;
    }
    let mut len = 0;
    while *text.add(len) != T::default() {
        len += 1;
        if len > 1024 {
            return None;
        }
    }
    Some(len)
}

unsafe fn wide_to_string(text: *const u16) -> Option<String> {
    let len = bounded_len(text)?;
    String::from_utf16(std::slice::from_raw_parts(text, len)).ok()
}

/// ANSI-строка в кодовой странице системы. Не-ASCII имя раньше уходило
/// системе как есть; теперь оно переводится в Unicode, а оттуда — в
/// punycode.
unsafe fn ansi_to_string(text: *const u8) -> Option<String> {
    let len = bounded_len(text)?;
    let bytes = std::slice::from_raw_parts(text, len);
    if bytes.is_ascii() {
        return Some(String::from_utf8_lossy(bytes).into_owned());
    }
    let mut wide = [0u16; 1025];
    let written = MultiByteToWideChar(
        CP_ACP,
        0,
        bytes.as_ptr(),
        len as i32,
        wide.as_mut_ptr(),
        wide.len() as i32,
    );
    if written <= 0 {
        return None;
    }
    String::from_utf16(wide.get(..written as usize)?).ok()
}

unsafe fn utf8_to_string(text: *const u8) -> Option<String> {
    let len = bounded_len(text)?;
    std::str::from_utf8(std::slice::from_raw_parts(text, len)).ok().map(str::to_owned)
}

/// `IdnToAscii` берётся по адресу при установке хуков: в kernel32 она есть
/// с Windows 7, раньше жила только в normaliz.dll.
static IDN_TO_ASCII: AtomicUsize = AtomicUsize::new(0);
type IdnToAsciiFn = unsafe extern "system" fn(u32, *const u16, i32, *mut u16, i32) -> i32;

fn to_ascii_name(name: &str) -> Option<String> {
    let function = IDN_TO_ASCII.load(Ordering::Acquire);
    if function == 0 {
        return None;
    }
    let function: IdnToAsciiFn = unsafe { std::mem::transmute(function) };
    let wide: Vec<u16> = name.encode_utf16().collect();
    if wide.is_empty() || wide.len() > 1024 {
        return None;
    }
    let mut out = [0u16; 256];
    let written = unsafe {
        function(0, wide.as_ptr(), wide.len() as i32, out.as_mut_ptr(), out.len() as i32)
    };
    if written <= 0 {
        return None;
    }
    String::from_utf16(out.get(..written as usize)?).ok()
}

// ----- GetAddrInfoW / getaddrinfo -----

unsafe extern "system" fn hook_getaddrinfow(
    node: *const u16,
    service: *const u16,
    hints: *const ADDRINFOW,
    result: *mut *mut ADDRINFOW,
) -> i32 {
    let original: GetAddrInfoWFn = std::mem::transmute(ORIG_GETADDRINFOW.load(Ordering::Acquire));
    let saved_error = GetLastError();
    let plan = catch_unwind(AssertUnwindSafe(|| {
        let (family, flags) = hints.as_ref().map_or((AF_UNSPEC as i32, 0), |h| (h.ai_family, h.ai_flags));
        decide(wide_to_string(node).as_deref(), family, flags, true)
    }))
    .unwrap_or(Plan::PassThrough);
    SetLastError(saved_error);

    match plan {
        Plan::Replace(address) => {
            let mut copy: ADDRINFOW = match hints.as_ref() {
                Some(given) => *given,
                None => std::mem::zeroed(),
            };
            copy.ai_flags = numeric_flags(copy.ai_flags);
            let text = wide_address(address);
            original(text.as_ptr(), service, &copy, result)
        }
        Plan::Fail(failure) => fail_addrinfo(failure, result),
        Plan::PassThrough => original(node, service, hints, result),
    }
}

unsafe extern "system" fn hook_getaddrinfoa(
    node: *const u8,
    service: *const u8,
    hints: *const ADDRINFOA,
    result: *mut *mut ADDRINFOA,
) -> i32 {
    let original: GetAddrInfoAFn = std::mem::transmute(ORIG_GETADDRINFOA.load(Ordering::Acquire));
    let saved_error = GetLastError();
    let plan = catch_unwind(AssertUnwindSafe(|| {
        let (family, flags) = hints.as_ref().map_or((AF_UNSPEC as i32, 0), |h| (h.ai_family, h.ai_flags));
        decide(ansi_to_string(node).as_deref(), family, flags, true)
    }))
    .unwrap_or(Plan::PassThrough);
    SetLastError(saved_error);

    match plan {
        Plan::Replace(address) => {
            let mut copy: ADDRINFOA = match hints.as_ref() {
                Some(given) => *given,
                None => std::mem::zeroed(),
            };
            copy.ai_flags = numeric_flags(copy.ai_flags);
            let text = narrow_address(address);
            original(text.as_ptr(), service, &copy, result)
        }
        Plan::Fail(failure) => fail_addrinfo(failure, result),
        Plan::PassThrough => original(node, service, hints, result),
    }
}

// ----- GetAddrInfoExW / GetAddrInfoExA -----

/// Подсказки любой версии. С `AI_EXTENDED` структура длиннее обычной, и
/// какой длины — говорит `ai_version`: копировать надо ровно столько,
/// иначе Windows прочтёт мусор за концом копии.
#[repr(C)]
union ExHintsW {
    base: ADDRINFOEXW,
    widest: ADDRINFOEX6,
}

#[repr(C)]
union ExHintsA {
    base: ADDRINFOEXA,
    widest: ADDRINFOEX2A,
}

/// Сколько байт занимают подсказки. `None` — версия нам неизвестна.
unsafe fn ex_hints_size_w(hints: &ADDRINFOEXW) -> Option<usize> {
    if hints.ai_flags as u32 & AI_EXTENDED == 0 {
        return Some(std::mem::size_of::<ADDRINFOEXW>());
    }
    let version = (*(hints as *const ADDRINFOEXW as *const ADDRINFOEX2W)).ai_version as u32;
    match version {
        ADDRINFOEX_VERSION_2 => Some(std::mem::size_of::<ADDRINFOEX2W>()),
        ADDRINFOEX_VERSION_3 => Some(std::mem::size_of::<ADDRINFOEX3>()),
        ADDRINFOEX_VERSION_4 => Some(std::mem::size_of::<ADDRINFOEX4>()),
        ADDRINFOEX_VERSION_5 => Some(std::mem::size_of::<ADDRINFOEX5>()),
        ADDRINFOEX_VERSION_6 => Some(std::mem::size_of::<ADDRINFOEX6>()),
        _ => None,
    }
}

unsafe fn ex_hints_size_a(hints: &ADDRINFOEXA) -> Option<usize> {
    if hints.ai_flags as u32 & AI_EXTENDED == 0 {
        return Some(std::mem::size_of::<ADDRINFOEXA>());
    }
    let version = (*(hints as *const ADDRINFOEXA as *const ADDRINFOEX2A)).ai_version as u32;
    (version == ADDRINFOEX_VERSION_2).then_some(std::mem::size_of::<ADDRINFOEX2A>())
}

/// Через `GetAddrInfoExW` разрешают .NET, WinHTTP и многие современные
/// программы. Перехватываются пространства имён «все» и DNS; остальные
/// (Bluetooth, NLA, e-mail) к DNS отношения не имеют.
fn ex_namespace_is_ours(namespace: u32) -> bool {
    namespace == NS_ALL || namespace == NS_DNS
}

/// Асинхронный вызов (`lpOverlapped`, процедура завершения или событие в
/// OVERLAPPED) завершается синхронно: ответ уже есть, и ждать нечего.
/// Оригинал зовётся без OVERLAPPED, его результат лежит в `*ppResult`, а
/// возвращается код завершения, а не `WSA_IO_PENDING`. Это законный путь
/// API: Windows сама так отвечает, когда управляется без ожидания, и
/// вызывающие обязаны его разбирать (так делают и пример Microsoft, и
/// .NET). Процедуру завершения и событие при этом не трогаем: вызвать их
/// вдобавок к синхронному ответу значило бы завершить запрос дважды, а
/// .NET, например, освободил бы свой контекст два раза.
///
/// Почему не отдаём асинхронный вызов оригиналу с подменённым адресом:
/// строка адреса и копия подсказок живут на нашем стеке, а пережили бы
/// они асинхронный запрос или нет — не документировано.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_getaddrinfoexw(
    name: *const u16,
    service: *const u16,
    namespace: u32,
    provider: *const c_void,
    hints: *const ADDRINFOEXW,
    result: *mut *mut ADDRINFOEXW,
    timeout: *const c_void,
    overlapped: *const c_void,
    routine: *const c_void,
    handle: *mut HANDLE,
) -> i32 {
    let original: GetAddrInfoExWFn = std::mem::transmute(ORIG_GETADDRINFOEXW.load(Ordering::Acquire));
    let saved_error = GetLastError();
    let plan = catch_unwind(AssertUnwindSafe(|| {
        if !ex_namespace_is_ours(namespace) {
            return Plan::PassThrough;
        }
        let (family, flags) = match hints.as_ref() {
            Some(given) => {
                if ex_hints_size_w(given).is_none() {
                    log::write("dns: GetAddrInfoExW с подсказками неизвестной версии — отдано системе");
                    return Plan::PassThrough;
                }
                (given.ai_family, given.ai_flags)
            }
            None => (AF_UNSPEC as i32, 0),
        };
        decide(wide_to_string(name).as_deref(), family, flags, true)
    }))
    .unwrap_or(Plan::PassThrough);
    SetLastError(saved_error);

    let asynchronous = !overlapped.is_null();
    match plan {
        Plan::Replace(address) => {
            let mut copy: ExHintsW = std::mem::zeroed();
            if let Some(given) = hints.as_ref() {
                let size = ex_hints_size_w(given).unwrap_or(std::mem::size_of::<ADDRINFOEXW>());
                std::ptr::copy_nonoverlapping(
                    given as *const ADDRINFOEXW as *const u8,
                    &mut copy as *mut ExHintsW as *mut u8,
                    size.min(std::mem::size_of::<ExHintsW>()),
                );
            }
            copy.base.ai_flags = numeric_flags(copy.base.ai_flags);
            let text = wide_address(address);
            if asynchronous && !handle.is_null() {
                // Отменять нечего: запрос завершён до возврата.
                *handle = std::ptr::null_mut();
            }
            original(
                text.as_ptr(),
                service,
                namespace,
                provider,
                &copy.base,
                result,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                if asynchronous { std::ptr::null_mut() } else { handle },
            )
        }
        Plan::Fail(failure) => {
            if asynchronous && !handle.is_null() {
                *handle = std::ptr::null_mut();
            }
            fail_addrinfo(failure, result)
        }
        Plan::PassThrough => original(
            name, service, namespace, provider, hints, result, timeout, overlapped, routine, handle,
        ),
    }
}

/// ANSI-вариант асинхронных вызовов не поддерживает вовсе, поэтому
/// параметры ожидания передаются оригиналу как есть: он сам ответит на
/// них отказом, как ответил бы и без нас.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_getaddrinfoexa(
    name: *const u8,
    service: *const u8,
    namespace: u32,
    provider: *const c_void,
    hints: *const ADDRINFOEXA,
    result: *mut *mut ADDRINFOEXA,
    timeout: *const c_void,
    overlapped: *const c_void,
    routine: *const c_void,
    handle: *mut HANDLE,
) -> i32 {
    let original: GetAddrInfoExAFn = std::mem::transmute(ORIG_GETADDRINFOEXA.load(Ordering::Acquire));
    let saved_error = GetLastError();
    let plan = catch_unwind(AssertUnwindSafe(|| {
        if !ex_namespace_is_ours(namespace) || !overlapped.is_null() {
            return Plan::PassThrough;
        }
        let (family, flags) = match hints.as_ref() {
            Some(given) => {
                if ex_hints_size_a(given).is_none() {
                    log::write("dns: GetAddrInfoExA с подсказками неизвестной версии — отдано системе");
                    return Plan::PassThrough;
                }
                (given.ai_family, given.ai_flags)
            }
            None => (AF_UNSPEC as i32, 0),
        };
        decide(ansi_to_string(name).as_deref(), family, flags, true)
    }))
    .unwrap_or(Plan::PassThrough);
    SetLastError(saved_error);

    match plan {
        Plan::Replace(address) => {
            let mut copy: ExHintsA = std::mem::zeroed();
            if let Some(given) = hints.as_ref() {
                let size = ex_hints_size_a(given).unwrap_or(std::mem::size_of::<ADDRINFOEXA>());
                std::ptr::copy_nonoverlapping(
                    given as *const ADDRINFOEXA as *const u8,
                    &mut copy as *mut ExHintsA as *mut u8,
                    size.min(std::mem::size_of::<ExHintsA>()),
                );
            }
            copy.base.ai_flags = numeric_flags(copy.base.ai_flags);
            let text = narrow_address(address);
            original(
                text.as_ptr(),
                service,
                namespace,
                provider,
                &copy.base,
                result,
                timeout,
                overlapped,
                routine,
                handle,
            )
        }
        Plan::Fail(failure) => fail_addrinfo(failure, result),
        Plan::PassThrough => original(
            name, service, namespace, provider, hints, result, timeout, overlapped, routine, handle,
        ),
    }
}

// ----- gethostbyname -----

/// `gethostbyname` отдаёт указатель на структуру, которой владеет Winsock:
/// своя на каждый поток, живёт до следующего вызова в том же потоке. Наш
/// ответ устроен так же — буфер на поток, без выделений и без деструктора.
#[repr(C)]
struct HostBuffer {
    entry: HOSTENT,
    list: [*mut i8; 2],
    aliases: [*mut i8; 1],
    address: [u8; 4],
    name: [u8; 256],
}

thread_local! {
    static HOST: UnsafeCell<HostBuffer> = const {
        UnsafeCell::new(HostBuffer {
            entry: HOSTENT {
                h_name: std::ptr::null_mut(),
                h_aliases: std::ptr::null_mut(),
                h_addrtype: 0,
                h_length: 0,
                h_addr_list: std::ptr::null_mut(),
            },
            list: [std::ptr::null_mut(); 2],
            aliases: [std::ptr::null_mut(); 1],
            address: [0; 4],
            name: [0; 256],
        })
    };
}

/// Заполняет буфер ответом с одним адресом.
fn fill_hostent(buffer: &mut HostBuffer, name: &str, address: Ipv4Addr) -> *mut HOSTENT {
    let bytes = name.as_bytes();
    let len = bytes.len().min(buffer.name.len() - 1);
    buffer.name[..len].copy_from_slice(&bytes[..len]);
    buffer.name[len] = 0;
    buffer.address = address.octets();
    buffer.list = [buffer.address.as_mut_ptr() as *mut i8, std::ptr::null_mut()];
    buffer.aliases = [std::ptr::null_mut()];
    buffer.entry = HOSTENT {
        h_name: buffer.name.as_mut_ptr(),
        h_aliases: buffer.aliases.as_mut_ptr(),
        h_addrtype: AF_INET as i16,
        h_length: 4,
        h_addr_list: buffer.list.as_mut_ptr(),
    };
    &mut buffer.entry
}

unsafe fn fail_hostent(failure: Failure) -> *mut HOSTENT {
    WSASetLastError(failure.wsa());
    std::ptr::null_mut()
}

unsafe extern "system" fn hook_gethostbyname(name: *const u8) -> *mut HOSTENT {
    let original: GetHostByNameFn = std::mem::transmute(ORIG_GETHOSTBYNAME.load(Ordering::Acquire));
    let saved_error = GetLastError();
    let host = catch_unwind(|| ansi_to_string(name)).unwrap_or(None);
    let plan = catch_unwind(AssertUnwindSafe(|| decide(host.as_deref(), AF_INET as i32, 0, true)))
        .unwrap_or(Plan::PassThrough);
    SetLastError(saved_error);

    match plan {
        Plan::Replace(IpAddr::V4(address)) => {
            let shown = host.as_deref().unwrap_or("");
            let filled = catch_unwind(AssertUnwindSafe(|| {
                HOST.try_with(|cell| fill_hostent(&mut *cell.get(), shown, address)).ok()
            }))
            .ok()
            .flatten();
            // Буфера потока уже нет — поток завершается. Ответить нечем.
            filled.unwrap_or_else(|| fail_hostent(Failure::TryAgain))
        }
        // Семейство IPv4 — адрес IPv6 сюда не попадёт; на всякий случай.
        Plan::Replace(IpAddr::V6(_)) => fail_hostent(Failure::NoData),
        Plan::Fail(failure) => fail_hostent(failure),
        Plan::PassThrough => original(name),
    }
}

// ----- WSAConnectByNameW / WSAConnectByNameA -----

/// `WSAConnectByName` сам разрешает имя и соединяется. Имя разрешаем мы,
/// а оригиналу отдаём готовый адрес: соединение он установит как обычно.
/// Сокет к этому времени уже привязан к туннелю — его создал `socket` или
/// `WSASocketW`. Семейство не известно, поэтому спрашиваем A, а при его
/// отсутствии AAAA: адрес IPv4 подходит и сокету AF_INET, и двухрежимному
/// AF_INET6, который рекомендует документация.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_wsaconnectbynamew(
    sock: SOCKET,
    node: *const u16,
    service: *const u16,
    local_len: *mut u32,
    local: *mut SOCKADDR,
    remote_len: *mut u32,
    remote: *mut SOCKADDR,
    timeout: *const c_void,
    reserved: *const c_void,
) -> i32 {
    let original: WsaConnectByNameWFn =
        std::mem::transmute(ORIG_WSACONNECTBYNAMEW.load(Ordering::Acquire));
    let saved_error = GetLastError();
    let plan = catch_unwind(AssertUnwindSafe(|| {
        decide(wide_to_string(node).as_deref(), AF_UNSPEC as i32, 0, true)
    }))
    .unwrap_or(Plan::PassThrough);
    SetLastError(saved_error);

    match plan {
        Plan::Replace(address) => {
            let text = wide_address(address);
            original(sock, text.as_ptr(), service, local_len, local, remote_len, remote, timeout, reserved)
        }
        Plan::Fail(failure) => {
            WSASetLastError(failure.wsa());
            0
        }
        Plan::PassThrough => {
            original(sock, node, service, local_len, local, remote_len, remote, timeout, reserved)
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_wsaconnectbynamea(
    sock: SOCKET,
    node: *const u8,
    service: *const u8,
    local_len: *mut u32,
    local: *mut SOCKADDR,
    remote_len: *mut u32,
    remote: *mut SOCKADDR,
    timeout: *const c_void,
    reserved: *const c_void,
) -> i32 {
    let original: WsaConnectByNameAFn =
        std::mem::transmute(ORIG_WSACONNECTBYNAMEA.load(Ordering::Acquire));
    let saved_error = GetLastError();
    let plan = catch_unwind(AssertUnwindSafe(|| {
        decide(ansi_to_string(node).as_deref(), AF_UNSPEC as i32, 0, true)
    }))
    .unwrap_or(Plan::PassThrough);
    SetLastError(saved_error);

    match plan {
        Plan::Replace(address) => {
            let text = narrow_address(address);
            original(sock, text.as_ptr(), service, local_len, local, remote_len, remote, timeout, reserved)
        }
        Plan::Fail(failure) => {
            WSASetLastError(failure.wsa());
            0
        }
        Plan::PassThrough => {
            original(sock, node, service, local_len, local, remote_len, remote, timeout, reserved)
        }
    }
}

// ----- DnsQuery_W / DnsQuery_A / DnsQuery_UTF8 -----

/// Решение для `DnsQuery_*`. Перехватываются только записи A и AAAA:
/// остальные типы (MX, TXT, SRV…) публичным адресом не подменить, они
/// по-прежнему идут через систему. Не трогаем и вызовы с `pExtra`: там
/// свой список серверов или просьба вернуть сырой ответ, которого у нас
/// нет; и вызовы «только из кеша» — они в сеть не ходят.
fn dns_query_plan(host: Option<&str>, wtype: u16, options: u32, extra: *const c_void) -> Plan {
    let family = match wtype {
        DNS_TYPE_A => AF_INET as i32,
        DNS_TYPE_AAAA => AF_INET6 as i32,
        _ => return Plan::PassThrough,
    };
    if options & DNS_QUERY_NO_WIRE_QUERY != 0 || !extra.is_null() {
        return Plan::PassThrough;
    }
    decide(host, family, 0, options & DNS_QUERY_NO_HOSTS_FILE == 0)
}

/// `DnsRecordSetCopyEx` из dnsapi: копия записи, выделенная самой dnsapi.
/// Только так приложение может освободить наш ответ своим
/// `DnsRecordListFree` / `DnsFree`: аллокатор dnsapi не документирован, и
/// угадывать его мы не берёмся.
static DNS_COPY: AtomicUsize = AtomicUsize::new(0);
type DnsRecordSetCopyExFn = unsafe extern "system" fn(*const DNS_RECORDW, i32, i32) -> *mut c_void;

// Данные AAAA (16 байт) записываются прямо в объединение данных записи.
const _: () = assert!(std::mem::size_of::<DNS_RECORDW_0>() >= 16);

/// Запись A или AAAA для `name` — на нашем стеке, строка тоже наша.
/// Наружу она не отдаётся, только копируется dnsapi.
fn build_record(name: &[u16], address: IpAddr) -> DNS_RECORDW {
    let mut record: DNS_RECORDW = unsafe { std::mem::zeroed() };
    record.pName = name.as_ptr() as *mut u16;
    // Раздел «ответ» в битах 0–1, кодировка строк — в битах 3–4.
    record.Flags.DW = DnsSectionAnswer as u32 | ((DnsCharSetUnicode as u32) << 3);
    // Короткий срок: адрес наш, перепроверять его не вредно.
    record.dwTtl = 60;
    match address {
        IpAddr::V4(v4) => {
            record.wType = DNS_TYPE_A;
            record.wDataLength = 4;
            record.Data.A.IpAddress = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            record.wType = DNS_TYPE_AAAA;
            record.wDataLength = 16;
            unsafe {
                std::ptr::write_unaligned(
                    &mut record.Data as *mut DNS_RECORDW_0 as *mut [u8; 16],
                    v6.octets(),
                )
            };
        }
    }
    record
}

/// Отдаёт приложению ответ с одним адресом в кодировке `charset`.
unsafe fn dns_answer(name: &str, address: IpAddr, wtype: u16, charset: i32, results: *mut *mut c_void) -> u32 {
    let matches = match address {
        IpAddr::V4(_) => wtype == DNS_TYPE_A,
        IpAddr::V6(_) => wtype == DNS_TYPE_AAAA,
    };
    if !matches {
        return Failure::NoData.dns();
    }
    if results.is_null() {
        // Спросили только «есть ли такое имя».
        return 0;
    }
    let copy = DNS_COPY.load(Ordering::Acquire);
    if copy == 0 {
        return Failure::TryAgain.dns();
    }
    let copy: DnsRecordSetCopyExFn = std::mem::transmute(copy);
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let record = build_record(&wide, address);
    let out = copy(&record, DnsCharSetUnicode, charset);
    if out.is_null() {
        return ERROR_OUTOFMEMORY;
    }
    *results = out;
    0
}

unsafe fn dns_query(
    host: Option<String>,
    wtype: u16,
    options: u32,
    extra: *mut c_void,
    results: *mut *mut c_void,
    charset: i32,
) -> Option<u32> {
    let saved_error = GetLastError();
    let plan = catch_unwind(AssertUnwindSafe(|| dns_query_plan(host.as_deref(), wtype, options, extra)))
        .unwrap_or(Plan::PassThrough);
    let status = match plan {
        Plan::PassThrough => None,
        Plan::Replace(address) => catch_unwind(AssertUnwindSafe(|| {
            dns_answer(host.as_deref().unwrap_or(""), address, wtype, charset, results)
        }))
        .ok()
        .or(Some(Failure::TryAgain.dns())),
        Plan::Fail(failure) => {
            if !results.is_null() {
                *results = std::ptr::null_mut();
            }
            Some(failure.dns())
        }
    };
    SetLastError(saved_error);
    status
}

unsafe extern "system" fn hook_dnsquery_w(
    name: *const u16,
    wtype: u16,
    options: u32,
    extra: *mut c_void,
    results: *mut *mut c_void,
    reserved: *mut *mut c_void,
) -> u32 {
    let original: DnsQueryWFn = std::mem::transmute(ORIG_DNSQUERY_W.load(Ordering::Acquire));
    let host = catch_unwind(|| wide_to_string(name)).unwrap_or(None);
    match dns_query(host, wtype, options, extra, results, DnsCharSetUnicode) {
        Some(status) => status,
        None => original(name, wtype, options, extra, results, reserved),
    }
}

unsafe extern "system" fn hook_dnsquery_a(
    name: *const u8,
    wtype: u16,
    options: u32,
    extra: *mut c_void,
    results: *mut *mut c_void,
    reserved: *mut *mut c_void,
) -> u32 {
    let original: DnsQueryAFn = std::mem::transmute(ORIG_DNSQUERY_A.load(Ordering::Acquire));
    let host = catch_unwind(|| ansi_to_string(name)).unwrap_or(None);
    match dns_query(host, wtype, options, extra, results, DnsCharSetAnsi) {
        Some(status) => status,
        None => original(name, wtype, options, extra, results, reserved),
    }
}

unsafe extern "system" fn hook_dnsquery_utf8(
    name: *const u8,
    wtype: u16,
    options: u32,
    extra: *mut c_void,
    results: *mut *mut c_void,
    reserved: *mut *mut c_void,
) -> u32 {
    let original: DnsQueryAFn = std::mem::transmute(ORIG_DNSQUERY_UTF8.load(Ordering::Acquire));
    let host = catch_unwind(|| utf8_to_string(name)).unwrap_or(None);
    match dns_query(host, wtype, options, extra, results, DnsCharSetUtf8) {
        Some(status) => status,
        None => original(name, wtype, options, extra, results, reserved),
    }
}

// ---------- сокеты ----------

unsafe extern "system" fn hook_wsasocketw(
    af: i32,
    kind: i32,
    protocol: i32,
    info: *const WSAPROTOCOL_INFOW,
    group: u32,
    flags: u32,
) -> SOCKET {
    let original: WsaSocketWFn = std::mem::transmute(ORIG_WSASOCKETW.load(Ordering::Acquire));
    let sock = original(af, kind, protocol, info, group, flags);
    if sock != INVALID_SOCKET {
        // При AF_UNSPEC семейство берётся из описания протокола.
        let family = if af == AF_UNSPEC as i32 && !info.is_null() {
            (*info).iAddressFamily
        } else {
            af
        };
        bind_quietly(sock, family);
    }
    sock
}

unsafe extern "system" fn hook_socket(af: i32, kind: i32, protocol: i32) -> SOCKET {
    let original: SocketFn = std::mem::transmute(ORIG_SOCKET.load(Ordering::Acquire));
    let sock = original(af, kind, protocol);
    if sock != INVALID_SOCKET {
        bind_quietly(sock, af);
    }
    sock
}

unsafe extern "system" fn hook_bind(sock: SOCKET, name: *const SOCKADDR, len: i32) -> i32 {
    release_if_local(sock, name, len);
    let original: AddrFn = std::mem::transmute(ORIG_BIND.load(Ordering::Acquire));
    original(sock, name, len)
}

unsafe extern "system" fn hook_connect(sock: SOCKET, name: *const SOCKADDR, len: i32) -> i32 {
    if before_connect(sock, name, len) == Verdict::Refuse {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }
    let original: AddrFn = std::mem::transmute(ORIG_CONNECT.load(Ordering::Acquire));
    original(sock, name, len)
}

/// `connect` мимо `hook_connect` — для сокетов нашего же резолвера: их
/// привязку к туннелю `before_connect` трогать не должен. Пока перехват не
/// поставлен (или в тестах), ws2_32!connect и есть оригинал.
pub(crate) unsafe fn connect_unhooked(sock: SOCKET, name: *const SOCKADDR, len: i32) -> i32 {
    match ORIG_CONNECT.load(Ordering::Acquire) {
        0 => windows_sys::Win32::Networking::WinSock::connect(sock, name, len),
        original => {
            let original: AddrFn = std::mem::transmute(original);
            original(sock, name, len)
        }
    }
}

unsafe extern "system" fn hook_wsaconnect(
    sock: SOCKET,
    name: *const SOCKADDR,
    len: i32,
    caller_data: *const c_void,
    callee_data: *mut c_void,
    sqos: *const c_void,
    gqos: *const c_void,
) -> i32 {
    if before_connect(sock, name, len) == Verdict::Refuse {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }
    let original: WsaConnectFn = std::mem::transmute(ORIG_WSACONNECT.load(Ordering::Acquire));
    original(sock, name, len, caller_data, callee_data, sqos, gqos)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Verdict {
    /// Зовём оригинал.
    Allow,
    /// Отказываем сами: туннеля больше нет, а наружу этому сокету нельзя.
    Refuse,
}

/// Что делать с сокетом перед тем, как он пойдёт наружу.
///
/// Здесь и живёт kill-switch. Пока туннель цел, привязка просто
/// подтверждается. Когда туннель падает, его индекс становится невалидным,
/// и Windows отказывает в `IP_UNICAST_IF` — вот этот отказ и ловится.
/// Раньше он молча игнорировался, и сокет уходил мимо туннеля: приложение
/// продолжало работать, а пользователь об этом не знал. Теперь соединение
/// не состоится вовсе.
fn before_connect(sock: SOCKET, name: *const SOCKADDR, len: i32) -> Verdict {
    if IFINDEX.load(Ordering::Relaxed) == 0 {
        return Verdict::Allow;
    }
    catch_unwind(AssertUnwindSafe(|| {
        if unsafe { is_local(name, len) } {
            if let Some(server) = unsafe { dns_destination(name, len) } {
                if !is_our_dns(server) {
                    // Встроенный DNS-клиент Chrome и Edge спрашивает DNS-сервер из
                    // настроек сети — обычно роутер. Выпусти мы его, имена ушли бы
                    // мимо туннеля. Быстрый отказ браузер понимает как сбой своего
                    // клиента и переходит на системный резолвер, то есть на наш
                    // перехват getaddrinfo.
                    log::write(&format!("сокет к DNS-серверу {server} своей сети не выпущен: имена — только через туннель"));
                    return Verdict::Refuse;
                }
                // DNS самого VPN (обычно 10.x или 192.168.x) приложение тоже
                // спрашивает только через туннель, как и наш резолвер. Снять
                // привязку значило бы отдать запрос таблице маршрутов: если
                // маршрута к нему через VPN нет или адрес совпал с домашним
                // роутером (192.168.1.1), имена ушли бы в домашнюю сеть.
                let family = unsafe { family_of(name, len) }.unwrap_or(AF_INET) as i32;
                if bind_to_tunnel(sock, family) {
                    return Verdict::Allow;
                }
                log::write(&format!("сокет к DNS туннеля {server} не выпущен: туннель не отвечает"));
                return Verdict::Refuse;
            }
            // Ноль означает «интерфейс не задан» — обычное поведение сокета.
            let _ = set_u32(sock, IPPROTO_IP, IP_UNICAST_IF, 0);
            let _ = set_u32(sock, IPPROTO_IPV6, IPV6_UNICAST_IF, 0);
            return Verdict::Allow;
        }
        let Some(family) = (unsafe { family_of(name, len) }) else {
            // Семейство не наше (Bluetooth, Hyper-V) — не мешаем.
            return Verdict::Allow;
        };
        if bind_to_tunnel(sock, family as i32) {
            Verdict::Allow
        } else {
            log::write("сокет наружу не выпущен: туннель не отвечает");
            Verdict::Refuse
        }
    }))
    // Паника здесь не повод выпускать сокет наружу, но и не повод ломать
    // приложение на ровном месте: решает прежнее поведение.
    .unwrap_or(Verdict::Allow)
}

unsafe fn family_of(name: *const SOCKADDR, len: i32) -> Option<u16> {
    if name.is_null() || len < std::mem::size_of::<SOCKADDR>() as i32 {
        return None;
    }
    let family = (*name).sa_family;
    (family == AF_INET || family == AF_INET6).then_some(family)
}

/// Снимает привязку с сокета, который работает с локальными адресами:
/// loopback и домашняя сеть. Вызывается ДО оригинальной функции, поэтому
/// код ошибки потом выставит она сама.
///
/// Зачем домашняя сеть: иначе туннельное приложение не видит роутер,
/// принтер и NAS. Исключение — порт 53 роутера: такое соединение
/// `before_connect` отклоняет сразу (см. `is_our_dns`), чтобы
/// встроенный DNS-клиент браузера не терял секунды на запрос, который в
/// VPN пропадёт, и не спрашивал роутер мимо туннеля.
fn release_if_local(sock: SOCKET, name: *const SOCKADDR, len: i32) {
    if IFINDEX.load(Ordering::Relaxed) == 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if unsafe { is_local(name, len) } {
            // Ноль означает «интерфейс не задан» — обычное поведение сокета.
            let _ = set_u32(sock, IPPROTO_IP, IP_UNICAST_IF, 0);
            let _ = set_u32(sock, IPPROTO_IPV6, IPV6_UNICAST_IF, 0);
        }
    }));
}

/// Локальный адрес: loopback, частные подсети RFC 1918, link-local; для
/// IPv6 — loopback, ULA, link-local и отображённые IPv4 из тех же диапазонов.
///
/// Адреса 10.x внутри самого VPN это не ломает: снятая привязка значит
/// «решает таблица маршрутов», а подсеть туннеля в ней указывает на TAP.
pub(crate) unsafe fn is_local(name: *const SOCKADDR, len: i32) -> bool {
    if name.is_null() || len < std::mem::size_of::<SOCKADDR>() as i32 {
        return false;
    }
    let family = (*name).sa_family;
    if family == AF_INET && len >= std::mem::size_of::<SOCKADDR_IN>() as i32 {
        let v4 = &*(name as *const SOCKADDR_IN);
        return is_local_v4(std::net::Ipv4Addr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes()));
    }
    if family == AF_INET6 && len >= std::mem::size_of::<SOCKADDR_IN6>() as i32 {
        let v6 = &*(name as *const SOCKADDR_IN6);
        let addr = std::net::Ipv6Addr::from(v6.sin6_addr.u.Byte);
        if let Some(v4) = addr.to_ipv4_mapped() {
            return is_local_v4(v4);
        }
        let first = addr.segments()[0];
        return addr.is_loopback()
            || (first & 0xfe00) == 0xfc00 // ULA fc00::/7
            || (first & 0xffc0) == 0xfe80; // link-local fe80::/10
    }
    false
}

/// Один ли это из серверов нашего резолвера (см. `dns::is_server`): DNS
/// туннеля нередко живёт в 10.x, и запрос к нему — ровно то, что нужно.
/// Такой сокет `before_connect` оставляет привязанным к туннелю, а к
/// остальным DNS-серверам своей сети (роутеру) не выпускает.
fn is_our_dns(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(v4) if dns::is_server(v4))
}

/// Адрес DNS-сервера, если соединение идёт на порт 53. Loopback сюда не
/// входит: это локальный прокси, которым пользователь управляет сам.
/// Отображённый IPv4 отдаётся как IPv4.
unsafe fn dns_destination(name: *const SOCKADDR, len: i32) -> Option<IpAddr> {
    const DNS_PORT: u16 = 53;
    if name.is_null() || len < std::mem::size_of::<SOCKADDR>() as i32 {
        return None;
    }
    let (address, port) = match (*name).sa_family {
        AF_INET if len >= std::mem::size_of::<SOCKADDR_IN>() as i32 => {
            let v4 = &*(name as *const SOCKADDR_IN);
            let address = Ipv4Addr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes());
            (IpAddr::V4(address), u16::from_be(v4.sin_port))
        }
        AF_INET6 if len >= std::mem::size_of::<SOCKADDR_IN6>() as i32 => {
            let v6 = &*(name as *const SOCKADDR_IN6);
            let address = std::net::Ipv6Addr::from(v6.sin6_addr.u.Byte);
            let address = match address.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(address),
            };
            (address, u16::from_be(v6.sin6_port))
        }
        _ => return None,
    };
    if port != DNS_PORT || address.is_loopback() {
        return None;
    }
    Some(address)
}

fn is_local_v4(addr: std::net::Ipv4Addr) -> bool {
    addr.is_loopback() || addr.is_private() || addr.is_link_local()
}

/// Привязывает сокет к туннелю, не меняя для приложения ни результата,
/// ни кода последней ошибки.
fn bind_quietly(sock: SOCKET, family: i32) {
    let saved_error = unsafe { WSAGetLastError() };
    let _ = catch_unwind(AssertUnwindSafe(|| bind_to_tunnel(sock, family)));
    unsafe { WSASetLastError(saved_error) };
}

/// Правда — сокет привязан к туннелю (или семейство не наше, и привязывать
/// нечего). Ложь означает, что туннеля больше нет.
fn bind_to_tunnel(sock: SOCKET, family: i32) -> bool {
    let index = IFINDEX.load(Ordering::Relaxed);
    if index == 0 {
        return true;
    }
    let iface = InterfaceIndex::new(index);

    let ok = if family == AF_INET as i32 {
        set_u32(sock, IPPROTO_IP, IP_UNICAST_IF, iface.ipv4_sockopt_value())
    } else if family == AF_INET6 as i32 {
        // Сокет IPv6 может быть двухрежимным и ходить на адреса IPv4, поэтому
        // ставим обе опции. Ошибка второй для чистого v6-сокета не важна.
        let v6 = set_u32(sock, IPPROTO_IPV6, IPV6_UNICAST_IF, iface.ipv6_sockopt_value());
        let _ = set_u32(sock, IPPROTO_IP, IP_UNICAST_IF, iface.ipv4_sockopt_value());
        v6
    } else {
        // Bluetooth, Hyper-V и прочие семейства не трогаем — и не считаем
        // это неудачей: наружу по IP они всё равно не идут.
        return true;
    };

    if ok {
        BOUND.fetch_add(1, Ordering::Relaxed);
    }
    ok
}

pub(crate) fn set_u32(sock: SOCKET, level: i32, option: i32, value: u32) -> bool {
    unsafe {
        setsockopt(
            sock,
            level,
            option,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        ) == 0
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

    fn v4(octets: [u8; 4]) -> SOCKADDR_IN {
        let mut a: SOCKADDR_IN = unsafe { std::mem::zeroed() };
        a.sin_family = AF_INET;
        a.sin_addr.S_un.S_addr = u32::from_ne_bytes(octets);
        a
    }

    fn v6(addr: std::net::Ipv6Addr) -> SOCKADDR_IN6 {
        let mut a: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
        a.sin6_family = AF_INET6;
        a.sin6_addr.u.Byte = addr.octets();
        a
    }

    fn check<T>(addr: &T) -> bool {
        unsafe { super::is_local(addr as *const T as *const SOCKADDR, std::mem::size_of::<T>() as i32) }
    }

    #[test]
    fn loopback_and_home_network_are_local() {
        assert!(check(&v4([127, 0, 0, 1])));
        assert!(check(&v4([192, 168, 31, 1]))); // домашний роутер
        assert!(check(&v4([10, 5, 5, 1]))); // шлюз туннеля: решает таблица маршрутов
        assert!(check(&v4([172, 16, 0, 1])));
        assert!(check(&v4([172, 31, 255, 255])));
        assert!(check(&v4([169, 254, 1, 1])));
    }

    #[test]
    fn internet_addresses_are_not_local() {
        assert!(!check(&v4([8, 8, 8, 8])));
        assert!(!check(&v4([172, 32, 0, 1]))); // сразу за 172.16/12
        assert!(!check(&v4([5, 129, 217, 118])));
        assert!(!check(&v4([0, 0, 0, 0])));
    }

    #[test]
    fn v6_local_ranges_and_mapped_v4() {
        assert!(check(&v6(std::net::Ipv6Addr::LOCALHOST)));
        assert!(check(&v6("fd00::1".parse().unwrap())));
        assert!(check(&v6("fe80::1".parse().unwrap())));
        assert!(check(&v6("::ffff:127.0.0.1".parse().unwrap())));
        assert!(check(&v6("::ffff:192.168.31.1".parse().unwrap())));
        assert!(!check(&v6("::ffff:8.8.8.8".parse().unwrap())));
        assert!(!check(&v6("2001:db8::1".parse().unwrap())));
        assert!(!check(&v6(std::net::Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn short_or_null_address_is_not_local() {
        assert!(!unsafe { super::is_local(std::ptr::null(), 16) });
        let a = v4([127, 0, 0, 1]);
        assert!(!unsafe { super::is_local(&a as *const _ as *const SOCKADDR, 4) });
    }

    #[test]
    fn home_dns_server_is_recognised_by_port_53() {
        let at = |mut a: SOCKADDR_IN, port: u16| {
            a.sin_port = port.to_be();
            a
        };
        let target = |a: &SOCKADDR_IN| unsafe {
            super::dns_destination(a as *const _ as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32)
        };
        // Роутер: DNS-сервер своей сети, не наш — `before_connect` отклонит.
        let dns_of = |a: &SOCKADDR_IN| target(a).filter(|address| !super::is_our_dns(*address));
        let router = at(v4([192, 168, 1, 1]), 53);
        assert_eq!(dns_of(&router), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(dns_of(&at(v4([192, 168, 1, 1]), 80)), None);
        // Локальный прокси и серверы нашего же резолвера — не утечка.
        assert_eq!(dns_of(&at(v4([127, 0, 0, 1]), 53)), None);
        assert_eq!(dns_of(&at(v4([1, 1, 1, 1]), 53)), None);
        // Свой сервер `before_connect` оставляет привязанным к туннелю.
        let public = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(target(&at(v4([1, 1, 1, 1]), 53)), Some(public));
        assert!(super::is_our_dns(public));
        assert_eq!(target(&router), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!super::is_our_dns(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(target(&at(v4([127, 0, 0, 1]), 53)), None);

        let mut six = v6("fe80::1".parse().unwrap());
        six.sin6_port = 53u16.to_be();
        let got = unsafe {
            super::dns_destination(&six as *const _ as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN6>() as i32)
        };
        assert_eq!(got, Some(IpAddr::V6("fe80::1".parse().unwrap())));
    }

    // ----- имена -----

    use super::{Failure, Plan};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, WSAHOST_NOT_FOUND, WSANO_DATA, WSATRY_AGAIN};

    const UNSPEC: i32 = AF_UNSPEC as i32;

    #[test]
    fn public_names_are_resolved_by_us() {
        assert_eq!(super::tunnel_name("example.com", UNSPEC, false), Some("example.com"));
        assert_eq!(super::tunnel_name(" example.com. ", AF_INET as i32, false), Some("example.com."));
        assert_eq!(super::tunnel_name("почта.рф", AF_INET6 as i32, false), Some("почта.рф"));
    }

    #[test]
    fn local_and_numeric_names_stay_with_the_system() {
        for name in ["", "  ", "router", "router.", "printer.local", "nas.lan", "1.2.3.4", "::1", "[::1]", "127.1", "0x7f.1"] {
            assert_eq!(super::tunnel_name(name, UNSPEC, false), None, "{name:?}");
        }
        // Приложение само сказало «это число».
        assert_eq!(super::tunnel_name("example.com", UNSPEC, true), None);
        // Не IP-семейство.
        assert_eq!(super::tunnel_name("example.com", 32, false), None);
    }

    #[test]
    fn user_domain_names_are_asked_through_the_tunnel_first() {
        // Имена домена AD больше не уходят системе сразу: их разбирает
        // наш резолвер (в режиме «все сказали нет»).
        assert_eq!(super::tunnel_name("mail.acme.com", UNSPEC, false), Some("mail.acme.com"));
        assert!(super::in_user_domain("mail.acme.com", Some("acme.com")));
        assert!(super::in_user_domain("ACME.COM.", Some("acme.com")));
        assert!(!super::in_user_domain("notacme.com", Some("acme.com")));
        assert!(!super::in_user_domain("mail.acme.com", None));
        assert!(!super::in_user_domain("mail.acme.com", Some("")));
    }

    #[test]
    fn ideographic_full_stops_are_dots() {
        assert_eq!(super::ascii_dots("例え。テスト"), "例え.テスト");
        assert_eq!(super::ascii_dots("a．b｡c"), "a.b.c");
        assert!(matches!(super::ascii_dots("example.com"), std::borrow::Cow::Borrowed(_)));
        // Имя без ASCII-точки больше не считается однословным.
        let host = super::ascii_dots("例え。テスト");
        assert_eq!(super::tunnel_name(&host, UNSPEC, false), Some("例え.テスト"));
    }

    #[test]
    fn v4_mapped_falls_back_to_a_records() {
        use crate::dns::{TYPE_A, TYPE_AAAA};
        use windows_sys::Win32::Networking::WinSock::{AI_ALL, AI_V4MAPPED};
        let six = AF_INET6 as i32;
        let mapped = AI_V4MAPPED as i32;
        assert!(super::wants_v4_mapped(six, mapped));
        assert!(super::wants_v4_mapped(six, (AI_V4MAPPED | AI_ALL) as i32));
        assert!(!super::wants_v4_mapped(six, 0));
        // Флаг имеет смысл только при AF_INET6.
        assert!(!super::wants_v4_mapped(UNSPEC, mapped));
        assert!(!super::wants_v4_mapped(AF_INET as i32, mapped));

        assert_eq!(super::query_order(six, true), (TYPE_AAAA, Some(TYPE_A)));
        assert_eq!(super::query_order(six, false), (TYPE_AAAA, None));
        assert_eq!(super::query_order(UNSPEC, false), (TYPE_A, Some(TYPE_AAAA)));
        assert_eq!(super::query_order(AF_INET as i32, false), (TYPE_A, None));

        // IPv4 для AF_INET6 отдаётся сопоставленным, остальное — как есть.
        let v4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let as_v6: IpAddr = "::ffff:93.184.216.34".parse().unwrap();
        assert_eq!(super::shaped(v4, six), as_v6);
        assert_eq!(super::shaped(v4, UNSPEC), v4);
        assert_eq!(super::shaped(v4, AF_INET as i32), v4);
        let native = IpAddr::V6("2001:db8::1".parse().unwrap());
        assert_eq!(super::shaped(native, six), native);
        // Строка, которую получит оригинал, — числовой IPv6.
        assert_eq!(as_v6.to_string(), "::ffff:93.184.216.34");
    }

    #[test]
    fn hosts_entry_with_only_ipv4_serves_v4_mapped_callers() {
        use crate::hosts::{Hit, Table};
        let table = Table::parse("0.0.0.0 blocked.example.com\n::1 six.example.com\n");
        let six = AF_INET6 as i32;
        let lookup = |name: &str, v4mapped: bool| super::hosts_lookup(&table, name, name, six, v4mapped);
        assert_eq!(lookup("blocked.example.com", false), Hit::OtherFamily);
        assert_eq!(lookup("blocked.example.com", true), Hit::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        // Есть свой IPv6 — он и отдаётся.
        assert_eq!(lookup("six.example.com", true), Hit::Address(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(lookup("other.example.com", true), Hit::Miss);
    }

    #[test]
    fn without_a_tunnel_nothing_is_intercepted() {
        // В тестовом процессе hook не инициализирован: индекс нулевой.
        assert_eq!(super::decide(Some("example.com"), UNSPEC, 0, true), Plan::PassThrough);
    }

    #[test]
    fn no_answer_never_goes_to_the_system() {
        use crate::dns::{Answer, Outcome};
        let found = Outcome::Found(Answer {
            address: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            server: Ipv4Addr::new(1, 1, 1, 1),
            source: None,
            millis: 1,
        });
        assert_eq!(super::verdict(&found), Ok(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(super::verdict(&Outcome::NoName), Err(Failure::NoName));
        assert_eq!(super::verdict(&Outcome::NoData), Err(Failure::NoData));
        assert_eq!(super::verdict(&Outcome::Unavailable), Err(Failure::TryAgain));
        assert_eq!(super::verdict(&Outcome::TunnelGone), Err(Failure::TryAgain));
    }

    #[test]
    fn failures_map_to_the_codes_of_each_api() {
        assert_eq!(Failure::NoName.wsa(), WSAHOST_NOT_FOUND);
        assert_eq!(Failure::NoData.wsa(), WSANO_DATA);
        assert_eq!(Failure::TryAgain.wsa(), WSATRY_AGAIN);
        assert_eq!(Failure::NoName.dns(), 9003);
        assert_eq!(Failure::NoData.dns(), 9501);
        assert_eq!(Failure::TryAgain.dns(), 1460);
    }

    #[test]
    fn numeric_flags_drop_canonical_name_requests() {
        use windows_sys::Win32::Networking::WinSock::{AI_CANONNAME, AI_FQDN, AI_NUMERICHOST, AI_PASSIVE};
        let flags = super::numeric_flags((AI_CANONNAME | AI_FQDN | AI_PASSIVE) as i32);
        assert_eq!(flags, (AI_NUMERICHOST | AI_PASSIVE) as i32);
    }

    #[test]
    fn extended_hints_are_copied_by_their_version() {
        use windows_sys::Win32::Networking::WinSock::{ADDRINFOEX2W, ADDRINFOEX6, ADDRINFOEXW, AI_EXTENDED};
        let size = |hints: &ADDRINFOEX6| unsafe {
            super::ex_hints_size_w(&*(hints as *const ADDRINFOEX6 as *const ADDRINFOEXW))
        };
        let mut hints: ADDRINFOEX6 = unsafe { std::mem::zeroed() };
        assert_eq!(size(&hints), Some(std::mem::size_of::<ADDRINFOEXW>()));
        hints.ai_flags = AI_EXTENDED as i32;
        hints.ai_version = 2;
        assert_eq!(size(&hints), Some(std::mem::size_of::<ADDRINFOEX2W>()));
        hints.ai_version = 6;
        assert_eq!(size(&hints), Some(std::mem::size_of::<ADDRINFOEX6>()));
        hints.ai_version = 99;
        assert_eq!(size(&hints), None);
    }

    #[test]
    fn hostent_points_into_the_thread_buffer() {
        super::HOST.with(|cell| {
            let buffer = unsafe { &mut *cell.get() };
            let entry = unsafe { &*super::fill_hostent(buffer, "example.com", Ipv4Addr::new(9, 8, 7, 6)) };
            let name = unsafe { std::ffi::CStr::from_ptr(entry.h_name as *const std::ffi::c_char) };
            assert_eq!(name.to_str().unwrap(), "example.com");
            assert_eq!(entry.h_addrtype, AF_INET as i16);
            assert_eq!(entry.h_length, 4);
            unsafe {
                assert!((*entry.h_aliases).is_null());
                let first = *entry.h_addr_list;
                assert_eq!(std::slice::from_raw_parts(first as *const u8, 4), &[9, 8, 7, 6]);
                assert!((*entry.h_addr_list.add(1)).is_null());
            }
            // Длинное имя обрезается, а не выходит за буфер.
            let long = "a".repeat(400);
            let entry = unsafe { &*super::fill_hostent(buffer, &long, Ipv4Addr::LOCALHOST) };
            let name = unsafe { std::ffi::CStr::from_ptr(entry.h_name as *const std::ffi::c_char) };
            assert_eq!(name.to_bytes().len(), 255);
        });
    }

    #[test]
    fn idn_names_become_punycode() {
        let kernel32 = unsafe { super::LoadLibraryA(c"kernel32.dll".as_ptr() as *const u8) };
        let function = super::proc_addr(kernel32, c"IdnToAscii").expect("IdnToAscii в kernel32");
        super::IDN_TO_ASCII.store(function as usize, std::sync::atomic::Ordering::Release);
        assert_eq!(super::to_ascii_name("почта.рф").as_deref(), Some("xn--80a1acny.xn--p1ai"));
    }

    #[test]
    fn dns_records_are_freeable_by_dnsapi() {
        use windows_sys::Win32::NetworkManagement::Dns::{
            DnsCharSetAnsi, DnsCharSetUnicode, DnsFreeRecordList, DNS_RECORDA, DNS_RECORDW, DNS_TYPE_A, DNS_TYPE_AAAA,
        };
        type CopyFn = unsafe extern "system" fn(*const DNS_RECORDW, i32, i32) -> *mut std::ffi::c_void;
        type FreeFn = unsafe extern "system" fn(*const std::ffi::c_void, i32);
        let dnsapi = unsafe { super::LoadLibraryA(c"dnsapi.dll".as_ptr() as *const u8) };
        assert!(!dnsapi.is_null());
        let copy: CopyFn = unsafe { std::mem::transmute(super::proc_addr(dnsapi, c"DnsRecordSetCopyEx").unwrap()) };
        let free: FreeFn = unsafe { std::mem::transmute(super::proc_addr(dnsapi, c"DnsFree").unwrap()) };

        let name: Vec<u16> = "example.com".encode_utf16().chain(std::iter::once(0)).collect();
        let record = super::build_record(&name, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        let out = unsafe { copy(&record, DnsCharSetUnicode, DnsCharSetAnsi) } as *mut DNS_RECORDA;
        assert!(!out.is_null());
        unsafe {
            let got = &*out;
            assert!(got.pNext.is_null());
            assert_eq!(got.wType, DNS_TYPE_A);
            assert_eq!(got.wDataLength, 4);
            assert_eq!(got.Data.A.IpAddress.to_ne_bytes(), [93, 184, 216, 34]);
            let shown = std::ffi::CStr::from_ptr(got.pName as *const std::ffi::c_char);
            assert_eq!(shown.to_str().unwrap(), "example.com");
            free(out as *const std::ffi::c_void, DnsFreeRecordList);
        }

        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let record = super::build_record(&name, IpAddr::V6(v6));
        let out = unsafe { copy(&record, DnsCharSetUnicode, DnsCharSetUnicode) } as *mut DNS_RECORDW;
        assert!(!out.is_null());
        unsafe {
            let got = &*out;
            assert_eq!(got.wType, DNS_TYPE_AAAA);
            assert_eq!(got.wDataLength, 16);
            let octets = std::ptr::read_unaligned(&got.Data as *const _ as *const [u8; 16]);
            assert_eq!(octets, v6.octets());
            free(out as *const std::ffi::c_void, DnsFreeRecordList);
        }
    }

    #[test]
    fn dns_query_intercepts_only_addresses() {
        use windows_sys::Win32::NetworkManagement::Dns::DNS_QUERY_NO_WIRE_QUERY;
        // MX и прочие типы — не наше дело; «только кеш» в сеть не ходит.
        assert_eq!(super::dns_query_plan(Some("example.com"), 15, 0, std::ptr::null()), Plan::PassThrough);
        assert_eq!(
            super::dns_query_plan(Some("example.com"), 1, DNS_QUERY_NO_WIRE_QUERY, std::ptr::null()),
            Plan::PassThrough
        );
        // Любой ненулевой указатель: содержимое pExtra мы не читаем.
        let extra = std::ptr::NonNull::<std::ffi::c_void>::dangling().as_ptr() as *const std::ffi::c_void;
        assert_eq!(super::dns_query_plan(Some("example.com"), 1, 0, extra), Plan::PassThrough);
    }

    #[test]
    fn strings_from_the_caller_are_bounded() {
        let wide: Vec<u16> = "example.com".encode_utf16().chain(std::iter::once(0)).collect();
        assert_eq!(unsafe { super::wide_to_string(wide.as_ptr()) }.as_deref(), Some("example.com"));
        assert_eq!(unsafe { super::ansi_to_string(c"example.com".as_ptr() as *const u8) }.as_deref(), Some("example.com"));
        assert_eq!(unsafe { super::utf8_to_string(c"почта.рф".as_ptr() as *const u8) }.as_deref(), Some("почта.рф"));
        assert_eq!(unsafe { super::wide_to_string(std::ptr::null()) }, None);
        let endless = vec![b'a'; 2000].into_iter().chain(std::iter::once(0)).collect::<Vec<u8>>();
        assert_eq!(unsafe { super::ansi_to_string(endless.as_ptr()) }, None);
    }
}

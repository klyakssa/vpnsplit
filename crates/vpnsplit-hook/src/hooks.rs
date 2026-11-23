//! Перехваты: сокеты и создание процессов.

use crate::{dns, log, BOUND, IFINDEX, INIT_OFFSET, SELF_PATH};
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use vpnsplit_core::hook::status;
use vpnsplit_core::InterfaceIndex;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, HANDLE};
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, WSASetLastError, ADDRINFOA, ADDRINFOW, AF_INET, AF_INET6,
    AF_UNSPEC, AI_CANONNAME, AI_NUMERICHOST, INVALID_SOCKET, IPPROTO_IP, IPPROTO_IPV6,
    IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET, SOCKET_ERROR,
    WSAENETUNREACH, WSAPROTOCOL_INFOW, WSATRY_AGAIN,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Threading::{ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION};

static ORIG_WSASOCKETW: AtomicUsize = AtomicUsize::new(0);
static ORIG_SOCKET: AtomicUsize = AtomicUsize::new(0);
static ORIG_BIND: AtomicUsize = AtomicUsize::new(0);
static ORIG_CONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSACONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATE_PROCESS: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETADDRINFOW: AtomicUsize = AtomicUsize::new(0);
static ORIG_GETADDRINFOA: AtomicUsize = AtomicUsize::new(0);

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

    for (target, detour, slot) in targets {
        if !unsafe { hook(target, detour, slot) } {
            IFINDEX.store(0, Ordering::SeqCst);
            return status::CREATE_HOOK;
        }
    }

    // Потомки — не обязательная часть: без неё однопроцессные приложения
    // всё равно работают, поэтому сбой здесь только пишется в журнал.
    let kernelbase = unsafe { LoadLibraryA(c"kernelbase.dll".as_ptr() as *const u8) };
    match (!kernelbase.is_null()).then(|| proc_addr(kernelbase, c"CreateProcessInternalW")).flatten() {
        Some(target) => {
            if !unsafe { hook(target, hook_create_process as *mut c_void, &ORIG_CREATE_PROCESS) } {
                log::write("потомки: не удалось перехватить CreateProcessInternalW");
            }
        }
        None => log::write("потомки: в kernelbase нет CreateProcessInternalW"),
    }

    if unsafe { minhook::MinHook::enable_all_hooks() }.is_err() {
        IFINDEX.store(0, Ordering::SeqCst);
        return status::ENABLE_HOOK;
    }
    status::OK
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
    if !token.is_null() {
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
            log::write(&format!(
                "потомок pid {}: пропущен — отдельный токен (песочница)",
                (*process_info).dwProcessId
            ));
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
    let offset = INIT_OFFSET.load(Ordering::Relaxed);
    match vpnsplit_inject::inject(info.hProcess, dll, offset, index) {
        Ok(()) => log::write(&format!("потомок pid {}: хуки установлены", info.dwProcessId)),
        Err(err) => log::write(&format!("потомок pid {}: НЕ внедрено — {err}", info.dwProcessId)),
    }
}

// ---------- имена ----------

/// Что подставить вместо имени: готовый адрес и подсказки с пометкой
/// «это уже число».
struct Substitute {
    address: String,
    hints: ADDRINFOW,
}

/// Как поступить с запросом имени.
enum Plan {
    /// Не наше дело — зовём оригинал как есть.
    PassThrough,
    /// Разрешили сами, подставляем адрес.
    Replace(Substitute),
    /// Туннеля нет. Отдать имя системе значит отправить его домашнему
    /// роутеру, поэтому отказываем: приложение получит ошибку, а не утечку.
    Refuse,
}

/// Решает, брать ли имя на себя, и если да — разрешает его через туннель.
///
/// Результат отдаётся не структурой `addrinfo`, а строкой с адресом:
/// структуру построит сама Windows, когда мы позовём оригинал с этим
/// адресом и флагом `AI_NUMERICHOST`. Иначе её пришлось бы выделять нам,
/// а освобождал бы её `FreeAddrInfoW` — чужим аллокатором по чужим
/// правилам. Цена решения в том, что приложение получает один адрес вместо
/// списка; за ней мы следим, но менять владение памятью в чужом процессе
/// ради второго адреса — плохой размен.
fn substitute(host: Option<String>, hints: Option<&ADDRINFOW>) -> Plan {
    let index = IFINDEX.load(Ordering::Relaxed);
    if index == 0 {
        return Plan::PassThrough;
    }
    let Some(host) = host else {
        return Plan::PassThrough;
    };
    let name = host.trim();
    if name.is_empty() {
        return Plan::PassThrough;
    }
    // Имя без точки — это имя в локальной сети (NetBIOS, суффиксы домена).
    // Публичный резолвер о нём не знает, и спрашивать его бессмысленно.
    if !name.contains('.') {
        return Plan::PassThrough;
    }
    // mDNS: только в своей сети, через туннель не работает.
    if name.to_ascii_lowercase().ends_with(".local") {
        return Plan::PassThrough;
    }
    // Уже адрес — разрешать нечего.
    if name.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
        return Plan::PassThrough;
    }

    let mut copy: ADDRINFOW = match hints {
        Some(given) => *given,
        None => unsafe { std::mem::zeroed() },
    };
    // Приложение само сказало «это число» — значит, имени здесь и нет.
    if copy.ai_flags & AI_NUMERICHOST as i32 != 0 {
        return Plan::PassThrough;
    }

    // IPv6 спрашиваем, только если его прямо попросили: на этой машине он
    // не маршрутизируется, и адрес AAAA приложению ничего не даст.
    let qtype = if copy.ai_family == AF_INET6 as i32 {
        dns::TYPE_AAAA
    } else {
        dns::TYPE_A
    };

    let answer = match dns::resolve(name, qtype, index) {
        dns::Outcome::Found(answer) => answer,
        dns::Outcome::NoAnswer => return Plan::PassThrough,
        dns::Outcome::TunnelGone => {
            log::write(&format!("dns: {name} не разрешено — туннеля нет"));
            return Plan::Refuse;
        }
    };
    log::write(&format!(
        "dns: {name} -> {} (с адреса {}, сервер {}, {} мс)",
        answer.address,
        answer.source.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
        answer.server,
        answer.millis
    ));

    copy.ai_flags |= AI_NUMERICHOST as i32;
    // Канонического имени у числа нет, а просьба его вернуть сделала бы
    // ещё один запрос — уже системный.
    copy.ai_flags &= !(AI_CANONNAME as i32);
    Plan::Replace(Substitute { address: answer.address.to_string(), hints: copy })
}

unsafe fn wide_to_string(text: *const u16) -> Option<String> {
    if text.is_null() {
        return None;
    }
    let mut len = 0;
    while *text.add(len) != 0 {
        len += 1;
        if len > 1024 {
            return None;
        }
    }
    String::from_utf16(std::slice::from_raw_parts(text, len)).ok()
}

unsafe fn ansi_to_string(text: *const u8) -> Option<String> {
    if text.is_null() {
        return None;
    }
    let mut len = 0;
    while *text.add(len) != 0 {
        len += 1;
        if len > 1024 {
            return None;
        }
    }
    let bytes = std::slice::from_raw_parts(text, len);
    // Имена для DNS всё равно должны быть ASCII; если здесь что-то иное,
    // разбираться с кодовой страницей — не наша работа.
    bytes.is_ascii().then(|| String::from_utf8_lossy(bytes).into_owned())
}

unsafe extern "system" fn hook_getaddrinfow(
    node: *const u16,
    service: *const u16,
    hints: *const ADDRINFOW,
    result: *mut *mut ADDRINFOW,
) -> i32 {
    let original: GetAddrInfoWFn = std::mem::transmute(ORIG_GETADDRINFOW.load(Ordering::Acquire));
    let plan = catch_unwind(AssertUnwindSafe(|| {
        substitute(wide_to_string(node), hints.as_ref())
    }))
    .unwrap_or(Plan::PassThrough);

    match plan {
        Plan::Replace(found) => {
            let address: Vec<u16> = found
                .address
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            original(address.as_ptr(), service, &found.hints, result)
        }
        Plan::Refuse => WSATRY_AGAIN,
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
    // Поля ANSI- и широкой структуры совпадают по смыслу и по раскладке,
    // кроме указателя на каноническое имя, который мы не трогаем.
    let wide_hints = hints.as_ref().map(|given| {
        let mut copy: ADDRINFOW = std::mem::zeroed();
        copy.ai_flags = given.ai_flags;
        copy.ai_family = given.ai_family;
        copy.ai_socktype = given.ai_socktype;
        copy.ai_protocol = given.ai_protocol;
        copy
    });
    let plan = catch_unwind(AssertUnwindSafe(|| {
        substitute(ansi_to_string(node), wide_hints.as_ref())
    }))
    .unwrap_or(Plan::PassThrough);

    match plan {
        Plan::Replace(found) => {
            let address: Vec<u8> = found
                .address
                .bytes()
                .chain(std::iter::once(0))
                .collect();
            let mut narrow: ADDRINFOA = std::mem::zeroed();
            narrow.ai_flags = found.hints.ai_flags;
            narrow.ai_family = found.hints.ai_family;
            narrow.ai_socktype = found.hints.ai_socktype;
            narrow.ai_protocol = found.hints.ai_protocol;
            original(address.as_ptr(), service, &narrow, result)
        }
        Plan::Refuse => WSATRY_AGAIN,
        Plan::PassThrough => original(node, service, hints, result),
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
/// принтер и NAS, а Edge со своим DNS-клиентом теряет ~2 с на каждый
/// запрос к роутеру, который уходит в VPN и там пропадает.
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
}

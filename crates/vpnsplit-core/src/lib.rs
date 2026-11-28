//! Общие типы vpnsplit: правила, протокол IPC, работа с индексами интерфейсов.
//!
//! Крейт намеренно без внешних зависимостей — он подключается и к службе,
//! и к UI, и к probe. Платформенный код живёт в крейтах-потребителях.

#![deny(unsafe_code)]

pub mod iface;
pub mod ipc;
pub mod ovpn;
pub mod policy;

pub use iface::InterfaceIndex;
pub use ipc::{
    describe_traffic, Event, Login, Request, Response, RuleTraffic, Secret, Status, TunnelInfo,
    TunnelState, VpnAction, VpnState,
};
pub use policy::{AppRule, AppTarget, Mechanism, Mode, Policy, Routing};

/// Имя named pipe службы.
pub const PIPE_NAME: &str = r"\\.\pipe\vpnsplit";

/// Имя службы Windows.
pub const SERVICE_NAME: &str = "vpnsplit";

/// Контракт между лончером и `vpnsplit-hook.dll`.
pub mod hook {
    /// Имя библиотеки, которую лончер ищет рядом с собой.
    pub const DLL_NAME: &str = "vpnsplit_hook.dll";

    /// Экспорт, который лончер вызывает в целевом процессе после загрузки DLL.
    /// Хуки ставятся здесь, а не в DllMain: в DllMain держится loader lock.
    pub const INIT_EXPORT: &str = "vpnsplit_hook_init";

    /// Экспорт-данные: 32-битный признак «хуки поставлены», не ноль после
    /// успешного `vpnsplit_hook_init`. Служба читает его через
    /// ReadProcessMemory: загруженная DLL ещё не значит, что хуки стоят, —
    /// потомка с несработавшим init hook.dll всё равно отпускает работать.
    pub const READY_EXPORT: &str = "vpnsplit_hook_ready";

    /// Переменная окружения с индексом интерфейса туннеля. Запасной путь:
    /// основной — параметр `vpnsplit_hook_init`. Дочерние процессы могут
    /// получить урезанное окружение, и тогда переменная до них не дойдёт.
    pub const IFINDEX_ENV: &str = "VPNSPLIT_IFINDEX";

    /// Путь к журналу hook.dll. Если переменной нет, журнал не пишется.
    pub const LOG_ENV: &str = "VPNSPLIT_LOG";

    /// DNS-серверы IPv4 через запятую — их hook.dll спрашивает первыми
    /// (через туннель), затем DNS адаптера туннеля и `DEFAULT_DNS`.
    ///
    /// Обычно её кладёт лончер: это `dhcp-option DNS`, который сервер VPN
    /// назначил подключению. Сам OpenVPN на TAP эти адреса не применяет, и
    /// без переменной hook.dll о них не узнал бы, а многие VPN режут порт 53
    /// к публичным резолверам. Уже заданное значение лончер не теряет, а
    /// ставит после DNS подключения.
    /// Домашний роутер сюда не годится: через туннель он недоступен, да и
    /// спрашивать его значило бы ровно ту утечку, от которой мы уходим.
    pub const DNS_ENV: &str = "VPNSPLIT_DNS";

    /// Куда идти за именами, если DNS VPN не ответил или его нет.
    pub const DEFAULT_DNS: [[u8; 4]; 2] = [[1, 1, 1, 1], [8, 8, 8, 8]];

    /// Коды возврата `vpnsplit_hook_init` (код завершения удалённого потока).
    pub mod status {
        pub const OK: u32 = 0;
        pub const NO_ENV: u32 = 1;
        pub const BAD_ENV: u32 = 2;
        pub const NO_WS2: u32 = 3;
        pub const NO_EXPORT: u32 = 4;
        pub const CREATE_HOOK: u32 = 5;
        pub const ENABLE_HOOK: u32 = 6;
        pub const PANIC: u32 = 0xFFFF;

        pub fn describe(code: u32) -> &'static str {
            match code {
                OK => "хуки установлены",
                NO_ENV => "в окружении процесса нет индекса интерфейса",
                BAD_ENV => "индекс интерфейса в окружении не число",
                NO_WS2 => "не удалось загрузить ws2_32.dll",
                NO_EXPORT => "в ws2_32.dll нет нужных функций",
                CREATE_HOOK => "MinHook не смог создать хук",
                ENABLE_HOOK => "MinHook не смог включить хук",
                PANIC => "паника внутри hook.dll",
                _ => "неизвестный код",
            }
        }
    }
}

/// Build number: digits of the release date and time, or zero for a development build.
/// The service compares it with the release on GitHub; the window compares it with the service.
pub const BUILD: u64 = parse_build(env!("VPNSPLIT_BUILD_NUMBER"));

const fn parse_build(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let mut number = 0u64;
    let mut at = 0;
    while at < bytes.len() {
        number = number * 10 + (bytes[at] - b'0') as u64;
        at += 1;
    }
    number
}

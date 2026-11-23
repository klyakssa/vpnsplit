//! Протокол между UI, лончером и службой.
//!
//! Транспорт — named pipe, по строке JSON на сообщение. Обычное соединение:
//! клиент шлёт `Request`, служба отвечает `Response`, и так сколько угодно
//! раз. После `Subscribe` служба отвечает `Ok` и дальше только присылает
//! `Event`, по одному на строку, пока клиент не закроет канал. Читать
//! из такого соединения больше не нужно и нельзя: на синхронном хэндле
//! Windows выполняет чтение и запись строго по очереди, и висящее чтение
//! заблокировало бы доставку событий.

use crate::policy::{AppTarget, Policy};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Request {
    GetStatus,
    GetPolicy,
    SetPolicy(Policy),
    /// Переключиться в режим подписки на события. Отписка — закрыть канал.
    Subscribe,
    /// Своё подключение: служба сама держит туннель OpenVPN по этому
    /// конфигу, пока в списке есть хоть одно приложение. Присылается текст
    /// `.ovpn` как он есть; что из него дойдёт до OpenVPN, решает служба
    /// (см. `ovpn::sanitize`).
    ///
    /// `key_password` — пароль закрытого ключа, если ключ им защищён.
    /// Служба хранит его рядом с конфигом и отдаёт OpenVPN сама: под
    /// службой спросить его не у кого, а подключаться надо и при старте
    /// Windows, когда никто ещё не вошёл.
    ///
    /// `name` — имя подключения: их может быть несколько, и приложению
    /// назначается одно из них по имени. Подключение с таким именем
    /// заменяется. `login` — логин и пароль, если сервер их спрашивает.
    SetVpnConfig {
        #[serde(default)]
        name: Option<String>,
        config: Secret,
        #[serde(default)]
        key_password: Option<Secret>,
        #[serde(default)]
        login: Option<Login>,
    },
    /// Забыть подключение с этим именем и опустить его. Без имени — все.
    ClearVpnConfig {
        #[serde(default)]
        name: Option<String>,
    },
    /// Одноразовый код для подключения, сервер которого ждёт его при
    /// каждом входе: подключиться с ним сейчас. Код нигде не хранится.
    ConnectVpn { name: String, code: Secret },
    /// Подключить, отключить или сделать подключением по умолчанию.
    VpnAction { name: String, action: VpnAction },
    /// Сменить логин и пароль подключения, не трогая его конфиг.
    SetVpnLogin { name: String, login: Login },
    /// Проверка kill-switch: закрыть приложению сеть на несколько секунд,
    /// не дожидаясь падения туннеля. Защита, которую нельзя проверить, —
    /// это обещание, а не защита.
    CheckKillswitch(PathBuf),
    /// Путь B, наблюдение: несколько секунд слушать события сокетов через
    /// WinDivert и записывать в журнал, кто их открывает. Только чтение.
    ProbeDivert { seconds: u32 },
    /// Путь B, наблюдение за потоками: открытие и закрытие с полной
    /// пятёркой. Отсюда берётся таблица «чей это поток». Только чтение.
    ProbeFlows { seconds: u32 },
    /// Путь B, опыт перенаправления: на несколько секунд перехватить обмен
    /// с одним адресом и подменить в нём адрес источника на адрес туннеля.
    /// Фильтр сужен до этого адреса — больше ничего пострадать не может.
    Reroute { target: String, seconds: u32 },
    /// Путь B целиком: приложение и всё, что оно запускает, на заданное
    /// число секунд уходит в туннель. `target` — подстрока пути к образу
    /// или имени семейства пакета.
    PathB { target: String, seconds: u32 },
    /// Этап 12: кто спрашивает имена. Несколько секунд слушать провайдер
    /// `DNS-Client` и записать, в контексте какого процесса приходят его
    /// события. Только чтение.
    ProbeDns { seconds: u32 },
    /// Этап 12, вопрос решающий: успевает ли привязка к процессу прийти
    /// раньше, чем запрос имени уходит на провод. Только чтение.
    ProbeDnsRace { seconds: u32 },
    /// Проверка отказа без туннеля: движок на несколько секунд делает вид,
    /// что туннеля нет, и пакеты выбранных приложений выбрасываются.
    ///
    /// Зачем это нужно отдельной командой — по той же причине, что и
    /// `CheckKillswitch`: иначе убедиться, что утечки нет, можно было бы
    /// только в момент настоящего падения туннеля, то есть когда проверять
    /// уже поздно. А отключить VPN ради проверки нельзя, если по нему же
    /// идёт работа.
    CheckNoTunnel { seconds: u32 },
    /// Этап 12, UDP: успевает ли событие о новом потоке прийти раньше его
    /// первого пакета и сколько вообще исходящего UDP на машине. От этих
    /// двух чисел зависит устройство перехвата UDP. Только чтение.
    ProbeUdp { seconds: u32 },
    /// Этап 12, запускатели: с каким опозданием доходит событие о запуске
    /// процесса при разных настройках доставки. Ничего не перехватывает:
    /// служба запускает пустые процессы и засекает время до события.
    ProbeFlush { rounds: u32 },
}

impl Request {
    /// Требует ли запрос прав администратора.
    ///
    /// Граница проведена по тому, что запрос может сделать **чужому**
    /// трафику. Читать состояние и править список должен уметь обычный
    /// пользователь: окно программы работает без повышения прав, и
    /// требовать администратора на каждое добавление приложения значило бы
    /// сделать программу непригодной. Всё остальное — проверки и опыты —
    /// перехватывает пакеты, отрезает приложения от сети или подменяет
    /// маршрут на время, и звать это любой программе вошедшего пользователя
    /// нельзя.
    ///
    /// Перечислено без «прочее»: новый запрос не скомпилируется, пока его
    /// не отнесут к одной из сторон.
    pub fn privileged(&self) -> bool {
        match self {
            Request::GetStatus | Request::GetPolicy | Request::SetPolicy(_) | Request::Subscribe => {
                false
            }
            // Конфиг выбирают в окне, а окно работает без повышения прав.
            // Цена этого решения — в том, что служба запускает OpenVPN под
            // SYSTEM по тексту от обычного пользователя, и уплачена она
            // разбором: до OpenVPN доходит только то, что не запускает
            // программ и не трогает файлов. Сделать чужому трафику этот
            // запрос может не больше, чем правка списка: решить, куда
            // пойдут выбранные приложения.
            Request::SetVpnConfig { .. }
            | Request::ClearVpnConfig { .. }
            | Request::ConnectVpn { .. }
            | Request::VpnAction { .. }
            | Request::SetVpnLogin { .. } => false,
            Request::CheckKillswitch(_)
            | Request::ProbeDivert { .. }
            | Request::ProbeFlows { .. }
            | Request::Reroute { .. }
            | Request::PathB { .. }
            | Request::ProbeDns { .. }
            | Request::ProbeDnsRace { .. }
            | Request::CheckNoTunnel { .. }
            | Request::ProbeUdp { .. }
            // Чужого трафика не трогает, но заставляет службу под SYSTEM
            // запускать процессы и заводить сеанс ETW — не дело каждой
            // программы вошедшего пользователя.
            | Request::ProbeFlush { .. } => true,
        }
    }
}

/// Текст с ключами. В канале это обычная строка, а вот напечатать его
/// нельзя ни в журнал, ни в сообщение об ошибке: `{:?}` показывает только
/// размер. Запросы службы печатаются — например, при отказе без прав, — и
/// полагаться на то, что этот никто никогда не напечатает, незачем.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "‹скрыто, {} байт›", self.0.len())
    }
}

/// Логин и пароль для сервера, который их спрашивает.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Login {
    pub user: Secret,
    pub password: Secret,
}

/// Что человек велит своему подключению.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum VpnAction {
    /// Подключаться снова (после «отключить»).
    Connect,
    /// Опустить и не поднимать, пока человек не включит. Приложения этого
    /// подключения остаются без сети — утечки нет.
    Disconnect,
    /// Вести через него приложения, которым подключение не выбрано.
    MakeDefault,
}

/// Одно своё подключение глазами службы.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct VpnState {
    /// Имя, которым подключение назначают приложениям.
    pub name: String,
    /// Что с ним сейчас, одной строкой: сервер и состояние.
    pub line: String,
    /// Туннель поднят и приложения по нему идут.
    pub connected: bool,
    /// Адрес, с которым приложения этого подключения выходят в туннель.
    #[serde(default)]
    pub address: Option<Ipv4Addr>,
    /// Сервер ждёт одноразовый код при каждом входе: само такое
    /// подключение не поднимется, код даёт человек.
    #[serde(default)]
    pub by_code: bool,
    /// Отключено человеком: само не поднимется.
    #[serde(default)]
    pub off: bool,
    /// Входит по логину и паролю — их можно сменить, не трогая конфиг.
    #[serde(default)]
    pub login: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Status(Status),
    Policy(Policy),
    Error(String),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Event {
    TunnelChanged(TunnelState),
    PolicyChanged(Policy),
    /// Приложение из списка запущено и перехвачено.
    ProcessAttached { pid: u32, target: AppTarget },
    ProcessGone { pid: u32 },
    /// Приложение из списка работает, но запущено мимо лончера, поэтому
    /// в туннель не попадает. UI обязан показать это явно.
    ProcessUnhooked { pid: u32, image: PathBuf },
    /// Изменилось, под какими правилами «приложение и все его потомки»
    /// сейчас есть хоть один процесс. Список полный, а не разница: окну не
    /// надо помнить прошлое, чтобы показать настоящее.
    ///
    /// Приходит только когда правило переходит между «никого» и «кто-то
    /// есть», а не на каждый процесс: браузер заводит и гасит их десятками,
    /// и будить окно ради числа, которого оно не показывает, незачем.
    SupervisedChanged(Vec<AppTarget>),
    /// Свои подключения изменили состояние: список тот же, что в
    /// `Status::vpns`, целиком.
    VpnChanged(Vec<VpnState>),
}

/// Поднятый туннель. Владеет им не vpnsplit, а OpenVPN, поэтому всё, что мы
/// о нём знаем, — какой это интерфейс и какой у него адрес.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TunnelInfo {
    /// Индекс интерфейса для `IP_UNICAST_IF`. Меняется при переподключении.
    pub index: u32,
    pub name: String,
    pub ipv4: Option<Ipv4Addr>,
    /// На интерфейсе туннеля стоят маршруты `0.0.0.0/1` и `128.0.0.0/1`
    /// (`redirect-gateway def1` у OpenVPN или чужая программа). Они точнее
    /// маршрута по умолчанию, поэтому в VPN уходит весь трафик, и раздельное
    /// туннелирование фактически не работает. Пользователь должен это видеть.
    #[serde(default)]
    pub captures_all: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TunnelState {
    Down,
    Up(TunnelInfo),
}

impl TunnelState {
    /// Описание для людей: журнал, `status`, лончер.
    pub fn describe(&self) -> String {
        match self {
            TunnelState::Down => "не поднят".to_owned(),
            TunnelState::Up(info) => {
                let mut text = format!(
                    "«{}», индекс {}, адрес {}",
                    info.name,
                    info.index,
                    info.ipv4.map(|a| a.to_string()).unwrap_or_default()
                );
                if info.captures_all {
                    text.push_str(
                        " — ВНИМАНИЕ: на нём маршруты 0.0.0.0/1 и 128.0.0.0/1, в VPN идёт весь трафик системы",
                    );
                }
                text
            }
        }
    }

    pub fn info(&self) -> Option<&TunnelInfo> {
        match self {
            TunnelState::Up(info) => Some(info),
            TunnelState::Down => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Status {
    pub tunnel: TunnelState,
    pub rules: usize,
    pub attached_processes: usize,
    /// Поднят ли путь B. Ложь означает, что WinDivert не загружен и не стоит ничего.
    pub divert_active: bool,
    /// Что путь B делает прямо сейчас, одной строкой: кого ведёт, сколько
    /// у него потоков и есть ли туннель. `None` — не поднят.
    #[serde(default)]
    pub divert: Option<String>,
    /// Правила «приложение и все его потомки», под которыми прямо сейчас
    /// есть хоть один процесс. Поднятый перехват ещё не значит, что
    /// приложение ведётся: программу могли запустить до правила или до
    /// перезапуска службы, значок-запускатель мог лишь разбудить уже
    /// открытый экземпляр. Именно так исходная утечка с запускателем
    /// осталась незамеченной — окно писало «ведётся» при нуле процессов.
    #[serde(default)]
    pub supervised: Vec<AppTarget>,
    /// Приложения, которым закрыта сеть (кроме локальной) на всё время,
    /// пока служба не работает: постоянные запреты, переживающие службу.
    /// Сюда входят и программы, которых в списке нет по имени, но которые
    /// служба видела под правилами «приложение и все его потомки».
    #[serde(default)]
    pub standing: Vec<PathBuf>,
    /// Программы, которые служба видела под правилом, но которые работают
    /// и сами по себе (`git`, запущенный приложением из списка). Им сеть на
    /// время простоя службы **не** закрывается — и это надо показывать, а
    /// не подразумевать: без службы они ходят домашним интернетом.
    #[serde(default)]
    pub alone: Vec<PathBuf>,
    /// Что процессы каждого правила пути B делали в сети с запуска службы
    /// и сколько из этого уведено в туннель.
    #[serde(default)]
    pub traffic: Vec<RuleTraffic>,
    /// Стоят ли запреты kill-switch: туннеля нет, и приложениям из списка
    /// закрыта сеть. Ложь при опущенном туннеле означает, что защиты нет —
    /// например, движок фильтрации не открылся.
    #[serde(default)]
    pub killswitch: bool,
    /// Свои подключения OpenVPN, в порядке их добавления; первое —
    /// подключение по умолчанию. Пусто — туннель поднимает другая
    /// программа.
    #[serde(default)]
    pub vpns: Vec<VpnState>,
    /// Номер сборки службы; ноль — сборка для разработки. Окно, увидев
    /// службу новее себя, перезапускается: обновление заменило и его файл.
    #[serde(default)]
    pub build: u64,
}

/// Сеть одного правила «приложение и все его потомки» глазами службы.
///
/// Смысл — в сравнении `connects` и `led`: первое говорит, сколько
/// соединений наружу процессы правила открыли, второе — сколько из них
/// служба увела в туннель. Разница — соединения, прошедшие мимо неё.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RuleTraffic {
    pub target: AppTarget,
    /// Сколько процессов правила ходило в сеть.
    pub processes: u64,
    /// Соединений TCP наружу по IPv4.
    pub connects: u64,
    /// Из них уведено в туннель.
    pub led: u64,
    /// Прошло через руки службы с домашним адресом и отпущено: процесс в
    /// тот миг ещё не был опознан. Это соединения мимо туннеля.
    #[serde(default)]
    pub past: u64,
    /// Открыто процессами до того, как они попали под правило (правило
    /// добавили при открытом приложении). Идут как шли до перезапуска.
    #[serde(default)]
    pub before: u64,
    /// Соединений по IPv6 — их служба не ведёт.
    pub v6: u64,
    /// Соединений в свою сеть — их не уводят намеренно.
    pub local: u64,
    /// Портов UDP, уведённых в туннель.
    pub udp: u64,
}

impl RuleTraffic {
    /// Соединений наружу, которые служба не увела.
    pub fn missed(&self) -> u64 {
        self.connects.saturating_sub(self.led)
    }

    /// Соединений, начало которых до службы не дошло: ни уведено, ни
    /// отпущено. Их забрала другая программа перехвата, стоящая раньше
    /// службы, либо они не состоялись.
    pub fn unseen(&self) -> u64 {
        self.connects.saturating_sub(self.led).saturating_sub(self.past)
    }

    pub fn describe(&self) -> String {
        describe_traffic(
            self.connects,
            self.led,
            self.past,
            self.before,
            self.v6,
            self.local,
            self.udp,
        )
    }
}

/// Счётчики соединений одной строкой — одними словами в журнале службы и в
/// `status`.
///
/// Три исхода соединения наружу названы порознь, потому что значат разное.
/// «Уведено» — служба сделала своё дело. «МИМО ТУННЕЛЯ» — утечка, и она
/// написана так, чтобы её нельзя было пропустить глазами. «До службы не
/// дошло» — не утечка и не успех: начало соединения забрал кто-то раньше
/// службы, и ручаться за него она не может. Пока второе и третье были одним
/// числом «не уведено», чужой перехват выглядел утечкой.
///
/// Четвёртое число, `before`, стоит отдельно и в конце: это соединения,
/// открытые до того, как приложение попало под правило. Они не исход
/// работы правила, но человек должен знать, что они есть и что лечатся
/// перезапуском приложения.
pub fn describe_traffic(
    connects: u64,
    led: u64,
    past: u64,
    before: u64,
    v6: u64,
    local: u64,
    udp: u64,
) -> String {
    let unseen = connects.saturating_sub(led).saturating_sub(past);
    let mut text = format!("соединений наружу {connects}, уведено в туннель {led}");
    if past > 0 {
        text.push_str(&format!(" — МИМО ТУННЕЛЯ {past}"));
    }
    if unseen > 0 {
        text.push_str(&format!(", до службы не дошло {unseen}"));
    }
    text.push_str(&format!("; по IPv6 {v6}, в свою сеть {local}, портов UDP {udp}"));
    if before > 0 {
        text.push_str(&format!(
            "; открыто до правила {before} — идут как шли, пока приложение не перезапустят"
        ));
    }
    text
}

impl Status {
    pub fn is_up(&self) -> bool {
        matches!(self.tunnel, TunnelState::Up(_))
    }
}

impl Default for Status {
    fn default() -> Self {
        Self {
            tunnel: TunnelState::Down,
            rules: 0,
            attached_processes: 0,
            divert_active: false,
            divert: None,
            supervised: Vec::new(),
            standing: Vec::new(),
            alone: Vec::new(),
            traffic: Vec::new(),
            killswitch: false,
            vpns: Vec::new(),
            build: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up() -> TunnelState {
        TunnelState::Up(TunnelInfo {
            index: 8,
            name: "OpenVPN TAP-Windows6".to_owned(),
            ipv4: Some(Ipv4Addr::new(10, 5, 5, 2)),
            captures_all: false,
        })
    }

    #[test]
    fn fresh_status_is_down() {
        let status = Status::default();
        assert!(!status.is_up());
        assert!(status.tunnel.info().is_none());
    }

    #[test]
    fn a_status_from_an_older_service_still_parses() {
        // Окно и служба обновляются не одновременно: состояние без нового
        // поля должно читаться, а не рвать связь.
        let old = r#"{"tunnel":"Down","rules":1,"attached_processes":0,"divert_active":true}"#;
        let status: Status = serde_json::from_str(old).unwrap();
        assert!(status.divert_active);
        assert!(status.supervised.is_empty());
    }

    #[test]
    fn supervised_rules_travel_both_ways() {
        let target = AppTarget::Executable(PathBuf::from(r"C:\Users\k\Desktop\Firefox.exe"));
        let status = Status { supervised: vec![target.clone()], ..Status::default() };
        let text = serde_json::to_string(&status).unwrap();
        assert_eq!(serde_json::from_str::<Status>(&text).unwrap(), status);

        let event = Event::SupervisedChanged(vec![target]);
        let text = serde_json::to_string(&event).unwrap();
        assert!(!text.contains('\n'), "{text}");
        assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), event);
        // Пустой список — тоже сообщение: «больше никого».
        let nobody = Event::SupervisedChanged(Vec::new());
        let text = serde_json::to_string(&nobody).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), nobody);
    }

    #[test]
    fn up_state_carries_the_index() {
        let status = Status { tunnel: up(), ..Status::default() };
        assert!(status.is_up());
        assert_eq!(status.tunnel.info().unwrap().index, 8);
    }

    #[test]
    fn messages_fit_on_one_json_line() {
        // Протокол построчный: перевод строки внутри сообщения сломал бы разбор.
        let messages = [
            serde_json::to_string(&Request::GetStatus).unwrap(),
            serde_json::to_string(&Response::Status(Status { tunnel: up(), ..Status::default() })).unwrap(),
            serde_json::to_string(&Event::TunnelChanged(up())).unwrap(),
        ];
        for text in messages {
            assert!(!text.contains('\n'), "{text}");
        }
    }

    #[test]
    fn full_capture_is_called_out() {
        let mut state = up();
        assert!(!state.describe().contains("ВНИМАНИЕ"));
        if let TunnelState::Up(info) = &mut state {
            info.captures_all = true;
        }
        assert!(state.describe().contains("весь трафик"));
    }

    #[test]
    fn old_json_without_flag_still_parses() {
        let text = r#"{"Up":{"index":8,"name":"tap","ipv4":"10.5.5.2"}}"#;
        let state: TunnelState = serde_json::from_str(text).unwrap();
        assert!(!state.info().unwrap().captures_all);
    }

    #[test]
    fn the_window_works_without_elevation_and_experiments_do_not() {
        // То, чем пользуется окно программы, — без повышения прав.
        for open in [
            Request::GetStatus,
            Request::GetPolicy,
            Request::SetPolicy(Policy::default()),
            Request::Subscribe,
            Request::SetVpnConfig {
                name: None,
                config: Secret("client".to_owned()),
                key_password: None,
                login: None,
            },
            Request::ClearVpnConfig { name: Some("Работа".to_owned()) },
        ] {
            assert!(!open.privileged(), "{open:?}");
        }
        // Всё, что трогает чужой трафик, — только администратору.
        for closed in [
            Request::CheckKillswitch(PathBuf::from(r"C:\app.exe")),
            Request::ProbeDivert { seconds: 1 },
            Request::ProbeFlows { seconds: 1 },
            Request::Reroute { target: "1.1.1.1".to_owned(), seconds: 1 },
            Request::PathB { target: "curl".to_owned(), seconds: 1 },
            Request::ProbeDns { seconds: 1 },
            Request::ProbeDnsRace { seconds: 1 },
            Request::CheckNoTunnel { seconds: 1 },
            Request::ProbeUdp { seconds: 1 },
            Request::ProbeFlush { rounds: 1 },
        ] {
            assert!(closed.privileged(), "{closed:?}");
        }
    }

    #[test]
    fn a_leak_and_a_foreign_interceptor_are_not_one_number() {
        // Всё уведено — ни одного тревожного слова.
        let clean = describe_traffic(5, 5, 0, 0, 0, 0, 0);
        assert!(!clean.contains("МИМО") && !clean.contains("не дошло"), "{clean}");
        assert!(!clean.contains("до правила"), "{clean}");
        // Ровно то, что показала живая проверка: двенадцать соединений,
        // одно увели, одиннадцать забрал чужой перехват. Утечки нет, и
        // слова «мимо» быть не должно.
        let taken = describe_traffic(12, 1, 0, 0, 0, 0, 0);
        assert!(taken.contains("до службы не дошло 11"), "{taken}");
        assert!(!taken.contains("МИМО"), "{taken}");
        // А настоящая утечка названа отдельно и не тонет в остальном.
        let leak = describe_traffic(12, 1, 2, 0, 0, 0, 0);
        assert!(leak.contains("МИМО ТУННЕЛЯ 2"), "{leak}");
        assert!(leak.contains("до службы не дошло 9"), "{leak}");
        // Счёт отпущенных может опередить счёт открытых; минуса не бывает.
        assert!(!describe_traffic(1, 0, 3, 0, 0, 0, 0).contains("не дошло"));
    }

    #[test]
    fn what_was_open_before_the_rule_is_told_apart_from_a_leak() {
        // Вторая живая проверка, на ChatGPT: правило добавили при открытом
        // приложении, оно перезапущено, все 45 новых соединений уведены.
        let text = describe_traffic(45, 45, 0, 84, 0, 0, 11);
        assert!(text.contains("открыто до правила 84"), "{text}");
        assert!(!text.contains("МИМО"), "{text}");
    }

    #[test]
    fn a_status_from_an_older_service_has_no_leak_count() {
        let old = r#"{"target":{"Package":"A_1"},"processes":1,"connects":3,"led":3,"v6":0,"local":0,"udp":0}"#;
        let rule: RuleTraffic = serde_json::from_str(old).unwrap();
        assert_eq!((rule.past, rule.unseen(), rule.missed()), (0, 0, 0));
    }

    #[test]
    fn a_config_travels_whole_but_is_never_printed() {
        // В канале — обычная строка, со всеми переводами строк внутри.
        let request = Request::SetVpnConfig {
            name: Some("Работа".to_owned()),
            config: Secret("client\n<key>\nS3CRET\n</key>\n".to_owned()),
            key_password: Some(Secret("P4SSW0RD".to_owned())),
            login: Some(Login { user: Secret("US3R".to_owned()), password: Secret("L0G1N".to_owned()) }),
        };
        let text = serde_json::to_string(&request).unwrap();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.contains(r#""config":"client\n<key>\nS3CRET\n</key>\n""#), "{text}");
        assert_eq!(serde_json::from_str::<Request>(&text).unwrap(), request);
        // А в журнал запрос попадает без содержимого — ни ключа, ни
        // паролей, ни логина; имя подключения — не тайна.
        let printed = format!("{request:?}");
        for secret in ["S3CRET", "P4SSW0RD", "US3R", "L0G1N"] {
            assert!(!printed.contains(secret), "{printed}");
        }
        assert!(printed.contains("байт") && printed.contains("Работа"), "{printed}");
        // Всё, кроме самого конфига, можно не присылать.
        let bare: Request = serde_json::from_str(r#"{"SetVpnConfig":{"config":"client"}}"#).unwrap();
        assert_eq!(
            bare,
            Request::SetVpnConfig {
                name: None,
                config: Secret("client".to_owned()),
                key_password: None,
                login: None,
            }
        );
    }

    #[test]
    fn the_state_of_the_own_connection_is_optional_both_ways() {
        let vpn = VpnState {
            name: "Работа".to_owned(),
            line: "a:1 (udp) — подключено".to_owned(),
            connected: true,
            address: Some(Ipv4Addr::new(10, 8, 0, 6)),
            by_code: true,
            off: false,
            login: true,
        };
        let status = Status { vpns: vec![vpn.clone()], ..Status::default() };
        let text = serde_json::to_string(&status).unwrap();
        assert_eq!(serde_json::from_str::<Status>(&text).unwrap(), status);
        let event = Event::VpnChanged(vec![vpn]);
        let text = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), event);
        let event = Event::VpnChanged(Vec::new());
        let text = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), event);
    }

    #[test]
    fn event_round_trip() {
        let event = Event::TunnelChanged(up());
        let text = serde_json::to_string(&event).unwrap();
        assert_eq!(serde_json::from_str::<Event>(&text).unwrap(), event);
    }
}

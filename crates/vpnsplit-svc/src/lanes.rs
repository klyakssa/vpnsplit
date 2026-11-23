//! Дорожки: какое правило через какой туннель ведётся.
//!
//! Пока туннель был один, вопроса не стояло: всё выбранное шло в него. С
//! несколькими своими подключениями у каждого правила своя дорожка —
//! адаптер туннеля, сервер имён, который назначил этот VPN, и внутренние
//! сети, которые через него достижимы. Перехват спрашивает дорожку на
//! каждый пакет, поэтому всё, что можно посчитать заранее (адрес адаптера),
//! считается при смене сети, а не при вопросе.
//!
//! Здесь же разбирается, что сервер назначил подключению: OpenVPN пишет
//! это в журнал одной строкой (`PUSH_REPLY`). Сами маршруты и серверы имён
//! в Windows не ставятся — иначе в туннель ушла бы вся машина, — но знать
//! их надо: по ним видно, какие внутренние адреса ведут в этот VPN и кого
//! спрашивать о внутренних именах.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Куда ведётся правило.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum Via {
    /// Как раньше: в тот туннель, который найдётся на машине. Так ведётся
    /// всё, пока своих подключений нет.
    #[default]
    Auto,
    /// В туннель на этом адаптере (имя точное).
    Adapter(String),
    /// Никуда: подключение правила не поднято. Его пакеты отклоняются —
    /// отказ в связи вместо утечки.
    Nowhere,
}

/// Сеть: адрес и маска, оба числом в привычном порядке.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Net {
    pub address: u32,
    pub mask: u32,
}

impl Net {
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & self.mask == self.address & self.mask
    }
}

/// Что служба велит перехвату о правиле.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Spec {
    pub via: Via,
    /// Сервер имён этого VPN; `None` — общий публичный.
    pub resolver: Option<Ipv4Addr>,
    /// Внутренние сети, достижимые через этот VPN.
    pub inside: Vec<Net>,
}

/// Дорожка, как она есть сейчас: с адресом вместо имени адаптера.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct Lane {
    tunnel: Option<Ipv4Addr>,
    resolver: Option<Ipv4Addr>,
    inside: Vec<Net>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Lanes {
    specs: HashMap<String, Spec>,
    lanes: HashMap<String, Lane>,
    /// Туннель «какой найдётся» — для правил без своей дорожки.
    auto: Option<Ipv4Addr>,
    /// Все адреса туннелей, по которым сейчас что-то ведётся.
    tunnels: Vec<Ipv4Addr>,
}

impl Lanes {
    /// Новые указания службы. Адреса пересчитает следующий `resolve`.
    pub fn set(&mut self, specs: HashMap<String, Spec>) {
        self.specs = specs;
    }

    /// Пересчитать адреса: сеть изменилась или пришли новые указания.
    /// `address_of` — адрес поднятого адаптера по точному имени.
    pub fn resolve(&mut self, auto: Option<Ipv4Addr>, address_of: impl Fn(&str) -> Option<Ipv4Addr>) {
        self.auto = auto;
        self.lanes = self
            .specs
            .iter()
            .map(|(rule, spec)| {
                let tunnel = match &spec.via {
                    Via::Auto => auto,
                    Via::Adapter(name) => address_of(name),
                    Via::Nowhere => None,
                };
                (rule.clone(), Lane { tunnel, resolver: spec.resolver, inside: spec.inside.clone() })
            })
            .collect();
        let mut tunnels: Vec<Ipv4Addr> =
            self.lanes.values().filter_map(|lane| lane.tunnel).chain(auto).collect();
        tunnels.sort();
        tunnels.dedup();
        self.tunnels = tunnels;
    }

    /// Адрес туннеля правила. Правило без своей дорожки (и процесс без
    /// правила) идёт в туннель «какой найдётся».
    pub fn tunnel(&self, rule: Option<&str>) -> Option<Ipv4Addr> {
        match rule.and_then(|rule| self.lanes.get(rule)) {
            Some(lane) => lane.tunnel,
            None => self.auto,
        }
    }

    /// Сервер имён правила, если у его VPN он свой.
    pub fn resolver(&self, rule: Option<&str>) -> Option<Ipv4Addr> {
        rule.and_then(|rule| self.lanes.get(rule)).and_then(|lane| lane.resolver)
    }

    /// Ведёт ли дорожка правила к этому внутреннему адресу.
    pub fn inside(&self, rule: Option<&str>, address: Ipv4Addr) -> bool {
        rule.and_then(|rule| self.lanes.get(rule))
            .is_some_and(|lane| lane.inside.iter().any(|net| net.contains(address)))
    }

    /// Есть ли хоть одна дорожка к этому внутреннему адресу. Дешёвый
    /// вопрос перед дорогим: чей пакет, выясняется по таблице ядра, и
    /// спрашивать её про каждый пакет в свою сеть незачем.
    pub fn any_inside(&self, address: Ipv4Addr) -> bool {
        self.lanes.values().any(|lane| lane.inside.iter().any(|net| net.contains(address)))
    }

    /// Есть ли дорожки со своим сервером имён.
    pub fn any_resolver(&self) -> bool {
        self.lanes.values().any(|lane| lane.resolver.is_some())
    }

    pub fn is_tunnel(&self, address: Ipv4Addr) -> bool {
        self.tunnels.contains(&address)
    }

    pub fn tunnels(&self) -> &[Ipv4Addr] {
        &self.tunnels
    }

    /// Туннель для того, о чём неизвестно, чьё оно: «какой найдётся», а без
    /// него — первый из своих.
    pub fn fallback(&self) -> Option<Ipv4Addr> {
        self.auto.or(self.tunnels.first().copied())
    }

    /// Одной строкой для журнала; пусто, пока дорожек нет.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = self
            .specs
            .iter()
            .map(|(rule, spec)| {
                let lane = self.lanes.get(rule);
                let place = match (&spec.via, lane.and_then(|lane| lane.tunnel)) {
                    (Via::Nowhere, _) => "подключение не поднято".to_owned(),
                    (Via::Auto, Some(tunnel)) => format!("{tunnel}"),
                    (Via::Adapter(name), Some(tunnel)) => format!("«{name}» {tunnel}"),
                    (Via::Adapter(name), None) => format!("«{name}» без адреса"),
                    (Via::Auto, None) => "туннеля нет".to_owned(),
                };
                let mut text = format!("{rule} → {place}");
                if let Some(resolver) = spec.resolver {
                    text.push_str(&format!(", имена у {resolver}"));
                }
                if !spec.inside.is_empty() {
                    text.push_str(&format!(", внутренних сетей {}", spec.inside.len()));
                }
                text
            })
            .collect();
        parts.sort();
        parts.join("; ")
    }
}

/// Что сервер назначил подключению.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Pushed {
    /// Серверы имён (`dhcp-option DNS`), в порядке сервера.
    pub dns: Vec<Ipv4Addr>,
    /// Сети за этим VPN (`route сеть маска`).
    pub routes: Vec<Net>,
}

/// Достаёт из журнала OpenVPN последнюю строку `PUSH_REPLY` и читает из
/// неё серверы имён и маршруты. Чего не понял — пропускает: лучше не знать
/// маршрута, чем придумать его.
pub fn pushed(log: &str) -> Pushed {
    let mut found = Pushed::default();
    // Длинные указания сервер шлёт несколькими строками подряд, помечая
    // все, кроме последней, «push-continuation 2». Новая строка без такой
    // предшественницы — указания нового подключения, прежние неверны.
    let mut options: Vec<&str> = Vec::new();
    let mut continuing = false;
    for line in log.lines().filter(|line| line.contains("PUSH_REPLY")) {
        let said = line.split("PUSH_REPLY").nth(1).unwrap_or_default().trim_end_matches(['\'', '"', ' ']);
        if !continuing {
            options.clear();
        }
        options.extend(said.split(','));
        continuing = said.contains("push-continuation 2");
    }
    for option in options {
        let words: Vec<&str> = option.split_whitespace().collect();
        match words.as_slice() {
            ["dhcp-option", "DNS", server] => {
                if let Ok(server) = server.parse() {
                    found.dns.push(server);
                }
            }
            // Маска может быть опущена — тогда это один адрес. Дальше идут
            // шлюз и метрика, нам они не нужны.
            ["route", network, rest @ ..] => {
                let mask = rest.first().copied().unwrap_or("255.255.255.255");
                if let (Ok(network), Ok(mask)) = (network.parse::<Ipv4Addr>(), mask.parse::<Ipv4Addr>()) {
                    let (address, mask) = (u32::from(network), u32::from(mask));
                    // Маска — единицы подряд от старшего бита. «Маршрут на
                    // всё» нам не указ: что вести, решает список.
                    if mask != 0 && mask.leading_ones() + mask.trailing_zeros() == 32 {
                        found.routes.push(Net { address, mask });
                    }
                }
            }
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(address: [u8; 4], bits: u32) -> Net {
        Net { address: u32::from(Ipv4Addr::from(address)), mask: u32::MAX << (32 - bits) }
    }

    fn specs(list: &[(&str, Spec)]) -> HashMap<String, Spec> {
        list.iter().map(|(rule, spec)| (rule.to_string(), spec.clone())).collect()
    }

    const FOREIGN: Ipv4Addr = Ipv4Addr::new(10, 5, 5, 2);
    const WORK: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 6);

    fn two() -> Lanes {
        let mut lanes = Lanes::default();
        lanes.set(specs(&[
            ("pkg:chat", Spec { via: Via::Adapter("TAP 1".to_owned()), ..Spec::default() }),
            (
                "exe:firefox",
                Spec {
                    via: Via::Adapter("TAP 2".to_owned()),
                    resolver: Some(Ipv4Addr::new(10, 77, 0, 1)),
                    inside: vec![net([10, 77, 0, 0], 16), net([192, 168, 50, 0], 24)],
                },
            ),
            ("pkg:down", Spec { via: Via::Nowhere, ..Spec::default() }),
        ]));
        lanes.resolve(None, |name| match name {
            "TAP 1" => Some(FOREIGN),
            "TAP 2" => Some(WORK),
            _ => None,
        });
        lanes
    }

    #[test]
    fn without_orders_everything_goes_where_it_always_went() {
        // Ровно прежнее поведение: один туннель, какой нашёлся, на всех.
        let mut lanes = Lanes::default();
        lanes.resolve(Some(FOREIGN), |_| None);
        assert_eq!(lanes.tunnel(Some("pkg:any")), Some(FOREIGN));
        assert_eq!(lanes.tunnel(None), Some(FOREIGN));
        assert_eq!(lanes.resolver(Some("pkg:any")), None);
        assert!(!lanes.any_inside(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(lanes.is_tunnel(FOREIGN) && lanes.tunnels() == [FOREIGN]);
        assert!(lanes.describe().is_empty());
        // Туннеля нет — никому некуда.
        lanes.resolve(None, |_| None);
        assert_eq!(lanes.tunnel(Some("pkg:any")), None);
        assert!(lanes.tunnels().is_empty());
    }

    #[test]
    fn each_rule_goes_into_its_own_tunnel() {
        let lanes = two();
        assert_eq!(lanes.tunnel(Some("pkg:chat")), Some(FOREIGN));
        assert_eq!(lanes.tunnel(Some("exe:firefox")), Some(WORK));
        // Подключение не поднято — правилу некуда, даже когда чужие
        // туннели стоят: увести его в «какой-нибудь» было бы утечкой в
        // чужой VPN.
        assert_eq!(lanes.tunnel(Some("pkg:down")), None);
        assert_eq!(lanes.tunnels(), [FOREIGN, WORK]);
        assert!(lanes.is_tunnel(WORK) && !lanes.is_tunnel(Ipv4Addr::new(192, 168, 31, 35)));
        // Свой сервер имён и свои внутренние сети — только у своего правила.
        assert_eq!(lanes.resolver(Some("exe:firefox")), Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!(lanes.resolver(Some("pkg:chat")), None);
        let portal = Ipv4Addr::new(10, 77, 3, 4);
        assert!(lanes.inside(Some("exe:firefox"), portal) && lanes.any_inside(portal));
        assert!(!lanes.inside(Some("pkg:chat"), portal));
        assert!(!lanes.any_inside(Ipv4Addr::new(192, 168, 31, 1)));
        assert!(lanes.any_resolver());
    }

    #[test]
    fn an_adapter_that_lost_its_address_leads_nowhere() {
        let mut lanes = two();
        lanes.resolve(None, |name| (name == "TAP 1").then_some(FOREIGN));
        assert_eq!(lanes.tunnel(Some("exe:firefox")), None, "не в чужой туннель");
        assert_eq!(lanes.tunnel(Some("pkg:chat")), Some(FOREIGN));
        assert_eq!(lanes.tunnels(), [FOREIGN]);
        assert!(lanes.describe().contains("exe:firefox → «TAP 2» без адреса"), "{}", lanes.describe());
        assert!(lanes.describe().contains("pkg:down → подключение не поднято"));
    }

    #[test]
    fn what_nobody_owns_goes_to_whatever_tunnel_there_is() {
        assert_eq!(two().fallback(), Some(FOREIGN));
        let mut lanes = Lanes::default();
        lanes.resolve(Some(WORK), |_| None);
        assert_eq!(lanes.fallback(), Some(WORK));
        lanes.resolve(None, |_| None);
        assert_eq!(lanes.fallback(), None);
    }

    #[test]
    fn the_servers_orders_are_read_from_its_one_line() {
        let log = "2026-11-23 02:00:01 TLS: Initial packet from [AF_INET]10.0.0.1:1194\n\
                   2026-11-23 02:00:02 PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,\
                   route 192.168.50.7,dhcp-option DNS 10.20.0.2,dhcp-option DNS 10.20.0.3,dhcp-option DOMAIN corp.example,\
                   redirect-gateway def1,route 0.0.0.0 0.0.0.0,route 10.9.0.0 255.0.255.0,route-gateway 10.8.0.1,\
                   topology subnet,ping 10,ifconfig 10.8.0.6 255.255.255.0,peer-id 0,cipher AES-256-GCM'\n\
                   2026-11-23 02:00:02 OPTIONS IMPORT: --ifconfig/up options modified\n";
        let found = pushed(log);
        assert_eq!(found.dns, [Ipv4Addr::new(10, 20, 0, 2), Ipv4Addr::new(10, 20, 0, 3)]);
        // Сеть, один адрес — и ни «маршрута на всё», ни маски с дыркой.
        assert_eq!(found.routes, [net([10, 20, 0, 0], 16), net([192, 168, 50, 7], 32)]);
        assert!(found.routes[0].contains(Ipv4Addr::new(10, 20, 200, 1)));
        assert!(!found.routes[0].contains(Ipv4Addr::new(10, 21, 0, 1)));
        // Переподключился с другими указаниями — верна последняя строка.
        let again = format!("{log}2026-11-23 03:00:00 PUSH: Received control message: 'PUSH_REPLY,ping 10'\n");
        assert_eq!(pushed(&again), Pushed::default());
        assert_eq!(pushed("ничего похожего"), Pushed::default());
    }
}

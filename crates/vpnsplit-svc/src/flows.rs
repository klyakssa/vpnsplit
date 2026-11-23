//! Таблица потоков пути B: какие соединения уводятся в туннель.
//!
//! Зачем она нужна. На слое пакетов WinDivert не видно, чей это процесс, —
//! видно только адреса, порты и протокол. Решение же принимается по
//! приложению. Поэтому владелец определяется один раз, в начале потока
//! (событие слоя FLOW или таблица соединений ядра), запоминается здесь, и
//! дальше все пакеты этого потока опознаются по пятёрке.
//!
//! Вторая задача таблицы — **сузить фильтр**. В Этапе 11b замерено, что
//! перехват стоит около трети ядра на потоке 62 Мбит/с. Платить эту цену за
//! весь трафик машины нельзя, значит фильтр должен перечислять ровно
//! нынешние потоки выбранных приложений и перестраиваться, когда они
//! появляются и закрываются.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Сколько потоков помещается в один фильтр. **Замерено**, а не выбрано:
/// команда `vpnsplit-svc filter-limit` перебирает длину, пока WinDivert не
/// скажет «Filter expression too long». Вышло 28 потоков, по 194 байта
/// строки на поток.
///
/// Что делать, когда потоков больше, — решается не здесь: оставить часть
/// без перехвата нельзя, это была бы молчаливая утечка. Значит, при
/// переполнении придётся переходить на широкий фильтр и платить за это
/// процессорным временем.
pub const MAX_IN_FILTER: usize = 28;

/// Поток, опознаваемый на слое пакетов. Местный адрес не входит: он у всех
/// один и тот же, домашний, а после подмены — адрес туннеля.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    pub protocol: u8,
    pub local_port: u16,
    pub remote: Ipv4Addr,
    pub remote_port: u16,
}

#[derive(Default)]
pub struct Table {
    tunneled: HashMap<Key, u32>,
}

/// Процесс, бывший под присмотром на момент остановки службы.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Remembered {
    pub pid: u32,
    /// Время создания: вместе с номером называет процесс однозначно.
    pub created: u64,
    /// Правило, которое его привело (`AppTarget::key`).
    pub rule: String,
}

/// Приложение и все его потомки.
///
/// Родословная ведётся по событиям запуска, а не по снимку системы: номера
/// процессов Windows переиспользует, и к моменту снимка номер родителя
/// может указывать уже на другую программу. Поэтому здесь только два
/// действия — «запустился» и «завершился», — и ни одного обращения к
/// системе: логика проверяется тестами, а не наблюдением.
///
/// У каждого члена записано, **какое правило его привело** — своё у того,
/// кто подошёл правилу сам, унаследованное у потомков. Без этого при
/// правке списка родословную приходилось строить заново по снимку, а
/// снимок не помнит умерших: браузер, запущенный значком-запускателем,
/// выпадал из туннеля при любой правке списка, потому что запускателя,
/// связывавшего его с правилом, уже нет в живых. Теперь при правке уходят
/// только те, чьё правило снято.
///
/// Живёт родословная только в памяти службы, и перезапуск службы стирал бы
/// её: программа, запущенная запускателем, осталась бы без присмотра, потому
/// что связь с правилом — умерший запускатель — нигде больше не записана.
/// Поэтому перед остановкой члены записываются ([`Remembered`]), а при
/// старте возвращаются ([`Family::restore`]).
#[derive(Default)]
pub struct Family {
    /// Номер процесса → правило, которое его привело.
    members: std::collections::HashMap<u32, String>,
}

#[allow(dead_code)]
impl Family {
    /// Процесс запустился. `rule` — правило, которому он подходит сам по
    /// себе (по пути к образу или имени пакета); `None` — не подходит ни
    /// одному, и тогда он наш, только если наш его родитель. Возвращает
    /// `true`, если процесс принят в родословную.
    pub fn started(&mut self, pid: u32, parent: u32, rule: Option<&str>) -> bool {
        let rule = match rule {
            Some(rule) => rule.to_owned(),
            None => match self.members.get(&parent) {
                Some(inherited) => inherited.clone(),
                None => return false,
            },
        };
        match self.members.entry(pid) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(place) => {
                place.insert(rule);
                true
            }
        }
    }

    /// Процесс завершился.
    pub fn stopped(&mut self, pid: u32) -> bool {
        self.members.remove(&pid).is_some()
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.members.contains_key(&pid)
    }

    /// Правило, которое привело процесс.
    pub fn rule_of(&self, pid: u32) -> Option<&str> {
        self.members.get(&pid).map(String::as_str)
    }

    /// Список правил изменился: уходят те, чьё правило снято. Остальные
    /// остаются, живы их предки или нет. Возвращает число ушедших.
    pub fn keep_rules(&mut self, keep: impl Fn(&str) -> bool) -> usize {
        let before = self.members.len();
        self.members.retain(|_, rule| keep(rule));
        before - self.members.len()
    }

    /// Добавляет тех, кого нашли заново (по снимку системы). Уже известные
    /// остаются при своём правиле: оно узнано по событиям, а события
    /// помнят больше снимка.
    ///
    /// Возвращает тех, кого до этого под присмотром не было: это процессы,
    /// запущенные раньше своего правила, и всё, что они успели сделать в
    /// сети, сделано ещё без нас.
    pub fn absorb(&mut self, other: Family) -> Vec<u32> {
        let mut came = Vec::new();
        for (pid, rule) in other.members {
            if let std::collections::hash_map::Entry::Vacant(place) = self.members.entry(pid) {
                place.insert(rule);
                came.push(pid);
            }
        }
        came
    }

    /// Все члены с их правилами — чтобы записать перед остановкой службы.
    pub fn members(&self) -> impl Iterator<Item = (u32, &str)> {
        self.members.iter().map(|(pid, rule)| (*pid, rule.as_str()))
    }

    /// Возвращает под присмотр тех, кто был под ним до перезапуска службы.
    ///
    /// Запись называет процесс номером **и временем создания**: номер за
    /// время простоя службы мог достаться посторонней программе, и принять
    /// её в туннель по одному номеру значило бы увести чужой трафик.
    /// `created` отвечает, когда создан процесс с таким номером сейчас;
    /// не совпало или процесса нет — запись выбрасывается. Так же
    /// выбрасываются записи правил, которых в списке больше нет.
    ///
    /// Возвращает число принятых.
    pub fn restore(
        &mut self,
        remembered: &[Remembered],
        created: impl Fn(u32) -> Option<u64>,
        keep: impl Fn(&str) -> bool,
    ) -> usize {
        let mut accepted = 0;
        for record in remembered {
            if !keep(&record.rule) || created(record.pid) != Some(record.created) {
                continue;
            }
            if self.started(record.pid, 0, Some(&record.rule)) {
                accepted += 1;
            }
        }
        accepted
    }

    /// Достраивает родословную по снимку системы: ребёнок члена — тоже
    /// член. `snapshot` — пары «процесс, его родитель».
    ///
    /// Снимок знает только номер родителя, а номера переиспользуются:
    /// «родителем» может оказаться наш процесс, получивший номер умершего
    /// настоящего родителя. Отличить можно по времени: ребёнок не бывает
    /// старше родителя. Кто заведомо старше — не принимается; если время
    /// узнать не удалось, верим снимку, как и раньше.
    ///
    /// Проходов несколько — внуки появляются только после детей.
    pub fn grow(&mut self, snapshot: &[(u32, u32)], created: impl Fn(u32) -> Option<u64>) -> usize {
        let before = self.members.len();
        for _ in 0..8 {
            let size = self.members.len();
            for (pid, parent) in snapshot {
                if pid == parent || self.members.contains_key(pid) || !self.members.contains_key(parent) {
                    continue;
                }
                if let (Some(child), Some(elder)) = (created(*pid), created(*parent)) {
                    if child < elder {
                        continue;
                    }
                }
                self.started(*pid, *parent, None);
            }
            if self.members.len() == size {
                break;
            }
        }
        self.members.len() - before
    }

    /// Правила, под которыми сейчас есть хоть один процесс, — по порядку и
    /// без повторов, чтобы два одинаковых состояния давали один и тот же
    /// ответ и их можно было сравнить.
    pub fn live_rules(&self) -> Vec<String> {
        let distinct: std::collections::BTreeSet<&String> = self.members.values().collect();
        distinct.into_iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

// Часть этих действий пока вызывается только из тестов: таблицей
// распоряжается перенаправление, которого ещё нет. Держать их здесь имеет
// смысл — они проверены, и на следующем шаге понадобятся все.
#[allow(dead_code)]
impl Table {
    /// Поток выбранного приложения открылся.
    pub fn opened(&mut self, key: Key, pid: u32) {
        self.tunneled.insert(key, pid);
    }

    /// Поток закрылся. `true`, если он у нас был — то есть фильтр надо
    /// перестроить.
    pub fn closed(&mut self, key: &Key) -> bool {
        self.tunneled.remove(key).is_some()
    }

    /// Все потоки процесса — на случай, когда приложение завершилось и
    /// событий закрытия по каждому потоку можно не дождаться.
    pub fn forget_process(&mut self, pid: u32) -> usize {
        let before = self.tunneled.len();
        self.tunneled.retain(|_, owner| *owner != pid);
        before - self.tunneled.len()
    }

    /// Оставить только потоки процессов, которые всё ещё наши.
    ///
    /// Нужно, когда пользователь снял правило на ходу: приложение работает
    /// дальше, но уводить его больше не надо, и его потоки должны уйти из
    /// фильтра. Возвращает, сколько потоков выброшено.
    pub fn forget_unless(&mut self, keep: impl Fn(u32) -> bool) -> usize {
        let before = self.tunneled.len();
        self.tunneled.retain(|_, owner| keep(*owner));
        before - self.tunneled.len()
    }

    pub fn contains(&self, key: &Key) -> bool {
        self.tunneled.contains_key(key)
    }

    /// Чей это поток: по хозяину выбирается туннель.
    pub fn owner(&self, key: &Key) -> Option<u32> {
        self.tunneled.get(key).copied()
    }

    pub fn len(&self) -> usize {
        self.tunneled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tunneled.is_empty()
    }

    /// Фильтр WinDivert, покрывающий нынешние потоки в обе стороны.
    ///
    /// Для каждого потока нужны два случая: исходящий пакет узнаётся по
    /// местному порту и собеседнику, входящий — по тем же числам,
    /// поменянным местами. Собственный адрес в условие не входит: наружу он
    /// домашний, обратно — адрес туннеля, и перечислять оба значения незачем.
    ///
    /// `None`, если перечислять нечего: открывать перехватывающую ручку
    /// «на всякий случай» нельзя, она глотает пакеты.
    pub fn filter(&self) -> Option<String> {
        self.filter_up_to(MAX_IN_FILTER)
    }

    /// То же, но с заданным числом потоков. Нужно для замера самого
    /// предела: иначе измерение упиралось бы в своё же ограничение.
    pub fn filter_up_to(&self, cap: usize) -> Option<String> {
        if self.tunneled.is_empty() {
            return None;
        }
        let mut keys: Vec<&Key> = self.tunneled.keys().collect();
        // Порядок устойчивый: иначе один и тот же набор потоков давал бы
        // разные строки, и перестройка фильтра случалась бы впустую.
        keys.sort_by_key(|k| (k.protocol, k.local_port, k.remote.octets(), k.remote_port));
        keys.truncate(cap);

        let parts: Vec<String> = keys
            .iter()
            .map(|k| {
                let p = protocol_name(k.protocol);
                format!(
                    "({p} and ((outbound and {p}.SrcPort == {lp} and ip.DstAddr == {r} and {p}.DstPort == {rp}) or \
                     (inbound and {p}.DstPort == {lp} and ip.SrcAddr == {r} and {p}.SrcPort == {rp})))",
                    lp = k.local_port,
                    r = k.remote,
                    rp = k.remote_port
                )
            })
            .collect();
        Some(parts.join(" or "))
    }
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        17 => "udp",
        _ => "tcp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> Key {
        Key {
            protocol: 6,
            local_port: port,
            remote: Ipv4Addr::new(104, 26, 12, 205),
            remote_port: 443,
        }
    }

    #[test]
    fn a_flow_is_remembered_and_forgotten() {
        let mut table = Table::default();
        assert!(table.is_empty());
        table.opened(key(50000), 1234);
        assert!(table.contains(&key(50000)));
        assert!(!table.contains(&key(50001)));
        assert!(table.closed(&key(50000)));
        // Второй раз закрывать нечего — фильтр перестраивать не надо.
        assert!(!table.closed(&key(50000)));
        assert!(table.is_empty());
    }

    #[test]
    fn a_dead_process_takes_all_its_flows_with_it() {
        let mut table = Table::default();
        table.opened(key(1), 100);
        table.opened(key(2), 100);
        table.opened(key(3), 200);
        assert_eq!(table.forget_process(100), 2);
        assert_eq!(table.len(), 1);
        assert!(table.contains(&key(3)));
    }

    #[test]
    fn a_child_of_ours_is_ours_and_a_stranger_is_not() {
        let mut family = Family::default();
        // Само приложение: подошло правилу.
        assert!(family.started(100, 1, Some("a")));
        // Ребёнок приложения: правилу не подходит, но родитель наш.
        assert!(family.started(200, 100, None));
        // Внук: родитель — ребёнок, тоже наш.
        assert!(family.started(300, 200, None));
        // Посторонний процесс с посторонним родителем.
        assert!(!family.started(400, 999, None));
        assert!(family.contains(300));
        assert!(!family.contains(400));
        assert_eq!(family.len(), 3);
        // Правило наследуется по всей цепочке.
        assert_eq!(family.rule_of(300), Some("a"));
        assert_eq!(family.rule_of(400), None);
    }

    #[test]
    fn a_child_started_after_the_parent_died_is_not_adopted() {
        let mut family = Family::default();
        family.started(100, 1, Some("a"));
        family.started(200, 100, None);
        assert!(family.stopped(100));
        // Номер 100 Windows может выдать другой программе. Её дети нашими
        // не становятся — иначе в туннель попадало бы что угодно.
        assert!(!family.started(500, 100, None));
        // А уже принятый ребёнок остаётся нашим: он живёт сам по себе.
        assert!(family.contains(200));
    }

    #[test]
    fn stopping_someone_else_changes_nothing() {
        let mut family = Family::default();
        family.started(100, 1, Some("a"));
        assert!(!family.stopped(777));
        assert_eq!(family.len(), 1);
    }

    /// Случай со значком-запускателем: запускатель подошёл правилу, запустил
    /// браузер и вышел. Потом список правят — добавляют другое приложение.
    #[test]
    fn editing_the_list_keeps_those_whose_launcher_is_gone() {
        let mut family = Family::default();
        family.started(100, 1, Some("значок"));
        family.started(200, 100, None);
        family.started(300, 200, None);
        family.stopped(100);

        // Снимок системы видит только живых и о значке ничего не знает:
        // по нему нашёлся бы один новый процесс нового правила.
        let mut snapshot = Family::default();
        snapshot.started(900, 1, Some("другое"));

        assert_eq!(family.keep_rules(|rule| rule == "значок" || rule == "другое"), 0);
        family.absorb(snapshot);
        assert!(family.contains(200) && family.contains(300), "браузер выпал из туннеля");
        assert!(family.contains(900));
        assert_eq!(family.rule_of(300), Some("значок"));
    }

    #[test]
    fn removing_a_rule_releases_its_whole_family_and_only_it() {
        let mut family = Family::default();
        family.started(100, 1, Some("значок"));
        family.started(200, 100, None);
        family.started(700, 1, Some("другое"));
        family.started(800, 700, None);

        assert_eq!(family.keep_rules(|rule| rule == "другое"), 2);
        assert!(!family.contains(100) && !family.contains(200));
        assert!(family.contains(700) && family.contains(800));
    }

    #[test]
    fn what_the_events_told_is_not_overwritten_by_the_snapshot() {
        let mut family = Family::default();
        family.started(100, 1, Some("по событию"));
        let mut snapshot = Family::default();
        snapshot.started(100, 1, Some("по снимку"));
        snapshot.started(101, 1, Some("по снимку"));
        family.absorb(snapshot);
        assert_eq!(family.rule_of(100), Some("по событию"));
        assert_eq!(family.rule_of(101), Some("по снимку"));
        // Повторный запуск уже принятого ничего не меняет и не считается
        // новым приёмом.
        assert!(!family.started(100, 1, Some("ещё раз")));
        assert_eq!(family.rule_of(100), Some("по событию"));
    }

    fn record(pid: u32, created: u64, rule: &str) -> Remembered {
        Remembered { pid, created, rule: rule.to_owned() }
    }

    /// Перезапуск службы: браузер, запущенный значком, должен вернуться
    /// под присмотр, хотя запускателя давно нет.
    #[test]
    fn those_alive_with_the_same_birth_come_back() {
        let remembered = [record(200, 1000, "значок"), record(300, 1100, "значок")];
        let now = |pid: u32| match pid {
            200 => Some(1000),
            300 => Some(1100),
            _ => None,
        };
        let mut family = Family::default();
        assert_eq!(family.restore(&remembered, now, |_| true), 2);
        assert_eq!(family.rule_of(200), Some("значок"));
        assert_eq!(family.live_rules(), ["значок"]);
    }

    /// Пока служба стояла, процесс умер, а его номер достался посторонней
    /// программе. Принять её — значит увести в туннель чужой трафик.
    #[test]
    fn a_reused_number_is_not_mistaken_for_the_old_process() {
        let remembered = [record(200, 1000, "значок"), record(300, 1100, "значок")];
        let now = |pid: u32| match pid {
            200 => Some(5000), // тот же номер, другой процесс
            _ => None,         // 300 умер
        };
        let mut family = Family::default();
        assert_eq!(family.restore(&remembered, now, |_| true), 0);
        assert!(family.is_empty());
    }

    #[test]
    fn a_rule_removed_while_the_service_was_down_brings_nobody_back() {
        let remembered = [record(200, 1000, "снятое"), record(300, 1100, "значок")];
        let now = |pid: u32| match pid {
            200 => Some(1000),
            300 => Some(1100),
            _ => None,
        };
        let mut family = Family::default();
        assert_eq!(family.restore(&remembered, now, |rule| rule == "значок"), 1);
        assert!(!family.contains(200));
        assert!(family.contains(300));
    }

    /// Дети, родившиеся, пока служба стояла, находятся по снимку — но
    /// только настоящие.
    #[test]
    fn growth_takes_children_and_refuses_those_older_than_the_parent() {
        let mut family = Family::default();
        family.started(200, 0, Some("значок"));
        let snapshot = [
            (500, 400), // внук — стоит в снимке раньше, чем узнаётся его родитель
            (400, 200), // ребёнок
            (600, 200), // «ребёнок» старше родителя: номер 200 переиспользован
            (700, 999), // посторонний
            (200, 100), // сам член, его родитель не наш
        ];
        let born = |pid: u32| match pid {
            200 => Some(1000),
            400 => Some(1200),
            500 => Some(1300),
            600 => Some(900),
            _ => None,
        };
        assert_eq!(family.grow(&snapshot, born), 2);
        assert!(family.contains(400) && family.contains(500));
        assert!(!family.contains(600), "принят процесс, который старше своего «родителя»");
        assert!(!family.contains(700));
        assert_eq!(family.rule_of(500), Some("значок"));
        // Повтор ничего не добавляет.
        assert_eq!(family.grow(&snapshot, born), 0);
    }

    #[test]
    fn growth_trusts_the_snapshot_when_the_time_is_unknown() {
        // Защищённый процесс не открыть и время не узнать. Отказать ему
        // значило бы выпустить его мимо туннеля — верим снимку.
        let mut family = Family::default();
        family.started(200, 0, Some("значок"));
        assert_eq!(family.grow(&[(400, 200)], |_| None), 1);
        assert!(family.contains(400));
    }

    /// То, что видит окно: под каким правилом кто-то есть. Меняется, когда
    /// приходит первый и когда уходит последний, а не на каждый процесс.
    #[test]
    fn a_rule_is_live_from_its_first_process_to_its_last() {
        let mut family = Family::default();
        assert!(family.live_rules().is_empty());
        family.started(100, 1, Some("значок"));
        assert_eq!(family.live_rules(), ["значок"]);
        // Потомки правила не добавляют и порядка не меняют.
        family.started(200, 100, None);
        family.started(300, 200, None);
        family.started(700, 1, Some("другое"));
        assert_eq!(family.live_rules(), ["другое", "значок"]);
        // Запускатель вышел, браузер работает: правило живо.
        family.stopped(100);
        family.stopped(200);
        assert_eq!(family.live_rules(), ["другое", "значок"]);
        // Ушёл последний.
        family.stopped(300);
        assert_eq!(family.live_rules(), ["другое"]);
    }

    #[test]
    fn an_empty_table_has_no_filter() {
        assert_eq!(Table::default().filter(), None);
    }

    #[test]
    fn the_filter_covers_both_directions_of_a_flow() {
        let mut table = Table::default();
        table.opened(key(50000), 1);
        let filter = table.filter().unwrap();
        assert!(filter.contains("outbound and tcp.SrcPort == 50000"));
        assert!(filter.contains("inbound and tcp.DstPort == 50000"));
        assert!(filter.contains("ip.DstAddr == 104.26.12.205"));
        assert!(filter.contains("ip.SrcAddr == 104.26.12.205"));
        assert!(filter.contains("tcp.DstPort == 443"));
        assert!(filter.contains("tcp.SrcPort == 443"));
    }

    #[test]
    fn udp_flows_are_named_udp() {
        let mut table = Table::default();
        table.opened(
            Key { protocol: 17, local_port: 5000, remote: Ipv4Addr::new(1, 1, 1, 1), remote_port: 53 },
            1,
        );
        let filter = table.filter().unwrap();
        assert!(filter.contains("udp.SrcPort == 5000"));
        assert!(!filter.contains("tcp"));
    }

    #[test]
    fn the_same_set_of_flows_always_gives_the_same_string() {
        let mut one = Table::default();
        let mut other = Table::default();
        for port in [50003u16, 50001, 50002] {
            one.opened(key(port), 1);
        }
        for port in [50002u16, 50003, 50001] {
            other.opened(key(port), 1);
        }
        assert_eq!(one.filter(), other.filter());
    }

    #[test]
    fn the_filter_does_not_grow_past_the_cap() {
        let mut table = Table::default();
        for port in 0..(MAX_IN_FILTER as u16 + 20) {
            table.opened(key(40000 + port), 1);
        }
        let filter = table.filter().unwrap();
        assert_eq!(filter.matches("outbound").count(), MAX_IN_FILTER);
        assert_eq!(table.len(), MAX_IN_FILTER + 20);
    }

    #[test]
    fn flows_of_a_process_that_is_no_longer_ours_leave_the_table() {
        // Пользователь снял правило на ходу: приложение работает дальше, а
        // уводить его больше не надо.
        let mut table = Table::default();
        table.opened(key(50001), 10);
        table.opened(key(50002), 10);
        table.opened(key(50003), 20);
        assert_eq!(table.forget_unless(|pid| pid == 20), 2);
        assert_eq!(table.len(), 1);
        assert!(table.contains(&key(50003)));
        // Повторный вызов ничего не меняет: выбрасывать больше нечего.
        assert_eq!(table.forget_unless(|pid| pid == 20), 0);
    }
}

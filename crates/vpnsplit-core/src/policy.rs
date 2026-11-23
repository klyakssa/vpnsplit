//! Правила: что именно отправляется в туннель.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Как приложение опознаётся в системе.
///
/// Win32-приложения опознаются по пути к исполняемому файлу — это то, что
/// отдают ETW и WFP. Store-приложения по пути опознать нельзя: многие живут
/// в общих хост-процессах, поэтому для них используется package family name.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AppTarget {
    /// Полный путь к .exe. Сравнение без учёта регистра.
    Executable(PathBuf),
    /// Package family name, например `Microsoft.WindowsStore_8wekyb3d8bbwe`.
    Package(String),
}

impl AppTarget {
    /// Каким путём это приложение будет перехвачено.
    pub fn mechanism(&self) -> Mechanism {
        match self {
            AppTarget::Executable(_) => Mechanism::Inject,
            AppTarget::Package(_) => Mechanism::Divert,
        }
    }

    pub fn display_name(&self) -> String {
        match self {
            AppTarget::Executable(path) => path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string_lossy().into_owned()),
            AppTarget::Package(pfn) => pfn.clone(),
        }
    }

    /// Имя цели, по которому её узнают между собой служба и её движок:
    /// каким правилом процесс приведён в туннель, под какими правилами
    /// сейчас кто-то есть. Регистр сложен: цель сравнивается с путём без
    /// его учёта, и два написания одного пути — одна цель.
    pub fn key(&self) -> String {
        match self {
            AppTarget::Executable(path) => format!("exe:{}", fold_case(path)),
            AppTarget::Package(pfn) => format!("pkg:{}", pfn.to_lowercase()),
        }
    }

    /// Подходит ли процесс этой цели. Нужно и правилам (служба решает,
    /// чей это процесс), и движку пути B (он спрашивает то же самое на
    /// каждый запуск процесса в системе).
    ///
    /// Сравнение целиком, а не по части строки: `notepad` подошёл бы к
    /// `notepad++`, а правило, которое прихватывает лишнее, хуже
    /// отсутствующего — пользователь считает, что выбрал одно приложение.
    pub fn matches(&self, image: Option<&std::path::Path>, package: Option<&str>) -> bool {
        match self {
            AppTarget::Executable(path) => {
                image.is_some_and(|image| fold_case(path) == fold_case(image))
            }
            // Имена семейств пакетов — только ASCII, их регистр складывается
            // без хитростей.
            AppTarget::Package(pfn) => {
                package.is_some_and(|package| package.eq_ignore_ascii_case(pfn))
            }
        }
    }

    /// Нужно ли ради этой цели спрашивать у процесса имя пакета. Отдельный
    /// системный вызов, и платить его на каждый запуск процесса в системе
    /// имеет смысл только если в списке есть пакеты.
    pub fn needs_package(&self) -> bool {
        matches!(self, AppTarget::Package(_))
    }
}

/// Механизм классификации. Путь A ничего не стоит на пакет, путь B стоит.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Mechanism {
    /// Путь A: инжект hook.dll и `IP_UNICAST_IF` на сокете.
    Inject,
    /// Путь B: WinDivert, фильтр на 5-tuple.
    Divert,
}

impl Mechanism {
    /// Короткое имя для списка.
    pub fn short(self) -> &'static str {
        match self {
            Mechanism::Inject => "путь A",
            Mechanism::Divert => "путь B",
        }
    }

    /// Чем этот способ отличается — одной строкой, для `policy` и UI.
    pub fn describe(self) -> &'static str {
        match self {
            Mechanism::Inject => "хуки в процессе; берёт только то, что запущено лончером",
            Mechanism::Divert => "приложение и все его потомки, как бы они ни были запущены",
        }
    }
}

/// Куда направляется трафик приложения.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Routing {
    Tunnel,
    Direct,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AppRule {
    pub target: AppTarget,
    pub routing: Routing,
    /// Наследуют ли дочерние процессы это правило. По умолчанию да —
    /// иначе лончеры и многопроцессные приложения рассыпаются.
    pub include_children: bool,
    /// Чем приложение перехватывается. `None` — как решит сам вид цели: у
    /// `.exe` это путь A, у пакета путь B. Задаётся явно, когда обычное
    /// приложение надо взять путём B: тогда лончер не нужен вовсе, но за
    /// перехват платится процессорным временем.
    ///
    /// Поле появилось позже самих правил, поэтому `default`: политика,
    /// записанная прежней версией, читается как раньше.
    #[serde(default)]
    pub mechanism: Option<Mechanism>,
    /// Через какое из своих подключений вести приложение — имя подключения
    /// из тех, что держит служба («Работа», «Зарубежный»). `None` — «по
    /// умолчанию»: чужой туннель, пока он есть, иначе первое своё
    /// подключение. Выбор действует для правил пути B: путь A привязывает
    /// сокеты к туннелю в момент запуска и подключений не различает.
    #[serde(default)]
    pub vpn: Option<String>,
}

impl AppRule {
    pub fn tunnel(target: AppTarget) -> Self {
        Self {
            target,
            routing: Routing::Tunnel,
            include_children: true,
            mechanism: None,
            vpn: None,
        }
    }

    /// Приложение и все его потомки — через путь B, как бы они ни были
    /// запущены.
    ///
    /// Разница с `tunnel` не в наследовании, а в том, кто перехватывает.
    /// Путь A ставит хуки в процесс, а поставить их может только лончер:
    /// приложение, запущенное из меню «Пуск», остаётся без них. Путь B
    /// переписывает пакеты снаружи процесса, и ему всё равно, кто его
    /// запустил и откуда.
    pub fn tunnel_family(target: AppTarget) -> Self {
        Self {
            target,
            routing: Routing::Tunnel,
            include_children: true,
            mechanism: Some(Mechanism::Divert),
            vpn: None,
        }
    }

    /// Чем это правило перехватывается на самом деле.
    pub fn mechanism(&self) -> Mechanism {
        self.mechanism.unwrap_or_else(|| self.target.mechanism())
    }
}

/// Полярность схемы.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Mode {
    /// Основной режим: в туннель идут только выбранные приложения.
    OnlySelected,
    /// Инверсия: в туннель идёт всё, кроме выбранных. Нужна для Store-приложений,
    /// которые не берёт ни путь A, ни путь B.
    AllExceptSelected,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub mode: Mode,
    pub rules: Vec<AppRule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::OnlySelected,
            rules: Vec::new(),
        }
    }
}

impl Policy {
    /// Сколько правил требует запущенного WinDivert. Ноль означает, что путь B
    /// можно не поднимать вовсе и не платить за него ничего.
    pub fn divert_rules(&self) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.mechanism() == Mechanism::Divert)
            .count()
    }

    pub fn needs_divert(&self) -> bool {
        self.divert_rules() > 0
    }

    /// Цели, которые уводит путь B. Пустой список означает, что движок
    /// перехвата поднимать не нужно вовсе, и тогда он не стоит ничего:
    /// WinDivert не загружен, пакеты в пользовательский режим не ходят.
    ///
    /// Режим `AllExceptSelected` здесь не учитывается: путь B умеет
    /// уводить выбранное, а не всё остальное. Решает это служба — она
    /// видит режим и скажет об этом в журнал, а не сделает вид, что
    /// защита стоит.
    pub fn divert_targets(&self) -> Vec<AppTarget> {
        self.rules
            .iter()
            .filter(|rule| rule.mechanism() == Mechanism::Divert && rule.routing == Routing::Tunnel)
            .map(|rule| rule.target.clone())
            .collect()
    }

    /// Правило пути A для образа. Только такие правила ждут хуков, и
    /// только о таких уместно говорить «работает мимо туннеля»: у правил
    /// пути B хуков нет и быть не должно.
    pub fn hook_rule_for_image(&self, image: &std::path::Path) -> Option<&AppRule> {
        self.rule_for_image(image)
            .filter(|rule| rule.mechanism() == Mechanism::Inject)
    }

    /// Правило для запущенного процесса по полному пути к его образу.
    ///
    /// Windows не различает регистр в путях, а приходят они из разных мест:
    /// из диалога выбора файла, из ETW, из `QueryFullProcessImageNameW`. У
    /// одного и того же файла там легко окажется разный регистр, поэтому
    /// сравнение регистронезависимое — и по-юникодному, а не только по ASCII:
    /// в путях бывает кириллица.
    pub fn rule_for_image(&self, image: &std::path::Path) -> Option<&AppRule> {
        let image = fold_case(image);
        self.rules.iter().find(|rule| match &rule.target {
            AppTarget::Executable(path) => fold_case(path) == image,
            AppTarget::Package(_) => false,
        })
    }
}

fn fold_case(path: &std::path::Path) -> String {
    path.to_string_lossy().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_target_has_one_key_however_it_is_spelled() {
        let a = AppTarget::Executable(PathBuf::from(r"C:\Users\K\Desktop\Firefox.exe"));
        let b = AppTarget::Executable(PathBuf::from(r"c:\users\k\desktop\firefox.EXE"));
        assert_eq!(a.key(), b.key());
        // Разные цели — разные имена, и путь не спутать с пакетом, даже
        // если строки совпали.
        let other = AppTarget::Executable(PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe"));
        assert_ne!(a.key(), other.key());
        let package = AppTarget::Package("Same.Name".to_owned());
        let path = AppTarget::Executable(PathBuf::from("same.name"));
        assert_ne!(package.key(), path.key());
    }

    #[test]
    fn executables_go_through_inject() {
        let target = AppTarget::Executable(PathBuf::from(r"C:\Program Files\app\app.exe"));
        assert_eq!(target.mechanism(), Mechanism::Inject);
        assert_eq!(target.display_name(), "app.exe");
    }

    #[test]
    fn packages_go_through_divert() {
        let target = AppTarget::Package("Microsoft.WindowsStore_8wekyb3d8bbwe".to_owned());
        assert_eq!(target.mechanism(), Mechanism::Divert);
    }

    #[test]
    fn divert_stays_off_without_store_apps() {
        let mut policy = Policy::default();
        assert!(!policy.needs_divert());

        policy.rules.push(AppRule::tunnel(AppTarget::Executable(
            PathBuf::from(r"C:\app.exe"),
        )));
        assert!(!policy.needs_divert());

        policy
            .rules
            .push(AppRule::tunnel(AppTarget::Package("Some.App_abc".to_owned())));
        assert_eq!(policy.divert_rules(), 1);
        assert!(policy.needs_divert());
    }

    #[test]
    fn image_matches_its_rule_whatever_the_case() {
        let mut policy = Policy::default();
        policy.rules.push(AppRule::tunnel(AppTarget::Executable(PathBuf::from(
            r"C:\Program Files\App\app.exe",
        ))));
        let found = policy.rule_for_image(std::path::Path::new(r"c:\program files\app\APP.EXE"));
        assert!(found.is_some());
    }

    #[test]
    fn same_name_in_another_folder_is_another_program() {
        let mut policy = Policy::default();
        policy.rules.push(AppRule::tunnel(AppTarget::Executable(PathBuf::from(
            r"C:\Program Files\App\app.exe",
        ))));
        assert!(policy
            .rule_for_image(std::path::Path::new(r"C:\Temp\app.exe"))
            .is_none());
    }

    #[test]
    fn store_packages_never_match_an_image_path() {
        // Store-приложения живут в общих хост-процессах: путь ничего не значит,
        // и совпадение по нему было бы ложным.
        let mut policy = Policy::default();
        policy
            .rules
            .push(AppRule::tunnel(AppTarget::Package("Some.App_abc".to_owned())));
        assert!(policy
            .rule_for_image(std::path::Path::new(r"C:\Some.App_abc"))
            .is_none());
    }

    #[test]
    fn policy_survives_json_round_trip() {
        let mut policy = Policy::default();
        policy.rules.push(AppRule::tunnel(AppTarget::Executable(PathBuf::from(
            r"C:\Program Files\app\app.exe",
        ))));
        policy.rules.push(AppRule::tunnel(AppTarget::Package("Some.App_abc".to_owned())));
        let text = serde_json::to_string(&policy).unwrap();
        let back: Policy = serde_json::from_str(&text).unwrap();
        assert_eq!(back, policy);
    }

    #[test]
    fn policy_written_by_the_old_version_still_reads() {
        // Поле способа перехвата появилось позже. Запись без него должна
        // читаться ровно как прежде, иначе обновление программы потеряет
        // пользователю весь список.
        let text = r#"{"mode":"OnlySelected","rules":[
            {"target":{"Executable":"C:\\app\\app.exe"},"routing":"Tunnel","include_children":true}
        ]}"#;
        let policy: Policy = serde_json::from_str(text).unwrap();
        assert_eq!(policy.rules[0].mechanism, None);
        assert_eq!(policy.rules[0].mechanism(), Mechanism::Inject);
        assert!(!policy.needs_divert());
    }

    #[test]
    fn an_ordinary_exe_can_be_taken_by_path_b() {
        let path = PathBuf::from(r"C:\Program Files\App\app.exe");
        let mut policy = Policy::default();
        policy.rules.push(AppRule::tunnel_family(AppTarget::Executable(path.clone())));

        assert_eq!(policy.divert_rules(), 1);
        assert!(policy.needs_divert());
        assert_eq!(policy.divert_targets().len(), 1);
        // Хуков у такого правила нет и не ждём: иначе служба объявила бы
        // приложение работающим «мимо туннеля», хотя его ведёт путь B.
        assert!(policy.rule_for_image(&path).is_some());
        assert!(policy.hook_rule_for_image(&path).is_none());
    }

    #[test]
    fn direct_rules_are_not_the_business_of_path_b() {
        let mut policy = Policy::default();
        let mut rule = AppRule::tunnel_family(AppTarget::Package("Some.App_abc".to_owned()));
        rule.routing = Routing::Direct;
        policy.rules.push(rule);
        assert!(policy.divert_targets().is_empty());
    }

    #[test]
    fn a_target_matches_the_whole_name_and_not_a_part_of_it() {
        let target = AppTarget::Executable(PathBuf::from(r"C:\tools\notepad.exe"));
        assert!(target.matches(Some(std::path::Path::new(r"c:\TOOLS\Notepad.exe")), None));
        assert!(!target.matches(Some(std::path::Path::new(r"C:\tools\notepad++.exe")), None));
        assert!(!target.matches(None, Some("notepad")));
        assert!(!target.needs_package());

        let package = AppTarget::Package("Microsoft.WindowsStore_8wekyb3d8bbwe".to_owned());
        assert!(package.matches(None, Some("microsoft.windowsstore_8wekyb3d8bbwe")));
        assert!(!package.matches(None, Some("Microsoft.WindowsStore")));
        assert!(!package.matches(Some(std::path::Path::new(r"C:\x.exe")), None));
        assert!(package.needs_package());
    }

    #[test]
    fn a_rule_with_the_mechanism_survives_json_round_trip() {
        let mut policy = Policy::default();
        policy
            .rules
            .push(AppRule::tunnel_family(AppTarget::Executable(PathBuf::from(r"C:\app.exe"))));
        let text = serde_json::to_string(&policy).unwrap();
        let back: Policy = serde_json::from_str(&text).unwrap();
        assert_eq!(back, policy);
        assert_eq!(back.rules[0].mechanism(), Mechanism::Divert);
    }
}

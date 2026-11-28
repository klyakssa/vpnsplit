//! Разговор со службой. Ни один вызов не делается из потока окна: канал
//! синхронный, и запрос к занятой службе подвесил бы интерфейс. Рабочий
//! поток кладёт результат в сообщение окна, окно просто его разбирает.

use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, Stdio};
use vpnsplit_core::{
    AppTarget, Event, Login, Policy, Request, Response, Secret, Status, VpnAction,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

/// Событие службы. В lparam — `Box<Event>`.
pub const WM_EVENT: u32 = WM_APP + 1;
/// Связь со службой: wparam 1 — есть, 0 — нет.
pub const WM_LINK: u32 = WM_APP + 2;
/// Ответ на наш запрос. В lparam — `Box<Reply>`.
pub const WM_REPLY: u32 = WM_APP + 3;
/// Щелчок по значку в трее.
pub const WM_TRAY: u32 = WM_APP + 4;

/// Окно между попытками подключения, когда службы нет. Это единственное
/// повторяющееся действие в программе; по бюджету Этапа 10 — раз в две
/// секунды, то есть вдвое реже разрешённого 1 Гц.
const RETRY: std::time::Duration = std::time::Duration::from_secs(2);

// One big variant (the full status) among small ones: these are messages
// that live for a moment, boxing them would buy nothing.
#[allow(clippy::large_enum_variant)]
pub enum Reply {
    Policy(Policy),
    State(Status),
    Saved,
    Launched(String),
    Failed(String),
    /// Служба приняла конфиг своего подключения.
    VpnSet,
    /// Служба конфиг не приняла — и вот почему. Отдельно от `Failed`:
    /// на отказ «пароль не подошёл» окно спрашивает пароль ещё раз.
    VpnRefused(String),
    /// Конфиг забыт, своё подключение опускается.
    VpnCleared,
    /// Служба взяла одноразовый код и подключается с ним.
    VpnConnecting(String),
    /// Служба сделала с подключением, что просили; внутри — что сказать.
    VpnDone(String),
    /// Установленные приложения из Store: название и семейство пакета.
    /// Спрашивает не службу, а оболочку Windows, но ждать её в потоке
    /// окна так же нельзя.
    Titles(Vec<(String, String)>),
}

/// Окно как число: `HWND` — указатель, через границу потока его так не
/// отдать, а числом — можно.
#[derive(Clone, Copy)]
pub struct Target(isize);

impl Target {
    pub fn new(hwnd: HWND) -> Self {
        Target(hwnd as isize)
    }

    fn hwnd(self) -> HWND {
        self.0 as HWND
    }

    fn post(self, message: u32, wparam: usize, lparam: isize) -> bool {
        unsafe { PostMessageW(self.hwnd(), message, wparam, lparam) != 0 }
    }

    /// Отдать окну значение в штучном боксе. Если окна уже нет, бокс
    /// забираем назад и роняем — иначе это была бы утечка.
    fn deliver<T>(self, message: u32, value: T) {
        let raw = Box::into_raw(Box::new(value));
        if !self.post(message, 0, raw as isize) {
            drop(unsafe { Box::from_raw(raw) });
        }
    }
}

// Числовой хэндл можно передавать между потоками: PostMessageW потокобезопасен.
unsafe impl Send for Target {}

/// Забрать значение, присланное через `deliver`.
pub unsafe fn take<T>(lparam: isize) -> Option<Box<T>> {
    if lparam == 0 {
        None
    } else {
        Some(Box::from_raw(lparam as *mut T))
    }
}

/// Поток подписки: пока служба жива — спит в чтении канала и пересылает
/// события окну. Служба ушла — ждёт и пробует снова.
pub fn watch(target: Target) {
    std::thread::Builder::new()
        .name("subscribe".into())
        .spawn(move || loop {
            // Ошибка подключения — это обычное «службы сейчас нет»:
            // ждём и пробуем снова, ничего не сообщая, кроме потери связи.
            if let Ok(events) = vpnsplit_net::pipe::subscribe() {
                target.post(WM_LINK, 1, 0);
                for event in events {
                    match event {
                        Ok(event) => target.deliver::<Event>(WM_EVENT, event),
                        Err(_) => break,
                    }
                }
            }
            target.post(WM_LINK, 0, 0);
            std::thread::sleep(RETRY);
        })
        .ok();
}

/// Отказ службы — словами, по которым понятно, что делать. Служба, которая
/// старее окна, новых команд не знает и отвечает перечнем известных ей;
/// человеку этот перечень ничего не говорит.
fn outdated(reason: String) -> String {
    if reason.contains("unknown variant") {
        "служба старее окна и этой команды ещё не знает. Обнови программу установщиком \
         vpnsplit-setup.exe — он заменит службу за несколько секунд"
            .to_owned()
    } else {
        reason
    }
}

fn ask(request: Request) -> Result<Response, String> {    vpnsplit_net::pipe::request(&request).map_err(|e| e.to_string())
}

/// Спросить список приложений.
pub fn load_policy(target: Target) {
    spawn(move || match ask(Request::GetPolicy) {
        Ok(Response::Policy(policy)) => Reply::Policy(policy),
        Ok(other) => Reply::Failed(format!("служба ответила неожиданно: {other:?}")),
        Err(e) => Reply::Failed(format!("служба не отвечает: {e}")),
    }, target);
}

/// Спросить состояние. Нужно ради kill-switch: события о туннеле несут
/// только сам туннель, а стоят ли запреты — знает служба.
pub fn load_state(target: Target) {
    spawn(move || match ask(Request::GetStatus) {
        Ok(Response::Status(status)) => Reply::State(status),
        Ok(other) => Reply::Failed(format!("служба ответила неожиданно: {other:?}")),
        Err(e) => Reply::Failed(format!("служба не отвечает: {e}")),
    }, target);
}

/// Сохранить список. Служба разошлёт `PolicyChanged`, в том числе нам, —
/// список в окне обновится оттуда, а не из этого ответа.
pub fn save_policy(target: Target, policy: Policy) {
    spawn(move || match ask(Request::SetPolicy(policy)) {
        Ok(Response::Ok) => Reply::Saved,
        Ok(Response::Error(e)) => Reply::Failed(outdated(e)),
        Ok(other) => Reply::Failed(format!("служба ответила неожиданно: {other:?}")),
        Err(e) => Reply::Failed(format!("служба не отвечает: {e}")),
    }, target);
}

/// Спросить у оболочки названия установленных приложений из Store.
pub fn load_titles(target: Target) {
    spawn(|| Reply::Titles(crate::apps::installed()), target);
}

/// Своё подключение, как его заказывает окно: имя, текст конфига и то, что
/// к нему спросили у человека.
#[derive(Clone)]
pub struct VpnOrder {
    pub name: String,
    pub config: String,
    pub key_password: Option<String>,
    pub login: Option<(String, String)>,
}

/// Отдать службе конфиг своего подключения. Отвечает она не сразу: сперва
/// проверяет конфиг холостым запуском OpenVPN, это секунда-другая.
pub fn set_vpn(target: Target, order: VpnOrder) {
    spawn(
        move || {
            let request = Request::SetVpnConfig {
                name: Some(order.name),
                config: Secret(order.config),
                key_password: order.key_password.map(Secret),
                login: order
                    .login
                    .map(|(user, password)| Login { user: Secret(user), password: Secret(password) }),
            };
            match ask(request) {
                Ok(Response::Ok) => Reply::VpnSet,
                Ok(Response::Error(e)) => Reply::VpnRefused(e),
                Ok(other) => Reply::VpnRefused(format!("служба ответила неожиданно: {other:?}")),
                Err(e) => Reply::VpnRefused(format!("служба не отвечает: {e}")),
            }
        },
        target,
    );
}

/// Подключить, отключить или сделать подключением по умолчанию.
pub fn vpn_action(target: Target, name: String, action: VpnAction, done: String) {
    spawn(
        move || match ask(Request::VpnAction { name, action }) {
            Ok(Response::Ok) => Reply::VpnDone(done),
            Ok(Response::Error(e)) => Reply::Failed(outdated(e)),
            Ok(other) => Reply::Failed(format!("служба ответила неожиданно: {other:?}")),
            Err(e) => Reply::Failed(format!("служба не отвечает: {e}")),
        },
        target,
    );
}

/// Сменить логин и пароль подключения.
pub fn set_vpn_login(target: Target, name: String, user: String, password: String) {
    spawn(
        move || {
            let done = format!("логин и пароль «{name}» заменены — подключение начинается заново");
            let login = Login { user: Secret(user), password: Secret(password) };
            match ask(Request::SetVpnLogin { name, login }) {
                Ok(Response::Ok) => Reply::VpnDone(done),
                Ok(Response::Error(e)) => Reply::Failed(outdated(e)),
                Ok(other) => Reply::Failed(format!("служба ответила неожиданно: {other:?}")),
                Err(e) => Reply::Failed(format!("служба не отвечает: {e}")),
            }
        },
        target,
    );
}

/// Отдать службе одноразовый код: подключиться с ним сейчас.
pub fn connect_vpn(target: Target, name: String, code: String) {
    spawn(
        move || {
            let request = Request::ConnectVpn { name: name.clone(), code: Secret(code) };
            match ask(request) {
                Ok(Response::Ok) => Reply::VpnConnecting(name),
                Ok(Response::Error(e)) => Reply::Failed(outdated(e)),
                Ok(other) => Reply::Failed(format!("служба ответила неожиданно: {other:?}")),
                Err(e) => Reply::Failed(format!("служба не отвечает: {e}")),
            }
        },
        target,
    );
}

/// Забыть своё подключение с этим именем.
pub fn clear_vpn(target: Target, name: String) {
    spawn(
        move || match ask(Request::ClearVpnConfig { name: Some(name) }) {
            Ok(Response::Ok) => Reply::VpnCleared,
            Ok(Response::Error(e)) => Reply::Failed(outdated(e)),
            Ok(other) => Reply::Failed(format!("служба ответила неожиданно: {other:?}")),
            Err(e) => Reply::Failed(format!("служба не отвечает: {e}")),
        },
        target,
    );
}

/// Запустить приложение через лончер. Сам лончер спросит у службы индекс
/// туннеля и откажется, если туннеля нет, — повторять эту проверку здесь
/// нельзя, иначе два места начнут решать одно и то же по-разному.
pub fn launch(target: Target, app: AppTarget) {
    let AppTarget::Executable(path) = app else {
        spawn(
            || Reply::Failed("Store-приложения пойдут через путь B — это Этап 11".to_owned()),
            target,
        );
        return;
    };
    spawn(move || run_launcher(&path), target);
}

fn spawn(work: impl FnOnce() -> Reply + Send + 'static, target: Target) {
    std::thread::Builder::new()
        .name("ipc".into())
        .spawn(move || target.deliver(WM_REPLY, work()))
        .ok();
}

/// Лончер лежит рядом с нами — так же, как hook.dll рядом с ним.
pub fn launcher_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("не найден свой путь: {e}"))?;
    let launcher = exe.with_file_name("vpnsplit-launch.exe");
    if !launcher.exists() {
        return Err(format!("рядом нет vpnsplit-launch.exe: {}", launcher.display()));
    }
    Ok(launcher)
}

fn run_launcher(path: &Path) -> Reply {
    match launch_now(path) {
        Ok(name) => Reply::Launched(name),
        Err(text) => Reply::Failed(text),
    }
}

/// Запускает приложение через лончер и ждёт, пока тот отчитается. Лончер
/// с `--no-wait` живёт недолго: поставил хуки — и вышел.
///
/// Отдельная функция, потому что этим же путём идёт ярлык с рабочего стола:
/// окно vpnsplit с ключом `--run` ничего не показывает, а просто зовёт
/// отсюда.
pub fn launch_now(path: &Path) -> Result<String, String> {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let launcher = launcher_path()?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());

    // Ждём выход самого лончера, а не конец его stderr: конец наступит,
    // только когда закроются все копии канала. Лончер своему приложению канал
    // не передаёт, но если копия где-то всё же осталась, окно не должно
    // висеть до закрытия браузера. Поэтому stderr читает отдельный поток,
    // а мы после выхода лончера ждём его недолго.
    //
    // Поток заводим до лончера: если создать его не выйдет, лончер получит
    // NUL вместо канала. Канал без читателя хуже: его закрытый конец
    // превращает следующий eprintln! лончера в панику, и уже запущенное
    // с хуками приложение окно назвало бы незапущенным.
    let (pipe_tx, pipe_rx) = std::sync::mpsc::channel::<ChildStderr>();
    let (text_tx, text_rx) = std::sync::mpsc::channel();
    let reader = std::thread::Builder::new()
        .name("launch-stderr".into())
        .spawn(move || {
            if let Ok(stderr) = pipe_rx.recv() {
                let _ = text_tx.send(read_tail(stderr));
            }
        });
    let stderr = if reader.is_ok() { Stdio::piped() } else { Stdio::null() };

    // --no-wait: лончер ставит хуки, отпускает приложение и выходит сам.
    // Иначе он жил бы ровно столько, сколько запущенная программа.
    // --detach-stdio: наш канал stderr приложению не передаётся (вместо него
    // NUL), иначе его конец наступил бы только с закрытием браузера. Лончер
    // ставится вместе с окном, поэтому этот ключ он знает.
    let mut child = std::process::Command::new(&launcher)
        .arg("--no-wait")
        .arg("--detach-stdio")
        .arg("--")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("не удалось запустить лончер: {e}"))?;

    // Если поток почему-то уже не принимает канал, держим его открытым сами
    // до выхода лончера — по той же причине, что выше.
    let unread = child.stderr.take().and_then(|stderr| pipe_tx.send(stderr).err());
    let status = child.wait().map_err(|e| format!("лончер: не дождались выхода: {e}"));
    drop(unread);
    if status?.success() {
        return Ok(name);
    }
    let text = text_rx.recv_timeout(STDERR_GRACE).unwrap_or_default();
    Err(format!("{name} не запущен: {}", last_line(&text)))
}

/// Сколько ждать остаток stderr после выхода лончера.
const STDERR_GRACE: std::time::Duration = std::time::Duration::from_secs(2);
/// Сколько хвоста stderr держать: причина отказа — последняя строка.
const STDERR_KEEP: usize = 16 * 1024;

/// Читает поток до конца, оставляя только последние [`STDERR_KEEP`] байт.
/// Дочитывать до конца нужно, иначе лончер мог бы встать на записи.
fn read_tail(mut input: impl Read) -> String {
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match input.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tail.extend_from_slice(&chunk[..n]);
                if tail.len() > STDERR_KEEP {
                    tail.drain(..tail.len() - STDERR_KEEP);
                }
            }
        }
    }
    String::from_utf8_lossy(&tail).into_owned()
}

/// Последняя непустая строка — то, чем лончер объясняет отказ.
fn last_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("лончер не объяснил причину")
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_only_the_end() {
        let mut input = vec![b'x'; STDERR_KEEP * 3];
        input.extend_from_slice("\nпоследняя строка\n".as_bytes());
        let text = read_tail(input.as_slice());
        assert!(text.len() <= STDERR_KEEP);
        assert_eq!(last_line(&text), "последняя строка");
    }

    #[test]
    fn last_line_skips_blanks_and_explains_silence() {
        assert_eq!(last_line("туннель: x\nотказ: нет прав\n\n  \n"), "отказ: нет прав");
        assert_eq!(last_line(""), "лончер не объяснил причину");
    }
}

//! Конфиг OpenVPN, по которому служба сама поднимает туннель.
//!
//! Конфиг приходит от пользователя, а запускает по нему `openvpn.exe`
//! служба под SYSTEM. Обычный `.ovpn` при этом умеет слишком многое:
//! директивы `up`, `route-up`, `plugin` запускают чужие программы, пути к
//! сертификатам читают чужие файлы, а `redirect-gateway` и
//! `block-outside-dns` перекраивают сеть всей машины — ровно то, чего
//! раздельное туннелирование делать не должно. Поэтому до службы доходит
//! не сам файл, а то, что от него осталось после разбора:
//!
//! - директивы из короткого списка разрешённых переписываются как есть;
//! - то, что забирает маршруты и DNS машины, **отбрасывается** — и об этом
//!   говорится, чтобы человек знал, что из его файла не сработает;
//! - всё, что запускает программы или читает файлы, и всё незнакомое —
//!   **отказ** с названием директивы. Угадывать здесь нельзя: пропущенная
//!   по незнанию директива — это команда, выполненная под SYSTEM.
//!
//! Модуль лежит в общем крейте, чтобы окно могло сказать о негодном файле
//! сразу, не дожидаясь службы. Верит служба только своему разбору.

/// Очищенный конфиг и то, что о нём стоит показать человеку.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    /// Текст, который служба положит рядом с собой и отдаст OpenVPN.
    pub text: String,
    /// Куда подключаемся: «адрес:порт (протокол)» первого сервера.
    pub remote: String,
    /// Директивы исходного файла, которые не сработают: они забирали бы
    /// сеть всей машины или не имеют смысла под службой.
    pub dropped: Vec<String>,
    /// Закрытый ключ в конфиге защищён паролем: без пароля OpenVPN
    /// остановится на вопросе, который под службой некому задать.
    pub needs_password: bool,
    /// Сервер спрашивает логин и пароль (`auth-user-pass`). Их, как и
    /// пароль ключа, служба хранит сама и отдаёт OpenVPN файлом.
    pub needs_login: bool,
    /// К паролю сервер ждёт одноразовый код (`static-challenge`) — при
    /// каждом подключении новый. Сохранить его нельзя: его спрашивают у
    /// человека всякий раз, когда подключение поднимается.
    pub needs_code: bool,
    /// Код приписывается к паролю как есть, а не в обёртке `SCRV1`.
    pub code_concat: bool,
    /// Тот же текст, но сервер в нём — этот же компьютер. По нему служба
    /// проверяет, что OpenVPN конфиг принимает и что пароль подходит, не
    /// тревожа настоящий сервер: второе подключение с тем же сертификатом
    /// выбило бы первое.
    pub probe: String,
}

/// Куда «подключается» проверочный запуск: порт discard этого же
/// компьютера, где никто не слушает.
pub const PROBE_REMOTE: &str = "remote 127.0.0.1 9";

/// Годится ли пароль ключа, чтобы отдать его OpenVPN файлом: одна
/// непустая строка.
pub fn check_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("пароль ключа пуст".to_owned());
    }
    if password.len() > 1000 || password.chars().any(char::is_control) {
        return Err("в пароле ключа есть перевод строки или он слишком длинный".to_owned());
    }
    Ok(())
}

/// Годятся ли логин и пароль, чтобы отдать их OpenVPN файлом: две непустые
/// строки.
pub fn check_login(user: &str, password: &str) -> Result<(), String> {
    for (what, value) in [("логин", user), ("пароль", password)] {
        if value.is_empty() {
            return Err(format!("{what} пуст"));
        }
        if value.len() > 1000 || value.chars().any(char::is_control) {
            return Err(format!("{what}: в нём перевод строки или он слишком длинный"));
        }
    }
    Ok(())
}

/// Годится ли одноразовый код: короткая строка без пробелов.
pub fn check_code(code: &str) -> Result<(), String> {
    if code.is_empty() {
        return Err("код пуст".to_owned());
    }
    if code.len() > 64 || !code.chars().all(|c| c.is_ascii_graphic()) {
        return Err("одноразовый код — до 64 букв и цифр без пробелов".to_owned());
    }
    Ok(())
}

/// Пароль с приложенным одноразовым кодом — таким, каким его составил бы
/// сам OpenVPN по директиве `static-challenge`: либо в обёртке `SCRV1`
/// (пароль и код порознь, каждый в base64), либо просто подряд.
pub fn with_code(password: &str, code: &str, concat: bool) -> String {
    if concat {
        format!("{password}{code}")
    } else {
        format!("SCRV1:{}:{}", base64(password.as_bytes()), base64(code.as_bytes()))
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = (chunk[0] as u32) << 16
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | chunk.get(2).copied().unwrap_or(0) as u32;
        for (at, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            // Чего в куске не было, то в ответе — знак «=».
            if at <= chunk.len() {
                out.push(ALPHABET[(group >> shift) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Текст конфига из байтов файла. Блокнот Windows любит UTF-16 и метку
/// порядка байтов; разбор ждёт обычный текст.
pub fn decode(bytes: Vec<u8>) -> Result<String, String> {
    let utf16 = |pairs: &[u8], big: bool| {
        let units: Vec<u16> = (0..pairs.len() / 2)
            .map(|at| [pairs[2 * at], pairs[2 * at + 1]])
            .map(|pair| if big { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) })
            .collect();
        String::from_utf16(&units).map_err(|_| "файл не текст".to_owned())
    };
    if bytes.len() > 4 * SIZE_LIMIT {
        return Err("файл слишком велик для конфига".to_owned());
    }
    match bytes.as_slice() {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        _ => String::from_utf8(bytes).map_err(|_| "файл не текст в UTF-8".to_owned()),
    }
}

/// Очищенный текст и его проверочная копия, строка в строку.
#[derive(Default)]
struct Out {
    text: String,
    probe: String,
    probed: bool,
}

impl Out {
    fn line(&mut self, line: &str) {
        for copy in [&mut self.text, &mut self.probe] {
            copy.push_str(line);
            copy.push('\n');
        }
    }

    /// Сервер: в настоящий текст — как есть, в проверочный — один раз и
    /// не настоящий.
    fn remote(&mut self, line: &str) {
        self.text.push_str(line);
        self.text.push('\n');
        if !std::mem::replace(&mut self.probed, true) {
            self.probe.push_str(PROBE_REMOTE);
            self.probe.push('\n');
        }
    }
}

/// Блоки с ключами и сертификатами, вписанные прямо в файл.
const BLOCKS: &[&str] = &["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs"];

/// Директивы, которые переписываются как есть: связь, шифры, сроки. Ни
/// одна из них не принимает путь к файлу и не запускает программ.
const KEEP: &[&str] = &[
    "client", "dev", "dev-type", "proto", "remote", "remote-random", "remote-random-hostname",
    "resolv-retry", "nobind", "persist-key", "persist-tun", "remote-cert-tls", "remote-cert-eku",
    "remote-cert-ku", "verify-x509-name", "ns-cert-type", "cipher", "data-ciphers",
    "data-ciphers-fallback", "ncp-ciphers", "auth", "comp-lzo", "compress", "allow-compression",
    "comp-noadapt", "verb", "mute", "mute-replay-warnings", "key-direction", "tls-client",
    "tls-version-min", "tls-version-max", "tls-cipher", "tls-ciphersuites", "tls-groups",
    "tls-cert-profile", "tls-timeout", "reneg-sec", "reneg-bytes", "reneg-pkts", "hand-window",
    "tran-window", "keepalive", "ping", "ping-restart", "ping-timer-rem", "float", "tun-mtu",
    "tun-mtu-extra", "mssfix", "fragment", "link-mtu", "mtu-disc", "sndbuf", "rcvbuf",
    "explicit-exit-notify", "connect-retry", "connect-timeout", "server-poll-timeout",
    "auth-nocache", "auth-retry", "topology", "pull", "port", "rport", "replay-window",
    // Свой порт и привязка к нему: числа и флаги, не пути. `lport 0` («порт
    // любой») пишет в конфиги OPNsense.
    "lport", "bind",
];

/// Директивы, которые молча выполнять нельзя, а отказывать из-за них
/// незачем: маршруты и DNS всей машины, журналы и режимы, которыми под
/// службой распоряжается она сама. Они выбрасываются, и человеку об этом
/// говорится.
const DROP: &[&str] = &[
    "redirect-gateway", "redirect-private", "block-outside-dns", "dhcp-option", "register-dns",
    "route", "route-ipv6", "route-metric", "route-gateway", "route-delay", "route-nopull",
    "route-noexec", "route-method", "pull-filter", "dns", "ip-win32", "block-ipv6",
    "allow-pull-fqdn", "daemon", "log", "log-append", "status", "writepid",
    "suppress-timestamps", "machine-readable-output", "user", "group", "persist-local-ip",
    "persist-remote-ip", "ping-exit", "inactive", "single-session", "connect-retry-max",
    "windows-driver", "disable-dco", "dev-node", "show-net-up", "tap-sleep", "dhcp-renew",
    "dhcp-release", "pause-exit", "service", "echo",
];

/// Директивы, из-за которых файл не принимается: они запускают программы,
/// читают или пишут файлы, открывают управление процессом или ведут связь
/// через посредника, о котором служба ничего не знает.
const REFUSE: &[&str] = &[
    "up", "down", "up-restart", "up-delay", "down-pre", "route-up", "route-pre-down", "ipchange",
    "tls-verify", "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address",
    "plugin", "script-security", "management", "management-client", "management-hold",
    "management-query-passwords", "management-external-key", "management-external-cert",
    "config", "cd", "chroot", "tmp-dir", "iproute", "engine", "pkcs11-providers", "pkcs11-id",
    "cryptoapicert", "http-proxy", "socks-proxy", "http-proxy-option", "askpass", "secret",
    "pkcs12", "setcon",
];

/// Больше настоящий конфиг с ключами не бывает; а читать под службой
/// мегабайты, присланные кем угодно, незачем.
const SIZE_LIMIT: usize = 256 * 1024;

/// OpenVPN читает файл кусками по 256 байт, и строка длиннее для него —
/// две строки: хвост длинной строки ключа он прочёл бы как директиву.
/// Настоящие строки ключей и сертификатов — 64–76 знаков.
const LINE_LIMIT: usize = 240;

/// С `verb 7` OpenVPN пишет в журнал ключи сеанса.
const VERB_LIMIT: u32 = 4;

/// Тише журнал делать нельзя: из него служба читает, какие адреса и какой
/// сервер имён сервер назначил подключению (строка `PUSH_REPLY`).
const VERB_FLOOR: u32 = 3;

const LOGIN_IN_FILE: &str = "логин и пароль в конфиге названы файлом или вписаны в него — так не \
                             принимается: оставьте просто «auth-user-pass», программа спросит их \
                             сама";

const CODE_WITHOUT_LOGIN: &str = "в конфиге одноразовый код (static-challenge) без логина и пароля \
                                  (auth-user-pass) — так не бывает";

/// Пометка в очищенном тексте: к паролю нужен одноразовый код. Сама
/// директива `static-challenge` до OpenVPN не доходит — под службой ему
/// некого спросить, код к паролю прикладываем мы, — а знать о ней после
/// перезапуска надо. `setenv` для OpenVPN — переменная для сценариев,
/// которых у нас нет.
const CODE_MARK: &str = "VPNSPLIT_CODE";

/// Пробелы по краям — те и только те, которые пробелами считает и OpenVPN.
fn strip(line: &str) -> &str {
    line.trim_matches(|c| c == ' ' || c == '\t')
}

/// Строка без пояснения. Пояснение начинается с «#» или «;» в начале
/// слова — так его понимает и OpenVPN. В кавычках он эти знаки пояснением
/// не считает, а мы считаем; от этого до него дойдёт меньше, чем было в
/// файле, но никогда не больше.
fn before_comment(line: &str) -> &str {
    let mut word_starts = true;
    for (at, c) in line.char_indices() {
        if word_starts && (c == '#' || c == ';') {
            return strip(&line[..at]);
        }
        word_starts = c == ' ' || c == '\t';
    }
    line
}

/// Строка, которую мы и OpenVPN заведомо читаем одинаково: печатные знаки
/// ASCII и табуляция, не длиннее куска, которым он читает файл.
///
/// Всё прочее — управляющие знаки, буквы не из ASCII — в директивах и
/// ключах не встречается, а разобрано двумя программами может быть
/// по-разному. Проверка, которая читает файл не так, как исполнитель, —
/// не проверка.
fn plain(line: &str) -> Result<(), String> {
    let shown = || line.chars().take(24).collect::<String>();
    if line.len() > LINE_LIMIT {
        return Err(format!("строка «{}…» длиннее {LINE_LIMIT} знаков", shown()));
    }
    if !line.chars().all(|c| c == '\t' || (' '..='~').contains(&c)) {
        return Err(format!(
            "в строке «{}» есть знаки, которых в конфиге быть не должно (не латиница или \
             управляющие)",
            shown()
        ));
    }
    Ok(())
}

/// Разбирает `.ovpn` и возвращает то, что из него можно отдать OpenVPN под
/// службой. Ошибка — готовая фраза для человека.
pub fn sanitize(source: &str) -> Result<Config, String> {
    if source.len() > SIZE_LIMIT {
        return Err(format!("конфиг больше {} КБ — это не похоже на .ovpn", SIZE_LIMIT / 1024));
    }
    let source = source.trim_start_matches('\u{feff}');
    let mut out = Out::default();
    out.line("# vpnsplit: sanitized copy, see service.log");
    let mut needs_password = false;
    let mut needs_login = false;
    // Нужен ли одноразовый код и в каком виде (`true` — подряд с паролем).
    let mut code: Option<bool> = None;
    let mut verb_given = false;
    let mut dropped = Vec::new();
    let mut blocks: Vec<&str> = Vec::new();
    let mut remote: Option<(String, Option<String>, Option<String>)> = None;
    let (mut proto, mut port) = (None::<String>, None::<String>);

    let mut lines = source.lines();
    while let Some(raw) = lines.next() {
        // Пояснения до OpenVPN не доходят вовсе — очищенный текст пишется
        // заново, — поэтому и писать в них можно что угодно.
        let line = before_comment(strip(raw));
        if line.is_empty() {
            continue;
        }
        plain(line)?;
        if let Some(tag) = line.strip_prefix('<').and_then(|rest| rest.strip_suffix('>')) {
            if tag == "auth-user-pass" {
                return Err(LOGIN_IN_FILE.to_owned());
            }
            let Some(known) = BLOCKS.iter().find(|block| **block == tag) else {
                return Err(format!("блок <{tag}> в конфиге не поддерживается"));
            };
            let close = format!("</{tag}>");
            out.line(line);
            let mut closed = false;
            for inner in lines.by_ref() {
                // Содержимое блока — ключ или сертификат; директивы в нём
                // не ищутся, оно переписывается построчно. Но конец блока
                // мы и OpenVPN обязаны видеть в одном и том же месте: тот
                // считает концом любую строку, которая с него начинается, и
                // всё после неё прочёл бы как директивы, которых мы не
                // проверяли. Поэтому строка, начинающаяся с «<», в блоке
                // может быть только его концом, написанным точно.
                let inner = strip(inner);
                // Саму строку в ошибке не показываем: это может быть кусок
                // закрытого ключа, а ошибка уйдёт в окно и в журнал.
                plain(inner).map_err(|_| {
                    format!(
                        "в блоке <{tag}> есть строка длиннее {LINE_LIMIT} знаков или со знаками \
                         не из латиницы — оставьте в блоке только сам ключ или сертификат"
                    )
                })?;
                if inner.starts_with('<') && inner != close {
                    return Err(format!(
                        "в блоке <{tag}> строка «{}» — не ключ и не конец блока",
                        inner.chars().take(24).collect::<String>()
                    ));
                }
                // Ключ, закрытый паролем, называет себя так в первой же
                // строке — и в новой записи, и в старой («Proc-Type»).
                needs_password |= tag == "key" && inner.contains("ENCRYPTED");
                out.line(inner);
                if inner == close {
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err(format!("блок <{tag}> в конфиге не закрыт"));
            }
            blocks.push(known);
            continue;
        }

        let mut words = line.split_whitespace();
        let name = words.next().unwrap_or_default().trim_start_matches("--");
        let arguments: Vec<&str> = words.collect();

        // `setenv opt X …` — «выполни X, если умеешь». По существу это X.
        if name == "setenv" {
            match arguments.as_slice() {
                ["opt", inner, ..] if DROP.contains(inner) => dropped.push(line.to_owned()),
                ["CLIENT_CERT", value] | ["FORWARD_COMPATIBLE", value] => {
                    out.line(&format!("setenv {} {value}", arguments[0]));
                }
                [CODE_MARK, "scrv1"] => code = Some(false),
                [CODE_MARK, "concat"] => code = Some(true),
                _ => return Err(format!("директива «{line}» не разрешена")),
            }
            continue;
        }
        if BLOCKS.contains(&name) {
            return Err(format!(
                "«{name}» в конфиге ссылается на отдельный файл; ключи и сертификаты должны \
                 быть вписаны в сам .ovpn (блок <{name}>…</{name}>)"
            ));
        }
        if name == "auth-user-pass" {
            // Без довода — «спроси у человека». Спросим мы, один раз, и
            // отдадим OpenVPN файлом; в очищенный текст директива не идёт,
            // её с путём к файлу ставит служба.
            if !arguments.is_empty() {
                return Err(LOGIN_IN_FILE.to_owned());
            }
            // В тексте остаётся сама пометка «нужен логин»: по ней служба
            // после перезапуска знает, что OpenVPN надо дать файл. Путь к
            // файлу она называет позже конфига, и он эту строку перекрывает.
            if !needs_login {
                out.line("auth-user-pass");
            }
            needs_login = true;
            continue;
        }
        if name == "static-challenge" {
            // Одноразовый код к паролю. Спросит его программа — при каждом
            // подключении — и приложит к паролю сама; текст вопроса нам не
            // нужен, а последнее слово говорит, как прикладывать.
            code = Some(arguments.last() == Some(&"concat"));
            continue;
        }
        if REFUSE.contains(&name) {
            return Err(format!(
                "директива «{name}» не разрешена: она запускает программы, работает с файлами \
                 или управлением, а служба выполняет конфиг с правами системы"
            ));
        }
        if DROP.contains(&name) {
            dropped.push(line.to_owned());
            continue;
        }
        if !KEEP.contains(&name) {
            return Err(format!(
                "директива «{name}» службе незнакома; незнакомое не выполняется, потому что \
                 конфиг работает с правами системы"
            ));
        }

        match name {
            // Имя устройства на Windows может быть именем адаптера;
            // выбирать адаптер конфигу незачем.
            "dev" if !matches!(arguments.as_slice(), ["tun"] | ["tap"]) => {
                return Err("в «dev» разрешены только tun и tap".to_owned());
            }
            "remote" => {
                let Some(host) = arguments.first() else {
                    return Err("в «remote» не указан сервер".to_owned());
                };
                if remote.is_none() {
                    remote = Some((
                        (*host).to_owned(),
                        arguments.get(1).map(|p| (*p).to_owned()),
                        arguments.get(2).map(|p| (*p).to_owned()),
                    ));
                }
            }
            "proto" => proto = arguments.first().map(|p| (*p).to_owned()),
            "port" | "rport" => port = arguments.first().map(|p| (*p).to_owned()),
            // Подробный журнал OpenVPN печатает ключи сеанса, а журнал
            // лежит там, где его читает любой пользователь машины.
            "verb" => {
                verb_given = true;
                let asked = arguments.first().and_then(|v| v.parse::<u32>().ok());
                if asked.is_none_or(|v| v > VERB_LIMIT) {
                    dropped.push(format!("{line} (журнал не подробнее verb {VERB_LIMIT})"));
                }
                // Слишком тихий журнал поднимается молча: человеку от этого
                // ни тепло ни холодно, а службе он нужен.
                let level = asked.unwrap_or(VERB_LIMIT).clamp(VERB_FLOOR, VERB_LIMIT);
                out.line(&format!("verb {level}"));
                continue;
            }
            _ => {}
        }
        let mut rebuilt = name.to_owned();
        for argument in &arguments {
            rebuilt.push(' ');
            rebuilt.push_str(argument);
        }
        if name == "remote" {
            out.remote(&rebuilt);
        } else {
            out.line(&rebuilt);
        }
    }

    let Some((host, remote_port, remote_proto)) = remote else {
        return Err("в конфиге нет сервера (директивы «remote»)".to_owned());
    };
    // Сертификат сервера нужен всегда. Свой сертификат с ключом — либо оба,
    // либо, если вход по логину и паролю, ни одного.
    let has = |block: &str| blocks.contains(&block);
    let needed: &[&str] = if needs_login && !has("cert") && !has("key") {
        &["ca"]
    } else {
        &["ca", "cert", "key"]
    };
    for block in needed {
        if !has(block) {
            return Err(format!(
                "в конфиге нет блока <{block}>: сертификаты и ключ должны быть вписаны в сам файл"
            ));
        }
    }
    if !verb_given {
        out.line(&format!("verb {VERB_FLOOR}"));
    }
    let remote = format!(
        "{host}:{} ({})",
        remote_port.or(port).unwrap_or_else(|| "1194".to_owned()),
        remote_proto.or(proto).unwrap_or_else(|| "udp".to_owned())
    );
    if code.is_some() && !needs_login {
        return Err(CODE_WITHOUT_LOGIN.to_owned());
    }
    if let Some(concat) = code {
        out.line(&format!("setenv {CODE_MARK} {}", if concat { "concat" } else { "scrv1" }));
    }
    Ok(Config {
        text: out.text,
        probe: out.probe,
        remote,
        dropped,
        needs_password,
        needs_login,
        needs_code: code.is_some(),
        code_concat: code == Some(true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: &str = "<ca>\nAAA\n</ca>\n<cert>\nBBB\n</cert>\n<key>\nCCC\n</key>\n";

    fn with(body: &str) -> String {
        format!("client\ndev tun\nproto udp\nremote 203.0.113.7 3333\n{KEYS}{body}")
    }

    #[test]
    fn an_ordinary_client_config_passes_and_keeps_its_keys() {
        // По образцу настоящего конфига пользователя.
        let source = with(
            "nobind\npersist-key\npersist-tun\nkey-direction 1\n<tls-auth>\nDDD\n</tls-auth>\n\
             remote-cert-tls server\ncomp-lzo\nverb 3\nredirect-gateway def1\n\
             pull-filter ignore \"route 192.168.\"\n",
        );
        let config = sanitize(&source).unwrap();
        assert_eq!(config.remote, "203.0.113.7:3333 (udp)");
        for kept in ["client\n", "dev tun\n", "comp-lzo\n", "key-direction 1\n", "<tls-auth>\nDDD\n</tls-auth>\n", "<key>\nCCC\n</key>\n"] {
            assert!(config.text.contains(kept), "нет {kept:?} в:\n{}", config.text);
        }
        // То, что забрало бы сеть всей машины, не доходит до OpenVPN — и
        // названо.
        assert!(!config.text.contains("redirect-gateway"));
        assert!(!config.text.contains("pull-filter"));
        assert_eq!(config.dropped.len(), 2, "{:?}", config.dropped);
        assert!(config.dropped[0].starts_with("redirect-gateway"));
    }

    #[test]
    fn anything_that_runs_a_program_is_refused_by_name() {
        for line in [
            "up \"C:\\\\Windows\\\\System32\\\\cmd.exe /c calc\"",
            "--up evil.bat",
            "route-up x.cmd",
            "script-security 2",
            "plugin evil.dll",
            "management 127.0.0.1 7505",
            "config other.ovpn",
            "tls-verify check.exe",
        ] {
            let error = sanitize(&with(&format!("{line}\n"))).unwrap_err();
            let name = line.split_whitespace().next().unwrap().trim_start_matches("--");
            assert!(error.contains(name), "{line}: {error}");
        }
    }

    #[test]
    fn the_unknown_is_refused_rather_than_guessed() {
        let error = sanitize(&with("some-future-option 1\n")).unwrap_err();
        assert!(error.contains("some-future-option"), "{error}");
        // Регистр в именах директив значим: «UP» — не «up», но и не
        // разрешённая директива.
        assert!(sanitize(&with("UP x\n")).is_err());
        assert!(sanitize(&with("setenv PATH C:\\evil\n")).is_err());
        assert!(sanitize(&with("<connection>\nremote a 1\n</connection>\n")).is_err());
    }

    #[test]
    fn keys_in_separate_files_and_passwords_are_refused_with_a_reason() {
        let error = sanitize("client\ndev tun\nremote a.example 1194\nca ca.crt\ncert c.crt\nkey c.key\n")
            .unwrap_err();
        assert!(error.contains("вписаны"), "{error}");
        // Логин и пароль спросит программа; названные файлом или вписанные
        // в конфиг — отказ, как и одноразовый код.
        let login = sanitize(&with("auth-user-pass\n")).unwrap();
        assert!(login.needs_login && login.text.contains("\nauth-user-pass\n"), "{}", login.text);
        // Очищенный текст, разобранный заново, говорит то же самое: по нему
        // служба узнаёт о логине после перезапуска.
        let again = sanitize(&login.text).unwrap();
        assert!(again.needs_login && again.text == login.text && !again.needs_code);
        assert!(!sanitize(&with("")).unwrap().needs_login);
        let error = sanitize(&with("auth-user-pass creds.txt\n")).unwrap_err();
        assert!(error.contains("логин"), "{error}");
        assert!(sanitize(&with("<auth-user-pass>\nu\np\n</auth-user-pass>\n")).is_err());
        // Одноразовый код: директива до OpenVPN не доходит, остаётся
        // пометка, и по ней очищенный текст читается так же.
        let coded = sanitize(&with("auth-user-pass\nstatic-challenge \"Enter OTP token:\" 1\n")).unwrap();
        assert!(coded.needs_login && coded.needs_code && !coded.code_concat);
        assert!(!coded.text.contains("static-challenge"), "{}", coded.text);
        assert!(coded.text.contains("setenv VPNSPLIT_CODE scrv1"), "{}", coded.text);
        let again = sanitize(&coded.text).unwrap();
        assert!(again.needs_code && again.text == coded.text);
        let concat =
            sanitize(&with("static-challenge \"Code\" 0 concat\nauth-user-pass\n")).unwrap();
        assert!(concat.needs_code && concat.code_concat);
        assert!(sanitize(&concat.text).unwrap().code_concat);
        let error = sanitize(&with("static-challenge \"Code\" 1\n")).unwrap_err();
        assert!(error.contains("без логина"), "{error}");
        assert!(sanitize(&with("auth-user-pass\nsetenv VPNSPLIT_CODE что-то\n")).is_err());
        // Пароль с кодом — как его составил бы сам OpenVPN.
        assert_eq!(with_code("pass", "123456", false), "SCRV1:cGFzcw==:MTIzNDU2");
        assert_eq!(with_code("pass", "123456", true), "pass123456");
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert!(check_code("123456").is_ok());
        assert!(check_code("").is_err() && check_code("12 34").is_err());
        assert!(check_code(&"1".repeat(65)).is_err());
        // Конфиг, каким его выдаёт OPNsense: свой порт «любой», имя
        // сервера в кавычках с запятыми, протокол при сервере.
        let opnsense = sanitize(&with(
            "lport 0\nreneg-sec 3600\nresolv-retry infinite\nauth SHA256\nremote-cert-tls server\n\
             verify-x509-name \"C=RU, ST=Moscow, O=Example LLC, CN=OVPN-SERVER\" subject\n\
             auth-user-pass\nstatic-challenge \"Enter OTP token:\" 1\n",
        ))
        .unwrap();
        assert!(opnsense.needs_code && opnsense.text.contains("\nlport 0\n"), "{}", opnsense.text);
        assert!(
            opnsense.text.contains("verify-x509-name \"C=RU, ST=Moscow, O=Example LLC, CN=OVPN-SERVER\" subject"),
            "{}",
            opnsense.text
        );
        // Со входом по логину свой сертификат не обязателен — но либо оба
        // блока, либо ни одного.
        let no_cert = "client\ndev tun\nremote a.example 1194\nauth-user-pass\n<ca>\nA\n</ca>\n";
        assert!(sanitize(no_cert).unwrap().needs_login);
        assert!(sanitize(&format!("{no_cert}<cert>\nB\n</cert>\n")).is_err());
        assert!(check_login("user", "пароль").is_ok());
        assert!(check_login("", "p").is_err() && check_login("u", "a\nb").is_err());
        // Без ключа или без сервера — тоже не конфиг.
        assert!(sanitize("client\ndev tun\nremote a 1\n<ca>\nA\n</ca>\n").is_err());
        assert!(sanitize(&format!("client\ndev tun\n{KEYS}")).is_err());
    }

    #[test]
    fn what_looks_like_a_directive_inside_a_key_is_not_one() {
        // Строка ключа может начинаться с чего угодно; разбирать её как
        // директиву значило бы отказывать настоящим ключам.
        let source = "client\ndev tun\nremote a.example\n<ca>\nup\nplugin\n</ca>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n";
        let config = sanitize(source).unwrap();
        assert!(config.text.contains("<ca>\nup\nplugin\n</ca>\n"));
        assert_eq!(config.remote, "a.example:1194 (udp)");
        // А незакрытый блок проглотил бы весь остаток файла.
        assert!(sanitize("client\nremote a 1\n<ca>\nA\n").unwrap_err().contains("не закрыт"));
    }

    #[test]
    fn the_machine_wide_switches_are_dropped_however_they_are_spelled() {
        let source = with(
            "block-outside-dns\nsetenv opt block-outside-dns\ndhcp-option DNS 10.8.0.1\n\
             route 10.0.0.0 255.0.0.0\nregister-dns\ndev-node MyTap\nlog c:\\\\x.log\n",
        );
        let config = sanitize(&source).unwrap();
        assert_eq!(config.dropped.len(), 7, "{:?}", config.dropped);
        for gone in ["block-outside-dns", "dhcp-option", "route ", "register-dns", "dev-node", "log "] {
            assert!(!config.text.contains(gone), "{gone} остался в:\n{}", config.text);
        }
        // И адаптер по имени конфиг выбрать не может.
        assert!(sanitize(&with("").replace("dev tun", "dev MyAdapter")).is_err());
    }

    #[test]
    fn the_end_of_a_block_is_where_openvpn_sees_it() {
        // OpenVPN считает концом блока строку, которая с него *начинается*.
        // Читай мы иначе, всё между его концом и нашим было бы директивами,
        // которых никто не проверял.
        let smuggled = "client\ndev tun\nremote a 1\n<ca>\nA\n</ca> x\nup evil.bat\n<extra-certs>\n</ca>\n\
                        </extra-certs>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n";
        let error = sanitize(smuggled).unwrap_err();
        assert!(error.contains("не ключ и не конец"), "{error}");
        // То же через длину: кусками по 256 байт хвост длинной строки стал
        // бы для OpenVPN отдельной строкой.
        let long = format!("{}</ca>", "A".repeat(255));
        let error = sanitize(&format!("client\nremote a 1\n<ca>\n{long}\nup evil.bat\n</ca>\n")).unwrap_err();
        assert!(error.contains("длиннее"), "{error}");
        // И содержимое ключа в ошибку не попадает.
        let secret = format!("<key>\n{}\n</key>\n", "S3CRET".repeat(50));
        let error = sanitize(&format!("client\nremote a 1\n{secret}")).unwrap_err();
        assert!(!error.contains("S3CRET"), "{error}");
        // Пробелы перед концом блока OpenVPN пропускает — и мы тоже.
        let config = sanitize("client\nremote a 1\n<ca>\nA\n \t</ca>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n").unwrap();
        assert!(config.text.contains("<ca>\nA\n</ca>\n<cert>"), "{}", config.text);
    }

    #[test]
    fn only_what_both_programs_read_alike_gets_through() {
        // Пояснения — на любом языке: до OpenVPN они не доходят.
        let config = sanitize(&with("# мой сервер\n; и это тоже\nnobind # не занимать порт\n")).unwrap();
        assert!(config.text.contains("nobind\n"), "{}", config.text);
        assert!(!config.text.contains("сервер") && !config.text.contains("порт"), "{}", config.text);
        assert!(config.text.is_ascii());
        // А директива — только из печатных знаков ASCII.
        assert!(sanitize(&with("remote сервер.рф 1194\n")).is_err());
        assert!(sanitize(&with("nobind\u{b}up x\n")).is_err());
        assert!(sanitize(&with("nobind\rup x\n")).is_err());
        assert!(sanitize(&with("no\u{a0}bind\n")).is_err());
        // Кавычки и косые OpenVPN снимает; имя с ними — уже другое имя.
        assert!(sanitize(&with("\"up\" x\n")).is_err());
        assert!(sanitize(&with("u\\p x\n")).is_err());
        // Слишком большой файл не читается вовсе.
        assert!(sanitize(&with(&"# x\n".repeat(80_000))).unwrap_err().contains("КБ"));
    }

    #[test]
    fn a_key_under_a_password_is_noticed() {
        assert!(!sanitize(&with("")).unwrap().needs_password);
        let modern = "client\nremote a 1\n<ca>\nA\n</ca>\n<cert>\nB\n</cert>\n<key>\n\
                      -----BEGIN ENCRYPTED PRIVATE KEY-----\nC\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n";
        assert!(sanitize(modern).unwrap().needs_password);
        let legacy = "client\nremote a 1\n<ca>\nA\n</ca>\n<cert>\nB\n</cert>\n<key>\n\
                      -----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nC\n</key>\n";
        assert!(sanitize(legacy).unwrap().needs_password);
        // Слово в сертификате, а не в ключе, ничего не значит.
        let elsewhere = "client\nremote a 1\n<ca>\nENCRYPTED\n</ca>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n";
        assert!(!sanitize(elsewhere).unwrap().needs_password);
        // Пароль — одна непустая строка.
        assert!(check_password("пароль с пробелом").is_ok());
        assert!(check_password("").is_err());
        assert!(check_password("a\nb").is_err());
    }

    #[test]
    fn a_file_saved_by_notepad_is_still_a_config() {
        let text = "client\n# сервер\n";
        assert_eq!(decode(text.as_bytes().to_vec()).as_deref(), Ok(text));
        let mut little = vec![0xFF, 0xFE];
        little.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode(little).as_deref(), Ok(text));
        let mut big = vec![0xFE, 0xFF];
        big.extend(text.encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode(big).as_deref(), Ok(text));
        // Метка UTF-8 остаётся в тексте — её снимает сам разбор.
        let mut marked = vec![0xEF, 0xBB, 0xBF];
        marked.extend(with("").into_bytes());
        assert!(sanitize(&decode(marked).unwrap()).is_ok());
        assert!(decode(vec![0xC3, 0x28]).is_err());
    }

    #[test]
    fn the_probe_copy_never_names_the_real_server() {
        let config = sanitize(&format!(
            "client\ndev tun\nremote vpn.example 8443\nremote backup.example 1194 tcp\nnobind\n{KEYS}"
        ))
        .unwrap();
        assert!(config.text.contains("remote vpn.example 8443\nremote backup.example 1194 tcp\n"));
        assert!(!config.probe.contains("example"), "{}", config.probe);
        assert_eq!(config.probe.matches("remote ").count(), 1, "{}", config.probe);
        assert!(config.probe.contains("dev tun\nremote 127.0.0.1 9\nnobind\n"), "{}", config.probe);
        // Всё остальное — то же самое, включая ключи: проверяется именно
        // то, что будет запущено.
        assert_eq!(
            config.probe.replace("remote 127.0.0.1 9\n", ""),
            config.text.replace("remote vpn.example 8443\nremote backup.example 1194 tcp\n", "")
        );
    }

    #[test]
    fn a_talkative_log_is_quietened() {
        let config = sanitize(&with("verb 9\n")).unwrap();
        assert!(config.text.contains("verb 4\n") && !config.text.contains("verb 9"), "{}", config.text);
        assert_eq!(config.dropped.len(), 1);
        let config = sanitize(&with("verb 3\n")).unwrap();
        assert!(config.text.contains("verb 3\n") && config.dropped.is_empty());
        assert!(sanitize(&with("verb много\n")).is_err());
        assert!(sanitize(&with("verb x\n")).unwrap().text.contains("verb 4\n"));
        // А слишком тихий — поднимается, и без него журнал тоже не молчит:
        // из него служба читает, что сервер назначил подключению.
        let quiet = sanitize(&with("verb 0\n")).unwrap();
        assert!(quiet.text.contains("verb 3\n") && quiet.dropped.is_empty(), "{}", quiet.text);
        assert!(sanitize(&with("")).unwrap().text.ends_with("verb 3\n"));
    }

    #[test]
    fn the_port_and_protocol_are_taken_from_wherever_they_are_given() {
        let config = sanitize(&format!("client\ndev tun\nproto tcp\nport 443\nremote vpn.example\n{KEYS}")).unwrap();
        assert_eq!(config.remote, "vpn.example:443 (tcp)");
        let config = sanitize(&format!("client\ndev tun\nremote vpn.example 8443 tcp-client\nremote b 1\n{KEYS}")).unwrap();
        assert_eq!(config.remote, "vpn.example:8443 (tcp-client)");
    }
}

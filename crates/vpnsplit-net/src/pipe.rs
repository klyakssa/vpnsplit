//! Канал до службы: named pipe, по строке JSON на сообщение.
//!
//! Сервер создаёт экземпляр канала, блокируется в ConnectNamedPipe до
//! подключения клиента (без опросов — поток просто спит) и отдаёт
//! соединение обработчику. Клиент — обычный `std::fs::File`.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use vpnsplit_core::{Event, Request, Response, PIPE_NAME};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, IsWellKnownSid, RevertToSelf,
    TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_WRITE_DATA, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, PeekNamedPipe,
    WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

/// Кто может подключаться: SYSTEM и администраторы — полный доступ, любой
/// вошедший пользователь — чтение и запись. Без явного дескриптора Windows
/// дала бы обычным пользователям только чтение, и UI не смог бы ничего
/// попросить у службы.
///
/// Запись пользователям — не `GW`, а явная маска 0x12019b
/// (FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
/// FILE_WRITE_EA). У канала FILE_APPEND_DATA — это тот же бит 0x4, что и
/// FILE_CREATE_PIPE_INSTANCE, а `GW` его включает: с ним любой
/// пользователь мог бы заводить свои экземпляры канала службы и отвечать
/// клиентам вместо неё.
///
/// Запрет бьёт и по самому серверу: новый экземпляр канала создаётся с
/// проверкой этого же списка. Службе (SY) и повышенной консоли (BA) хватает
/// своих записей, а консольному `vpnsplit-svc run` без прав `Server::new`
/// дописывает полный доступ для его пользователя (см. `pipe_sddl`).
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)";

/// Список доступа канала для сервера, запущенного от `own` без повышения.
/// Право заводить экземпляры получает только он сам: процесс той же
/// учётной записи и без канала может всё, что может этот сервер.
/// Повышенному серверу своя запись не нужна, и её нет: иначе необычные
/// процессы того же администратора заводили бы экземпляры канала с
/// владельцем «администраторы», которому клиенты верят.
fn pipe_sddl(own: Option<&str>) -> String {
    match own {
        Some(sid) => format!("{PIPE_SDDL}(A;;GA;;;{sid})"),
        None => PIPE_SDDL.to_owned(),
    }
}

/// Предел одной строки протокола. Самое длинное, что ходит по каналу, —
/// политика и текст `.ovpn` с сертификатами, это десятки килобайт. Без
/// предела клиент, который шлёт байты без перевода строки, растил бы
/// строку в службе под SYSTEM, пока не кончится память.
pub const MAX_LINE: usize = 1024 * 1024;

const ERROR_PIPE_CONNECTED: u32 = 535;
const ERROR_PIPE_BUSY: u32 = 231;
const ERROR_FILE_NOT_FOUND: u32 = 2;

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect()
}

/// Соединение с одной стороны канала, построчный JSON.
pub struct Connection {
    reader: BufReader<File>,
}

impl Connection {
    fn new(file: File) -> Self {
        Connection { reader: BufReader::new(file) }
    }

    pub fn send<T: Serialize>(&mut self, message: &T) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(message).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let file = self.reader.get_mut();
        file.write_all(&line)?;
        file.flush()
    }

    /// `Ok(None)` — собеседник закрыл канал. Строка длиннее `MAX_LINE` —
    /// ошибка протокола: дочитывать её никто не станет, соединение
    /// закрывается.
    pub fn receive<T: DeserializeOwned>(&mut self) -> std::io::Result<Option<T>> {
        parse_line(read_line_limited(&mut self.reader, MAX_LINE))
    }

    /// Как `receive`, но `heard` встаёт, как только от собеседника пришёл
    /// первый байт, ещё до конца строки. По нему служба отличает клиента,
    /// который передаёт длинный запрос, от того, кто молчит.
    pub fn receive_noting<T: DeserializeOwned>(&mut self, heard: &AtomicBool) -> std::io::Result<Option<T>> {
        parse_line(read_line_limited(&mut Noting { inner: &mut self.reader, heard }, MAX_LINE))
    }

    /// Закрыл ли собеседник свой конец. Для того, кто сам только пишет
    /// (подписка): без чтения уход клиента иначе заметен лишь при
    /// следующей записи. Не читает из канала и не ждёт.
    pub fn peer_gone(&self) -> bool {
        let pipe = self.reader.get_ref().as_raw_handle() as HANDLE;
        let mut available = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                pipe,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        // ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED. Прочие
        // ошибки — не повод выкидывать живого подписчика.
        ok == 0 && matches!(unsafe { GetLastError() }, 109 | 232 | 233)
    }

    /// Запущен ли клиент на том конце с повышенными правами. Имеет смысл
    /// только на стороне сервера. Любая неудача по дороге означает «нет»:
    /// отказать администратору — неудобство, пропустить постороннего — дыра.
    pub fn client_elevated(&self) -> bool {
        self.client().is_some_and(|client| client.elevated)
    }

    /// Кто на том конце канала — по токену самого клиента канала. Имеет
    /// смысл только на стороне сервера и только после того, как от клиента
    /// что-то прочитано: раньше Windows не даёт примерить его личность.
    ///
    /// Раньше спрашивали процесс по номеру из `GetNamedPipeClientProcessId`,
    /// но номер процесс не держит: клиент мог отдать ручку канала потомку и
    /// выйти, а его номер достался бы другому, хоть повышенному, процессу.
    /// Токен клиента канала так не подменить.
    ///
    /// Личность примеряет отдельный короткий поток. Служба работает от
    /// SYSTEM, и поток, который примерил чужую личность и не смог её снять,
    /// остался бы работать от имени клиента. Короткий поток кончается сразу,
    /// а вместе с ним и примеренная личность, — что бы ни вернул
    /// `RevertToSelf`.
    pub fn client(&self) -> Option<Client> {
        let pipe = self.reader.get_ref().as_raw_handle() as usize;
        let token = std::thread::Builder::new()
            .name("pipe-client".into())
            .spawn(move || unsafe {
                if ImpersonateNamedPipeClient(pipe as HANDLE) == 0 {
                    return None;
                }
                let mut token: HANDLE = std::ptr::null_mut();
                // OpenAsSelf: право открыть токен проверяется у службы, а не
                // у примеренного клиента.
                let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
                RevertToSelf();
                (opened != 0).then_some(token as usize)
            })
            .ok()?
            .join()
            .ok()??;
        let token = token as HANDLE;
        let elevated = token_elevated(token).unwrap_or(false);
        let sid = token_user(token).and_then(|user| sid_string(user.sid()));
        unsafe { CloseHandle(token) };
        Some(Client { elevated, sid })
    }
}

/// Клиент канала глазами службы.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    /// Токен клиента повышен: администратор в окне с правами.
    pub elevated: bool,
    /// SID пользователя строкой (`S-1-5-21-…`); `None` — не узнали.
    pub sid: Option<String>,
}

/// Разбор прочитанной строки протокола.
fn parse_line<T: DeserializeOwned>(read: std::io::Result<Option<Vec<u8>>>) -> std::io::Result<Option<T>> {
    match read {
        Ok(None) => Ok(None),
        Ok(Some(line)) => {
            let text = std::str::from_utf8(&line).map_err(std::io::Error::other)?;
            serde_json::from_str(text.trim_end())
                .map(Some)
                .map_err(std::io::Error::other)
        }
        // ERROR_BROKEN_PIPE: клиент ушёл — для сервера это обычный конец.
        Err(e) if e.raw_os_error() == Some(109) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Чтение, которое отмечает, что от собеседника что-то пришло.
struct Noting<'a, R> {
    inner: &'a mut R,
    heard: &'a AtomicBool,
}

impl<R: BufRead> Read for Noting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read > 0 {
            self.heard.store(true, Ordering::Relaxed);
        }
        Ok(read)
    }
}

impl<R: BufRead> BufRead for Noting<'_, R> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        let buf = self.inner.fill_buf()?;
        if !buf.is_empty() {
            self.heard.store(true, Ordering::Relaxed);
        }
        Ok(buf)
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount)
    }
}

/// Строка до перевода строки включительно, не длиннее `limit` байт.
/// `Ok(None)` — поток кончился до первого байта.
fn read_line_limited<R: BufRead>(reader: &mut R, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    // Байт сверх предела — чтобы отличить «ровно предел» от «больше».
    let read = reader.take(limit as u64 + 1).read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("строка длиннее {limit} байт"),
        ));
    }
    Ok(Some(line))
}

/// TOKEN_USER с SID следом за ним, в буфере с выравниванием структуры.
struct TokenUserBuf(Vec<u64>);

impl TokenUserBuf {
    fn sid(&self) -> PSID {
        unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
    }
}

fn token_user(token: HANDLE) -> Option<TokenUserBuf> {
    let mut size = 0u32;
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size) };
    // SID не длиннее 68 байт; предел здесь — от ошибки, а не от жадности.
    if size == 0 || size > 1024 {
        return None;
    }
    let mut buf = TokenUserBuf(vec![0u64; (size as usize).div_ceil(8)]);
    let ok = unsafe {
        GetTokenInformation(token, TokenUser, buf.0.as_mut_ptr() as *mut _, size, &mut size)
    };
    (ok != 0).then_some(buf)
}

fn token_elevated(token: HANDLE) -> Option<bool> {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut size = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    };
    (ok != 0).then_some(elevation.TokenIsElevated != 0)
}

fn sid_string(sid: PSID) -> Option<String> {
    let mut text: windows_sys::core::PWSTR = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return None;
    }
    let len = (0..).take_while(|&at| unsafe { *text.add(at) } != 0).count();
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) }).ok();
    unsafe { LocalFree(text as _) };
    result
}

/// Та ли служба на том конце канала, за которую себя выдаёт. Сторона
/// клиента.
///
/// Пока служба остановлена (обновление, падение), имя канала свободно, и
/// создать канал с ним может любой процесс. А клиент шлёт по каналу
/// закрытые ключи и пароли VPN, и лончер берёт из ответа интерфейс, к
/// которому привяжет сокеты. Поэтому сервер проверяется до первого байта.
///
/// Смотрим владельца самого канала, а не процесс-сервер по номеру: номер
/// процесс не держит — самозванец мог создать канал, отдать его ручку
/// другому своему процессу и выйти, а номер достался бы процессу SYSTEM.
/// Владельца же канала назначает тот, кто его создал, и назначить SYSTEM
/// или группу администраторов может только SYSTEM или повышенный
/// администратор. Добавить свой экземпляр к каналу службы посторонний не
/// может (см. `PIPE_SDDL`).
///
/// Служба работает от SYSTEM; повышенный консольный режим `vpnsplit-svc
/// run` создаёт канал с владельцем «администраторы». Консольный режим без
/// прав создаёт его от имени того, кто его запустил, — такому серверу
/// верим, если это ты сам: процесс твоей же учётной записи и без канала
/// может всё, что можешь ты, а чужой пользователь так не притворится.
fn server_trusted(file: &File) -> bool {
    let me = own_user();
    pipe_owner_trusted(file.as_raw_handle() as HANDLE, me.as_ref().map(TokenUserBuf::sid))
}

/// Пользователь этого процесса.
fn own_user() -> Option<TokenUserBuf> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let user = token_user(token);
    unsafe { CloseHandle(token) };
    user
}

/// SID пользователя этого процесса, если процесс не повышен. Не узнали,
/// повышен ли, — считаем, что нет: своя запись в списке канала даёт права
/// только своей же учётной записи.
fn own_unelevated_sid() -> Option<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let elevated = token_elevated(token).unwrap_or(false);
    let sid = token_user(token).and_then(|user| sid_string(user.sid()));
    unsafe { CloseHandle(token) };
    if elevated {
        None
    } else {
        sid
    }
}

/// Владелец канала — SYSTEM, администраторы или `me`.
fn pipe_owner_trusted(pipe: HANDLE, me: Option<PSID>) -> bool {
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return false;
    }
    let trusted = !owner.is_null()
        && unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
                || me.is_some_and(|me| EqualSid(owner, me) != 0)
        };
    unsafe { LocalFree(descriptor as _) };
    trusted
}

pub struct Server {
    name: Vec<u16>,
    descriptor: PSECURITY_DESCRIPTOR,
    first: AtomicBool,
}

// Дескриптор безопасности только читается при создании экземпляров канала.
unsafe impl Send for Server {}
unsafe impl Sync for Server {}

impl Server {
    pub fn new() -> Result<Self, String> {
        Self::named(PIPE_NAME)
    }

    fn named(name: &str) -> Result<Self, String> {
        let own = own_unelevated_sid();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(&pipe_sddl(own.as_deref())).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!("не удалось собрать дескриптор безопасности (код {})", unsafe {
                GetLastError()
            }));
        }
        Ok(Server { name: wide(name), descriptor, first: AtomicBool::new(true) })
    }

    /// Ждёт следующего клиента. Блокируется, CPU не тратит.
    pub fn accept(&self) -> Result<Connection, String> {
        self.create_instance()?.wait()
    }

    /// Создаёт экземпляр канала, не дожидаясь клиента. Первый вызов падает,
    /// если канал с таким именем уже существует, — значит, служба запущена
    /// или кто-то выдаёт себя за неё.
    pub fn create_instance(&self) -> Result<Instance, String> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if self.first.swap(false, Ordering::SeqCst) {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let handle = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                &attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!("CreateNamedPipeW не удался (код {}) — служба уже запущена?", unsafe {
                GetLastError()
            }));
        }
        Ok(Instance { file: unsafe { File::from_raw_handle(handle as RawHandle) } })
    }
}

/// Экземпляр канала, ещё не принявший клиента.
pub struct Instance {
    file: File,
}

impl Instance {
    pub fn wait(self) -> Result<Connection, String> {
        let handle = std::os::windows::io::AsRawHandle::as_raw_handle(&self.file);
        let connected = unsafe { ConnectNamedPipe(handle as _, std::ptr::null_mut()) };
        if connected == 0 {
            let code = unsafe { GetLastError() };
            // Клиент успел подключиться между созданием и ожиданием — это успех.
            if code != ERROR_PIPE_CONNECTED {
                return Err(format!("ConnectNamedPipe не удался (код {code})"));
            }
        }
        Ok(Connection::new(self.file))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe { LocalFree(self.descriptor as _) };
    }
}

/// Подключение клиента. Между обслуживанием одного клиента и созданием
/// следующего экземпляра у сервера есть короткое окно, поэтому «занято»
/// и «не найдено» повторяются несколько раз.
pub fn connect() -> std::io::Result<Connection> {
    let name = wide(PIPE_NAME);
    // «Занято» — все экземпляры обслуживают других клиентов, ждём.
    // «Не найдено» — либо короткое окно между экземплярами, либо служба не
    // запущена вовсе; второе частый случай, поэтому повторов мало.
    let mut not_found = 0;
    for _ in 0..20 {
        // Права — явной маской, а не `write(true)`: GENERIC_WRITE у канала
        // включает FILE_CREATE_PIPE_INSTANCE, которого служба обычным
        // пользователям не даёт (см. `PIPE_SDDL`), и открытие не удалось бы.
        // Уровень подмены — только опознание: серверу хватит узнать, кто
        // клиент, а действовать от его имени ему незачем — тем более
        // самозванцу, если он всё же окажется на том конце.
        let opened = std::fs::OpenOptions::new()
            .access_mode(GENERIC_READ | FILE_WRITE_DATA)
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(PIPE_NAME);
        match opened {
            Ok(file) => {
                if !server_trusted(&file) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "на том конце канала vpnsplit не служба: канал завёл не SYSTEM, не \
                         администратор и не ты сам. Запрос не отправлен",
                    ));
                }
                return Ok(Connection::new(file));
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                unsafe { WaitNamedPipeW(name.as_ptr(), 500) };
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                not_found += 1;
                if not_found >= 3 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "служба vpnsplit не отвечает"))
}

/// Один запрос — один ответ.
pub fn request(request: &Request) -> std::io::Result<Response> {
    let mut connection = connect()?;
    connection.send(request)?;
    connection
        .receive()?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "служба закрыла канал"))
}

/// Подписка на события. Возвращает итератор, который блокируется до
/// следующего события и заканчивается, когда служба закрывает канал.
pub fn subscribe() -> std::io::Result<impl Iterator<Item = std::io::Result<Event>>> {
    let mut connection = connect()?;
    connection.send(&Request::Subscribe)?;
    match connection.receive::<Response>()? {
        Some(Response::Ok) => {}
        other => {
            return Err(std::io::Error::other(format!("служба не приняла подписку: {other:?}")));
        }
    }
    Ok(std::iter::from_fn(move || connection.receive::<Event>().transpose()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_token() -> (bool, Option<String>) {
        let mut token: HANDLE = std::ptr::null_mut();
        let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        assert_ne!(unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }, 0);
        let elevated = token_elevated(token).unwrap();
        let sid = token_user(token).and_then(|user| sid_string(user.sid()));
        unsafe { CloseHandle(token) };
        (elevated, sid)
    }

    #[test]
    fn both_ends_know_who_is_on_the_other_one() {
        // Свой канал под своим именем: служба тут ни при чём. Сервер — этот
        // же процесс, и его канал клиент примет всегда: владелец — либо
        // администраторы, либо ты сам. А без «себя» в доверенных — ровно
        // тогда, когда процесс повышен: канал обычного процесса чужого
        // пользователя службой не сочтётся.
        let name = format!(r"\\.\pipe\vpnsplit-test-{}", std::process::id());
        let wide_name = wide(&name);
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let server = unsafe { File::from_raw_handle(handle as RawHandle) };
        let client = std::fs::OpenOptions::new()
            .access_mode(GENERIC_READ | FILE_WRITE_DATA)
            .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
            .open(&name)
            .unwrap();
        let (elevated, sid) = own_token();
        assert!(server_trusted(&client));
        assert_eq!(pipe_owner_trusted(client.as_raw_handle() as HANDLE, None), elevated);

        let mut server = Connection::new(server);
        let mut client = Connection::new(client);
        client.send(&Request::GetStatus).unwrap();
        assert_eq!(server.receive::<Request>().unwrap(), Some(Request::GetStatus));
        let seen = server.client().unwrap();
        assert_eq!(seen.elevated, elevated);
        assert!(sid.is_some());
        assert_eq!(seen.sid, sid);
    }

    #[test]
    fn own_server_gets_full_access_and_others_do_not() {
        assert_eq!(pipe_sddl(None), PIPE_SDDL);
        let sddl = pipe_sddl(Some("S-1-5-21-1-2-3-1001"));
        assert!(sddl.starts_with(PIPE_SDDL), "{sddl}");
        assert!(sddl.ends_with("(A;;GA;;;S-1-5-21-1-2-3-1001)"), "{sddl}");
        // У всех остальных бита FILE_CREATE_PIPE_INSTANCE (0x4) нет.
        assert_eq!(0x12019b & 0x4, 0);
    }

    #[test]
    fn the_server_opens_a_second_instance_with_its_own_rights() {
        // Тот самый список доступа службы, но на своём имени. Первый
        // экземпляр создаётся без проверки списка, второй — с ней: без
        // повышения его создать позволяет только своя запись в списке.
        let name = format!(r"\\.\pipe\vpnsplit-test-two-{}", std::process::id());
        let server = Server::named(&name).unwrap();
        let open = || {
            std::fs::OpenOptions::new()
                .access_mode(GENERIC_READ | FILE_WRITE_DATA)
                .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)
                .open(&name)
        };
        let first = server.create_instance().unwrap();
        let first_client = open().unwrap();
        let _first = first.wait().unwrap();

        let second = server.create_instance().unwrap();
        let second_client = open().unwrap();
        let mut second = second.wait().unwrap();
        assert!(server_trusted(&second_client));
        let mut client = Connection::new(second_client);
        client.send(&Request::GetStatus).unwrap();
        assert_eq!(second.receive::<Request>().unwrap(), Some(Request::GetStatus));
        assert!(!second.peer_gone());
        drop(client);
        assert!(second.peer_gone());
        drop(first_client);
    }

    #[test]
    fn noting_marks_the_first_byte_before_the_line_ends() {
        let heard = AtomicBool::new(false);
        let mut silent: &[u8] = b"";
        assert_eq!(read_line_limited(&mut Noting { inner: &mut silent, heard: &heard }, 64).unwrap(), None);
        assert!(!heard.load(Ordering::Relaxed));
        // Строка оборвалась без перевода — байты всё же пришли.
        let mut partial: &[u8] = b"{\"a\"";
        let _ = read_line_limited(&mut Noting { inner: &mut partial, heard: &heard }, 64);
        assert!(heard.load(Ordering::Relaxed));
    }

    #[test]
    fn a_line_within_the_limit_is_read_whole() {
        let mut input: &[u8] = b"{\"a\":1}\n{\"b\":2}\n";
        assert_eq!(read_line_limited(&mut input, 64).unwrap().as_deref(), Some(&b"{\"a\":1}\n"[..]));
        assert_eq!(read_line_limited(&mut input, 64).unwrap().as_deref(), Some(&b"{\"b\":2}\n"[..]));
        assert_eq!(read_line_limited(&mut input, 64).unwrap(), None);
    }

    #[test]
    fn a_line_exactly_at_the_limit_passes_and_one_byte_more_does_not() {
        let mut exact: &[u8] = b"1234567\n";
        assert!(read_line_limited(&mut exact, 8).unwrap().is_some());
        let mut over: &[u8] = b"12345678\n";
        let error = read_line_limited(&mut over, 8).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn an_endless_line_is_not_swallowed() {
        // Байты без перевода строки: читается не больше предела и ещё одного
        // байта, остальное остаётся непрочитанным.
        let endless = vec![b'x'; 10 * 1024];
        let mut input: &[u8] = &endless;
        assert!(read_line_limited(&mut input, 100).is_err());
        assert_eq!(input.len(), 10 * 1024 - 101);
    }
}

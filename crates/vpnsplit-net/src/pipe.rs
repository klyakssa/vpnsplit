//! Канал до службы: named pipe, по строке JSON на сообщение.
//!
//! Сервер создаёт экземпляр канала, блокируется в ConnectNamedPipe до
//! подключения клиента (без опросов — поток просто спит) и отдаёт
//! соединение обработчику. Клиент — обычный `std::fs::File`.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use vpnsplit_core::{Event, Request, Response, PIPE_NAME};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Кто может подключаться: SYSTEM и администраторы — полный доступ, любой
/// вошедший пользователь — чтение и запись. Без явного дескриптора Windows
/// дала бы обычным пользователям только чтение, и UI не смог бы ничего
/// попросить у службы.
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

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

    /// `Ok(None)` — собеседник закрыл канал.
    pub fn receive<T: DeserializeOwned>(&mut self) -> std::io::Result<Option<T>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => serde_json::from_str(line.trim_end())
                .map(Some)
                .map_err(std::io::Error::other),
            // ERROR_BROKEN_PIPE: клиент ушёл — для сервера это обычный конец.
            Err(e) if e.raw_os_error() == Some(109) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Запущен ли клиент на том конце с повышенными правами. Имеет смысл
    /// только на стороне сервера.
    ///
    /// Спрашивается у процесса клиента, а не через подмену личности потока
    /// (`ImpersonateNamedPipeClient`), и вот почему. Служба работает от
    /// SYSTEM; поток, который примерил чужую личность и не смог её снять,
    /// — отдельный класс бед, и заводить его ради одного вопроса незачем.
    /// К тому же уровень подмены выбирает клиент, а номер своего процесса
    /// он подделать не может.
    ///
    /// Любая неудача по дороге означает «нет»: отказать администратору —
    /// неудобство, пропустить постороннего — дыра.
    pub fn client_elevated(&self) -> bool {
        let pipe = std::os::windows::io::AsRawHandle::as_raw_handle(self.reader.get_ref());
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(pipe as _, &mut pid) } == 0 {
            return false;
        }
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return false;
        }
        let mut token = std::ptr::null_mut();
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        unsafe { CloseHandle(process) };
        if opened == 0 {
            return false;
        }
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
        unsafe { CloseHandle(token) };
        ok != 0 && elevation.TokenIsElevated != 0
    }
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
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(PIPE_SDDL).as_ptr(),
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
        Ok(Server { name: wide(PIPE_NAME), descriptor, first: AtomicBool::new(true) })
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
        match std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME) {
            Ok(file) => return Ok(Connection::new(file)),
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

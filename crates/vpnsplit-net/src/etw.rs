//! Старт и завершение процессов через ETW, без опросов.
//!
//! Провайдер `Microsoft-Windows-Kernel-Process`, ключевое слово только
//! `PROCESS` — то есть ровно два события из всех, что он умеет: процесс
//! начался и процесс кончился. Загрузку модулей мы не слушаем: её на порядки
//! больше, а нужна она была бы ради одного ответа, который дешевле получить
//! потом и по запросу.
//!
//! Из полезной нагрузки берутся три поля: номер процесса, номер родителя и
//! путь к образу. Разбирать её целиком пришлось бы через TDH, а раскладка
//! полей от версии Windows к версии меняется, поэтому каждое поле берётся
//! так, чтобы ошибку было видно: номер процесса — первое поле во всех
//! версиях; смещение родителя зависит от версии и сверяется службой со
//! снимком системы; путь ищется не по смещению, а по своему началу.
//!
//! Путь к образу сначала не брался вовсе — его спрашивали у самого
//! процесса. Этого хватало, пока процесс жив. Но запускатель (значок на
//! рабочем столе, который стартует настоящую программу и тут же выходит)
//! к приходу события уже мёртв, и спросить не у кого: правило на него не
//! срабатывало, а запущенный им браузер шёл мимо туннеля.
//!
//! События доставляются пачками, с задержкой в секунду и больше
//! (`FlushTimer`; замерено до 1,35 с и дольше). Кому это много, тот просит
//! отдать накопленное сейчас: [`flush_process_events`]. Просьба действует
//! только при одном наборе буферов на сеанс — см. [`PROCESS_TUNING`].
//!
//! Нужны права администратора: сеанс ETW заводит только он. Служба работает
//! под SYSTEM, и для неё это не ограничение, а вот `vpnsplit-svc run` из
//! обычной консоли сеанс не создаст.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, FlushTraceW, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    WNODE_FLAG_TRACED_GUID,
};

/// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} — Microsoft-Windows-Kernel-Process.
const KERNEL_PROCESS: GUID = GUID {
    data1: 0x22FB2CD6,
    data2: 0x0E7B,
    data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};

/// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} — Microsoft-Windows-DNS-Client.
///
/// Зачем он нужен: имя для приложения спрашивает не оно само, а системная
/// служба кеша, одна на всю машину. На проводе запрос принадлежит ей, и
/// привязать его к приложению по пакету нельзя. А вот событие этого
/// провайдера пишется **в контексте того, кто спросил**, — то есть номер
/// процесса в нём наш. Так ли это, проверяется командой `dns`, а не
/// предполагается.
pub const DNS_CLIENT: GUID = GUID {
    data1: 0x1C95126E,
    data2: 0x7EEA,
    data3: 0x49A9,
    data4: [0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D],
};

/// Сеанс для провайдера DNS — отдельный от сеанса процессов.
pub const DNS_SESSION: &str = "vpnsplit-dns";

/// Рабочий сеанс того же провайдера — им путь B узнаёт, кто спросил имя.
/// Имя другое, чем у сеанса замеров, намеренно: сеанс с занятым именем при
/// запуске закрывается как осиротевший, и замер из консоли оставил бы
/// работающую службу без заказчиков имён.
pub const NAMES_SESSION: &str = "vpnsplit-names";

/// WINEVENT_KEYWORD_PROCESS — только старт и завершение процессов.
const KEYWORD_PROCESS: u64 = 0x10;
/// TRACE_LEVEL_INFORMATION.
const LEVEL_INFORMATION: u8 = 4;

const EVENT_PROCESS_START: u16 = 1;
const EVENT_PROCESS_STOP: u16 = 2;

/// Имя сеанса. Постоянное: сеанс ETW переживает смерть своего создателя, и
/// при следующем запуске осиротевший сеанс надо найти и закрыть.
const SESSION_NAME: &str = "vpnsplit-process";

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProcessEvent {
    /// Запуск процесса. Родитель нужен для правила «приложение и всё, что
    /// оно запускает»: у дочернего процесса приложения из Store нет ни его
    /// пути, ни его принадлежности пакету, и родословная — единственная
    /// связь с ним. Брать её надо отсюда, а не из снимка системы: номера
    /// процессов переиспользуются, и к моменту снимка номер родителя может
    /// указывать уже на другую программу.
    ///
    /// `image` — путь к образу, как его записало ядро
    /// (`\Device\HarddiskVolume3\…`). Он нужен ради процессов, которые к
    /// приходу события уже умерли: запускатель живёт мгновения, событие
    /// опаздывает до секунды, и спросить путь у самого процесса тогда
    /// нельзя. Без него правило на значок-запускатель не работало вовсе:
    /// запускатель не опознавался, и всё, что он запустил, оставалось
    /// сиротой.
    Started { pid: u32, parent: u32, image: Option<String> },
    Stopped(u32),
}

/// Буфер под свойства сеанса. Windows ждёт одну область памяти, в конце
/// которой есть место под имена; сами имена она туда и запишет.
#[repr(C)]
struct Properties {
    props: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; 128],
    log_file_name: [u16; 128],
}

/// Настройка доставки событий: от неё зависит, с каким опозданием они
/// доходят. Вынесена наружу ради замера (`vpnsplit-svc flush`): какая из
/// настроек действительно сокращает опоздание, выясняется опытом, а не по
/// описанию.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuning {
    /// Добавка к режиму сеанса (`LogFileMode`).
    pub mode: u32,
    /// Значение `FlushTimer`: секунды — или миллисекунды, если в режиме
    /// стоит [`MODE_MS_FLUSH_TIMER`].
    pub flush_timer: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        // Секунда задержки доставки. Буферы без событий не отправляются,
        // поэтому в простое это не будит ни один наш поток.
        Tuning { mode: 0, flush_timer: 1 }
    }
}

/// `EVENT_TRACE_USE_MS_FLUSH_TIMER`: `FlushTimer` в миллисекундах. В
/// описании режимов сеанса этого бита нет, в `windows-sys` тоже — он из
/// заголовков для драйверов. Понимает ли его система, показывает замер.
pub const MODE_MS_FLUSH_TIMER: u32 = 0x10;

/// `EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING`: один набор буферов на сеанс,
/// а не по набору на процессор.
pub const MODE_SINGLE_BUFFER: u32 = 0x1000_0000;

/// Настройка сеанса процессов. Выбрана замером (`vpnsplit-svc flush`,
/// 22.11.2026, по 10 запусков пустого процесса на настройку; время — от
/// создания процесса до события у нас в руках):
///
/// | настройка                                   | опоздание                         |
/// |---------------------------------------------|-----------------------------------|
/// | таймер 1 с, буферы по процессорам           | 1028–1349 мс, 6 из 10 дольше 1,5 с |
/// | то же + просьба отдать (по имени)           | 1002–1014 мс                      |
/// | то же + просьба отдать (по хэндлу)          | 1000–1014 мс                      |
/// | **один набор буферов + просьба (по имени)** | **0,1 мс**, 10 из 10              |
/// | таймер 50 мс (бит миллисекунд)              | 64–180 мс                         |
/// | таймер 10 мс (бит миллисекунд)              | 22–39 мс                          |
///
/// Два вывода. Первый: при буферах по процессорам просьба отдать события
/// ничего не ускоряет — она лишь выравнивает опоздание на ровную секунду.
/// Именно поэтому первая починка запускателей не сработала: ждали 50 мс
/// то, что приходит через тысячу. Второй: с одним набором буферов та же
/// просьба (84 мкс) доставляет событие сразу, и таймер в миллисекундах,
/// который будил бы ядро десятки раз в секунду, не нужен.
///
/// Попутная польза одного набора буферов — порядок: события с разных
/// процессоров идут в один буфер и не могут обогнать друг друга. А
/// родословная на порядке и стоит: запуск запускателя должен быть
/// обработан раньше запуска того, что он запустил.
pub const PROCESS_TUNING: Tuning = Tuning { mode: MODE_SINGLE_BUFFER, flush_timer: 1 };

impl Properties {
    fn new() -> Self {
        Properties::tuned(Tuning::default())
    }

    fn tuned(tuning: Tuning) -> Self {
        let mut properties: Properties = unsafe { std::mem::zeroed() };
        properties.props.Wnode.BufferSize = std::mem::size_of::<Properties>() as u32;
        properties.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // QPC — часы событий; для нас неважно, но поле обязательное.
        properties.props.Wnode.ClientContext = 1;
        properties.props.BufferSize = 16;
        properties.props.MinimumBuffers = 2;
        properties.props.MaximumBuffers = 8;
        properties.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | tuning.mode;
        properties.props.FlushTimer = tuning.flush_timer;
        // Смещения внутри этой же структуры: repr(C), выравнивание u16 — 2,
        // а размер EVENT_TRACE_PROPERTIES кратен 8, так что дыр между полями нет.
        properties.props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        properties.props.LogFileNameOffset =
            properties.props.LoggerNameOffset + std::mem::size_of::<[u16; 128]>() as u32;
        properties
    }
}

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Сырое событие: ровно то, что нужно для разбора, и ничего лишнего.
pub struct Raw<'a> {
    /// Номер процесса, в контексте которого событие записано. Это не всегда
    /// «кто виноват»: у `Kernel-Process` события пишет система, а вот у
    /// `DNS-Client` — тот процесс, который спросил имя. Ради второго это
    /// поле здесь и есть.
    pub pid: u32,
    pub id: u16,
    /// Версия события. Раскладка полезной нагрузки от версии к версии
    /// меняется, и разбирать её без версии — значит угадывать.
    pub version: u8,
    pub payload: &'a [u8],
}

type RawSink = Box<dyn Fn(Raw) + Send + Sync>;

/// Сеанс ETW на один провайдер. Пока объект жив, обработчик вызывается; при
/// уничтожении сеанс останавливается и поток разбора завершается.
///
/// Разбор событий сюда не входит намеренно: он у каждого провайдера свой, а
/// возня с сеансом, трассой и потоком — одна и та же, и повторять её для
/// второго провайдера было бы копированием сотни строк.
pub struct Trace {
    session: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
    worker: Option<std::thread::JoinHandle<()>>,
    sink: *mut RawSink,
    name: Vec<u16>,
}

// Хэндлы сеанса — просто числа, обработчик Send + Sync.
unsafe impl Send for Trace {}

impl Trace {
    pub fn start(
        session_name: &str,
        provider: &GUID,
        keyword: u64,
        on_event: impl Fn(Raw) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        Trace::start_tuned(session_name, provider, keyword, Tuning::default(), on_event)
    }

    pub fn start_tuned(
        session_name: &str,
        provider: &GUID,
        keyword: u64,
        tuning: Tuning,
        on_event: impl Fn(Raw) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let name = wide(session_name);
        let session = start_session(&name, tuning)?;

        let status = unsafe {
            EnableTraceEx2(
                session,
                provider,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                LEVEL_INFORMATION,
                keyword,
                0,
                0,
                std::ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            stop_session(session, &name);
            return Err(format!("EnableTraceEx2 вернул {status}"));
        }

        let sink: *mut RawSink = Box::into_raw(Box::new(Box::new(on_event)));
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        logfile.LoggerName = name.as_ptr() as *mut u16;
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_record);
        logfile.Context = sink as *mut c_void;

        let trace = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == u64::MAX {
            let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            stop_session(session, &name);
            unsafe { drop(Box::from_raw(sink)) };
            return Err(format!("OpenTraceW не удался (код {code})"));
        }

        // ProcessTrace блокируется до закрытия трассы — ему нужен свой поток.
        let worker = std::thread::Builder::new()
            .name("etw".into())
            .spawn(move || {
                let handles = [trace];
                unsafe { ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null()) };
            })
            .map_err(|e| format!("не удалось запустить поток ETW: {e}"))?;

        Ok(Trace { session, trace, worker: Some(worker), sink, name })
    }

    /// Просит отдать накопленные события сейчас — по хэндлу сеанса.
    pub fn flush(&self) -> Result<(), u32> {
        let mut properties = Properties::new();
        let status =
            unsafe { FlushTraceW(self.session, std::ptr::null(), &mut properties.props) };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }
}

/// Слежение за процессами: старт и завершение, с номером родителя.
pub struct ProcessWatcher {
    trace: Trace,
}

impl ProcessWatcher {
    pub fn start(on_event: impl Fn(ProcessEvent) + Send + Sync + 'static) -> Result<Self, String> {
        ProcessWatcher::start_tuned(SESSION_NAME, PROCESS_TUNING, on_event)
    }

    /// То же под другим именем сеанса и с другой настройкой доставки —
    /// для замера, который не должен трогать рабочий сеанс службы.
    pub fn start_tuned(
        session_name: &str,
        tuning: Tuning,
        on_event: impl Fn(ProcessEvent) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let trace = Trace::start_tuned(session_name, &KERNEL_PROCESS, KEYWORD_PROCESS, tuning, move |raw| {
            let Some(pid) = pid_from_payload(raw.payload) else {
                return;
            };
            let event = match raw.id {
                EVENT_PROCESS_START => ProcessEvent::Started {
                    pid,
                    // Нет родителя — ноль: процесс просто не попадёт ни в
                    // чью родословную, и это лучше, чем попасть в чужую.
                    parent: parent_from_payload(raw.payload, raw.version).unwrap_or(0),
                    image: image_from_payload(raw.payload),
                },
                EVENT_PROCESS_STOP => ProcessEvent::Stopped(pid),
                _ => return,
            };
            on_event(event);
        })?;
        Ok(ProcessWatcher { trace })
    }

    pub fn flush(&self) -> Result<(), u32> {
        self.trace.flush()
    }
}

impl Drop for Trace {
    fn drop(&mut self) {
        // Сначала сеанс: после него новых событий не будет. Потом трасса —
        // от этого ProcessTrace возвращается и поток заканчивается. И только
        // когда поток присоединён, можно освобождать обработчик.
        let name = std::mem::take(&mut self.name);
        stop_session(self.session, &name);
        unsafe { CloseTrace(self.trace) };
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        unsafe { drop(Box::from_raw(self.sink)) };
    }
}

fn start_session(name: &[u16], tuning: Tuning) -> Result<CONTROLTRACE_HANDLE, String> {
    let mut session = CONTROLTRACE_HANDLE { Value: 0 };
    let mut properties = Properties::tuned(tuning);
    let status =
        unsafe { StartTraceW(&mut session, name.as_ptr(), &mut properties.props) };
    if status == ERROR_ALREADY_EXISTS {
        // Сеанс остался от прошлого запуска, который не успел прибраться.
        // Нулевой хэндл здесь законен: сеанс ищется по имени.
        let mut stale = Properties::new();
        unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                name.as_ptr(),
                &mut stale.props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        let mut properties = Properties::tuned(tuning);
        let status =
            unsafe { StartTraceW(&mut session, name.as_ptr(), &mut properties.props) };
        if status != ERROR_SUCCESS {
            return Err(describe_start(status));
        }
        return Ok(session);
    }
    if status != ERROR_SUCCESS {
        return Err(describe_start(status));
    }
    Ok(session)
}

fn describe_start(status: u32) -> String {
    match status {
        5 => "StartTraceW: отказано в доступе — сеанс ETW заводит только администратор".to_owned(),
        other => format!("StartTraceW вернул {other}"),
    }
}

fn stop_session(session: CONTROLTRACE_HANDLE, name: &[u16]) {
    let mut properties = Properties::new();
    unsafe {
        ControlTraceW(session, name.as_ptr(), &mut properties.props, EVENT_TRACE_CONTROL_STOP);
    }
}

/// Номер процесса из полезной нагрузки. Он первое поле и у ProcessStart, и у
/// ProcessStop, во всех версиях этих событий.
fn pid_from_payload(data: &[u8]) -> Option<u32> {
    let head: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(head))
}

/// Номер родителя из нагрузки `ProcessStart`.
///
/// Смещение зависит от версии события: в ранних версиях сразу за номером
/// процесса идёт время создания (8 байт), а в версии 2 и выше между ними
/// появился `ProcessSequenceNumber` — ещё 8 байт.
///
/// Такое смещение угадывать нельзя: ошибка дала бы не отказ, а правдоподобное
/// число, и правило «всё, что запускает приложение» тихо указывало бы на
/// посторонние процессы. Поэтому служба при запуске сверяет первые события
/// со снимком системы и пишет результат в журнал.
fn parent_from_payload(data: &[u8], version: u8) -> Option<u32> {
    let offset = if version >= 2 { 4 + 8 + 8 } else { 4 + 8 };
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// `\Device\` в UTF-16LE: с этого начинается путь к образу в событии.
const DEVICE_MARK: [u8; 16] = [
    0x5C, 0, b'D', 0, b'e', 0, b'v', 0, b'i', 0, b'c', 0, b'e', 0, 0x5C, 0,
];

/// Путь к образу из нагрузки `ProcessStart` — в том виде, в каком его
/// записало ядро: `\Device\HarddiskVolume3\Program Files\…`.
///
/// Смещение этого поля не постоянно даже в пределах одной версии события:
/// перед ним лежит метка целостности — SID переменной длины, — а в старых
/// версиях её нет вовсе. Высчитывать смещение значило бы повторить ту же
/// ошибку, что возможна с родителем, только с большим числом способов
/// ошибиться. Поэтому поле ищется по своему началу: ядро записывает путь
/// в собственном пространстве имён, и он всегда начинается с `\Device\`.
/// Не нашлось — ответа нет, а не чужие байты.
///
/// Служба сверяет первые события с тем, что отвечает сам процесс, и пишет
/// результат в журнал.
fn image_from_payload(data: &[u8]) -> Option<String> {
    let at = data
        .windows(DEVICE_MARK.len())
        .position(|window| window == DEVICE_MARK)?;
    leading_string(&data[at..])
}

/// Просит систему отдать накопленные события процессов сейчас, не
/// дожидаясь секунды.
///
/// Сеанс ищется по имени, а не по хэндлу: так просить может любой поток
/// службы, не зная, кто сеансом владеет. Сами события придут обычным
/// порядком, в поток разбора; вызов их не возвращает и не ждёт.
///
/// Ошибка — это код Windows. Чаще всего она значит, что сеанса нет:
/// слежение за процессами не поднялось, и ждать событий бессмысленно.
pub fn flush_process_events() -> Result<(), u32> {
    flush_by_name(SESSION_NAME)
}

/// То же для сеанса с любым именем.
pub fn flush_by_name(session_name: &str) -> Result<(), u32> {
    let name = wide(session_name);
    let mut properties = Properties::new();
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            &mut properties.props,
            EVENT_TRACE_CONTROL_FLUSH,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

/// Первая строка UTF-16 из полезной нагрузки, без завершающего нуля.
///
/// У событий `DNS-Client` имя запроса — первое поле, и это единственное,
/// что нам от них нужно. Разбирать нагрузку через TDH ради одного поля
/// дорого: это загрузка схемы провайдера на каждое событие.
pub fn leading_string(payload: &[u8]) -> Option<String> {
    let words: Vec<u16> = payload
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|word| *word != 0)
        .collect();
    if words.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&words))
}

unsafe extern "system" fn on_record(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = &*record;
    let sink = record.UserContext as *const RawSink;
    if sink.is_null() {
        return;
    }
    let payload = if record.UserData.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize)
    };
    let raw = Raw {
        pid: record.EventHeader.ProcessId,
        id: record.EventHeader.EventDescriptor.Id,
        version: record.EventHeader.EventDescriptor.Version,
        payload,
    };
    let sink = &*sink;
    // Паника в обработчике не должна уронить службу — это поток ETW.
    let _ = catch_unwind(AssertUnwindSafe(|| sink(raw)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_is_the_first_four_bytes() {
        let payload = [0x34, 0x12, 0x00, 0x00, 0xFF, 0xFF];
        assert_eq!(pid_from_payload(&payload), Some(0x1234));
    }

    #[test]
    fn short_payload_is_refused_instead_of_read_past_the_end() {
        assert_eq!(pid_from_payload(&[1, 2, 3]), None);
        assert_eq!(pid_from_payload(&[]), None);
    }

    /// Нагрузка ProcessStart: номер процесса, в версии 2 и выше — ещё
    /// номер последовательности, потом время создания, потом родитель.
    fn start_payload(pid: u32, parent: u32, version: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&pid.to_le_bytes());
        if version >= 2 {
            bytes.extend_from_slice(&7u64.to_le_bytes()); // ProcessSequenceNumber
        }
        bytes.extend_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes()); // CreateTime
        bytes.extend_from_slice(&parent.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // SessionID
        bytes
    }

    #[test]
    fn parent_is_read_after_the_create_time() {
        let payload = start_payload(4321, 1234, 0);
        assert_eq!(pid_from_payload(&payload), Some(4321));
        assert_eq!(parent_from_payload(&payload, 0), Some(1234));
        assert_eq!(parent_from_payload(&payload, 1), Some(1234));
    }

    #[test]
    fn newer_versions_have_a_sequence_number_in_between() {
        let payload = start_payload(4321, 1234, 3);
        assert_eq!(pid_from_payload(&payload), Some(4321));
        assert_eq!(parent_from_payload(&payload, 3), Some(1234));
        // Если версию прочитать неверно, выйдет не отказ, а чужое число —
        // ровно поэтому служба сверяет разбор со снимком системы.
        assert_ne!(parent_from_payload(&payload, 0), Some(1234));
    }

    #[test]
    fn a_payload_without_the_parent_field_is_refused() {
        let short = [1u8, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(parent_from_payload(&short, 0), None);
        assert_eq!(parent_from_payload(&short, 3), None);
        assert_eq!(parent_from_payload(&[], 0), None);
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    /// Нагрузка версии 3 целиком, как её пишет Windows 10 и 11: после
    /// родителя — ещё его номер последовательности, сеанс, флаги, сведения
    /// о токене, метка целостности и только потом путь.
    fn full_start_payload(image: &str, sub_authorities: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4321u32.to_le_bytes()); // ProcessID
        bytes.extend_from_slice(&7u64.to_le_bytes()); // ProcessSequenceNumber
        bytes.extend_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes()); // CreateTime
        bytes.extend_from_slice(&1234u32.to_le_bytes()); // ParentProcessID
        bytes.extend_from_slice(&6u64.to_le_bytes()); // ParentProcessSequenceNumber
        bytes.extend_from_slice(&1u32.to_le_bytes()); // SessionID
        bytes.extend_from_slice(&0u32.to_le_bytes()); // Flags
        bytes.extend_from_slice(&3u32.to_le_bytes()); // ProcessTokenElevationType
        bytes.extend_from_slice(&0u32.to_le_bytes()); // ProcessTokenIsElevated
        // MandatoryLabel: S-1-16-8192 и подобные.
        bytes.extend_from_slice(&[1, sub_authorities, 0, 0, 0, 0, 0, 16]);
        for _ in 0..sub_authorities {
            bytes.extend_from_slice(&0x2000u32.to_le_bytes());
        }
        bytes.extend_from_slice(&utf16(image));
        bytes.extend_from_slice(&0u32.to_le_bytes()); // ImageChecksum
        bytes.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        bytes.extend_from_slice(&utf16("")); // PackageFullName
        bytes.extend_from_slice(&utf16("")); // PackageRelativeAppId
        bytes
    }

    #[test]
    fn the_image_is_found_whatever_lies_before_it() {
        let image = r"\Device\HarddiskVolume3\Users\klyaksa\Desktop\Firefox.exe";
        // Метка целостности бывает разной длины — путь находится всё равно.
        for sub_authorities in [0u8, 1, 2] {
            let payload = full_start_payload(image, sub_authorities);
            assert_eq!(image_from_payload(&payload).as_deref(), Some(image));
            // И соседние поля при этом читаются как раньше.
            assert_eq!(pid_from_payload(&payload), Some(4321));
            assert_eq!(parent_from_payload(&payload, 3), Some(1234));
        }
    }

    #[test]
    fn the_image_stops_at_its_own_end() {
        // За путём идут другие строки; прихватить их нельзя.
        let mut payload = full_start_payload(r"\Device\HarddiskVolume3\a.exe", 1);
        payload.extend_from_slice(&utf16(r"\Device\Other\b.exe"));
        assert_eq!(
            image_from_payload(&payload).as_deref(),
            Some(r"\Device\HarddiskVolume3\a.exe")
        );
    }

    #[test]
    fn a_payload_without_a_kernel_path_gives_no_image() {
        // Старые версии и события завершения: пути ядра в них нет, и
        // выдумывать его не из чего.
        assert_eq!(image_from_payload(&start_payload(4321, 1234, 3)), None);
        assert_eq!(image_from_payload(&utf16(r"C:\Windows\notepad.exe")), None);
        assert_eq!(image_from_payload(&[]), None);
    }

    #[test]
    fn properties_leave_room_for_both_names() {
        // Если смещения уедут, Windows запишет имя сеанса мимо буфера.
        let properties = Properties::new();
        let size = std::mem::size_of::<Properties>() as u32;
        assert!(properties.props.LoggerNameOffset + 256 <= size);
        assert!(properties.props.LogFileNameOffset + 256 <= size);
        assert_eq!(properties.props.Wnode.BufferSize, size);
    }
}

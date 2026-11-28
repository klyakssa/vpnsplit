//! Отмена зависшего синхронного ввода-вывода из сторожевого потока.
//!
//! Канал службы работает синхронно: поток клиента спит в ReadFile или
//! WriteFile, пока собеседник не пришлёт или не прочтёт. Собеседник,
//! который молчит или не читает, держал бы поток вечно. Сторож отменяет
//! такую операцию через `CancelSynchronousIo` — по сроку или по просьбе
//! другого потока (`Remote::doom`, `Remote::hurry`).
//!
//! `CancelSynchronousIo` отменяет любую синхронную операцию потока, а не
//! одну выбранную. Поэтому отменить можно только операцию внутри
//! `Watch::guard`: пометка «под охраной» ставится и снимается под тем же
//! замком, под которым сторож зовёт отмену, а снимается она сразу, как
//! операция вернулась, — до любого другого ввода-вывода потока. Отмена,
//! пришедшая раньше, чем поток вошёл в ReadFile, теряется (отменять ещё
//! нечего), поэтому сторож повторяет её, пока пометка стоит.

use std::marker::PhantomData;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};
use windows_sys::Win32::System::IO::CancelSynchronousIo;

/// Как часто повторяется отмена, которая ещё не подействовала.
const RETRY: Duration = Duration::from_millis(50);

struct Entry {
    id: u64,
    /// Своя ручка потока (`HANDLE` числом: так её можно держать в static).
    thread: usize,
    /// Поток внутри `guard`.
    armed: bool,
    deadline: Option<Instant>,
    /// Другой поток попросил прекратить: текущая операция отменяется,
    /// новые не начинаются.
    doomed: bool,
    /// Другой поток попросил не ждать: операции дают доделать то, что уже
    /// пришло, а ждать большего — нет (срок «сейчас»).
    hurried: bool,
    /// Отмена звалась во время текущей операции.
    fired: bool,
}

struct Registry {
    entries: Vec<Entry>,
    next: u64,
    watchdog: bool,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry { entries: Vec::new(), next: 0, watchdog: false });
/// Будит сторожа: новая охраняемая операция со сроком или просьба отменить.
static WAKE: Condvar = Condvar::new();

fn registry() -> MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

impl Registry {
    fn entry(&mut self, id: u64) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|entry| entry.id == id)
    }
}

/// Охрана ввода-вывода одного потока. Создаётся в самом потоке и в другие
/// потоки не передаётся; другим потокам — `Remote`.
pub struct Watch {
    id: u64,
    _thread_bound: PhantomData<*const ()>,
}

/// Просьба из другого потока прекратить ввод-вывод охраняемого потока.
#[derive(Clone, Debug)]
pub struct Remote {
    id: u64,
}

fn cancelled() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "операция канала отменена сторожем")
}

impl Watch {
    /// Охрана текущего потока.
    pub fn this_thread() -> std::io::Result<Watch> {
        let mut thread: HANDLE = std::ptr::null_mut();
        // GetCurrentThread — псевдоручка, в другом потоке она значила бы
        // тот поток. Сторожу нужна настоящая.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentThread(),
                GetCurrentProcess(),
                &mut thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut registry = registry();
        if !registry.watchdog {
            if let Err(e) = std::thread::Builder::new().name("pipe-watchdog".into()).spawn(watchdog) {
                unsafe { CloseHandle(thread) };
                return Err(e);
            }
            registry.watchdog = true;
        }
        let id = registry.next;
        registry.next += 1;
        registry.entries.push(Entry {
            id,
            thread: thread as usize,
            armed: false,
            deadline: None,
            doomed: false,
            hurried: false,
            fired: false,
        });
        Ok(Watch { id, _thread_bound: PhantomData })
    }

    pub fn remote(&self) -> Remote {
        Remote { id: self.id }
    }

    /// Снять просьбу `Remote::hurry`. Зовётся из своего потока, когда
    /// поторопивший больше не может её повторить, — иначе просьба
    /// действовала бы на все будущие операции потока.
    pub fn pardon(&self) {
        if let Some(entry) = registry().entry(self.id) {
            entry.hurried = false;
        }
    }

    /// Выполняет `io`; не уложилась в `limit` (`None` — без срока) или
    /// поток приговорили (`Remote::doom`) — операция отменяется и
    /// возвращается ошибка `TimedOut`. В `io` — только ввод-вывод, который
    /// не жалко прервать: отмена бьёт по любой синхронной операции потока.
    pub fn guard<T>(&self, limit: Option<Duration>, io: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
        let timed = {
            let mut registry = registry();
            let Some(entry) = registry.entry(self.id) else {
                // Замок общий для всех потоков и сторожа: под ним ввод-вывод
                // не выполняем.
                drop(registry);
                return io();
            };
            if entry.doomed {
                return Err(cancelled());
            }
            entry.armed = true;
            entry.fired = false;
            // Поторопленный поток: то, что уже лежит в канале, ReadFile
            // отдаст сразу, а операция, которая ждёт, будет отменена.
            entry.deadline = if entry.hurried {
                Some(Instant::now())
            } else {
                limit.map(|limit| Instant::now() + limit)
            };
            entry.deadline.is_some()
        };
        if timed {
            WAKE.notify_all();
        }
        // Пометка снимается и при панике внутри `io`: иначе сторож отменял
        // бы потом чужие операции потока.
        struct Disarm(u64);
        impl Drop for Disarm {
            fn drop(&mut self) {
                if let Some(entry) = registry().entry(self.0) {
                    entry.armed = false;
                    entry.deadline = None;
                }
            }
        }
        let result = {
            let _disarm = Disarm(self.id);
            io()
        };
        // Без пометки сторож запись не трогает: `fired` уже не изменится.
        let fired = registry().entry(self.id).is_some_and(|entry| entry.fired);
        match result {
            // Отмена могла опоздать: операция успела закончиться сама.
            Err(_) if fired => Err(cancelled()),
            other => other,
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let mut registry = registry();
        if let Some(at) = registry.entries.iter().position(|entry| entry.id == self.id) {
            let entry = registry.entries.swap_remove(at);
            unsafe { CloseHandle(entry.thread as HANDLE) };
        }
    }
}

impl Remote {
    /// Прервать текущую охраняемую операцию потока и не начинать новых.
    /// Поток, который уже кончился, ничего не заметит.
    pub fn doom(&self) {
        if let Some(entry) = registry().entry(self.id) {
            entry.doomed = true;
        }
        WAKE.notify_all();
    }

    /// Не ждать: текущая и следующие охраняемые операции потока получают
    /// срок «сейчас». Что уже пришло, поток дочитает, а ждать собеседника
    /// не станет. Мягче `doom`: клиент, чей запрос уже лежит в канале, его
    /// не потеряет. Действует, пока поток не позовёт `Watch::pardon`.
    pub fn hurry(&self) {
        if let Some(entry) = registry().entry(self.id) {
            entry.hurried = true;
            if entry.armed {
                entry.deadline = Some(Instant::now());
            }
        }
        WAKE.notify_all();
    }
}

fn watchdog() {
    let mut registry = registry();
    loop {
        let now = Instant::now();
        let mut next: Option<Instant> = None;
        for entry in registry.entries.iter_mut().filter(|entry| entry.armed) {
            if entry.doomed || entry.deadline.is_some_and(|deadline| deadline <= now) {
                // Под замком: пометку `armed` поток снимает под ним же, так
                // что отмена достаётся только охраняемой операции.
                unsafe { CancelSynchronousIo(entry.thread as HANDLE) };
                entry.fired = true;
                next = Some(next.map_or(now + RETRY, |next| next.min(now + RETRY)));
            } else if let Some(deadline) = entry.deadline {
                next = Some(next.map_or(deadline, |next| next.min(deadline)));
            }
        }
        // Ждать нечего — сторож спит, пока не позовут: без таймеров.
        registry = match next {
            None => WAKE.wait(registry).unwrap_or_else(|e| e.into_inner()),
            Some(at) => {
                WAKE.wait_timeout(registry, at.saturating_duration_since(now)).unwrap_or_else(|e| e.into_inner()).0
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::System::Pipes::CreatePipe;

    fn pipe() -> (File, File) {
        let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        assert_ne!(unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) }, 0);
        unsafe { (File::from_raw_handle(read as RawHandle), File::from_raw_handle(write as RawHandle)) }
    }

    #[test]
    fn a_silent_read_is_cancelled_at_its_deadline() {
        let (mut read, _write) = pipe();
        let watch = Watch::this_thread().unwrap();
        let started = Instant::now();
        let mut byte = [0u8; 1];
        let error = watch.guard(Some(Duration::from_millis(200)), || read.read(&mut byte)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_read_after_the_guard_is_not_cancelled() {
        let (mut read, mut write) = pipe();
        let watch = Watch::this_thread().unwrap();
        write.write_all(b"a").unwrap();
        let mut byte = [0u8; 1];
        // Уложилась в срок — дальше поток свободен от сторожа.
        assert_eq!(watch.guard(Some(Duration::from_millis(100)), || read.read(&mut byte)).unwrap(), 1);
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            write.write_all(b"b").unwrap();
        });
        // Чтение без охраны дольше прежнего срока: отмены быть не должно.
        assert_eq!(read.read(&mut byte).unwrap(), 1);
        assert_eq!(&byte, b"b");
        writer.join().unwrap();
    }

    #[test]
    fn a_doomed_thread_stops_its_io_and_starts_no_more() {
        let (mut read, _write) = pipe();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let watch = Watch::this_thread().unwrap();
            tx.send(watch.remote()).unwrap();
            let mut byte = [0u8; 1];
            let first = watch.guard(None, || read.read(&mut byte)).map_err(|e| e.kind());
            let second = watch.guard(None, || Ok(())).map_err(|e| e.kind());
            (first, second)
        });
        let remote = rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        remote.doom();
        let (first, second) = reader.join().unwrap();
        assert_eq!(first, Err(std::io::ErrorKind::TimedOut));
        assert_eq!(second, Err(std::io::ErrorKind::TimedOut));
        // Поток кончился — просьба к нему ничего не ломает.
        remote.doom();
    }

    #[test]
    fn a_hurried_thread_reads_what_has_arrived_but_does_not_wait() {
        let (mut read, mut write) = pipe();
        let watch = Watch::this_thread().unwrap();
        // Поторопили до входа в охрану, а данные уже в канале: их отдают.
        write.write_all(b"a").unwrap();
        watch.remote().hurry();
        let mut byte = [0u8; 1];
        assert_eq!(watch.guard(None, || read.read(&mut byte)).unwrap(), 1);
        // Больше ничего не пришло — чтение не ждёт.
        let started = Instant::now();
        let error = watch.guard(None, || read.read(&mut byte)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(10));
        // Прощённый поток снова ждёт, сколько нужно.
        watch.pardon();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            write.write_all(b"b").unwrap();
        });
        assert_eq!(watch.guard(None, || read.read(&mut byte)).unwrap(), 1);
        assert_eq!(&byte, b"b");
        writer.join().unwrap();
    }

    #[test]
    fn hurrying_cuts_a_wait_that_is_already_going() {
        let (mut read, _write) = pipe();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let watch = Watch::this_thread().unwrap();
            tx.send(watch.remote()).unwrap();
            let mut byte = [0u8; 1];
            watch.guard(None, || read.read(&mut byte)).map_err(|e| e.kind())
        });
        let remote = rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        remote.hurry();
        assert_eq!(reader.join().unwrap(), Err(std::io::ErrorKind::TimedOut));
    }
}

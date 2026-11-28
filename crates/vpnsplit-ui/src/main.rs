//! vpnsplit-ui — трей и окно: состояние туннеля, список приложений, запуск
//! через лончер.
//!
//! Подсистема — windows: консольного окна нет, поэтому всё, что надо сказать
//! до появления окна, говорится окном сообщения.
//!
//! Закрытие окна завершает процесс полностью. «Свернуть в трей» здесь нет
//! сознательно: программа, которая остаётся в памяти после того, как её
//! закрыли, — ровно то поведение, от которого хотелось уйти.
//!
//! Единственный случай, когда процесс живёт без видимого окна, — запуск
//! вместе с Windows (`--tray`, см. `autostart`): там окно никто не
//! открывал, так что и «закрыли, а она осталась» не происходит. Открыл его
//! щелчком по значку и закрыл — программа вышла, как всегда.
#![windows_subsystem = "windows"]

mod apps;
mod ask;
mod autostart;
mod icon;
mod list;
mod shortcut;
mod svc;
mod tray;
mod win;
mod window;

/// Путь к приложению из `--run ПУТЬ`. Кроме него у окна один ключ —
/// `--tray`, с ним нас зовёт автозапуск; всё остальное делается в самом
/// окне.
fn run_argument(args: &[String]) -> Option<String> {
    let mut rest = args.iter();
    while let Some(argument) = rest.next() {
        if argument == "--run" {
            return rest.next().cloned();
        }
    }
    None
}

/// Сборка службы, на которую нас перезапустило прежнее окно: `--after-update
/// N`. `Some(None)` — ключ есть, а номера нет (так запускает окно прежних
/// версий); `None` — ключа нет.
fn after_update(args: &[String]) -> Option<Option<u64>> {
    let at = args.iter().position(|argument| argument == "--after-update")?;
    Some(args.get(at + 1).and_then(|number| number.parse().ok()))
}

use win::wide;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, ICC_LISTVIEW_CLASSES, INITCOMMONCONTROLSEX,
};
use windows_sys::Win32::Graphics::Gdi::UpdateWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DispatchMessageW, FindWindowW, GetMessageW, IsDialogMessageW, LoadCursorW,
    RegisterClassW, SetForegroundWindow, ShowWindow, TranslateMessage, CW_USEDEFAULT, IDC_ARROW,
    MSG, SW_RESTORE, SW_SHOW, WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

fn main() {
    // Ярлык с рабочего стола зовёт нас так: запустить приложение через
    // туннель и сразу уйти, не показывая окна. Отдельной программы для
    // этого нет намеренно — лончер консольный, и ярлык на него мигал бы
    // чёрным окном при каждом запуске.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(app) = run_argument(&args) {
        if let Err(reason) = svc::launch_now(std::path::Path::new(&app)) {
            win::error_box(std::ptr::null_mut(), &reason);
        }
        return;
    }

    // Нас запустило прежнее окно после обновления: дождаться, пока оно
    // уйдёт, иначе мы примем его за «уже открытое» и уйдём сами.
    if let Some(build) = after_update(&args) {
        let done = build.unwrap_or(window::RESTARTED_FOR_UNKNOWN);
        window::RESTARTED_FOR.store(done, std::sync::atomic::Ordering::Release);
        for _ in 0..50 {
            let old = unsafe { FindWindowW(wide(window::CLASS_NAME).as_ptr(), std::ptr::null()) };
            if old.is_null() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // Окна уже нет, а процесс ещё отпускает свою пометку «я запущен».
        std::thread::sleep(std::time::Duration::from_millis(300));
    }

    // Второй экземпляр не нужен: два значка в трее и две подписки на события
    // ничего не добавляют. Вместо ругани — поднять уже открытое окно.
    if !win::first_instance() {
        let existing = unsafe { FindWindowW(wide(window::CLASS_NAME).as_ptr(), std::ptr::null()) };
        if !existing.is_null() {
            unsafe {
                ShowWindow(existing, SW_RESTORE);
                SetForegroundWindow(existing);
            }
        }
        return;
    }

    // Установленная копия прибирает за прежним местом: автозапуск,
    // оставшийся от папки сборки, переводит на себя и заводит себе ярлык
    // в меню «Пуск». Узнаёт она себя по установщику, который лежит рядом;
    // копия из папки сборки ничего не трогает.
    let installed = std::env::current_exe()
        .is_ok_and(|exe| exe.with_file_name("vpnsplit-setup.exe").is_file());
    if installed {
        autostart::adopt();
        let _ = shortcut::ensure_start_menu();
    }

    unsafe {
        // Без этого SysListView32 не зарегистрирован, и таблица не создастся.
        let controls = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES,
        };
        InitCommonControlsEx(&controls);
    }

    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class_name = wide(window::CLASS_NAME);
    let class = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(window::wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance as _,
        hIcon: std::ptr::null_mut(),
        hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
        hbrBackground: unsafe {
            windows_sys::Win32::Graphics::Gdi::GetSysColorBrush(
                windows_sys::Win32::Graphics::Gdi::COLOR_WINDOW,
            )
        },
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        win::error_box(std::ptr::null_mut(), "не удалось зарегистрировать класс окна");
        return;
    }

    // Окно получает Shell в lpParam и пользуется им, пока живо. Освобождается
    // он здесь, после цикла сообщений: окно уничтожается изнутри своего же
    // обработчика, и освободи оно Shell в WM_DESTROY, обработчики выше по
    // стеку остались бы с освобождённой памятью.
    let shell = Box::into_raw(window::Shell::new());
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide("vpnsplit — раздельное туннелирование").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance as _,
            shell as *const _,
        )
    };
    if hwnd.is_null() {
        drop(unsafe { Box::from_raw(shell) });
        win::error_box(std::ptr::null_mut(), "не удалось создать окно");
        return;
    }

    // Размер по умолчанию — чтобы в таблице сразу было видно путь целиком.
    let dpi = win::dpi_of(hwnd);
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            0,
            0,
            win::scale(820, dpi),
            win::scale(520, dpi),
            windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOMOVE
                | windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOZORDER,
        );
    }
    // Автозапуск: значок в трее уже стоит (его ставит само окно при
    // создании), а окно остаётся невидимым до щелчка по значку. И без
    // сообщений: окно сообщения при каждом входе в Windows — хуже, чем
    // недоступная кнопка, о которой скажет само окно, когда его откроют.
    let in_tray = autostart::wants_tray(&args);
    if !in_tray {
        unsafe {
            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);
        }
        if let Err(e) = svc::launcher_path() {
            win::info_box(hwnd, &format!("Запуск приложений будет недоступен: {e}"));
        }
    }

    // Подписка на события службы. Первым событием служба присылает текущее
    // состояние туннеля, так что окно не начинает вслепую.
    svc::watch(svc::Target::new(hwnd));

    let mut message: MSG = unsafe { std::mem::zeroed() };
    unsafe {
        while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
            // Tab и Enter между кнопками и таблицей — работа IsDialogMessage.
            if IsDialogMessageW(hwnd, &message) != 0 {
                continue;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    // Окна уже нет (или цикл оборвался ошибкой — тогда уходим и так), и ни
    // одного обработчика на стеке.
    let shell = unsafe { Box::from_raw(shell) };
    shell.finish();
    drop(shell);
}

#[cfg(test)]
mod tests {
    use super::after_update;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|argument| argument.to_string()).collect()
    }

    #[test]
    fn the_build_comes_after_the_key() {
        assert_eq!(after_update(&args(&["--after-update", "42"])), Some(Some(42)));
        assert_eq!(after_update(&args(&["--after-update", "42", "--tray"])), Some(Some(42)));
    }

    #[test]
    fn an_old_window_passes_no_number() {
        assert_eq!(after_update(&args(&["--after-update"])), Some(None));
        assert_eq!(after_update(&args(&["--after-update", "--tray"])), Some(None));
    }

    #[test]
    fn without_the_key_there_was_no_restart() {
        assert_eq!(after_update(&args(&["--tray"])), None);
    }
}

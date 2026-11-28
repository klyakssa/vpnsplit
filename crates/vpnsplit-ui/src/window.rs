//! Окно: состояние туннеля сверху, список приложений, три кнопки.
//!
//! Ни одного таймера. Всё, что окно показывает, приходит событием службы;
//! единственное повторяющееся действие во всей программе — попытка
//! переподключиться к службе раз в две секунды, и она в рабочем потоке.

use crate::icon::Dot;
use crate::list;
use crate::svc::{self, Reply, Target};
use crate::tray::{self, Tray};
use crate::win::{self, rgb, scale, wide};
use crate::{apps, ask};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use vpnsplit_core::{
    ovpn, AppRule, AppTarget, Event, Mechanism, Policy, Routing, TunnelState, VpnAction, VpnState,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    DeleteObject, DrawTextW, GetDC, GetSysColor, GetSysColorBrush, InvalidateRect, ReleaseDC,
    SelectObject, SetBkColor, SetTextColor, COLOR_WINDOW, DT_CALCRECT, DT_WORDBREAK, HBRUSH, HDC,
    HFONT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Controls::{
    CDDS_ITEMPREPAINT, CDDS_PREPAINT, CDRF_DODEFAULT, CDRF_NEWFONT, CDRF_NOTIFYITEMDRAW, NMHDR,
    NMLVCUSTOMDRAW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu,
    DestroyWindow, GetClientRect, GetSystemMetrics, GetWindowLongPtrW, GetWindowRect,
    IsWindowVisible, MessageBoxW, PostQuitMessage, SendMessageW,
    SetForegroundWindow, SetWindowLongPtrW,
    RegisterWindowMessageW, BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX,
    SetWindowPos, SetWindowTextW, ShowWindow, TrackPopupMenu, BS_PUSHBUTTON, CREATESTRUCTW,
    GWLP_USERDATA, HICON, HMENU, ICON_BIG, ICON_SMALL, IDNO, IDOK, IDYES, MB_ICONINFORMATION,
    MB_ICONQUESTION, MB_OKCANCEL, MB_YESNOCANCEL, MF_CHECKED, MF_GRAYED, MF_MENUBARBREAK,
    MF_POPUP, MF_SEPARATOR, MF_STRING,
    MINMAXINFO, SM_CXICON,
    SWP_NOACTIVATE, SWP_NOZORDER, SW_HIDE, SW_RESTORE, SW_SHOW, TPM_BOTTOMALIGN,
    TPM_LEFTALIGN, TPM_RETURNCMD, WM_CLOSE, WM_COMMAND, WM_CREATE,
    WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WM_GETMINMAXINFO, WM_LBUTTONDBLCLK,
    WM_LBUTTONUP, WM_NCCREATE, WM_NOTIFY, WM_RBUTTONUP, WM_SETICON, WM_SIZE, WS_CHILD,
    WS_TABSTOP, WS_VISIBLE,
};

/// Ширины колонок при 96 точках на дюйм; последняя, с путём, добирает
/// остаток. Колонка состояния самая широкая из трёх не случайно: в ней
/// стоит то, что пользователь должен прочесть целиком. При прежних 150
/// строка «не ведётся — запустите заново» обрезалась на слове «запустите»,
/// то есть ровно на том, что надо сделать. Путь обрезать можно — он
/// длинный у всех и нужен реже.
const COL_APP: i32 = 155;
const COL_STATE: i32 = 215;
/// В колонке «Куда» стоит имя подключения — под него и ширина.
const COL_WHERE: i32 = 120;

const IDC_LIST: u32 = 1001;
const IDC_ADD: u32 = 1002;
const IDC_DEL: u32 = 1003;
const IDC_RUN: u32 = 1004;
const IDC_SHORTCUT: u32 = 1005;
const IDC_STORE: u32 = 1006;
const IDC_AUTOSTART: u32 = 1007;
const IDC_VPN: u32 = 1008;
const IDC_LANE: u32 = 1009;

/// Ширина галочки «Запускать с Windows» при 96 точках на дюйм.
const AUTOSTART_WIDTH: i32 = 168;

/// С этого номера идут строки меню «Из Store…». Меню показывается с
/// `TPM_RETURNCMD`, так что номера никуда не рассылаются и пересечься с
/// кнопками не могут; отдельный диапазон — чтобы ноль остался «ничего не
/// выбрано».
const ID_STORE_FIRST: u32 = 3000;
/// Установленных приложений бывает под сотню; больше в меню не уместить
/// и на большом экране.
const STORE_MENU_LIMIT: usize = 240;
/// Столько строк в столбце меню: длинное меню в один столбец Windows
/// прокручивает стрелками, и выбирать из него мучение.
const STORE_MENU_COLUMN: usize = 24;

/// Строки меню кнопки «VPN…» — тоже через `TPM_RETURNCMD`.
const ID_VPN_CHOOSE: u32 = 4001;
/// Строки подменю подключений: на каждое подключение — свой десяток
/// номеров, внутри него номер говорит, что делать.
const ID_VPN_ITEM_FIRST: u32 = 4400;
const VPN_ITEM_STEP: usize = 8;
const VPN_ITEM_CONNECT: usize = 0;
const VPN_ITEM_DISCONNECT: usize = 1;
const VPN_ITEM_CODE: usize = 2;
const VPN_ITEM_DEFAULT: usize = 3;
const VPN_ITEM_LOGIN: usize = 4;
const VPN_ITEM_FORGET: usize = 5;
/// Строки меню кнопки «Куда…»: по умолчанию и по строке на подключение.
const ID_LANE_DEFAULT: u32 = 4200;
const ID_LANE_FIRST: u32 = 4201;
/// Больше подключений в меню не показываем: столько не бывает, а номера
/// строк не должны налезать друг на друга.
const VPN_MENU_LIMIT: usize = 32;
/// Длиннее имя подключения служба не примет.
const VPN_NAME_LIMIT: usize = 40;

/// С этого начинается отказ службы, на который окно отвечает повторным
/// вопросом о пароле. Слова — службы (`vpn::probe_failure`).
const WRONG_PASSWORD: &str = "пароль ключа не подошёл";

/// Коды извещений SysListView32. В windows-sys они отрицательные числа, а в
/// `NMHDR.code` лежит беззнаковое — сравнивать удобнее уже приведёнными.
const NM_DBLCLK_CODE: u32 = (-3i32) as u32;
const NM_CUSTOMDRAW_CODE: u32 = (-12i32) as u32;
const LVN_ITEMCHANGED_CODE: u32 = (-101i32) as u32;

pub const CLASS_NAME: &str = "vpnsplit.ui.main";

/// На какую сборку службы окно уже перезапускалось (ключ `--after-update
/// N`); ноль — ни на какую. На ту же сборку второй раз оно этого не делает:
/// если его файл почему-то остался прежним, перезапуски шли бы по кругу. А
/// на следующую — делает: прежний флаг «уже перезапускалось» жил до конца
/// процесса, и окно, однажды перезапущенное, все следующие обновления
/// пропускало.
pub static RESTARTED_FOR: AtomicU64 = AtomicU64::new(0);

/// Окно запустило прежнее, которое номера сборки не передаёт (`--after-update`
/// без числа): на какую сборку был перезапуск, неизвестно. Первая же
/// увиденная сборка службы считается ею.
pub const RESTARTED_FOR_UNKNOWN: u64 = u64::MAX;

/// Что делать с окном, увидев сборку службы.
#[derive(Debug, PartialEq, Eq)]
enum Restart {
    No,
    /// Не перезапускаться, но запомнить эту сборку как уже пройденную.
    Remember(u64),
    Now,
}

/// `own` — сборка окна (0 — собрано без номера), `service` — службы,
/// `done` — на какую уже перезапускались.
fn restart_plan(own: u64, service: u64, done: u64) -> Restart {
    if done == RESTARTED_FOR_UNKNOWN {
        return Restart::Remember(service);
    }
    if own != 0 && service > own && service > done {
        Restart::Now
    } else {
        Restart::No
    }
}

pub struct App {
    hwnd: HWND,
    dpi: u32,
    font: HFONT,
    font_head: HFONT,
    back: HBRUSH,
    status: HWND,
    warn: HWND,
    list: HWND,
    hint: HWND,
    add: HWND,
    store: HWND,
    del: HWND,
    shortcut: HWND,
    run: HWND,
    /// Галочка «Запускать с Windows» — в строке состояния справа.
    autostart: HWND,
    /// Кнопка «VPN…»: добавить своё подключение или забыть одно из них.
    vpn_button: HWND,
    /// Кнопка «Куда…»: через какое подключение вести выбранное приложение.
    lane_button: HWND,
    /// Строка под состоянием туннеля: что со своим подключением. Видна,
    /// только когда конфиг задан.
    vpn_note: HWND,
    tray: Tray,
    /// Значок самого окна — та же точка, что в трее, только крупнее.
    win_icon: HICON,
    /// Отвечает ли служба. Пока не отвечает, о туннеле мы ничего не знаем —
    /// и показывать «туннель не поднят» было бы прямой ложью.
    linked: bool,
    tunnel: TunnelState,
    /// Стоят ли запреты kill-switch. Спрашивается у службы при каждом
    /// изменении туннеля: само событие о туннеле этого не несёт.
    killswitch: bool,
    /// Поднят ли перехват пути B. Без него правила «приложение и все его
    /// потомки» не работают вовсе.
    divert: bool,
    /// Почему перехват не поднялся — словами службы.
    divert_error: Option<String>,
    /// Правила пути B, под которыми прямо сейчас есть хоть один процесс.
    /// Поднятый перехват этого не обещает: программу могли запустить
    /// раньше правила или раньше службы, значок-запускатель мог лишь
    /// разбудить уже открытый экземпляр. Пока окно судило по одному
    /// перехвату, оно писало «ведётся» про браузер, который шёл мимо
    /// туннеля, — так исходная утечка с запускателем и осталась
    /// незамеченной.
    supervised: Vec<AppTarget>,
    policy: Policy,
    /// Запущенные приложения из списка: номер процесса → путь и признак
    /// «хуки стоят». Приходит событиями службы, в том числе при подписке.
    processes: HashMap<u32, (PathBuf, bool)>,
    warn_text: String,
    warn_shown: bool,
    hint_error: bool,
    /// Свои подключения, как их описывает служба; пусто — ни одного не
    /// задано, туннель поднимает другая программа. Первое — то, куда идут
    /// приложения без выбранного подключения.
    vpns: Vec<VpnState>,
    /// Служба уже рассказала о подключениях: до этого судить, есть ли
    /// названное в правиле, не по чему.
    vpns_known: bool,
    vpn_text: String,
    /// Что написано в строке подсказки над кнопками: по тексту считается её
    /// высота.
    hint_text: String,
    /// Названия приложений из Store по семейству пакета (в нижнем
    /// регистре): в таблице человек ищет «ChatGPT», а не
    /// `OpenAI.Codex_2p2nqsd0c76g0`.
    titles: HashMap<String, String>,
    /// Спрашивали ли уже оболочку о названиях. Спрашиваем один раз и
    /// только когда в списке появился пакет: это сотни миллисекунд.
    titles_loaded: bool,
    /// Конфиг, отправленный службе вместе с паролем ключа. Если служба
    /// ответит «пароль не подошёл», спросим пароль ещё раз и отправим этот
    /// же текст, не заставляя выбирать файл заново.
    /// Конфиг, отправленный службе с паролем ключа: на «не подошёл» пароль
    /// спрашивается ещё раз, а выбирать файл заново незачем.
    pending: Option<svc::VpnOrder>,
    /// Пора уходить: «Выход» в меню значка или перезапуск после
    /// обновления. Само окно уничтожается не там, где это решено, а когда
    /// обработчик вернулся (`Shell::settle`): на стеке не должно остаться
    /// ни одного кадра, который ещё работает с окном.
    leaving: bool,
    /// Последний список правил от службы, пришедший, пока обработчик
    /// держал `App` и ждал человека (выбор файла, меню, вопрос). Сам ответ
    /// встаёт в очередь `Shell` и разбирается после обработчика — но
    /// обработчик успеет отправить службе список, собранный из
    /// `self.policy` до модального окна, и вернёт этим убранное за это
    /// время правило. Поэтому перед сохранением он берёт отсюда свежее
    /// (`catch_up_policy`). Общий с `Shell`: вложенный вызов `App` не видит.
    newest_policy: Rc<RefCell<Option<Policy>>>,
}

/// Окно и всё, что ему нужно, когда `App` занят.
///
/// Обработчики окна открывают модальные окна: вопросы, сообщения, меню,
/// выбор файла. Их собственный цикл сообщений снова зовёт оконную
/// процедуру, пока внешний обработчик держит `App`. Раньше вложенный вызов
/// брал второй `&mut App` поверх живого первого: ответ службы, пришедший
/// во время вопроса, подменял список правил под ссылкой внешнего кадра, а
/// «Выход» из меню значка освобождал `App` прямо из-под него. Теперь `App`
/// лежит в `RefCell`: вложенный вызов его не получает, а то, что пришло
/// за это время, откладывается и разбирается, когда внешний вернётся.
/// Освобождает `Shell` не окно, а `main` — после выхода из цикла сообщений.
pub struct Shell {
    app: RefCell<App>,
    /// Пришедшее, пока `App` был занят, — по порядку прихода.
    later: RefCell<VecDeque<Later>>,
    /// Чем красить надписи и какой наименьший размер окна, — то, что
    /// нужно и вложенному вызову. Обновляется после каждого обработчика.
    look: Cell<Look>,
    /// Отложенные перерисовки: повторять их по числу пропущенных сообщений
    /// незачем, достаточно знать, что они нужны.
    relayout: Cell<bool>,
    buttons: Cell<bool>,
    repaint: Cell<bool>,
    taskbar: Cell<bool>,
    dpi: Cell<Option<u32>>,
    /// Окно уничтожено: отложенное уже некому показывать.
    gone: Cell<bool>,
    /// То же, что `App::newest_policy`.
    newest_policy: Rc<RefCell<Option<Policy>>>,
}

/// То, что пришло, пока `App` был занят.
enum Later {
    Event(Box<Event>),
    Reply(Box<Reply>),
    Link(bool),
    Exit,
}

#[derive(Clone, Copy)]
struct Look {
    list: HWND,
    warn: HWND,
    vpn_note: HWND,
    hint: HWND,
    back: HBRUSH,
    hint_error: bool,
    dpi: u32,
}

impl Shell {
    /// Создаётся до окна и отдаётся в `CreateWindowExW`; поле `hwnd` у
    /// `App` заполняется в WM_NCCREATE, когда окно уже есть.
    pub fn new() -> Box<Shell> {
        let app = App::pending();
        let look = app.look();
        let newest_policy = Rc::clone(&app.newest_policy);
        Box::new(Shell {
            app: RefCell::new(app),
            later: RefCell::new(VecDeque::new()),
            look: Cell::new(look),
            relayout: Cell::new(false),
            buttons: Cell::new(false),
            repaint: Cell::new(false),
            taskbar: Cell::new(false),
            dpi: Cell::new(None),
            gone: Cell::new(false),
            newest_policy,
        })
    }

    /// Окна больше нет: снять значок и отдать то, что создали мы. Зовёт
    /// `main`, когда цикл сообщений закончился и ни одного обработчика на
    /// стеке не осталось.
    pub fn finish(&self) {
        if let Ok(mut app) = self.app.try_borrow_mut() {
            app.destroy();
        }
    }

    fn postpone(&self, later: Later) {
        self.later.borrow_mut().push_back(later);
    }

    /// Разобрать отложенное. Зовётся, когда обработчик верхнего уровня
    /// вернул `App`; то, что придёт, пока разбирается отложенное (оно тоже
    /// может спросить человека), встаёт в ту же очередь и разбирается здесь
    /// же.
    fn settle(&self) {
        loop {
            if self.gone.get() {
                self.later.borrow_mut().clear();
                return;
            }
            let Ok(mut app) = self.app.try_borrow_mut() else { return };
            if app.leaving {
                app.leave();
                continue;
            }
            if let Some(dpi) = self.dpi.take() {
                app.dpi = dpi;
                app.make_fonts();
                self.relayout.set(true);
            }
            if self.taskbar.replace(false) {
                app.on_taskbar_created();
            }
            if self.relayout.replace(false) {
                app.layout();
            }
            if self.buttons.replace(false) {
                app.update_buttons();
            }
            if self.repaint.replace(false) {
                // Строки таблицы и подсказка, нарисованные во время
                // модального окна, красились без знания о состоянии.
                unsafe {
                    InvalidateRect(app.list, std::ptr::null(), 1);
                    InvalidateRect(app.hint, std::ptr::null(), 1);
                }
            }
            self.look.set(app.look());
            let next = self.later.borrow_mut().pop_front();
            match next {
                Some(later) => app.run_later(later),
                None => return,
            }
        }
    }
}

/// Что показывать в колонке состояния.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mark {
    /// Приложение не запущено.
    Idle,
    /// Запущено и идёт через туннель.
    Tunnel(usize),
    /// Хоть один экземпляр идёт мимо туннеля — его трафик в обход VPN.
    Past { past: usize, total: usize },
}

impl App {
    fn pending() -> App {
        App {
            hwnd: std::ptr::null_mut(),
            dpi: 96,
            font: std::ptr::null_mut(),
            font_head: std::ptr::null_mut(),
            back: std::ptr::null_mut(),
            status: std::ptr::null_mut(),
            warn: std::ptr::null_mut(),
            list: std::ptr::null_mut(),
            hint: std::ptr::null_mut(),
            add: std::ptr::null_mut(),
            store: std::ptr::null_mut(),
            del: std::ptr::null_mut(),
            shortcut: std::ptr::null_mut(),
            run: std::ptr::null_mut(),
            autostart: std::ptr::null_mut(),
            vpn_button: std::ptr::null_mut(),
            lane_button: std::ptr::null_mut(),
            vpn_note: std::ptr::null_mut(),
            tray: Tray::new(std::ptr::null_mut()),
            win_icon: std::ptr::null_mut(),
            linked: false,
            tunnel: TunnelState::Down,
            killswitch: false,
            divert: false,
            divert_error: None,
            supervised: Vec::new(),
            policy: Policy::default(),
            processes: HashMap::new(),
            warn_text: String::new(),
            warn_shown: false,
            hint_error: false,
            vpns: Vec::new(),
            vpns_known: false,
            vpn_text: String::new(),
            hint_text: String::new(),
            titles: HashMap::new(),
            titles_loaded: false,
            pending: None,
            leaving: false,
            newest_policy: Rc::new(RefCell::new(None)),
        }
    }

    fn look(&self) -> Look {
        Look {
            list: self.list,
            warn: self.warn,
            vpn_note: self.vpn_note,
            hint: self.hint,
            back: self.back,
            hint_error: self.hint_error,
            dpi: self.dpi,
        }
    }

    fn run_later(&mut self, later: Later) {
        match later {
            Later::Event(event) => self.on_event(*event),
            Later::Reply(reply) => self.on_reply(*reply),
            Later::Link(linked) => self.on_link(linked),
            Later::Exit => self.leaving = true,
        }
    }

    /// Взять список правил, пришедший, пока обработчик ждал человека.
    /// Зовётся после модального окна и до того, как из `self.policy`
    /// собирается сохраняемый список.
    fn catch_up_policy(&mut self) {
        let newest = self.newest_policy.borrow_mut().take();
        if let Some(policy) = newest {
            self.policy = policy;
            self.refresh_list();
        }
    }

    /// Уйти: снять значок, пока окно живо (по нему значок и снимается), и
    /// уничтожить окно. Зовётся только из `Shell::settle`, когда на стеке
    /// нет обработчиков, которым окно ещё нужно.
    fn leave(&mut self) {
        // Сброс до DestroyWindow: если оно не удастся, по кругу не пойдём.
        self.leaving = false;
        self.tray.remove();
        unsafe { DestroyWindow(self.hwnd) };
    }

    fn build(&mut self) {
        self.dpi = win::dpi_of(self.hwnd);
        self.back = unsafe { GetSysColorBrush(COLOR_WINDOW) };
        self.status = self.static_text("");
        self.vpn_note = self.static_text("");
        self.warn = self.static_text("");
        self.hint = self.static_text("");
        self.list = list::create(self.hwnd, IDC_LIST);
        list::add_column(self.list, 0, "Приложение", scale(COL_APP, self.dpi));
        list::add_column(self.list, 1, "Состояние", scale(COL_STATE, self.dpi));
        list::add_column(self.list, 2, "Куда", scale(COL_WHERE, self.dpi));
        list::add_column(self.list, 3, "Путь", scale(325, self.dpi));
        self.add = self.button("Добавить…", IDC_ADD);
        self.store = self.button("Из Store…", IDC_STORE);
        self.del = self.button("Убрать", IDC_DEL);
        self.shortcut = self.button("Сделать ярлык", IDC_SHORTCUT);
        self.lane_button = self.button("Куда…", IDC_LANE);
        self.vpn_button = self.button("VPN…", IDC_VPN);
        self.run = self.button("Запустить через VPN", IDC_RUN);
        // Галочка показывает то, что записано в Windows, а не то, что мы
        // помним: автозапуск выключают и в диспетчере задач, мимо нас.
        self.autostart = self.checkbox("Запускать с Windows", IDC_AUTOSTART);
        self.show_autostart(crate::autostart::enabled());

        self.tray = Tray::new(self.hwnd);
        self.make_fonts();
        self.refresh_head();
        self.refresh_list();
        unsafe {
            ShowWindow(self.warn, SW_HIDE);
            ShowWindow(self.vpn_note, SW_HIDE);
        }
    }

    fn static_text(&self, text: &str) -> HWND {
        unsafe {
            CreateWindowExW(
                0,
                wide("Static").as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE,
                0,
                0,
                0,
                0,
                self.hwnd,
                std::ptr::null_mut(),
                GetModuleHandleW(std::ptr::null()) as _,
                std::ptr::null(),
            )
        }
    }

    fn button(&self, text: &str, id: u32) -> HWND {
        unsafe {
            CreateWindowExW(
                0,
                wide("Button").as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                0,
                0,
                0,
                0,
                self.hwnd,
                id as usize as HMENU,
                GetModuleHandleW(std::ptr::null()) as _,
                std::ptr::null(),
            )
        }
    }

    fn checkbox(&self, text: &str, id: u32) -> HWND {
        unsafe {
            CreateWindowExW(
                0,
                wide("Button").as_ptr(),
                wide(text).as_ptr(),
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32,
                0,
                0,
                0,
                0,
                self.hwnd,
                id as usize as HMENU,
                GetModuleHandleW(std::ptr::null()) as _,
                std::ptr::null(),
            )
        }
    }

    fn show_autostart(&self, on: bool) {
        unsafe { SendMessageW(self.autostart, BM_SETCHECK, on as usize, 0) };
    }

    /// Щелчок по галочке. Windows к этому моменту уже перерисовала её в
    /// новое состояние; если запись не удалась, галочка возвращается —
    /// иначе она показывала бы то, чего нет.
    fn toggle_autostart(&mut self) {
        let on = unsafe { SendMessageW(self.autostart, BM_GETCHECK, 0, 0) } == 1;
        match crate::autostart::set(on) {
            Ok(()) if on => self.set_hint(
                "при входе в Windows появится значок в трее; окно откроется по щелчку на нём",
                false,
            ),
            Ok(()) => self.set_hint(
                "окно с Windows запускаться не будет; служба работает и без него",
                false,
            ),
            Err(reason) => {
                self.show_autostart(crate::autostart::enabled());
                self.set_hint(&format!("автозапуск не изменён: {reason}"), true);
            }
        }
    }

    /// Проводник перезапустился и потерял все значки. Обычной программе
    /// это неудобство, а запущенной вместе с Windows — беда: окна у неё
    /// нет, и без значка до неё не добраться.
    fn on_taskbar_created(&mut self) {
        self.tray.lost();
        self.refresh_head();
    }

    fn make_fonts(&mut self) {
        let old = (self.font, self.font_head);
        self.font = win::ui_font(self.dpi, 9, false);
        self.font_head = win::ui_font(self.dpi, 11, true);
        for control in [
            self.warn,
            self.vpn_note,
            self.hint,
            self.list,
            self.add,
            self.store,
            self.del,
            self.shortcut,
            self.lane_button,
            self.vpn_button,
            self.run,
            self.autostart,
        ] {
            win::set_font(control, self.font);
        }
        win::set_font(self.status, self.font_head);
        unsafe {
            if !old.0.is_null() {
                DeleteObject(old.0 as _);
            }
            if !old.1.is_null() {
                DeleteObject(old.1 as _);
            }
        }
    }

    fn layout(&self) {
        let mut rect = unsafe { std::mem::zeroed() };
        if unsafe { GetClientRect(self.hwnd, &mut rect) } == 0 {
            return;
        }
        let (w, h) = (rect.right, rect.bottom);
        let m = scale(14, self.dpi);
        let line = scale(20, self.dpi);
        let gap = scale(8, self.dpi);
        // Высота и ширины по порядку слева направо: «Добавить…», «Из Store…»,
        // «Убрать», «Сделать ярлык», «Куда…», «VPN…» и прижатая к правому
        // краю «Запустить». Семь кнопок с промежутками и полями — 808
        // точек, отсюда и наименьшая ширина окна в WM_GETMINMAXINFO.
        let height = scale(30, self.dpi);
        let wide_as = [100, 100, 88, 124, 72, 72].map(|w| scale(w, self.dpi));
        let run_w = scale(176, self.dpi);
        let width = w - 2 * m;

        let mut top = m;
        // Строка состояния делит ширину с галочкой автозапуска: та стоит
        // справа, а состоянию хватает оставшегося и в самом узком окне.
        let check = scale(AUTOSTART_WIDTH, self.dpi);
        place(self.status, m, top, width - check - gap, line);
        place(self.autostart, w - m - check, top, check, line);
        top += line + gap;
        if !self.vpn_text.is_empty() {
            // Причина неудачи бывает длинной — строка растёт под текст.
            let height = self.text_height(&self.vpn_text, width).max(line);
            place(self.vpn_note, m, top, width, height);
            top += height + gap;
        }
        if self.warn_shown {
            // Высота считается по самому тексту: предупреждения разной длины,
            // а обрезанное предупреждение хуже, чем никакого.
            let height = self.text_height(&self.warn_text, width).max(line);
            place(self.warn, m, top, width, height);
            top += height + gap;
        }

        let buttons_y = h - m - height;
        // Подсказка растёт под свой текст, до четырёх строк: надпись Windows
        // рисует и за пределами своей рамки, и длинное сообщение ложилось
        // прямо на кнопки (замечено пользователем 23.11.2026).
        let hint_h = if self.hint_text.is_empty() {
            line
        } else {
            self.text_height(&self.hint_text, width).clamp(line, line * 4)
        };
        let hint_y = buttons_y - gap - hint_h;
        let list_h = (hint_y - gap - top).max(scale(80, self.dpi));
        place(self.list, m, top, width, list_h);
        place(self.hint, m, hint_y, width, hint_h);
        let mut x = m;
        for (control, width) in
            [self.add, self.store, self.del, self.shortcut, self.lane_button, self.vpn_button]
                .into_iter()
                .zip(wide_as)
        {
            place(control, x, buttons_y, width, height);
            x += width + gap;
        }
        place(self.run, w - m - run_w, buttons_y, run_w, height);

        // Последняя колонка добирает остаток ширины таблицы.
        let taken = scale(COL_APP + COL_STATE + COL_WHERE + 24, self.dpi);
        list::set_column_width(self.list, 3, (width - taken).max(scale(120, self.dpi)));
    }

    /// Сколько места займёт текст, если разложить его по словам в такой ширине.
    fn text_height(&self, text: &str, width: i32) -> i32 {
        let mut buffer = wide(text);
        let mut rect = RECT { left: 0, top: 0, right: width, bottom: 0 };
        unsafe {
            let dc = GetDC(self.hwnd);
            let previous = SelectObject(dc, self.font as _);
            DrawTextW(dc, buffer.as_mut_ptr(), -1, &mut rect, DT_CALCRECT | DT_WORDBREAK);
            SelectObject(dc, previous);
            ReleaseDC(self.hwnd, dc);
        }
        rect.bottom - rect.top
    }
}

fn place(control: HWND, x: i32, y: i32, w: i32, h: i32) {
    if control.is_null() {
        return;
    }
    unsafe { SetWindowPos(control, std::ptr::null_mut(), x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE) };
}

fn set_text(control: HWND, text: &str) {
    unsafe { SetWindowTextW(control, wide(text).as_ptr()) };
}

impl App {
    /// Шапка, значок в трее, значок окна и доступность кнопок — всё, что
    /// зависит от состояния туннеля и связи со службой.
    fn refresh_head(&mut self) {
        let (dot, status, warning) = if !self.linked {
            (
                Dot::NoService,
                "Служба vpnsplit не отвечает".to_owned(),
                Some(
                    // Про закрытую сеть — обязательно: иначе человек увидит
                    // «браузер не открывает сайты» и не свяжет это с нами.
                    "Без службы не видно ни туннеля, ни списка приложений. \
                     Пока она не работает, приложениям из списка закрыт выход в \
                     интернет (локальная сеть доступна) — чтобы они не пошли мимо \
                     VPN. Проверь, запущена ли служба vpnsplit; снять запреты без \
                     неё — vpnsplit-svc unblock из окна администратора."
                        .to_owned(),
                ),
            )
        } else {
            match &self.tunnel {
                // Туннель поднимает сама служба: «подключи VPN-клиент»
                // было бы советом сделать то, что делать уже не надо.
                TunnelState::Down if !self.vpns.is_empty() => (
                    Dot::Down,
                    "Туннель не поднят".to_owned(),
                    Some(
                        "Туннель поднимает сама служба — что с подключением, написано \
                         строкой выше. Пока туннеля нет, приложения из списка наружу не \
                         ходят; локальная сеть им доступна."
                            .to_owned(),
                    ),
                ),
                TunnelState::Down if self.killswitch => (
                    Dot::Down,
                    "Туннель не поднят".to_owned(),
                    Some(
                        "Приложениям из списка сеть закрыта — так и задумано: пока \
                         туннеля нет, наружу они не пойдут. Локальная сеть им \
                         доступна. Подключи VPN-клиент, и запреты снимутся сами."
                            .to_owned(),
                    ),
                ),
                TunnelState::Down => (
                    Dot::Down,
                    "Туннель не поднят".to_owned(),
                    Some(
                        "Подключи VPN-клиент. Пока туннеля нет, запускать приложения \
                         через него нельзя — иначе они молча пойдут мимо VPN."
                            .to_owned(),
                    ),
                ),
                TunnelState::Up(info) => {
                    let address = info
                        .ipv4
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "адреса нет".to_owned());
                    let text = format!("Туннель поднят: «{}», {address}", info.name);
                    if info.captures_all {
                        (
                            Dot::Captures,
                            text,
                            Some(
                                "На туннеле стоят маршруты 0.0.0.0/1 и 128.0.0.0/1 — в VPN \
                                 уходит весь трафик системы, и раздельное туннелирование \
                                 сейчас не работает. Убери redirect-gateway из профиля \
                                 или отключи лишнее VPN-подключение."
                                    .to_owned(),
                            ),
                        )
                    } else {
                        (Dot::Up, text, None)
                    }
                }
            }
        };

        // Приложение, идущее мимо туннеля, — отдельная беда, и показать её
        // надо даже тогда, когда с туннелем всё хорошо.
        let past = self.past_the_tunnel();
        let mut warnings: Vec<String> = warning.into_iter().collect();
        if past > 0 {
            warnings.push(format!(
                "Мимо туннеля работает приложений: {past}. Их трафик идёт в обход VPN — \
                 закрой их и запусти заново кнопкой «Запустить через VPN»."
            ));
        }
        // Правила «приложение и все его потомки» держит перехват. Если он
        // не поднялся, правила в списке есть, а защиты нет — и молчать об
        // этом нельзя: список выглядел бы работающим.
        if self.linked && !self.divert && self.policy.needs_divert() {
            // Причину называет сама служба; «смотри журнал» — не ответ тому,
            // кто видит программу первый раз.
            let why = match &self.divert_error {
                Some(reason) => format!("Причина: {reason}."),
                None => "Чаще всего это значит, что служба работает без прав администратора \
                         или не загрузился драйвер WinDivert; подробности — в журнале службы."
                    .to_owned(),
            };
            warnings.push(format!(
                "Правила «приложение и все его потомки» в списке есть, но перехват не \
                 поднят — эти приложения идут мимо VPN. {why}"
            ));
        }

        set_text(self.status, &status);
        let before =
            (self.warn_shown, std::mem::take(&mut self.warn_text), std::mem::take(&mut self.vpn_text));
        self.warn_text = warnings.join("\r\n\r\n");
        self.warn_shown = !self.warn_text.is_empty();
        if self.warn_shown {
            set_text(self.warn, &self.warn_text);
        }
        unsafe { ShowWindow(self.warn, if self.warn_shown { SW_SHOW } else { SW_HIDE }) };
        // Своё подключение — отдельной строкой и только когда оно есть и
        // служба на связи: без неё эта строка была бы воспоминанием.
        let shown = self.linked && !self.vpns.is_empty();
        self.vpn_text = if shown { vpn_lines(&self.vpns) } else { String::new() };
        if shown {
            set_text(self.vpn_note, &self.vpn_text);
        }
        unsafe { ShowWindow(self.vpn_note, if shown { SW_SHOW } else { SW_HIDE }) };
        if before != (self.warn_shown, self.warn_text.clone(), self.vpn_text.clone()) {
            self.layout();
        }

        // Приложение мимо туннеля — повод пожелтеть, даже если сам туннель цел:
        // значок должен означать «всё ли идёт как задумано», а не «жив ли TAP».
        // Не поднявшийся перехват — ровно такой же повод.
        let amiss = past > 0 || (self.linked && !self.divert && self.policy.needs_divert());
        let dot = if amiss && dot == Dot::Up { Dot::Captures } else { dot };
        let tip = if past > 0 {
            format!("vpnsplit — {past} приложений мимо туннеля")
        } else {
            format!("vpnsplit — {}", short(&status))
        };
        self.tray.show(dot, &tip);
        self.set_window_icon(dot);
        self.update_buttons();
    }

    fn set_window_icon(&mut self, dot: Dot) {
        let size = unsafe { GetSystemMetrics(SM_CXICON) }.max(16);
        let fresh = crate::icon::dot(dot, size);
        if fresh.is_null() {
            return;
        }
        unsafe {
            SendMessageW(self.hwnd, WM_SETICON, ICON_BIG as usize, fresh as isize);
            SendMessageW(self.hwnd, WM_SETICON, ICON_SMALL as usize, fresh as isize);
            // Прежний значок освобождается только после того, как окно взяло
            // новый: до этого Windows ещё может его рисовать.
            if !self.win_icon.is_null() {
                DestroyIcon(self.win_icon);
            }
        }
        self.win_icon = fresh;
    }

    /// Годится ли выбранная строка для лончера.
    ///
    /// Кнопка запуска и ярлык — это лончер, то есть хуки пути A. Правилу
    /// «приложение и все его потомки» они не нужны: такое приложение
    /// запускают как обычно, и уводит его перехват. Оставь мы кнопку
    /// живой, она ставила бы хуки в приложение, которое и так ведётся, —
    /// два способа сразу, и уже не понять, который из них сработал.
    /// Ровно это и случилось при первой же живой проверке.
    fn runnable(&self) -> bool {
        list::selected(self.list)
            .and_then(|row| self.policy.rules.get(row))
            .is_some_and(|rule| {
                matches!(rule.target, AppTarget::Executable(_)) && rule.mechanism() == Mechanism::Inject
            })
    }

    /// Можно ли запустить выбранное через лончер прямо сейчас. Одно условие
    /// и для кнопки, и для двойного щелчка по строке: иначе щелчок обходил бы
    /// всё, из-за чего кнопка серая.
    fn can_run(&self) -> bool {
        // Туннеля нет — лончер всё равно откажется, и честнее показать
        // это недоступной кнопкой, а не ошибкой после щелчка.
        let up = matches!(self.tunnel, TunnelState::Up(_));
        self.linked && up && self.runnable()
    }

    fn update_buttons(&self) {
        let chosen = list::selected(self.list).and_then(|row| self.policy.rules.get(row));
        let runnable = self.runnable();
        unsafe {
            EnableWindow(self.add, self.linked as i32);
            EnableWindow(self.store, self.linked as i32);
            EnableWindow(self.vpn_button, self.linked as i32);
            // Подключение выбирают тому, что идёт в VPN; правилу «напрямую»
            // выбирать нечего.
            let led = chosen.is_some_and(|rule| rule.routing == Routing::Tunnel);
            EnableWindow(self.lane_button, (self.linked && led) as i32);
            EnableWindow(self.del, (self.linked && chosen.is_some()) as i32);
            // Ярлык делается и при опущенном туннеле: это просто файл на
            // рабочем столе, туннель понадобится потом, при запуске.
            EnableWindow(self.shortcut, runnable as i32);
            EnableWindow(self.run, self.can_run() as i32);
        }
    }

    /// Сколько запущенных приложений идёт мимо туннеля.
    fn past_the_tunnel(&self) -> usize {
        self.processes.values().filter(|(_, hooked)| !hooked).count()
    }

    /// Состояние строки: сколько её процессов запущено и как именно.
    /// Приложение может быть запущено в нескольких экземплярах, и если хоть
    /// один идёт мимо туннеля, строка считается плохой: показывать надо
    /// худшее, а не среднее.
    fn mark(&self, target: &AppTarget) -> Mark {
        let AppTarget::Executable(path) = target else {
            return Mark::Idle;
        };
        let wanted = path.to_string_lossy().to_lowercase();
        let mut hooked = 0;
        let mut past = 0;
        for (image, is_hooked) in self.processes.values() {
            if image.to_string_lossy().to_lowercase() != wanted {
                continue;
            }
            if *is_hooked {
                hooked += 1;
            } else {
                past += 1;
            }
        }
        match (hooked, past) {
            (0, 0) => Mark::Idle,
            (_, 0) => Mark::Tunnel(hooked),
            _ => Mark::Past { past, total: hooked + past },
        }
    }

    /// Имя приложения для человека: у программы — имя файла, у пакета —
    /// название, под которым оно стоит в меню «Пуск», если оболочка его
    /// знает.
    fn shown_name(&self, target: &AppTarget) -> String {
        match target {
            AppTarget::Package(family) => self
                .titles
                .get(&family.to_lowercase())
                .cloned()
                .unwrap_or_else(|| target.display_name()),
            AppTarget::Executable(_) => target.display_name(),
        }
    }

    /// Названия пакетов спрашиваются у оболочки один раз и только когда
    /// есть кого называть: без пакетов в списке окну они не нужны. И не в
    /// потоке окна: оболочка отвечает полсекунды, и на это время окно
    /// замерло бы. Пока ответа нет, в таблице стоит имя пакета.
    fn learn_titles(&mut self) {
        let needed = self.policy.rules.iter().any(|rule| rule.target.needs_package());
        if needed && !self.titles_loaded {
            self.titles_loaded = true;
            svc::load_titles(Target::new(self.hwnd));
        }
    }

    fn remember_titles(&mut self, installed: &[(String, String)]) {
        self.titles_loaded = true;
        self.titles = package_titles(installed);
    }

    fn refresh_list(&mut self) {
        self.learn_titles();
        let keep = list::selected(self.list);
        list::clear(self.list);
        for (row, rule) in self.policy.rules.iter().enumerate() {
            let routing = where_to(rule, &self.vpns, self.vpns_known);
            let path = match &rule.target {
                AppTarget::Executable(path) => path.display().to_string(),
                AppTarget::Package(pfn) => format!("пакет {pfn}"),
            };
            // У правил «приложение и все его потомки» хуков нет: их ведёт
            // перехват, и служба говорит, под какими из них сейчас есть
            // процессы.
            if rule.mechanism() == Mechanism::Divert {
                let state = divert_state(
                    self.linked,
                    self.divert,
                    self.supervised.contains(&rule.target),
                )
                .to_owned();
                list::push(
                    self.list,
                    row as i32,
                    &[self.shown_name(&rule.target), state, routing.to_owned(), path],
                );
                continue;
            }
            let state = match self.mark(&rule.target) {
                Mark::Idle => "не запущено".to_owned(),
                Mark::Tunnel(1) => "идёт через VPN".to_owned(),
                Mark::Tunnel(n) => format!("идёт через VPN ({n})"),
                // Когда мимо идут не все экземпляры, сказать это прямо:
                // «МИМО VPN» про приложение, половина которого в туннеле,
                // было бы правдой, но не всей.
                Mark::Past { past, total } if past == total => {
                    if past == 1 {
                        "МИМО VPN".to_owned()
                    } else {
                        format!("МИМО VPN ({past})")
                    }
                }
                Mark::Past { past, total } => format!("МИМО VPN ({past} из {total})"),
            };
            list::push(
                self.list,
                row as i32,
                &[rule.target.display_name(), state, routing, path],
            );
        }
        if let Some(row) = keep {
            if row < self.policy.rules.len() {
                list::select(self.list, row);
            }
        }
        self.update_buttons();
    }

    /// Строка приложения, которое идёт мимо туннеля, красится в красный.
    /// Обычный ListView красить ячейки не умеет — это и есть тот случай,
    /// ради которого существует NM_CUSTOMDRAW.
    ///
    /// # Safety
    /// Вызывается только из обработчика WM_NOTIFY с его же указателем.
    unsafe fn paint_row(&self, raw: *mut NMLVCUSTOMDRAW) -> LRESULT {
        if raw.is_null() {
            return CDRF_DODEFAULT as LRESULT;
        }
        let draw = &mut *raw;
        match draw.nmcd.dwDrawStage {
            // Без этой подписки Windows про отдельные строки не спросит.
            CDDS_PREPAINT => CDRF_NOTIFYITEMDRAW as LRESULT,
            CDDS_ITEMPREPAINT => {
                let row = draw.nmcd.dwItemSpec;
                if let Some(rule) = self.policy.rules.get(row) {
                    // Правило пути B без поднятого перехвата — такая же
                    // беда, как приложение мимо туннеля: правило есть, а
                    // защиты нет.
                    let bad = if rule.mechanism() == Mechanism::Divert {
                        self.linked && !self.divert
                    } else {
                        matches!(self.mark(&rule.target), Mark::Past { .. })
                    };
                    if bad {
                        draw.clrText = rgb(192, 40, 35);
                    }
                }
                CDRF_NEWFONT as LRESULT
            }
            _ => CDRF_DODEFAULT as LRESULT,
        }
    }

    fn set_hint(&mut self, text: &str, error: bool) {
        self.hint_error = error;
        // Длиннее четырёх строк подсказке не бывать: остальное обрезается
        // здесь, а не поверх кнопок.
        let text = clipped(text, HINT_LIMIT);
        let text = text.as_str();
        let changed = self.hint_text != text;
        self.hint_text = text.to_owned();
        if changed {
            // Высота строки зависит от текста.
            self.layout();
        }
        set_text(self.hint, text);
        // Цвет берётся в WM_CTLCOLORSTATIC, поэтому строку надо перерисовать.
        unsafe { InvalidateRect(self.hint, std::ptr::null(), 1) };
    }

    fn on_command(&mut self, id: u32) {
        match id {
            IDC_ADD => self.add_app(),
            IDC_STORE => self.add_store_app(),
            IDC_VPN => self.vpn_menu(),
            IDC_LANE => self.lane_menu(),
            IDC_AUTOSTART => self.toggle_autostart(),
            IDC_DEL => self.remove_app(),
            IDC_RUN => self.run_app(),
            IDC_SHORTCUT => self.make_shortcut(),
            // «Открыть окно» разбирает сама оконная процедура: ему `App` не
            // нужен, и работать оно должно и при открытом вопросе.
            // Уничтожается окно не здесь, а когда обработчик вернётся.
            tray::ID_EXIT => self.leaving = true,
            _ => {}
        }
    }

    fn add_app(&mut self) {
        let Some(path) = self.pick_file() else { return };
        let target = AppTarget::Executable(path.clone());
        if self.policy.rules.iter().any(|rule| rule.target == target) {
            self.set_hint(&format!("{} уже в списке", target.display_name()), false);
            return;
        }
        let Some(family) = self.ask_family(&target.display_name()) else {
            // Отказ в вопросе — отказ от добавления: правило «не то»
            // хуже отсутствующего.
            return;
        };
        // Пока висели выбор файла и вопрос, список мог смениться.
        self.catch_up_policy();
        if self.policy.rules.iter().any(|rule| rule.target == target) {
            self.set_hint(&format!("{} уже в списке", target.display_name()), false);
            return;
        }
        let mut policy = self.policy.clone();
        policy.rules.push(if family {
            AppRule::tunnel_family(target)
        } else {
            AppRule::tunnel(target)
        });
        self.set_hint(&format!("добавляю {}…", path.display()), false);
        svc::save_policy(Target::new(self.hwnd), policy);
    }

    /// Добавить приложение из Microsoft Store.
    ///
    /// Диалог выбора файла здесь не годится: пакеты лежат в
    /// `Program Files\WindowsApps`, куда пользователя не пускают, а правило
    /// для них пишется не по пути, а по имени семейства пакета.
    ///
    /// Выбирают из всего установленного — того же, что стоит в меню
    /// «Пуск», под теми же названиями; запускать приложение ради того,
    /// чтобы добавить его, не надо. (До 22.11.2026 меню показывало только
    /// запущенное: имя семейства брали у процесса.) Запущенные пакеты, у
    /// которых значка в «Пуске» нет, в меню тоже попадают — под именем
    /// программы.
    fn add_store_app(&mut self) {
        let listed: Vec<AppTarget> =
            self.policy.rules.iter().map(|rule| rule.target.clone()).collect();
        let installed = apps::installed();
        // Заодно освежить названия для таблицы: за это уже заплачено.
        self.remember_titles(&installed);
        let choices = store_choices(&installed, &running_packages(), &listed);
        if choices.is_empty() {
            self.set_hint("приложений из Store, которых ещё нет в списке, не нашлось", false);
            return;
        }
        let Some(family) = self.pick_from_menu(&choices) else { return };
        if !self.confirm_store(&family) {
            return;
        }
        // Пока висели меню и вопрос, список мог смениться.
        self.catch_up_policy();
        let target = AppTarget::Package(family.clone());
        if self.policy.rules.iter().any(|rule| rule.target == target) {
            self.set_hint(&format!("пакет {family} уже в списке"), false);
            return;
        }
        let mut policy = self.policy.clone();
        policy.rules.push(AppRule::tunnel_family(target));
        self.set_hint(&format!("добавляю пакет {family}…"), false);
        svc::save_policy(Target::new(self.hwnd), policy);
    }

    /// Меню над кнопкой «Из Store…»; возвращает семейство выбранного пакета.
    fn pick_from_menu(&self, choices: &[(String, String)]) -> Option<String> {
        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return None;
            }
            for (index, (label, _)) in choices.iter().enumerate() {
                // Одиночный «&» в строке меню — подчёркнутая буква, а не знак.
                let label = label.replace('&', "&&");
                // Каждые несколько строк — новый столбец: всё меню видно
                // сразу, без прокрутки.
                let column = if index > 0 && index % STORE_MENU_COLUMN == 0 { MF_MENUBARBREAK } else { 0 };
                AppendMenuW(
                    menu,
                    MF_STRING | column,
                    ID_STORE_FIRST as usize + index,
                    wide(&label).as_ptr(),
                );
            }
            let mut rect: RECT = std::mem::zeroed();
            GetWindowRect(self.store, &mut rect);
            // С TPM_RETURNCMD выбор возвращается числом, а не WM_COMMAND:
            // ноль — меню закрыли, ничего не выбрав.
            let chosen = TrackPopupMenu(
                menu,
                TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                rect.left,
                rect.top,
                0,
                self.hwnd,
                std::ptr::null(),
            );
            DestroyMenu(menu);
            let index = (chosen as u32).checked_sub(ID_STORE_FIRST)? as usize;
            choices.get(index).map(|(_, family)| family.clone())
        }
    }

    /// У пакета выбора «с потомками или через лончер» нет: лончеру нечего
    /// запускать, приложение открывает сама Windows. Но цена названа так
    /// же прямо, как в `ask_family`, и согласие спрашивается до правила.
    fn confirm_store(&self, family: &str) -> bool {
        let title = self.shown_name(&AppTarget::Package(family.to_owned()));
        // Название — то, что человек выбрал; имя пакета — то, что запишется
        // в правило. Когда названия нет, второе и есть первое.
        let name = if title == family {
            format!("пакет «{family}»")
        } else {
            format!("«{title}» (пакет {family})")
        };
        let text = format!(
            "Вести {name} через VPN?\n\n\
             Приложение из Store ведётся целиком: все его процессы и всё, что они \
             запустят, откуда бы его ни открыли — вместе с его запросами имён. \
             Пока оно в списке, работает перехват пакетов: он стоит процессорного \
             времени и на несколько миллисекунд задерживает запросы имён остальных \
             программ, пока служба выясняет, чей запрос.\n\n\
             Соединения, которые приложение уже открыло, останутся как были — \
             надёжнее закрыть его и открыть заново."
        );
        let answer = unsafe {
            MessageBoxW(
                self.hwnd,
                wide(&text).as_ptr(),
                wide("Приложение из Store").as_ptr(),
                MB_OKCANCEL | MB_ICONINFORMATION,
            )
        };
        answer == IDOK
    }

    /// Вести приложение вместе с потомками или только через лончер.
    ///
    /// Вопрос задаётся один раз на приложение и именно здесь, в момент
    /// выбора: разница видна пользователю не в терминах путей A и B, а в
    /// том, откуда приложение можно запускать и что программа будет
    /// перехватывать. Цена первого варианта — процессорное время и задержка
    /// запросов имён у остальных программ — названа прямо: узнать о ней
    /// потом, по тормозящему браузеру, было бы хуже. (До 22.11.2026 ценой
    /// был весь DNS машины в туннеле; теперь туда идут только имена,
    /// которые спросили приложения из списка.)
    ///
    /// `None` — пользователь отменил.
    fn ask_family(&self, name: &str) -> Option<bool> {
        let text = format!(
            "Вести «{name}» вместе со всеми процессами, которые оно запускает?\n\n\
             Да — запускать можно как обычно, откуда угодно: и само приложение, и \
             всё, что оно запустит, уйдёт в туннель вместе с запросами имён. Пока \
             такое приложение есть в списке, работает перехват пакетов: он стоит \
             процессорного времени и на несколько миллисекунд задерживает запросы \
             имён остальных программ, пока служба выясняет, чей запрос.\n\n\
             Нет — только само приложение и только когда запущено кнопкой \
             «Запустить через VPN» или ярлыком. Ничего лишнего не перехватывается."
        );
        let answer = unsafe {
            MessageBoxW(
                self.hwnd,
                wide(&text).as_ptr(),
                wide("Как вести приложение").as_ptr(),
                MB_YESNOCANCEL | MB_ICONQUESTION,
            )
        };
        match answer {
            IDYES => Some(true),
            // Явное «нет» — обычное правило; всё остальное (отмена, закрытие
            // окна, отказ Windows показать вопрос) трактуем как отмену:
            // молча выбрать за пользователя здесь нельзя.
            IDNO => Some(false),
            _ => None,
        }
    }

    /// Меню кнопки «VPN…»: добавить своё подключение, а у каждого из уже
    /// заданных — подменю: подключить и отключить, сделать подключением по
    /// умолчанию, сменить логин, забыть.
    fn vpn_menu(&mut self) {
        // Номер строки меню — номер подключения в том списке, по которому
        // меню построено. Действие ищет подключение по имени из этого
        // снимка, а не по номеру в `self.vpns`: служба могла переставить
        // подключения, и «Отключить» досталось бы другому.
        let names: Vec<String> =
            self.vpns.iter().take(VPN_MENU_LIMIT).map(|vpn| vpn.name.clone()).collect();
        let chosen = unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            let add = if self.vpns.is_empty() {
                "Подключаться самому: выбрать конфиг OpenVPN…"
            } else {
                "Добавить или заменить подключение: выбрать конфиг OpenVPN…"
            };
            AppendMenuW(menu, MF_STRING, ID_VPN_CHOOSE as usize, wide(add).as_ptr());
            if !self.vpns.is_empty() {
                AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
            }
            // Строка есть и тогда, когда нажать её нельзя: так видно, что
            // возможность существует.
            let item = |on: bool| if on { MF_STRING } else { MF_STRING | MF_GRAYED };
            for (index, vpn) in self.vpns.iter().enumerate().take(VPN_MENU_LIMIT) {
                let sub = CreatePopupMenu();
                if sub.is_null() {
                    continue;
                }
                let base = ID_VPN_ITEM_FIRST as usize + index * VPN_ITEM_STEP;
                if vpn.by_code {
                    // Сервер ждёт одноразовый код: «подключить» — это
                    // ввести его.
                    AppendMenuW(
                        sub,
                        item(!vpn.connected),
                        base + VPN_ITEM_CODE,
                        wide("Подключить: ввести одноразовый код…").as_ptr(),
                    );
                } else {
                    // Не отключённое подключается само — включать нечего.
                    AppendMenuW(sub, item(vpn.off), base + VPN_ITEM_CONNECT, wide("Подключить").as_ptr());
                }
                AppendMenuW(sub, item(!vpn.off), base + VPN_ITEM_DISCONNECT, wide("Отключить").as_ptr());
                AppendMenuW(sub, MF_SEPARATOR, 0, std::ptr::null());
                AppendMenuW(
                    sub,
                    item(index != 0),
                    base + VPN_ITEM_DEFAULT,
                    wide("Сделать подключением по умолчанию").as_ptr(),
                );
                AppendMenuW(
                    sub,
                    item(vpn.login),
                    base + VPN_ITEM_LOGIN,
                    wide("Сменить логин и пароль…").as_ptr(),
                );
                AppendMenuW(sub, MF_SEPARATOR, 0, std::ptr::null());
                AppendMenuW(
                    sub,
                    MF_STRING,
                    base + VPN_ITEM_FORGET,
                    wide("Отключить и забыть конфиг").as_ptr(),
                );
                let title = vpn_title(vpn, index == 0 && self.vpns.len() > 1);
                // Подменю принадлежит меню и уничтожается вместе с ним.
                AppendMenuW(menu, MF_POPUP, sub as usize, wide(&title).as_ptr());
            }
            let mut rect: RECT = std::mem::zeroed();
            GetWindowRect(self.vpn_button, &mut rect);
            let chosen = TrackPopupMenu(
                menu,
                TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                rect.left,
                rect.top,
                0,
                self.hwnd,
                std::ptr::null(),
            );
            DestroyMenu(menu);
            chosen as u32
        };
        if chosen == ID_VPN_CHOOSE {
            self.choose_vpn_config();
            return;
        }
        let Some(offset) = chosen.checked_sub(ID_VPN_ITEM_FIRST) else { return };
        let (index, what) = (offset as usize / VPN_ITEM_STEP, offset as usize % VPN_ITEM_STEP);
        let Some(name) = names.get(index).cloned() else { return };
        if !self.vpns.iter().any(|vpn| vpn.name == name) {
            // Пока меню было открыто, подключение забыли.
            return;
        }
        let target = Target::new(self.hwnd);
        match what {
            VPN_ITEM_CONNECT => {
                self.set_hint(&format!("включаю «{name}»…"), false);
                let done = format!("«{name}» снова подключается само");
                svc::vpn_action(target, name, VpnAction::Connect, done);
            }
            VPN_ITEM_DISCONNECT => {
                self.set_hint(&format!("отключаю «{name}»…"), false);
                let done = format!(
                    "«{name}» отключено и само не поднимется; его приложения пока без сети"
                );
                svc::vpn_action(target, name, VpnAction::Disconnect, done);
            }
            VPN_ITEM_CODE => self.enter_vpn_code(&name),
            VPN_ITEM_DEFAULT => {
                let done = format!(
                    "«{name}» теперь по умолчанию: через него идут приложения без выбранного \
                     подключения"
                );
                svc::vpn_action(target, name, VpnAction::MakeDefault, done);
            }
            VPN_ITEM_LOGIN => {
                if let Some((user, password)) = self.ask_login() {
                    self.set_hint(&format!("меняю логин и пароль «{name}»…"), false);
                    svc::set_vpn_login(target, name, user, password);
                }
            }
            VPN_ITEM_FORGET => self.forget_vpn(&name),
            _ => {}
        }
    }

    /// Одноразовый код для подключения: спросить и отдать службе. Код
    /// живёт полминуты, поэтому спрашивается в последний момент и нигде
    /// не хранится.
    fn enter_vpn_code(&mut self, name: &str) {
        let prompt = format!(
            "Одноразовый код для входа на сервер подключения «{name}» — из приложения или \
             устройства, которое их выдаёт. Логин и пароль служба уже знает."
        );
        loop {
            let Some(code) = ask::text(self.hwnd, "Одноразовый код", &prompt, "") else { return };
            let code = code.trim().to_owned();
            match ovpn::check_code(&code) {
                Ok(()) => {
                    self.set_hint(&format!("отдаю код службе, «{name}» подключается…"), false);
                    svc::connect_vpn(Target::new(self.hwnd), name.to_owned(), code);
                    return;
                }
                Err(reason) => win::error_box(self.hwnd, &format!("Так не годится: {reason}.")),
            }
        }
    }

    /// Выбрать `.ovpn`, по которому служба будет подключаться сама.
    ///
    /// Файл разбирается здесь же, теми же правилами, что и в службе: о
    /// негодном конфиге человек узнаёт сразу и своими словами, а о том,
    /// что из годного не сработает, — до того, как согласится. Решает всё
    /// равно служба: она разберёт текст заново и проверит его запуском
    /// OpenVPN вхолостую.
    fn choose_vpn_config(&mut self) {
        let Some(path) = self.pick_ovpn() else { return };
        let read = std::fs::read(&path).map_err(|e| e.to_string()).and_then(ovpn::decode);
        let text = match read {
            Ok(text) => text,
            Err(reason) => {
                win::error_box(self.hwnd, &format!("Файл не прочитан: {reason}"));
                return;
            }
        };
        let config = match ovpn::sanitize(&text) {
            Ok(config) => config,
            Err(reason) => {
                win::error_box(self.hwnd, &format!("Этот конфиг не подходит: {reason}."));
                return;
            }
        };
        // Имя подсказывает файл: «work.ovpn» — скорее всего «work».
        let suggested: String = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default()
            .chars()
            .take(VPN_NAME_LIMIT)
            .collect();
        let Some(name) = self.ask_vpn_name(&suggested) else { return };
        let replacing = self.vpns.iter().any(|vpn| same_name(&vpn.name, &name));
        // Туннель есть, а ни одно наше подключение не поднято — значит,
        // держит его кто-то другой.
        let foreign = matches!(self.tunnel, TunnelState::Up(_))
            && !self.vpns.iter().any(|vpn| vpn.connected);
        let answer = unsafe {
            MessageBoxW(
                self.hwnd,
                wide(&vpn_question(&config, &name, replacing, foreign)).as_ptr(),
                wide("Своё подключение к VPN").as_ptr(),
                MB_OKCANCEL | MB_ICONQUESTION,
            )
        };
        if answer != IDOK {
            return;
        }
        let key_password = if config.needs_password {
            let Some(password) = self.ask_key_password(false) else { return };
            Some(password)
        } else {
            None
        };
        let login = if config.needs_login {
            let Some(login) = self.ask_login() else { return };
            Some(login)
        } else {
            None
        };
        let order = svc::VpnOrder { name, config: text, key_password, login };
        // Заказ помним только пока ждём ответа и только если был пароль
        // ключа: на «не подошёл» спросим его ещё раз.
        self.pending = order.key_password.is_some().then(|| order.clone());
        self.set_hint("проверяю конфиг самим OpenVPN — секунду…", false);
        svc::set_vpn(Target::new(self.hwnd), order);
    }

    /// Имя подключения: по нему его потом выбирают для приложения.
    fn ask_vpn_name(&self, suggested: &str) -> Option<String> {
        let mut prompt = "Как назвать это подключение? По имени его выбирают для приложения \
                          кнопкой «Куда…»."
            .to_owned();
        if !self.vpns.is_empty() {
            prompt.push_str(" Имя уже существующего подключения заменит его конфиг.");
        }
        loop {
            let name = ask::text(self.hwnd, "Имя подключения", &prompt, suggested)?;
            let name = name.trim();
            if name.is_empty() || name.chars().count() > VPN_NAME_LIMIT {
                win::error_box(
                    self.hwnd,
                    &format!("Имя — от одного до {VPN_NAME_LIMIT} знаков."),
                );
                continue;
            }
            return Some(name.to_owned());
        }
    }

    /// Пароль закрытого ключа. `again` — прошлый не подошёл.
    fn ask_key_password(&self, again: bool) -> Option<String> {
        let mut prompt = String::new();
        if again {
            prompt.push_str("Пароль не подошёл. ");
        }
        prompt.push_str(
            "Пароль закрытого ключа из конфига. Он сохранится у службы рядом с конфигом; \
             читать их могут только система и администраторы.",
        );
        loop {
            let password = ask::password(self.hwnd, "Пароль ключа", &prompt)?;
            match ovpn::check_password(&password) {
                Ok(()) => return Some(password),
                Err(reason) => win::error_box(self.hwnd, &format!("Так не годится: {reason}.")),
            }
        }
    }

    /// Логин и пароль, которые спрашивает сервер.
    fn ask_login(&self) -> Option<(String, String)> {
        let prompt = "Логин и пароль, которые спрашивает сервер. Они сохранятся у службы рядом \
                      с конфигом; читать их могут только система и администраторы.";
        loop {
            let (user, password) = ask::login(self.hwnd, "Вход на сервер VPN", prompt)?;
            let user = user.trim().to_owned();
            match ovpn::check_login(&user, &password) {
                Ok(()) => return Some((user, password)),
                Err(reason) => win::error_box(self.hwnd, &format!("Так не годится: {reason}.")),
            }
        }
    }

    fn forget_vpn(&mut self, name: &str) {
        let users = self
            .policy
            .rules
            .iter()
            .filter(|rule| rule.vpn.as_deref().is_some_and(|chosen| same_name(chosen, name)))
            .count();
        let mut text =
            format!("Отключить подключение «{name}» и забыть его конфиг вместе с паролями?");
        if users > 0 {
            text.push_str(&format!(
                "\n\nЕму назначено приложений: {users}. Они останутся без сети, пока им не \
                 выберут другое подключение кнопкой «Куда…»."
            ));
        }
        if self.vpns.len() == 1 {
            text.push_str(
                "\n\nТуннель снова станет заботой другой программы. Пока его нет, приложения \
                 из списка наружу не ходят.",
            );
        }
        let answer = unsafe {
            MessageBoxW(
                self.hwnd,
                wide(&text).as_ptr(),
                wide("Своё подключение к VPN").as_ptr(),
                MB_OKCANCEL | MB_ICONQUESTION,
            )
        };
        if answer == IDOK {
            self.set_hint(&format!("отключаю «{name}»…"), false);
            svc::clear_vpn(Target::new(self.hwnd), name.to_owned());
        }
    }

    /// Меню кнопки «Куда…»: через какое подключение вести выбранное
    /// приложение.
    fn lane_menu(&mut self) {
        let Some(row) = list::selected(self.list) else { return };
        let Some(rule) = self.policy.rules.get(row) else { return };
        // Снимок до меню: правило — по тому, что оно ведёт, подключения — по
        // именам. После меню номер строки таблицы и номер подключения могли
        // означать уже другое.
        let target = rule.target.clone();
        let current = rule.vpn.clone();
        let names: Vec<String> =
            self.vpns.iter().take(VPN_MENU_LIMIT).map(|vpn| vpn.name.clone()).collect();
        let check = |on: bool| if on { MF_STRING | MF_CHECKED } else { MF_STRING };
        let chosen = unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            let default = match self.vpns.first() {
                Some(first) => format!(
                    "По умолчанию: «{}»; пока туннель держит другая программа — через неё",
                    menu_text(&first.name)
                ),
                None => "По умолчанию: туннель, который держит другая программа".to_owned(),
            };
            AppendMenuW(
                menu,
                check(current.is_none()),
                ID_LANE_DEFAULT as usize,
                wide(&default).as_ptr(),
            );
            AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
            if self.vpns.is_empty() {
                AppendMenuW(
                    menu,
                    MF_STRING | MF_GRAYED,
                    ID_LANE_FIRST as usize,
                    wide("Своих подключений нет — добавь кнопкой «VPN…»").as_ptr(),
                );
            }
            for (index, vpn) in self.vpns.iter().enumerate().take(VPN_MENU_LIMIT) {
                let on = current.as_deref().is_some_and(|chosen| same_name(chosen, &vpn.name));
                let line = format!("Через «{}»", menu_text(&vpn.name));
                AppendMenuW(menu, check(on), ID_LANE_FIRST as usize + index, wide(&line).as_ptr());
            }
            let mut rect: RECT = std::mem::zeroed();
            GetWindowRect(self.lane_button, &mut rect);
            let chosen = TrackPopupMenu(
                menu,
                TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                rect.left,
                rect.top,
                0,
                self.hwnd,
                std::ptr::null(),
            );
            DestroyMenu(menu);
            chosen as u32
        };
        let vpn = match chosen {
            ID_LANE_DEFAULT => None,
            id if (ID_LANE_FIRST..ID_LANE_FIRST + VPN_MENU_LIMIT as u32).contains(&id) => {
                match names.get((id - ID_LANE_FIRST) as usize) {
                    Some(name) if self.vpns.iter().any(|vpn| vpn.name == *name) => Some(name.clone()),
                    _ => return,
                }
            }
            _ => return,
        };
        self.set_lane(&target, vpn);
    }

    /// Назначить правилу подключение.
    ///
    /// Выбирать подключение умеет только перехват (путь B): хук пути A
    /// привязывает сокеты к одному туннелю на всех. Поэтому правило пути A
    /// при выборе подключения становится правилом пути B — с согласия.
    ///
    /// Правило ищется по тому, что оно ведёт, а не по номеру строки, и
    /// заново после вопроса: ссылку на правило через модальное окно не
    /// держим — пока оно открыто, список мог смениться.
    fn set_lane(&mut self, target: &AppTarget, vpn: Option<String>) {
        // Пока было открыто меню «Куда…», список мог смениться.
        self.catch_up_policy();
        let Some(rule) = self.policy.rules.iter().find(|rule| rule.target == *target) else {
            return;
        };
        if rule.vpn == vpn {
            return;
        }
        let name = self.shown_name(&rule.target);
        let convert = vpn.is_some() && rule.mechanism() != Mechanism::Divert;
        if convert {
            let text = format!(
                "Выбрать подключение можно только тому, что ведётся перехватом: {name} будет \
                 вестись вместе со всеми программами, которые запустит, — как бы его ни \
                 запустили. Кнопка «Запустить через VPN» и ярлык ему больше не нужны.\n\n\
                 Если {name} сейчас работает, закрой его и запусти заново."
            );
            let answer = unsafe {
                MessageBoxW(
                    self.hwnd,
                    wide(&text).as_ptr(),
                    wide("Через какое подключение вести").as_ptr(),
                    MB_OKCANCEL | MB_ICONQUESTION,
                )
            };
            if answer != IDOK {
                return;
            }
        }
        self.catch_up_policy();
        let mut policy = self.policy.clone();
        let Some(rule) = policy.rules.iter_mut().find(|rule| rule.target == *target) else {
            // Правило убрали, пока висел вопрос.
            return;
        };
        if convert && rule.mechanism() != Mechanism::Divert {
            *rule = AppRule::tunnel_family(target.clone());
        }
        rule.vpn = vpn.clone();
        let hint = match &vpn {
            Some(vpn) => format!("{name}: через «{vpn}»…"),
            None => format!("{name}: через подключение по умолчанию…"),
        };
        self.set_hint(&hint, false);
        svc::save_policy(Target::new(self.hwnd), policy);
    }

    fn pick_ovpn(&self) -> Option<PathBuf> {
        let mut buffer = [0u16; 1024];
        let filter = win::wide_filter(&[("Конфиги OpenVPN (*.ovpn)", "*.ovpn"), ("Все файлы", "*.*")]);
        let title = wide("Конфиг OpenVPN, по которому подключаться");
        let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        dialog.hwndOwner = self.hwnd;
        dialog.lpstrFilter = filter.as_ptr();
        dialog.lpstrFile = buffer.as_mut_ptr();
        dialog.nMaxFile = buffer.len() as u32;
        dialog.lpstrTitle = title.as_ptr();
        dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
            return None;
        }
        Some(PathBuf::from(win::from_wide(&buffer)))
    }

    fn remove_app(&mut self) {
        let Some(row) = list::selected(self.list) else { return };
        let Some(rule) = self.policy.rules.get(row) else { return };
        let name = self.shown_name(&rule.target);
        let target = rule.target.clone();
        let mut policy = self.policy.clone();
        policy.rules.retain(|rule| rule.target != target);
        self.set_hint(&format!("убираю {name}…"), false);
        svc::save_policy(Target::new(self.hwnd), policy);
    }

    /// Ярлык на рабочем столе. Отсюда приложение запускается привычным
    /// щелчком — и всё равно через туннель, потому что ярлык ведёт не к
    /// самому приложению, а к нам с ключом `--run`.
    fn make_shortcut(&mut self) {
        let Some(row) = list::selected(self.list) else { return };
        let Some(rule) = self.policy.rules.get(row) else { return };
        let AppTarget::Executable(path) = rule.target.clone() else {
            return;
        };
        match crate::shortcut::create(&path) {
            Ok(created) => {
                let name = created
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                self.set_hint(&format!("ярлык «{name}» лежит на рабочем столе"), false);
            }
            Err(reason) => self.set_hint(&format!("ярлык не создан: {reason}"), true),
        }
    }

    fn run_app(&mut self) {
        // Двойной щелчок приходит сюда и тогда, когда кнопка выключена.
        if !self.can_run() {
            return;
        }
        let Some(row) = list::selected(self.list) else { return };
        let Some(rule) = self.policy.rules.get(row) else { return };
        let target = rule.target.clone();
        self.set_hint(&format!("запускаю {}…", target.display_name()), false);
        svc::launch(Target::new(self.hwnd), target);
    }

    fn pick_file(&self) -> Option<PathBuf> {
        let mut buffer = [0u16; 1024];
        let filter = win::wide_filter(&[("Программы (*.exe)", "*.exe"), ("Все файлы", "*.*")]);
        let title = wide("Какая программа должна ходить через VPN");
        let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        dialog.hwndOwner = self.hwnd;
        dialog.lpstrFilter = filter.as_ptr();
        dialog.lpstrFile = buffer.as_mut_ptr();
        dialog.nMaxFile = buffer.len() as u32;
        dialog.lpstrTitle = title.as_ptr();
        dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
            return None;
        }
        Some(PathBuf::from(win::from_wide(&buffer)))
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::TunnelChanged(tunnel) => {
                self.tunnel = tunnel;
                self.refresh_head();
                // Стоят ли запреты — знает только служба; событие о туннеле
                // этого не несёт. Ответ придёт и шапку поправит.
                svc::load_state(Target::new(self.hwnd));
            }
            Event::PolicyChanged(policy) => {
                self.policy = policy;
                self.refresh_list();
                // От списка зависит, поднят ли перехват: появилось первое
                // правило пути B — он поднялся, ушло последнее — погас.
                svc::load_state(Target::new(self.hwnd));
            }
            Event::ProcessAttached { pid, target } => {
                let image = match target {
                    AppTarget::Executable(path) => path,
                    AppTarget::Package(pfn) => PathBuf::from(pfn),
                };
                self.processes.insert(pid, (image, true));
                self.refresh_processes();
            }
            Event::ProcessUnhooked { pid, image } => {
                self.processes.insert(pid, (image, false));
                self.refresh_processes();
            }
            Event::ProcessGone { pid } => {
                if self.processes.remove(&pid).is_some() {
                    self.refresh_processes();
                }
            }
            Event::SupervisedChanged(targets) => {
                if self.supervised != targets {
                    self.supervised = targets;
                    self.refresh_list();
                }
            }
            Event::VpnChanged(vpns) => {
                if self.vpns != vpns {
                    // Имена могли смениться — а они стоят в колонке «Куда».
                    let renamed = self.vpns.len() != vpns.len()
                        || self.vpns.iter().zip(&vpns).any(|(old, new)| old.name != new.name);
                    self.vpns = vpns;
                    self.vpns_known = true;
                    self.refresh_head();
                    if renamed {
                        self.refresh_list();
                    }
                }
            }
        }
    }

    /// Процессы меняют и строки таблицы, и шапку со значком: мимо туннеля
    /// работающее приложение — такая же беда, как упавший туннель.
    fn refresh_processes(&mut self) {
        self.refresh_list();
        self.refresh_head();
    }

    fn on_link(&mut self, linked: bool) {
        self.linked = linked;
        if linked {
            self.set_hint("", false);
            svc::load_policy(Target::new(self.hwnd));
            svc::load_state(Target::new(self.hwnd));
        } else {
            self.killswitch = false;
            self.divert = false;
            self.vpns.clear();
            self.vpns_known = false;
            self.supervised.clear();
            // Что мы знали о процессах, устарело в тот же миг: без службы
            // некому сказать, что они закончились. Лучше пусто, чем ложь.
            self.processes.clear();
            self.refresh_list();
            self.set_hint("связь со службой потеряна, пробую снова", true);
        }
        self.refresh_head();
    }

    fn on_reply(&mut self, reply: Reply) {
        match reply {
            Reply::Policy(policy) => {
                self.policy = policy;
                self.refresh_list();
            }
            Reply::State(status) => {
                // Служба новее окна — значит, обновление уже поставлено и
                // файл окна подменён: пора стать новым и самому.
                self.divert_error = status.divert_error.clone();
                let done = RESTARTED_FOR.load(Ordering::Acquire);
                match restart_plan(vpnsplit_core::BUILD, status.build, done) {
                    Restart::Now => self.restart_updated(status.build),
                    Restart::Remember(build) => RESTARTED_FOR.store(build, Ordering::Release),
                    Restart::No => {}
                }
                if self.divert != status.divert_active || self.supervised != status.supervised {
                    self.divert = status.divert_active;
                    self.supervised = status.supervised;
                    // Строки правил пути B показывают именно это, поэтому
                    // список тоже надо перерисовать.
                    self.refresh_list();
                }
                if self.killswitch != status.killswitch {
                    self.killswitch = status.killswitch;
                }
                let renamed = !self.vpns_known
                    || self.vpns.len() != status.vpns.len()
                    || self.vpns.iter().zip(&status.vpns).any(|(old, new)| old.name != new.name);
                self.vpns = status.vpns;
                self.vpns_known = true;
                self.refresh_head();
                if renamed {
                    self.refresh_list();
                }
            }
            Reply::Titles(installed) => {
                self.remember_titles(&installed);
                self.refresh_list();
            }
            Reply::VpnSet => {
                self.pending = None;
                self.set_hint(
                    "конфиг принят — служба подключается сама, пока подключение нужно \
                     приложениям из списка",
                    false,
                );
                svc::load_state(Target::new(self.hwnd));
            }
            Reply::VpnCleared => {
                self.set_hint("подключение забыто и отключено", false);
                svc::load_state(Target::new(self.hwnd));
            }
            Reply::VpnDone(text) => {
                self.set_hint(&text, false);
                svc::load_state(Target::new(self.hwnd));
            }
            Reply::VpnConnecting(name) => {
                self.set_hint(
                    &format!("«{name}» подключается с этим кодом — что вышло, строкой выше"),
                    false,
                );
                svc::load_state(Target::new(self.hwnd));
            }
            Reply::VpnRefused(reason) => {
                // Не подошёл пароль — спросить ещё раз и отправить тот же
                // конфиг: выбирать файл заново ради опечатки незачем.
                let retry = self.pending.take().filter(|_| reason.starts_with(WRONG_PASSWORD));
                match retry {
                    Some(mut order) => match self.ask_key_password(true) {
                        Some(password) => {
                            order.key_password = Some(password);
                            self.pending = Some(order.clone());
                            self.set_hint("проверяю конфиг самим OpenVPN — секунду…", false);
                            svc::set_vpn(Target::new(self.hwnd), order);
                        }
                        None => self.set_hint("конфиг не принят: пароль ключа не подошёл", true),
                    },
                    None => {
                        self.set_hint("конфиг не принят", true);
                        win::error_box(self.hwnd, &format!("Служба конфиг не приняла: {reason}."));
                    }
                }
            }
            Reply::Saved => {
                self.set_hint("список сохранён", false);
                // Ответ «сохранено» приходит, когда служба уже привела
                // перехват в согласие со списком. Событие о смене списка
                // приходит раньше, и состояние, спрошенное по нему, успевало
                // устареть: окно показывало «перехват не поднят» при
                // работающем перехвате. Спрашиваем ещё раз — теперь по
                // делу.
                svc::load_state(Target::new(self.hwnd));
            }
            Reply::Launched(name) => {
                self.set_hint(&format!("{name} запущен — его трафик идёт через туннель"), false)
            }
            Reply::Failed(text) => self.set_hint(&text, true),
        }
    }

    /// Запускает себя заново — уже из обновлённого файла — и уходит. Если
    /// окно было спрятано, новое тоже останется значком.
    /// `build` — сборка службы: новое окно узнает по ней, что на эту сборку
    /// перезапуск уже был.
    fn restart_updated(&mut self, build: u64) {
        let Ok(exe) = std::env::current_exe() else { return };
        let mut fresh = std::process::Command::new(exe);
        fresh.arg("--after-update").arg(build.to_string());
        if unsafe { IsWindowVisible(self.hwnd) } == 0 {
            fresh.arg(crate::autostart::TRAY_FLAG);
        }
        // Сборка запоминается только после удачного запуска: не вышло —
        // попробуем на следующем ответе службы.
        if fresh.spawn().is_ok() {
            RESTARTED_FOR.store(build, Ordering::Release);
            // Выход — тем же путём, что «Выход» в меню значка: окно
            // уничтожится, когда этот обработчик вернётся.
            self.leaving = true;
        }
    }

    /// Освобождение ровно того, что создали мы. Системная кисть окна —
    /// не наша, её удалять нельзя.
    fn destroy(&mut self) {
        self.tray.remove();
        unsafe {
            if !self.win_icon.is_null() {
                DestroyIcon(self.win_icon);
                self.win_icon = std::ptr::null_mut();
            }
            if !self.font.is_null() {
                DeleteObject(self.font as _);
                self.font = std::ptr::null_mut();
            }
            if !self.font_head.is_null() {
                DeleteObject(self.font_head as _);
                self.font_head = std::ptr::null_mut();
            }
        }
    }
}

/// Короткая строка для подсказки в трее: szTip обрезается, длинный текст там
/// не нужен.
fn short(status: &str) -> String {
    match status.split_once(':') {
        Some((head, _)) => head.to_lowercase(),
        None => status.to_lowercase(),
    }
}

/// Что написать в строке правила «приложение и все его потомки».
///
/// Четыре ответа, и важна граница между двумя последними. Поднятый
/// перехват сам по себе значит только «готов вести»: ведётся ли приложение,
/// видно по тому, есть ли под правилом процессы. Когда их нет, окно не
/// знает почему — приложение не запущено, запущено раньше правила или
/// значок лишь разбудил уже открытый экземпляр, — и поэтому не пишет «не
/// запущено», чего утверждать не может. Зато действие во всех трёх случаях
/// одно: запустить заново.
fn divert_state(linked: bool, divert: bool, supervised: bool) -> &'static str {
    match (linked, divert, supervised) {
        (false, _, _) => "неизвестно",
        (true, false, _) => "ПЕРЕХВАТ НЕ ПОДНЯТ",
        (true, true, true) => "идёт через VPN",
        (true, true, false) => "не ведётся — запустите заново",
    }
}

/// Запущенные процессы приложений-пакетов: имя программы и семейство пакета.
///
/// Части самой Windows — меню «Пуск», поиск, панель ввода — тоже пакеты и
/// работают всегда. В меню выбора они только заслоняли бы то, что человек
/// открыл сам, поэтому пропускается всё, что лежит под `%SystemRoot%`, и
/// всё, что подписано самой Windows. Одной папки мало: поиск Windows при
/// первой же живой проверке оказался в меню строкой «msedgewebview2.exe —
/// Microsoft.Windows.Search», потому что рисует себя чужой программой из
/// `Program Files`.
fn running_packages() -> Vec<(String, String)> {
    let system = std::env::var_os("SystemRoot").map(PathBuf::from);
    let mut found = Vec::new();
    for (pid, name) in vpnsplit_net::proc::list() {
        let Some(family) = vpnsplit_net::proc::package_family(pid) else { continue };
        if part_of_windows(&family) {
            continue;
        }
        if let (Some(root), Some(image)) = (&system, vpnsplit_net::proc::image_path(pid)) {
            if under(root, &image) {
                continue;
            }
        }
        found.push((name, family));
    }
    found
}

/// Пакет из состава самой Windows. Имя семейства кончается знаком издателя,
/// и у встроенных частей системы он один — `cw5n1h2txyewy`. У приложений
/// Microsoft из Store (Терминал, Калькулятор, winget) издатель другой,
/// `8wekyb3d8bbwe`, и они остаются в меню.
fn part_of_windows(family: &str) -> bool {
    family.to_lowercase().ends_with("_cw5n1h2txyewy")
}

/// Лежит ли файл под этой папкой. Регистр не важен, а вот граница имени
/// важна: `C:\Windows2` — не под `C:\Windows`.
fn under(root: &Path, image: &Path) -> bool {
    let root = root.to_string_lossy().to_lowercase();
    let image = image.to_string_lossy().to_lowercase();
    image
        .strip_prefix(root.trim_end_matches('\\'))
        .is_some_and(|rest| rest.starts_with('\\'))
}

/// Названия пакетов для человека: семейство (в нижнем регистре) → как оно
/// называется в меню «Пуск». У пакета с несколькими приложениями — все
/// названия через запятую: «Почта, Календарь».
fn package_titles(installed: &[(String, String)]) -> HashMap<String, String> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut names: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for (title, family) in installed {
        let title = title.trim();
        if !title.is_empty() {
            names.entry(family.to_lowercase()).or_default().insert(title);
        }
    }
    names
        .into_iter()
        .map(|(family, titles)| (family, titles.into_iter().collect::<Vec<_>>().join(", ")))
        .collect()
}

/// Что предложить в меню «Из Store…»: подпись строки и семейство пакета.
///
/// Пакет — одна строка, сколько бы приложений и процессов у него ни было:
/// правило пишется на пакет, и выбирать внутри него нечего. Подпись —
/// название из меню «Пуск»; у запущенного пакета без значка в «Пуске» —
/// имя его программы и семейство. Одинаково названные пакеты различаются
/// семейством в подписи. Пакеты, которые уже в списке, и части самой
/// Windows не предлагаются.
fn store_choices(
    installed: &[(String, String)],
    running: &[(String, String)],
    listed: &[AppTarget],
) -> Vec<(String, String)> {
    use std::collections::{BTreeMap, BTreeSet};
    let taken: Vec<String> = listed.iter().map(AppTarget::key).collect();
    let offered = |family: &str| {
        !part_of_windows(family) && !taken.contains(&AppTarget::Package(family.to_owned()).key())
    };
    let titles = package_titles(installed);

    // Семейство в нижнем регистре → как оно написано и чем подписать.
    let mut packages: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (_, family) in installed {
        let key = family.to_lowercase();
        if let (true, Some(title)) = (offered(family), titles.get(&key)) {
            packages.entry(key).or_insert_with(|| (family.clone(), title.clone()));
        }
    }
    // Запущенное, чего в «Пуске» нет: имя семейства взять больше неоткуда.
    let mut programs: BTreeMap<String, (String, BTreeSet<&str>)> = BTreeMap::new();
    for (name, family) in running {
        let key = family.to_lowercase();
        if offered(family) && !packages.contains_key(&key) {
            programs.entry(key).or_insert_with(|| (family.clone(), BTreeSet::new())).1.insert(name);
        }
    }
    for (key, (family, names)) in programs {
        let first = names.iter().next().copied().unwrap_or_default();
        let label = match names.len() {
            0 | 1 => format!("{first} — {family}"),
            more => format!("{first} и ещё {} — {family}", more - 1),
        };
        packages.insert(key, (family, label));
    }

    let mut counts: HashMap<String, usize> = HashMap::new();
    for (_, label) in packages.values() {
        *counts.entry(label.to_lowercase()).or_default() += 1;
    }
    let mut choices: Vec<(String, String)> = packages
        .into_values()
        .map(|(family, label)| {
            let twin = counts.get(&label.to_lowercase()).copied().unwrap_or(0) > 1;
            (if twin { format!("{label} — {family}") } else { label }, family)
        })
        .collect();
    choices.sort_by_key(|(label, _)| label.to_lowercase());
    choices.truncate(STORE_MENU_LIMIT);
    choices
}

/// О чём спросить, прежде чем отдать конфиг службе: куда подключаемся, что
/// это значит и что из файла не сработает.
///
/// `foreign` — туннель сейчас держит другая программа.
///
/// `replacing` — подключение с таким именем уже есть, и конфиг его заменит.
fn vpn_question(config: &ovpn::Config, name: &str, replacing: bool, foreign: bool) -> String {
    let mut text = format!(
        "Подключаться к {} самой программой? Подключение будет называться «{name}».\n\n\
         Служба vpnsplit будет держать его сама: с запуска Windows, пока оно нужно хоть \
         одному приложению из списка, и поднимать заново после обрыва. Отдельный VPN-клиент \
         для этого не нужен.\n\n\
         В туннель пойдут только приложения из списка — те, которым это подключение выбрано \
         кнопкой «Куда…», а первое из подключений ещё и те, которым не выбрано никакое. \
         Маршруты и DNS, которые сервер велит поставить всей машине, не применяются: \
         внутренние адреса и имена сервера получат только приложения этого подключения.",
        config.remote
    );
    if replacing {
        text.push_str(&format!(
            "\n\nПодключение «{name}» уже есть: его конфиг и пароли будут заменены этими."
        ));
    }
    if !config.dropped.is_empty() {
        text.push_str("\n\nИз конфига не сработает:");
        for line in &config.dropped {
            text.push_str(&format!("\n    {line}"));
        }
    }
    if foreign {
        text.push_str(
            "\n\nСейчас туннель держит другая программа. Свои подключения начнутся, когда \
             она отключится: два подключения с одним сертификатом выбивали бы друг друга.",
        );
    }
    if config.needs_password {
        text.push_str(
            "\n\nЗакрытый ключ в конфиге защищён паролем — следующим шагом программа его \
             спросит и сохранит у службы: иначе подключаться при запуске Windows было бы \
             некому.",
        );
    }
    if config.needs_login {
        text.push_str(
            "\n\nСервер спрашивает логин и пароль — программа их спросит и сохранит у службы. \
             Проверить их заранее нечем: подойдут ли, скажет сервер при подключении.",
        );
    }
    if config.needs_code {
        text.push_str(
            "\n\nК паролю сервер ждёт одноразовый код, каждый раз новый. Поэтому это \
             подключение само не поднимается: его подключаешь ты — «VPN…» → «Подключить…» — \
             и после обрыва или перезагрузки тоже. Пока оно не поднято, приложения, которым \
             оно назначено, наружу не ходят.",
        );
    }
    text
}

/// Строка подключения в меню «VPN…»: имя и что с ним, коротко.
fn vpn_title(vpn: &VpnState, default: bool) -> String {
    let state = match (vpn.connected, vpn.off, vpn.by_code) {
        (_, true, _) => "отключено",
        (true, ..) => "подключено",
        (false, false, true) => "ждёт кода или подключается",
        (false, false, false) => "не подключено",
    };
    let default = if default { ", по умолчанию" } else { "" };
    format!("{}  —  {state}{default}", menu_text(&vpn.name))
}

/// Сколько знаков подсказки показываем: около четырёх строк в самом узком
/// окне.
const HINT_LIMIT: usize = 420;

/// Текст не длиннее предела; обрезанный кончается многоточием.
fn clipped(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut short: String = text.chars().take(limit.saturating_sub(1)).collect();
    short.push('…');
    short
}

/// Имя подключения в строке меню: `&` там — подчёркивание следующей буквы.
fn menu_text(name: &str) -> String {
    name.replace('&', "&&")
}

/// Одно ли это имя подключения. Регистр не различается — как у службы.
fn same_name(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

/// Что в колонке «Куда» у правила.
fn where_to(rule: &AppRule, vpns: &[VpnState], known: bool) -> String {
    match (rule.routing, &rule.vpn) {
        (Routing::Direct, _) => "напрямую".to_owned(),
        (Routing::Tunnel, None) => "в VPN".to_owned(),
        // Пока служба не рассказала о подключениях, судить не о чем.
        (Routing::Tunnel, Some(name))
            if !known || vpns.iter().any(|vpn| same_name(&vpn.name, name)) =>
        {
            name.clone()
        }
        (Routing::Tunnel, Some(name)) => format!("{name} — нет такого"),
    }
}

/// Строка о своих подключениях под состоянием туннеля.
fn vpn_lines(vpns: &[VpnState]) -> String {
    match vpns {
        [] => String::new(),
        [only] => format!("Своё подключение «{}»: {}", only.name, only.line),
        many => {
            let mut lines = vec!["Свои подключения:".to_owned()];
            // Первое — то, куда идут приложения без выбранного подключения.
            lines.extend(many.iter().enumerate().map(|(at, vpn)| {
                let default = if at == 0 { " (по умолчанию)" } else { "" };
                format!("    «{}»{default}: {}", vpn.name, vpn.line)
            }));
            lines.join("\r\n")
        }
    }
}

/// Сообщение, которым проводник извещает все окна, что панель задач
/// создана заново: значки в трее надо ставить снова.
fn taskbar_created() -> u32 {
    static NUMBER: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *NUMBER.get_or_init(|| unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) })
}

fn shell_of(hwnd: HWND) -> *const Shell {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Shell }
}

/// Поднять окно из трея. `App` для этого не нужен.
fn show_window(hwnd: HWND) {
    unsafe {
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
    }
}

/// Щелчок по значку в трее.
fn tray_click(hwnd: HWND, mouse: u32) {
    match mouse {
        WM_RBUTTONUP => tray::menu(hwnd),
        WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_window(hwnd),
        _ => {}
    }
}

/// Сообщения, которым нужен `App`. Остальные разбираются без него, и
/// прежде всего `DefWindowProcW`: перетаскивание и растягивание окна — его
/// собственный модальный цикл, и держи мы на это время `App`, все WM_SIZE
/// и перерисовки таблицы внутри него стали бы «вложенными».
fn needs_app(message: u32) -> bool {
    message == taskbar_created()
        || matches!(
            message,
            WM_CREATE
                | WM_SIZE
                | WM_DPICHANGED
                | WM_COMMAND
                | WM_NOTIFY
                | svc::WM_EVENT
                | svc::WM_LINK
                | svc::WM_REPLY
        )
}

pub unsafe extern "system" fn wndproc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = lparam as *const CREATESTRUCTW;
        let shell = (*create).lpCreateParams as *const Shell;
        if !shell.is_null() {
            if let Ok(mut app) = (*shell).app.try_borrow_mut() {
                app.hwnd = hwnd;
            }
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, shell as isize);
        }
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }

    let shell = shell_of(hwnd);
    if shell.is_null() {
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
    // Shell живёт до выхода из цикла сообщений в `main`, то есть дольше
    // окна; общая ссылка на него безопасна и во вложенном вызове.
    let shell = &*shell;

    // Без App.
    match message {
        WM_CTLCOLORSTATIC => {
            let look = shell.look.get();
            if look.back.is_null() {
                return DefWindowProcW(hwnd, message, wparam, lparam);
            }
            if shell.app.try_borrow_mut().is_err() {
                // Красим по снимку, который мог отстать от подсказки:
                // перерисуем, когда App освободится.
                shell.repaint.set(true);
            }
            let control = lparam as HWND;
            let dc = wparam as HDC;
            SetBkColor(dc, GetSysColor(COLOR_WINDOW));
            let color = if control == look.warn {
                rgb(154, 103, 0)
            } else if control == look.vpn_note {
                rgb(96, 100, 106)
            } else if control == look.hint {
                if look.hint_error {
                    rgb(192, 40, 35)
                } else {
                    rgb(96, 100, 106)
                }
            } else {
                rgb(20, 22, 26)
            };
            SetTextColor(dc, color);
            return look.back as LRESULT;
        }
        WM_GETMINMAXINFO => {
            let info = lparam as *mut MINMAXINFO;
            if !info.is_null() {
                let dpi = shell.look.get().dpi;
                (*info).ptMinTrackSize.x = scale(840, dpi);
                (*info).ptMinTrackSize.y = scale(400, dpi);
            }
            return 0;
        }
        svc::WM_TRAY => {
            tray_click(hwnd, (lparam as u32) & 0xFFFF);
            return 0;
        }
        WM_COMMAND if (wparam & 0xFFFF) as u32 == tray::ID_OPEN => {
            show_window(hwnd);
            return 0;
        }
        WM_CLOSE => {
            // Крестик прячет окно, а программа остаётся значком в области
            // уведомлений: по значку окно и открывают. Раньше закрытие окна
            // было выходом — значок пропадал, и вернуть окно можно было
            // только запустив программу заново (замечено пользователем
            // 23.11.2026). Выход — пунктом «Выход» в меню значка.
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }
        WM_DESTROY => {
            // App здесь не освобождается: WM_DESTROY приходит изнутри
            // DestroyWindow, то есть пока обработчик, который его позвал,
            // ещё на стеке. Освобождает всё `main`, когда цикл кончится.
            shell.gone.set(true);
            PostQuitMessage(0);
            return 0;
        }
        _ => {}
    }
    if !needs_app(message) {
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }

    if message == WM_DPICHANGED {
        // Оба пути двигают окно по предложенному прямоугольнику, а
        // SetWindowPos тут же спрашивает WM_GETMINMAXINFO — наименьший
        // размер должен быть уже для нового DPI, иначе окно, переехавшее на
        // монитор с меньшим масштабом, упрётся в старый минимум.
        let mut look = shell.look.get();
        look.dpi = (wparam & 0xFFFF) as u32;
        shell.look.set(look);
    }
    let Ok(mut app) = shell.app.try_borrow_mut() else {
        return while_busy(shell, hwnd, message, wparam, lparam);
    };
    // Списки правил, запомненные во время прошлых обработчиков, уже
    // разобраны из очереди в `settle`; новому обработчику они только
    // подсунули бы старое.
    shell.newest_policy.borrow_mut().take();
    let result = app.handle(hwnd, message, wparam, lparam);
    drop(app);
    shell.settle();
    result
}

/// Сообщение пришло, пока `App` занят внешним обработчиком (он открыл
/// модальное окно или послал сообщение сам себе). Ничего из `App` здесь
/// не трогается: что нужно сделать — откладывается до `Shell::settle`.
unsafe fn while_busy(
    shell: &Shell,
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == taskbar_created() {
        shell.taskbar.set(true);
        return 0;
    }
    match message {
        WM_SIZE => shell.relayout.set(true),
        WM_DPICHANGED => {
            shell.dpi.set(Some((wparam & 0xFFFF) as u32));
            move_to_suggested(hwnd, lparam);
        }
        // Кнопки, пока открыто модальное окно, не нажать: окно выключено.
        // Откладывать стоит только выход — иначе «Выход» из меню значка во
        // время вопроса потерялся бы.
        WM_COMMAND if (wparam & 0xFFFF) as u32 == tray::ID_EXIT => shell.postpone(Later::Exit),
        WM_NOTIFY => {
            let header = lparam as *const NMHDR;
            if header.is_null() || (*header).hwndFrom != shell.look.get().list {
                return 0;
            }
            match (*header).code {
                LVN_ITEMCHANGED_CODE => shell.buttons.set(true),
                NM_CUSTOMDRAW_CODE => {
                    // Строку рисуем как есть, а красим потом — по состоянию.
                    shell.repaint.set(true);
                    return CDRF_DODEFAULT as LRESULT;
                }
                // Двойной щелчок во время вопроса ничего не запускает.
                _ => {}
            }
        }
        svc::WM_EVENT => {
            if let Some(event) = svc::take::<Event>(lparam) {
                if let Event::PolicyChanged(policy) = &*event {
                    *shell.newest_policy.borrow_mut() = Some(policy.clone());
                }
                shell.postpone(Later::Event(event));
            }
        }
        svc::WM_LINK => shell.postpone(Later::Link(wparam != 0)),
        svc::WM_REPLY => {
            if let Some(reply) = svc::take::<Reply>(lparam) {
                if let Reply::Policy(policy) = &*reply {
                    *shell.newest_policy.borrow_mut() = Some(policy.clone());
                }
                shell.postpone(Later::Reply(reply));
            }
        }
        _ => {}
    }
    0
}

/// WM_DPICHANGED: Windows предлагает новый прямоугольник окна.
unsafe fn move_to_suggested(hwnd: HWND, lparam: LPARAM) {
    let suggested = lparam as *const RECT;
    if !suggested.is_null() {
        let r = &*suggested;
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

impl App {
    /// Сообщения, которым нужен `App` (`needs_app`), — на верхнем уровне.
    unsafe fn handle(&mut self, hwnd: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // Номер этого сообщения Windows выдаёт по имени, в `match` его не
        // поставить.
        if message == taskbar_created() {
            self.on_taskbar_created();
            return 0;
        }
        match message {
            WM_CREATE => {
                self.build();
                0
            }
            WM_SIZE => {
                self.layout();
                0
            }
            WM_DPICHANGED => {
                self.dpi = (wparam & 0xFFFF) as u32;
                self.make_fonts();
                move_to_suggested(hwnd, lparam);
                self.layout();
                0
            }
            WM_COMMAND => {
                self.on_command((wparam & 0xFFFF) as u32);
                0
            }
            WM_NOTIFY => {
                let header = lparam as *const NMHDR;
                if header.is_null() || (*header).hwndFrom != self.list {
                    return 0;
                }
                match (*header).code {
                    NM_DBLCLK_CODE => self.run_app(),
                    LVN_ITEMCHANGED_CODE => self.update_buttons(),
                    NM_CUSTOMDRAW_CODE => return self.paint_row(lparam as *mut NMLVCUSTOMDRAW),
                    _ => {}
                }
                0
            }
            svc::WM_EVENT => {
                if let Some(event) = svc::take::<Event>(lparam) {
                    self.on_event(*event);
                }
                0
            }
            svc::WM_LINK => {
                self.on_link(wparam != 0);
                0
            }
            svc::WM_REPLY => {
                if let Some(reply) = svc::take::<Reply>(lparam) {
                    self.on_reply(*reply);
                }
                0
            }
            _ => DefWindowProcW(hwnd, message, wparam, lparam),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        divert_state, restart_plan, short, store_choices, under, Restart, RESTARTED_FOR_UNKNOWN,
    };
    use std::path::Path;
    use vpnsplit_core::AppTarget;

    #[test]
    fn a_newer_service_restarts_the_window() {
        assert_eq!(restart_plan(10, 11, 0), Restart::Now);
        assert_eq!(restart_plan(10, 10, 0), Restart::No);
        assert_eq!(restart_plan(10, 9, 0), Restart::No);
    }

    #[test]
    fn the_same_build_does_not_restart_twice_but_the_next_one_does() {
        // Окно перезапустилось на 11, а файл почему-то остался 10: по кругу
        // не ходим.
        assert_eq!(restart_plan(10, 11, 11), Restart::No);
        // Пришла 12 — перезапуск снова нужен: раньше флаг «уже было» жил
        // до конца процесса и его не пускал.
        assert_eq!(restart_plan(11, 12, 11), Restart::Now);
    }

    #[test]
    fn a_window_built_without_a_number_never_restarts() {
        assert_eq!(restart_plan(0, 11, 0), Restart::No);
    }

    #[test]
    fn an_unknown_restart_remembers_the_first_seen_build() {
        assert_eq!(restart_plan(10, 11, RESTARTED_FOR_UNKNOWN), Restart::Remember(11));
    }

    fn running(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(name, family)| (name.to_string(), family.to_string())).collect()
    }

    #[test]
    fn a_package_is_one_line_however_many_processes_it_has() {
        let choices = store_choices(
            &[],
            &running(&[
                ("WindowsTerminal.exe", "Microsoft.WindowsTerminal_8wekyb3d8bbwe"),
                ("OpenConsole.exe", "Microsoft.WindowsTerminal_8wekyb3d8bbwe"),
                ("OpenConsole.exe", "Microsoft.WindowsTerminal_8wekyb3d8bbwe"),
                ("Calculator.exe", "Microsoft.WindowsCalculator_8wekyb3d8bbwe"),
            ]),
            &[],
        );
        assert_eq!(choices.len(), 2, "{choices:?}");
        // По подписи, то есть по имени программы: его человек и ищет глазами.
        assert_eq!(choices[0].1, "Microsoft.WindowsCalculator_8wekyb3d8bbwe");
        assert_eq!(choices[0].0, "Calculator.exe — Microsoft.WindowsCalculator_8wekyb3d8bbwe");
        assert_eq!(
            choices[1].0,
            "OpenConsole.exe и ещё 1 — Microsoft.WindowsTerminal_8wekyb3d8bbwe"
        );
    }

    #[test]
    fn what_is_already_listed_is_not_offered_again() {
        let listed = [AppTarget::Package("microsoft.windowscalculator_8WEKYB3D8BBWE".into())];
        let calculator = running(&[("Calculator.exe", "Microsoft.WindowsCalculator_8wekyb3d8bbwe")]);
        assert!(store_choices(&[], &calculator, &listed).is_empty());
        // И установленное — тоже, запущено оно или нет.
        let installed = running(&[("Калькулятор", "Microsoft.WindowsCalculator_8wekyb3d8bbwe")]);
        assert!(store_choices(&installed, &calculator, &listed).is_empty());
        assert!(store_choices(&installed, &[], &listed).is_empty());
    }

    #[test]
    fn anything_installed_can_be_chosen_without_being_started() {
        // Ровно то, о чём просили: приложение не запущено, а в меню есть —
        // и под названием из «Пуска», а не под именем пакета.
        let installed = running(&[
            ("ChatGPT", "OpenAI.Codex_2p2nqsd0c76g0"),
            ("Claude", "Claude_pzs8sxrjxfjjc"),
            ("Параметры", "windows.immersivecontrolpanel_cw5n1h2txyewy"),
        ]);
        let choices = store_choices(&installed, &[], &[]);
        assert_eq!(
            choices,
            running(&[("ChatGPT", "OpenAI.Codex_2p2nqsd0c76g0"), ("Claude", "Claude_pzs8sxrjxfjjc")]),
            "части самой Windows не предлагаются"
        );
        // Запущенное приложение не становится второй строкой и не теряет
        // названия.
        let open = running(&[("ChatGPT.exe", "OpenAI.Codex_2p2nqsd0c76g0"), ("codex.exe", "openai.codex_2P2NQSD0C76G0")]);
        assert_eq!(store_choices(&installed, &open, &[]), choices);
        // А запущенный пакет без значка в «Пуске» — строкой с именем
        // программы, как раньше.
        let hidden = running(&[("helper.exe", "Some.Background_abcdefghjkmnp")]);
        let both = store_choices(&installed, &hidden, &[]);
        assert_eq!(both.len(), 3);
        assert!(both.iter().any(|(label, _)| label == "helper.exe — Some.Background_abcdefghjkmnp"));
    }

    #[test]
    fn a_package_with_several_apps_is_one_line_and_twins_are_told_apart() {
        let installed = running(&[
            ("Почта", "microsoft.windowscommunicationsapps_8wekyb3d8bbwe"),
            ("Календарь", "microsoft.windowscommunicationsapps_8wekyb3d8bbwe"),
            ("Terminal", "Microsoft.WindowsTerminal_8wekyb3d8bbwe"),
            ("Terminal", "Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe"),
        ]);
        let choices = store_choices(&installed, &[], &[]);
        assert_eq!(choices.len(), 3, "{choices:?}");
        assert_eq!(choices[0].0, "Terminal — Microsoft.WindowsTerminal_8wekyb3d8bbwe");
        assert_eq!(choices[1].0, "Terminal — Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe");
        assert_eq!(choices[2].0, "Календарь, Почта");
        // Те же названия идут в таблицу.
        let titles = super::package_titles(&installed);
        assert_eq!(
            titles.get("microsoft.windowscommunicationsapps_8wekyb3d8bbwe").map(String::as_str),
            Some("Календарь, Почта")
        );
    }

    #[test]
    fn the_question_about_a_config_says_what_will_not_work() {
        let keys = "<ca>\nA\n</ca>\n<cert>\nB\n</cert>\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nC\n</key>\n";
        let config = vpnsplit_core::ovpn::sanitize(&format!(
            "client\nremote vpn.example 3333\nredirect-gateway def1\n{keys}"
        ))
        .unwrap();
        let text = super::vpn_question(&config, "Работа", true, true);
        assert!(text.contains("vpn.example:3333 (udp)"), "{text}");
        assert!(text.contains("«Работа»") && text.contains("будут заменены"), "{text}");
        assert!(!text.contains("логин"), "{text}");
        assert!(text.contains("redirect-gateway def1"), "{text}");
        assert!(text.contains("другая программа"), "{text}");
        assert!(text.contains("паролем"), "{text}");
        // Самого ключа в вопросе нет и быть не может.
        assert!(!text.contains("BEGIN"), "{text}");
        let plain = vpnsplit_core::ovpn::sanitize(
            "client\nremote vpn.example 3333\n<ca>\nA\n</ca>\n<cert>\nB\n</cert>\n<key>\nC\n</key>\n",
        )
        .unwrap();
        let text = super::vpn_question(&plain, "Дом", false, false);
        assert!(!text.contains("не сработает") && !text.contains("паролем"), "{text}");
        assert!(!text.contains("другая программа") && !text.contains("заменены"), "{text}");
        // Вход по логину: о нём сказано, и о том, чего программа не умеет.
        let login = vpnsplit_core::ovpn::sanitize(
            "client\nremote vpn.example 3333\nauth-user-pass\n<ca>\nA\n</ca>\n",
        )
        .unwrap();
        let text = super::vpn_question(&login, "Работа", false, false);
        assert!(text.contains("логин и пароль") && !text.contains("одноразовый код"), "{text}");
        // С одноразовым кодом — честно: само не поднимется.
        let coded = vpnsplit_core::ovpn::sanitize(
            "client\nremote vpn.example 3333\nauth-user-pass\nstatic-challenge \"OTP\" 1\n<ca>\nA\n</ca>\n",
        )
        .unwrap();
        let text = super::vpn_question(&coded, "Работа", false, false);
        assert!(text.contains("одноразовый код") && text.contains("само не поднимается"), "{text}");
    }

    #[test]
    fn the_where_column_names_the_connection() {
        use vpnsplit_core::{AppRule, Routing, VpnState};
        let vpn = |name: &str| VpnState {
            name: name.to_owned(),
            line: "s:1 (udp) — подключено".to_owned(),
            connected: true,
            address: None,
            by_code: false,
            off: false,
            login: false,
        };
        let vpns = [vpn("Зарубежный"), vpn("Работа")];
        let mut rule = AppRule::tunnel_family(AppTarget::Package("chat".to_owned()));
        assert_eq!(super::where_to(&rule, &vpns, true), "в VPN");
        rule.vpn = Some("работа".to_owned());
        assert_eq!(super::where_to(&rule, &vpns, true), "работа");
        rule.vpn = Some("Старое".to_owned());
        assert_eq!(super::where_to(&rule, &vpns, true), "Старое — нет такого");
        // Пока служба о подключениях не рассказала, зря не пугаем.
        assert_eq!(super::where_to(&rule, &[], false), "Старое");
        rule.routing = Routing::Direct;
        assert_eq!(super::where_to(&rule, &vpns, true), "напрямую");
        // Одно подключение — одной строкой, несколько — списком.
        assert_eq!(super::vpn_lines(&[]), "");
        assert_eq!(
            super::vpn_lines(&vpns[..1]),
            "Своё подключение «Зарубежный»: s:1 (udp) — подключено"
        );
        let both = super::vpn_lines(&vpns);
        assert_eq!(both.lines().count(), 3, "{both}");
        assert!(both.contains("«Работа»"), "{both}");
        assert_eq!(super::menu_text("R&D"), "R&&D");
        // Длинная подсказка обрезается по знакам, а не по байтам.
        assert_eq!(super::clipped("короткая", 20), "короткая");
        let long = super::clipped(&"я".repeat(500), super::HINT_LIMIT);
        assert_eq!(long.chars().count(), super::HINT_LIMIT);
        assert!(long.ends_with('…'));
        assert!(both.contains("«Зарубежный» (по умолчанию)"), "{both}");
        // В меню — имя и состояние; «отключено» важнее всего остального.
        assert_eq!(super::vpn_title(&vpns[0], true), "Зарубежный  —  подключено, по умолчанию");
        let mut off = vpns[1].clone();
        off.off = true;
        assert_eq!(super::vpn_title(&off, false), "Работа  —  отключено");
        off.off = false;
        off.connected = false;
        off.by_code = true;
        assert!(super::vpn_title(&off, false).contains("ждёт кода"));
    }

    #[test]
    fn windows_own_packages_are_told_from_store_apps() {
        assert!(super::part_of_windows("Microsoft.Windows.Search_cw5n1h2txyewy"));
        assert!(super::part_of_windows("MicrosoftWindows.Client.CBS_CW5N1H2TXYEWY"));
        assert!(!super::part_of_windows("Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"));
        assert!(!super::part_of_windows("Claude_pzs8sxrjxfjjc"));
    }

    #[test]
    fn nothing_installed_and_nothing_running_offers_nothing() {
        assert!(store_choices(&[], &[], &[]).is_empty());
    }

    #[test]
    fn a_folder_is_told_by_its_whole_name_and_without_case() {
        let root = Path::new(r"C:\WINDOWS");
        assert!(under(root, Path::new(r"C:\Windows\SystemApps\X_cw5n1h2txyewy\SearchHost.exe")));
        assert!(under(Path::new(r"C:\Windows\"), Path::new(r"c:\windows\explorer.exe")));
        assert!(!under(root, Path::new(r"C:\Windows2\app.exe")));
        assert!(!under(root, Path::new(r"C:\Program Files\WindowsApps\A_1\a.exe")));
    }

    #[test]
    fn a_raised_intercept_alone_is_not_called_working() {
        // Ровно та ложь, из-за которой утечку с запускателем не заметили:
        // перехват поднят, под правилом никого, а в строке — «ведётся».
        let idle = divert_state(true, true, false);
        assert!(idle.starts_with("не ведётся"), "{idle}");
        assert_eq!(divert_state(true, true, true), "идёт через VPN");
        assert_ne!(idle, divert_state(true, true, true));
    }

    #[test]
    fn without_the_intercept_nothing_else_matters() {
        // Устаревшее «под правилом кто-то есть» не должно перекрыть
        // главное: перехвата нет.
        assert_eq!(divert_state(true, false, true), "ПЕРЕХВАТ НЕ ПОДНЯТ");
        assert_eq!(divert_state(true, false, false), "ПЕРЕХВАТ НЕ ПОДНЯТ");
    }

    #[test]
    fn without_the_service_nothing_is_claimed() {
        for divert in [false, true] {
            for supervised in [false, true] {
                assert_eq!(divert_state(false, divert, supervised), "неизвестно");
            }
        }
    }

    #[test]
    fn tip_keeps_only_the_head_of_the_status() {
        assert_eq!(short("Туннель поднят: «TAP», 10.5.5.2"), "туннель поднят");
    }

    #[test]
    fn status_without_colon_goes_whole() {
        assert_eq!(short("Туннель не поднят"), "туннель не поднят");
    }
}

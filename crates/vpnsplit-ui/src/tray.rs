//! Значок в трее. Он — индикатор, а не способ спрятать программу: окно
//! закрыли — процесса нет (критерий Этапа 6), поэтому «свернуть в трей»
//! здесь сознательно отсутствует.

use crate::icon::{self, Dot};
use crate::win::wide;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyIcon, DestroyMenu, GetCursorPos, GetSystemMetrics,
    SetForegroundWindow, TrackPopupMenu, HICON, MF_SEPARATOR, MF_STRING, SM_CXSMICON,
    TPM_BOTTOMALIGN, TPM_RIGHTBUTTON,
};

pub const ID_OPEN: u32 = 2001;
pub const ID_EXIT: u32 = 2002;

const ICON_ID: u32 = 1;

pub struct Tray {
    hwnd: HWND,
    icon: HICON,
    size: i32,
    added: bool,
}

impl Tray {
    pub fn new(hwnd: HWND) -> Self {
        let size = unsafe { GetSystemMetrics(SM_CXSMICON) }.max(16);
        Tray { hwnd, icon: std::ptr::null_mut(), size, added: false }
    }

    /// Поставить или обновить значок. Подсказка — короткая строка: Windows
    /// обрезает её по 127 знакам, поэтому полное описание живёт в окне.
    pub fn show(&mut self, kind: Dot, tip: &str) {
        let fresh = icon::dot(kind, self.size);
        let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.hwnd;
        data.uID = ICON_ID;
        data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        data.uCallbackMessage = crate::svc::WM_TRAY;
        data.hIcon = fresh;

        let text = wide(tip);
        let take = fit(&text, data.szTip.len());
        data.szTip[..take].copy_from_slice(&text[..take]);

        let action = if self.added { NIM_MODIFY } else { NIM_ADD };
        let ok = unsafe { Shell_NotifyIconW(action, &data) != 0 };
        if ok {
            self.added = true;
        }
        // Старый значок освобождается только после того, как Windows взяла
        // новый: до этого он ещё нарисован в трее.
        if !self.icon.is_null() {
            unsafe { DestroyIcon(self.icon) };
        }
        self.icon = fresh;
    }

    /// Проводник перезапустился: значка в трее больше нет, хотя мы его не
    /// снимали. Следующий `show` поставит его заново, а не станет менять
    /// несуществующий.
    pub fn lost(&mut self) {
        self.added = false;
    }

    pub fn remove(&mut self) {
        if self.added {
            let mut data: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
            data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            data.hWnd = self.hwnd;
            data.uID = ICON_ID;
            unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
            self.added = false;
        }
        if !self.icon.is_null() {
            unsafe { DestroyIcon(self.icon) };
            self.icon = std::ptr::null_mut();
        }
    }
}

/// Меню значка. `SetForegroundWindow` перед показом — иначе меню не закроется
/// по щелчку мимо него: известная особенность трея.
pub fn menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        AppendMenuW(menu, MF_STRING, ID_OPEN as usize, wide("Открыть окно").as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, ID_EXIT as usize, wide("Выход").as_ptr());

        let mut point = std::mem::zeroed();
        GetCursorPos(&mut point);
        SetForegroundWindow(hwnd);
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
            point.x,
            point.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        DestroyMenu(menu);
    }
}

/// Сколько символов подсказки влезет в `szTip`. На входе строка уже с нулём
/// на конце; место под этот ноль в буфере остаётся всегда, иначе Windows
/// прочитает за границу массива.
fn fit(text: &[u16], capacity: usize) -> usize {
    text.len().min(capacity).saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::fit;
    use crate::win::wide;

    #[test]
    fn short_tip_fits_whole() {
        let text = wide("туннель поднят");
        assert_eq!(fit(&text, 128), "туннель поднят".chars().count());
    }

    #[test]
    fn empty_tip_copies_nothing() {
        assert_eq!(fit(&wide(""), 128), 0);
    }

    #[test]
    fn long_tip_leaves_room_for_the_final_zero() {
        let text = wide(&"я".repeat(500));
        assert_eq!(fit(&text, 128), 127);
    }
}

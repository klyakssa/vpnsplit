//! Мелкие обёртки над Win32: строки, шрифт, масштаб по DPI, окно сообщения.

use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{HWND, ERROR_ALREADY_EXISTS, GetLastError};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DEFAULT_CHARSET, DEFAULT_QUALITY, FF_DONTCARE, FW_NORMAL, FW_SEMIBOLD, HFONT,
    OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_PITCH,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, SendMessageW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, WM_SETFONT,
};

/// Строка для Win32: UTF-16 с нулём на конце.
pub fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Обратно из буфера, который заполнила Windows: до первого нуля.
pub fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// Фильтр для диалога открытия файла: пары «описание\0маска\0», в конце ещё ноль.
pub fn wide_filter(pairs: &[(&str, &str)]) -> Vec<u16> {
    let mut out = Vec::new();
    for (label, mask) in pairs {
        out.extend(std::ffi::OsStr::new(label).encode_wide());
        out.push(0);
        out.extend(std::ffi::OsStr::new(mask).encode_wide());
        out.push(0);
    }
    out.push(0);
    out
}

pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    // COLORREF — это 0x00BBGGRR, порядок обратный привычному HTML.
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

/// DPI окна. Ноль Windows возвращает для ещё не созданного окна — тогда 96.
pub fn dpi_of(hwnd: HWND) -> u32 {
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    if dpi == 0 {
        96
    } else {
        dpi
    }
}

/// Размер в «логических» пикселях → в настоящие при текущем DPI.
pub fn scale(value: i32, dpi: u32) -> i32 {
    value * dpi as i32 / 96
}

/// Системный шрифт интерфейса. Segoe UI есть во всех поддерживаемых Windows.
pub fn ui_font(dpi: u32, points: i32, semibold: bool) -> HFONT {
    let height = -(points * dpi as i32 / 72);
    let weight = if semibold { FW_SEMIBOLD } else { FW_NORMAL };
    unsafe {
        CreateFontW(
            height,
            0,
            0,
            0,
            weight as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_TT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            DEFAULT_QUALITY as u32,
            (DEFAULT_PITCH | FF_DONTCARE) as u32,
            wide("Segoe UI").as_ptr(),
        )
    }
}

pub fn set_font(hwnd: HWND, font: HFONT) {
    unsafe { SendMessageW(hwnd, WM_SETFONT, font as usize, 1) };
}

pub fn error_box(parent: HWND, text: &str) {
    unsafe {
        MessageBoxW(
            parent,
            wide(text).as_ptr(),
            wide("vpnsplit").as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

pub fn info_box(parent: HWND, text: &str) {
    unsafe {
        MessageBoxW(
            parent,
            wide(text).as_ptr(),
            wide("vpnsplit").as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

/// Правда — мы первый экземпляр. Два окна с двумя значками в трее не нужны,
/// а мьютекс сеанса пользователя исчезает сам вместе с процессом.
pub fn first_instance() -> bool {
    let handle = unsafe { CreateMutexW(std::ptr::null(), 1, wide("Local\\vpnsplit-ui").as_ptr()) };
    if handle.is_null() {
        return true; // Не смогли проверить — лучше запуститься, чем промолчать.
    }
    let code = unsafe { GetLastError() };
    code != ERROR_ALREADY_EXISTS
}

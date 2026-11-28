//! Значок — цветная точка, нарисованная в памяти. Файла .ico в проекте нет
//! намеренно: цвет значка и есть состояние туннеля, а значит он меняется
//! на ходу, и заготовка в ресурсах всё равно не подошла бы.

use windows_sys::Win32::Graphics::Gdi::{
    CreateBitmap, CreateDIBSection, DeleteObject, GetDC, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER,
    HBITMAP, RGBQUAD,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, HICON, ICONINFO};

/// Цвет точки. Это состояние, которое пользователь видит, не открывая окна.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dot {
    /// Туннель поднят, раздельное туннелирование работает.
    Up,
    /// Туннель поднят, но тянет на себя весь трафик системы.
    Captures,
    /// Туннеля нет.
    Down,
    /// Служба не отвечает — мы вообще ничего не знаем.
    NoService,
}

impl Dot {
    const fn color(self) -> (u8, u8, u8) {
        match self {
            Dot::Up => (46, 160, 67),
            Dot::Captures => (210, 153, 34),
            Dot::Down => (110, 118, 129),
            Dot::NoService => (218, 54, 51),
        }
    }
}

/// Значок `size`×`size` с точкой нужного цвета. Вызывающий обязан отдать его
/// в `DestroyIcon`.
pub fn dot(kind: Dot, size: i32) -> HICON {
    let (r, g, b) = kind.color();
    let pixels = (size * size) as usize;

    let mut info: BITMAPINFO = unsafe { std::mem::zeroed() };
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: size,
        // Минус — строки сверху вниз, как их удобно писать.
        biHeight: -size,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: 0, // BI_RGB
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    info.bmiColors = [RGBQUAD { rgbBlue: 0, rgbGreen: 0, rgbRed: 0, rgbReserved: 0 }];

    let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
    let (color, mask) = unsafe {
        let dc = GetDC(std::ptr::null_mut());
        let color = CreateDIBSection(dc, &info, 0, &mut bits, std::ptr::null_mut(), 0);
        ReleaseDC(std::ptr::null_mut(), dc);
        // Маска при 32 битах не используется — прозрачность берётся из альфы,
        // но структура значка её всё равно требует.
        let mask: HBITMAP = CreateBitmap(size, size, 1, 1, std::ptr::null());
        (color, mask)
    };
    if color.is_null() || bits.is_null() || mask.is_null() {
        // Что успело создаться, удаляется и здесь: значок рисуется при каждой
        // смене состояния, и на нехватке GDI каждая неудача теряла бы ещё
        // растр, приближая отказ всего остального.
        unsafe {
            if !color.is_null() {
                DeleteObject(color as _);
            }
            if !mask.is_null() {
                DeleteObject(mask as _);
            }
        }
        return std::ptr::null_mut();
    }

    // Круг с мягким краем: четыре подвыборки на пиксель по каждой оси.
    let center = size as f32 / 2.0;
    let radius = center - size as f32 / 16.0 - 0.5;
    let buffer = unsafe { std::slice::from_raw_parts_mut(bits as *mut u32, pixels) };
    for y in 0..size {
        for x in 0..size {
            let mut covered = 0u32;
            for sy in 0..4 {
                for sx in 0..4 {
                    let px = x as f32 + (sx as f32 + 0.5) / 4.0 - center;
                    let py = y as f32 + (sy as f32 + 0.5) / 4.0 - center;
                    if px * px + py * py <= radius * radius {
                        covered += 1;
                    }
                }
            }
            let alpha = covered * 255 / 16;
            buffer[(y * size + x) as usize] =
                (alpha << 24) | ((r as u32) << 16) | ((g as u32) << 8) | b as u32;
        }
    }

    let icon_info = ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask,
        hbmColor: color,
    };
    let icon = unsafe { CreateIconIndirect(&icon_info) };
    // CreateIconIndirect делает свои копии — наши растры больше не нужны.
    unsafe {
        DeleteObject(color as _);
        DeleteObject(mask as _);
    }
    icon
}

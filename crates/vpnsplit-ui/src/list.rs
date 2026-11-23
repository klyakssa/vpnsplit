//! Таблица приложений — системный SysListView32 в режиме отчёта.

use crate::win::wide;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    LVCFMT_LEFT, LVCF_SUBITEM, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_STATE, LVIF_TEXT, LVITEMW,
    LVM_DELETEALLITEMS, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW,
    LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMSTATE, LVM_SETITEMW,
    LVNI_SELECTED, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_EX_LABELTIP, LVS_REPORT,
    LVS_SHOWSELALWAYS, LVS_SINGLESEL,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, SendMessageW, WS_BORDER, WS_CHILD, WS_TABSTOP, WS_VISIBLE,
};

pub fn create(parent: HWND, id: u32) -> HWND {
    let list = unsafe {
        CreateWindowExW(
            0,
            wide("SysListView32").as_ptr(),
            std::ptr::null(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | LVS_REPORT | LVS_SINGLESEL
                | LVS_SHOWSELALWAYS,
            0,
            0,
            0,
            0,
            parent,
            id as usize as _,
            GetModuleHandleW(std::ptr::null()) as _,
            std::ptr::null(),
        )
    };
    if list.is_null() {
        return list;
    }
    unsafe {
        SendMessageW(
            list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            0,
            (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize,
        )
    };
    list
}

pub fn add_column(list: HWND, index: i32, title: &str, width: i32) {
    let mut text = wide(title);
    let mut column: LVCOLUMNW = unsafe { std::mem::zeroed() };
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.fmt = LVCFMT_LEFT;
    column.cx = width;
    column.pszText = text.as_mut_ptr();
    column.iSubItem = index;
    unsafe { SendMessageW(list, LVM_INSERTCOLUMNW, index as usize, &column as *const _ as isize) };
}

pub fn set_column_width(list: HWND, index: i32, width: i32) {
    unsafe { SendMessageW(list, LVM_SETCOLUMNWIDTH, index as usize, width as isize) };
}

pub fn clear(list: HWND) {
    unsafe { SendMessageW(list, LVM_DELETEALLITEMS, 0, 0) };
}

/// Добавить строку. Первая ячейка — сам элемент, остальные — подэлементы.
pub fn push(list: HWND, row: i32, cells: &[String]) {
    for (column, cell) in cells.iter().enumerate() {
        let mut text = wide(cell);
        let mut item: LVITEMW = unsafe { std::mem::zeroed() };
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.iSubItem = column as i32;
        item.pszText = text.as_mut_ptr();
        let message = if column == 0 { LVM_INSERTITEMW } else { LVM_SETITEMW };
        unsafe { SendMessageW(list, message, 0, &item as *const _ as isize) };
    }
}

pub fn selected(list: HWND) -> Option<usize> {
    let index = unsafe {
        SendMessageW(list, LVM_GETNEXTITEM, (-1isize) as usize, LVNI_SELECTED as isize)
    };
    if index < 0 {
        None
    } else {
        Some(index as usize)
    }
}

/// Выделить строку — чтобы после правки списка выделение не терялось.
pub fn select(list: HWND, row: usize) {
    const LVIS_SELECTED: u32 = 0x0002;
    const LVIS_FOCUSED: u32 = 0x0001;
    let mut item: LVITEMW = unsafe { std::mem::zeroed() };
    item.mask = LVIF_STATE;
    item.state = LVIS_SELECTED | LVIS_FOCUSED;
    item.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    unsafe { SendMessageW(list, LVM_SETITEMSTATE, row, &item as *const _ as isize) };
}

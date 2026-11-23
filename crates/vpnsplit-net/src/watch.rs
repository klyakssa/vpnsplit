//! Слежение за сетью без опросов.
//!
//! Windows сама вызывает наш обработчик, когда меняется любой интерфейс
//! (поднялся, упал, сменил параметры) или любой адрес на нём. Между
//! событиями ни один наш поток не просыпается — бюджет CPU в простое ноль.
//!
//! Подписок три: интерфейсы, адреса и маршруты. При переподключении OpenVPN
//! интерфейс TAP может остаться тем же, а поменяется только адрес — или
//! наоборот. А маршруты `0.0.0.0/1` и `128.0.0.0/1` может добавить кто
//! угодно в любой момент, не трогая ни интерфейс, ни адрес.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

type Callback = Box<dyn Fn() + Send + Sync>;

/// Подписка на изменения сети. Пока объект жив, обработчик вызывается;
/// при уничтожении подписки снимаются.
pub struct Watcher {
    interface: HANDLE,
    address: HANDLE,
    route: HANDLE,
    // Двойной Box: Windows получает тонкий указатель на внешний Box.
    context: *mut Callback,
}

// Хэндлы подписок и контекст безопасно передавать между потоками:
// сам обработчик Send + Sync, а хэндлы — просто числа для CancelMibChangeNotify2.
unsafe impl Send for Watcher {}

impl Watcher {
    pub fn start(on_change: impl Fn() + Send + Sync + 'static) -> Result<Self, String> {
        let context: *mut Callback = Box::into_raw(Box::new(Box::new(on_change)));
        let mut interface: HANDLE = std::ptr::null_mut();
        let mut address: HANDLE = std::ptr::null_mut();

        let status = unsafe {
            NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), context as *const c_void, 0, &mut interface)
        };
        if status != 0 {
            unsafe { drop(Box::from_raw(context)) };
            return Err(format!("NotifyIpInterfaceChange вернул {status}"));
        }
        let status = unsafe {
            NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), context as *const c_void, 0, &mut address)
        };
        if status != 0 {
            unsafe {
                CancelMibChangeNotify2(interface);
                drop(Box::from_raw(context));
            }
            return Err(format!("NotifyUnicastIpAddressChange вернул {status}"));
        }
        let mut route: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            NotifyRouteChange2(AF_UNSPEC, Some(on_route), context as *const c_void, 0, &mut route)
        };
        if status != 0 {
            unsafe {
                CancelMibChangeNotify2(interface);
                CancelMibChangeNotify2(address);
                drop(Box::from_raw(context));
            }
            return Err(format!("NotifyRouteChange2 вернул {status}"));
        }
        Ok(Watcher { interface, address, route, context })
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // CancelMibChangeNotify2 дожидается завершения уже идущих обработчиков,
        // поэтому после неё контекст освобождать безопасно.
        unsafe {
            CancelMibChangeNotify2(self.interface);
            CancelMibChangeNotify2(self.address);
            CancelMibChangeNotify2(self.route);
            drop(Box::from_raw(self.context));
        }
    }
}

fn fire(context: *const c_void) {
    if context.is_null() {
        return;
    }
    let callback = unsafe { &*(context as *const Callback) };
    // Паника в обработчике не должна уронить процесс — это системный поток.
    let _ = catch_unwind(AssertUnwindSafe(callback));
}

unsafe extern "system" fn on_interface(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    fire(context);
}

unsafe extern "system" fn on_address(
    context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    fire(context);
}

unsafe extern "system" fn on_route(
    context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    fire(context);
}

//! Обвязка диспетчера служб Windows: запуск под SCM, установка, удаление.

use crate::daemon;
use crate::store::Store;
use std::ffi::{OsStr, OsString};
use std::sync::mpsc;
use std::time::Duration;
use vpnsplit_core::SERVICE_NAME;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

const DISPLAY_NAME: &str = "vpnsplit — раздельное туннелирование";
const DESCRIPTION: &str = "Направляет выбранные приложения через VPN, остальной трафик идёт напрямую.";

/// Сколько `uninstall` ждёт остановки службы: с запасом сверх тех 20 с,
/// что она сама просит на остановку (столько же ждёт и установщик).
const STOP_PATIENCE: Duration = Duration::from_secs(45);

define_windows_service!(ffi_service_main, service_main);

/// Точка входа, когда процесс запустил диспетчер служб.
pub fn run_dispatcher() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("диспетчер служб не принял процесс: {e}. Эту команду запускает Windows, не человек"))
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        if let Ok(store) = Store::for_service() {
            store.log(&format!("служба остановлена с ошибкой: {e}"));
        }
    }
}

fn run_service() -> Result<(), String> {
    let (stop_tx, stop_rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler).map_err(|e| e.to_string())?;
    let report = |state: ServiceState, accept: ServiceControlAccept, code: u32| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
    };

    let result = (|| {
        let store = Store::for_service()?;
        let daemon = daemon::start(store)?;
        // Служба, установленная до того, как это появилось, настроена без
        // возврата после падения — поэтому настройка проверяется при каждом
        // запуске, а не только при установке.
        match ensure_recovery() {
            Ok(()) => daemon.log("после падения Windows запустит службу снова через секунду"),
            Err(e) => daemon.log(&format!(
                "возврат после падения НЕ настроен ({e}): упавшая служба сама не поднимется, и \
                 приложения из списка останутся без сети до её запуска руками"
            )),
        }
        report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0)
            .map_err(|e| e.to_string())?;
        // Главный поток службы спит до команды остановки.
        let _ = stop_rx.recv();
        daemon.log("остановка по команде");
        // Остановка теперь не мгновенная: своё подключение опускается
        // по-хорошему, и OpenVPN на это даётся несколько секунд. Windows
        // должна знать, что мы не зависли, а уходим.
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(20),
            process_id: None,
        });
        drop(daemon);
        Ok::<(), String>(())
    })();

    let code = if result.is_ok() { 0 } else { 1 };
    let _ = report(ServiceState::Stopped, ServiceControlAccept::empty(), code);
    result
}

/// Велит Windows запускать службу заново, если её процесс исчез, не
/// доложив об остановке.
///
/// Без этого падение службы — тупик именно из-за того, что сделано для
/// защиты: постоянные запреты закрывают приложениям из списка сеть, пока
/// службы нет, а вернуть её некому. Первые два раза — через секунду,
/// дальше — через пять; последнее действие Windows повторяет при каждом
/// следующем сбое, так что служба, падающая сразу после запуска, будет
/// подниматься раз в пять секунд, пока её не остановят. Это выбрано
/// сознательно: без службы приложения из списка без сети, и сдаться здесь
/// значило бы оставить их так насовсем. Счёт сбоев сбрасывается через час.
pub fn ensure_recovery() -> Result<(), String> {
    use windows_service::service::{
        ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("нет доступа к диспетчеру служб: {e}"))?;
    // START нужен не нам: Windows требует его у того, кто назначает
    // действие «запустить заново».
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| format!("служба не открылась для настройки: {e}"))?;
    let restart = |seconds| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(seconds),
    };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart(1), restart(1), restart(5)]),
        })
        .map_err(|e| format!("действия при сбое не записались: {e}"))
}

pub fn install() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| admin_hint(format!("нет доступа к диспетчеру служб: {e}")))?;
    let exe = std::env::current_exe().map_err(|e| format!("не удалось определить свой путь: {e}"))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| admin_hint(format!("не удалось создать службу: {e}")))?;
    let _ = service.set_description(DESCRIPTION);
    if let Err(e) = ensure_recovery() {
        println!("  возврат после падения не настроен: {e}");
    }
    service.start(&[] as &[&OsStr]).map_err(|e| format!("служба создана, но не запустилась: {e}"))?;
    println!("служба «{SERVICE_NAME}» установлена и запущена");
    println!("  исполняемый файл: {}", exe.display());
    println!("  данные и журнал:  %ProgramData%\\vpnsplit");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| admin_hint(format!("нет доступа к диспетчеру служб: {e}")))?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        .map_err(|e| admin_hint(format!("служба не найдена или нет прав: {e}")))?;
    // Ждём настоящей остановки: служба на остановке опускает своё
    // подключение по-хорошему и просит на это до 20 с. Снять запреты под
    // ещё живой службой — значит дать ей поставить их заново, а удалённая
    // она их уже не снимет.
    let mut stopped = true;
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            let deadline = std::time::Instant::now() + STOP_PATIENCE;
            stopped = loop {
                match service.query_status() {
                    Ok(s) if s.current_state == ServiceState::Stopped => break true,
                    _ if std::time::Instant::now() >= deadline => break false,
                    _ => std::thread::sleep(Duration::from_millis(200)),
                }
            };
        }
    }
    service.delete().map_err(|e| format!("не удалось удалить службу: {e}"))?;
    if !stopped {
        println!(
            "ВНИМАНИЕ: служба не остановилась за {} с; Windows удалит её, когда она остановится.\n  \
             Если после этого у приложений из списка не будет интернета — выполни\n  \
             vpnsplit-svc unblock из окна администратора.",
            STOP_PATIENCE.as_secs()
        );
    }
    println!("служба «{SERVICE_NAME}» удалена. Данные в %ProgramData%\\vpnsplit оставлены.");
    // Постоянные запреты службу переживают — в этом их смысл. Но удалённая
    // служба уже не вернётся и не перекроет их своими разрешениями, так
    // что оставить их значило бы отрезать приложения из списка от сети
    // навсегда. Не получилось снять — сказать об этом и назвать команду.
    match unblock() {
        Ok(apps) => println!("запреты на время простоя сняты с приложений: {apps}"),
        Err(e) => println!(
            "ВНИМАНИЕ: запреты на время простоя снять не удалось ({e}).\n  \
             Приложения из списка останутся без интернета, пока не выполнить\n  \
             vpnsplit-svc unblock из окна администратора."
        ),
    }
    Ok(())
}

/// Снимает все постоянные запреты vpnsplit. Работает без службы — это и
/// есть аварийный выход на случай, когда служба сломана или удалена.
pub fn unblock() -> Result<usize, String> {
    vpnsplit_net::wfp::Standing::open()
        .map_err(|e| admin_hint(format!("движок фильтрации не открылся: {e}")))?
        .clear()
}

fn admin_hint(message: String) -> String {
    format!("{message}\n  установка и удаление службы требуют PowerShell, запущенного от имени администратора")
}

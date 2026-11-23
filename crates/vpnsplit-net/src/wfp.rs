//! Kill-switch: пока туннеля нет, приложениям из списка закрыта сеть.
//!
//! Зачем это нужно, если хук и так отказывает сокету. Хук стоит только в
//! тех процессах, которые запустил лончер. Приложение из списка, запущенное
//! мимо него (Этап 7 такие показывает красным), никаких хуков не имеет — и
//! при упавшем туннеле спокойно пойдёт через домашний интернет. Фильтр
//! Windows Filtering Platform действует на процесс независимо от того, как
//! его запустили.
//!
//! Сеанс kill-switch объявлен динамическим: его фильтры живут ровно столько,
//! сколько открыт хэндл.
//!
//! **А вот простой самой службы закрыт иначе** (решение пользователя от
//! 22.11.2026: приложение без сети лучше, чем приложение мимо VPN). Пока
//! служба остановлена или упала, некому ни ставить хуки, ни переписывать
//! пакеты, и приложения из списка ходили домашним адресом. Теперь на каждое
//! из них стоит **постоянный** запрет ([`Standing`]), который службу
//! переживает, а работающая служба кладёт поверх него динамическое
//! разрешение ([`Guard::permit_alive`]). Умерла служба — разрешение исчезло
//! вместе с её сеансом, запрет остался. Запрет не снимается и не ставится
//! на остановке: момент, когда служба умирает, она сама может и не застать.
//!
//! Прежний размен («сломанная программа не должна отрезать интернет
//! насовсем») остаётся в силе для всего, кроме приложений из списка:
//! постоянные фильтры названы поимённо, по одному приложению, и снимаются
//! командой `vpnsplit-svc unblock` без участия службы.
//!
//! Только IPv4: на этой машине IPv6 не маршрутизируется (решение из раздела
//! «не сейчас»), а блокировать его значило бы заодно отрезать `::1`.

use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER_UNIVERSAL, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
    FWP_FILTER_ENUM_FULLY_CONTAINED, FWP_MATCH_EQUAL, FWP_UINT8, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// Веса фильтров, от слабого к сильному. Внутри одного подслоя решает
/// самый тяжёлый из подошедших, и весь замысел держится на этом порядке:
///
/// | вес | фильтр | чей | смысл |
/// |-----|--------|-----|-------|
/// | 2 | запрет приложению | постоянный | службы нет — сети нет |
/// | 4 | разрешение на локальную сеть | постоянный | …кроме своей сети |
/// | 6 | разрешение приложению | динамический | служба жива и ведёт его сама |
/// | 8 | запрет приложению | динамический | туннель упал (kill-switch) |
/// | 12 | разрешение на локальную сеть | динамический | …кроме своей сети |
///
/// Служба умерла — два динамических слоя исчезли, остались нижние два.
const WEIGHT_STANDING_BLOCK: u8 = 2;
const WEIGHT_STANDING_LOCAL: u8 = 4;
const WEIGHT_ALIVE: u8 = 6;
const WEIGHT_BLOCK: u8 = 8;
const WEIGHT_PERMIT: u8 = 12;

/// {6B1F5A0E-3C2D-4E7A-9B41-76707E53504C} — поставщик vpnsplit. По нему
/// постоянные фильтры отличаются от чужих: снимать можно только свои, и
/// узнавать их по названию было бы гаданием.
const PROVIDER: GUID = GUID {
    data1: 0x6B1F_5A0E,
    data2: 0x3C2D,
    data3: 0x4E7A,
    data4: [0x9B, 0x41, 0x76, 0x70, 0x7E, 0x53, 0x50, 0x4C],
};

/// FWP_E_ALREADY_EXISTS — поставщик уже заведён прошлым запуском.
const ALREADY_EXISTS: u32 = 0x8032_0009;

/// Сколько постоянных фильтров приходится на одно приложение: запрет и по
/// разрешению на каждую локальную сеть. Неполный набор считается
/// испорченным и ставится заново.
const FILTERS_PER_APP: usize = 1 + LOCAL.len();

/// Куда приложению можно ходить даже при упавшем туннеле: к себе, к роутеру,
/// к принтеру, к NAS. Это та же граница, что и в хуке, — иначе получилось бы,
/// что при живом туннеле локальная сеть доступна, а при упавшем нет.
const LOCAL: [(Ipv4Addr, u32); 5] = [
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
];

fn wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Имя приложения, под которым его знают фильтры: путь со сложенным
/// регистром. По нему же постоянные фильтры находят «своё» приложение.
fn app_key(exe: &Path) -> String {
    exe.to_string_lossy().to_lowercase()
}

fn short_name(exe: &Path) -> String {
    exe.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| exe.to_string_lossy().into_owned())
}

/// Опознавательный знак приложения в WFP. Освобождается сам.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    /// Файл должен существовать: Windows открывает его, чтобы узнать путь в
    /// записи ядра. Нет файла — нет и знака, и запретить нечего.
    fn of(exe: &Path) -> Result<AppId, String> {
        let path = wide(&exe.to_string_lossy());
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let code = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob) };
        if code != 0 || blob.is_null() {
            return Err(format!("не удалось опознать {}: {}", exe.display(), describe(code)));
        }
        Ok(AppId(blob))
    }

    fn condition(&self) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: self.0 },
            },
        }
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0(&mut self.0 as *mut *mut FWP_BYTE_BLOB as *mut *mut std::ffi::c_void)
        };
    }
}

/// Локальные сети в том виде, в каком их ждёт WFP: адрес в хостовом порядке
/// байт, а не в сетевом.
fn local_masks() -> Vec<FWP_V4_ADDR_AND_MASK> {
    LOCAL
        .iter()
        .map(|(network, bits)| FWP_V4_ADDR_AND_MASK {
            addr: u32::from_be_bytes(network.octets()),
            mask: u32::MAX << (32 - bits),
        })
        .collect()
}

/// Постоянный ли фильтр и чьё приложение он касается. У постоянного в
/// описании записан путь приложения — по нему набор фильтров потом
/// находится и снимается.
#[derive(Clone, Copy)]
enum Life<'a> {
    Dynamic,
    Persistent { app: &'a str },
}

/// Один фильтр на слое исходящих соединений IPv4.
///
/// # Safety
/// `engine` — открытый хэндл движка; указатели в `conditions` живы до
/// возврата.
unsafe fn add_filter(
    engine: HANDLE,
    conditions: &[FWPM_FILTER_CONDITION0],
    action: u32,
    weight: u8,
    title: &str,
    life: Life,
) -> Result<u64, String> {
    // Фильтр без условий подошёл бы ко всему трафику машины. Ни одному
    // нашему фильтру это не нужно, а запрет такого рода отрезал бы от сети
    // всё разом — в том числе связь, по которой его можно было бы снять.
    if conditions.is_empty() {
        return Err("фильтр без условий не ставится: он касался бы всей машины".to_owned());
    }
    let mut title = wide(title);
    let mut filter: FWPM_FILTER0 = std::mem::zeroed();
    filter.displayData.name = title.as_mut_ptr();
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight = FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: weight },
    };
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0;
    filter.action = FWPM_ACTION0 {
        r#type: action,
        Anonymous: std::mem::zeroed(),
    };
    let mut provider = PROVIDER;
    let mut description;
    if let Life::Persistent { app } = life {
        description = wide(app);
        filter.displayData.description = description.as_mut_ptr();
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        filter.providerKey = &mut provider;
    }

    let mut id = 0u64;
    let code = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut id);
    if code != 0 {
        return Err(format!("фильтр не добавлен: {}", describe(code)));
    }
    Ok(id)
}

/// Запрет приложению и разрешения на локальную сеть поверх него.
///
/// # Safety
/// `engine` — открытый хэндл движка.
unsafe fn add_block_set(
    engine: HANDLE,
    app: &AppId,
    block: (u8, &str),
    local: (u8, &str),
    life: Life,
) -> Result<Vec<u64>, String> {
    let by_app = app.condition();
    let mut added = vec![add_filter(engine, &[by_app], FWP_ACTION_BLOCK, block.0, block.1, life)?];
    let mut masks = local_masks();
    for mask in masks.iter_mut() {
        let by_address = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: mask },
            },
        };
        added.push(add_filter(
            engine,
            &[by_app, by_address],
            FWP_ACTION_PERMIT,
            local.0,
            local.1,
            life,
        )?);
    }
    Ok(added)
}

fn open_engine(dynamic: bool) -> Result<HANDLE, String> {
    let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    if dynamic {
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    }
    let mut engine: HANDLE = std::ptr::null_mut();
    let code = unsafe {
        FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut engine)
    };
    if code != 0 {
        return Err(describe(code));
    }
    Ok(engine)
}

/// Открытый движок фильтрации и всё, что мы в него добавили на время жизни
/// службы: запреты kill-switch и разрешения «служба жива».
pub struct Guard {
    engine: HANDLE,
    /// Запреты kill-switch и их разрешения на локальную сеть.
    filters: Vec<u64>,
    /// Разрешения «служба жива»: приложение → номер фильтра.
    alive: Vec<(String, u64)>,
}

// Хэндл движка — обычное число; работа с ним идёт под общим замком службы.
unsafe impl Send for Guard {}

impl Guard {
    /// Требует прав администратора. Служба работает под SYSTEM, а вот
    /// консольный режим движок не откроет — и это не повод падать.
    pub fn open() -> Result<Guard, String> {
        Ok(Guard { engine: open_engine(true)?, filters: Vec::new(), alive: Vec::new() })
    }

    pub fn blocked(&self) -> usize {
        self.filters.len()
    }

    /// Запрещает приложению сеть, кроме локальной.
    pub fn block(&mut self, exe: &Path) -> Result<(), String> {
        let app = AppId::of(exe)?;
        let name = short_name(exe);
        let added = unsafe {
            add_block_set(
                self.engine,
                &app,
                (WEIGHT_BLOCK, &format!("vpnsplit: {name} без туннеля")),
                (WEIGHT_PERMIT, &format!("vpnsplit: {name} в локальную сеть")),
                Life::Dynamic,
            )?
        };
        self.filters.extend(added);
        Ok(())
    }

    /// Снимает запреты kill-switch. Чужие фильтры не трогает: удаляем
    /// только то, что сами добавили, по сохранённым номерам. Разрешения
    /// «служба жива» остаются — они не про туннель.
    pub fn clear(&mut self) {
        for id in self.filters.drain(..) {
            unsafe { FwpmFilterDeleteById0(self.engine, id) };
        }
    }

    /// Разрешение «служба жива»: перевешивает постоянный запрет, пока этот
    /// сеанс открыт. Возвращает `false`, если разрешение уже стояло.
    ///
    /// Ставить его надо **раньше** постоянного запрета: иначе у работающего
    /// приложения между двумя шагами оказался бы один запрет, и Windows,
    /// перепроверяя живые соединения, оборвала бы их.
    pub fn permit_alive(&mut self, exe: &Path) -> Result<bool, String> {
        let key = app_key(exe);
        if self.alive.iter().any(|(known, _)| *known == key) {
            return Ok(false);
        }
        let app = AppId::of(exe)?;
        let id = unsafe {
            add_filter(
                self.engine,
                &[app.condition()],
                FWP_ACTION_PERMIT,
                WEIGHT_ALIVE,
                &format!("vpnsplit: {} — служба работает", short_name(exe)),
                Life::Dynamic,
            )?
        };
        self.alive.push((key, id));
        Ok(true)
    }

    /// Снимает разрешения с тех, кого больше нет в списке. Возвращает,
    /// сколько снято.
    pub fn revoke_alive_except(&mut self, keep: &[PathBuf]) -> usize {
        let keep: Vec<String> = keep.iter().map(|exe| app_key(exe)).collect();
        let before = self.alive.len();
        let engine = self.engine;
        self.alive.retain(|(key, id)| {
            let stays = keep.contains(key);
            if !stays {
                unsafe { FwpmFilterDeleteById0(engine, *id) };
            }
            stays
        });
        before - self.alive.len()
    }

    pub fn alive(&self) -> usize {
        self.alive.len()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Сеанс динамический: с закрытием хэндла уходит всё, что в нём
        // добавлено, — и запреты kill-switch, и разрешения «служба жива».
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

/// Что изменилось при приведении постоянных запретов в согласие со списком.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Change {
    /// Приложения, получившие запрет.
    pub added: Vec<PathBuf>,
    /// Приложения, с которых запрет снят (их уже нет в списке).
    pub removed: Vec<String>,
    /// Приложения, которым запрет поставить не удалось, и почему. Чаще
    /// всего файла нет на диске: запрещать нечего, но знать об этом надо.
    pub failed: Vec<(PathBuf, String)>,
    /// Сколько приложений уже были под запретом и остались.
    pub kept: usize,
}

/// Постоянные запреты: приложениям из списка закрыта сеть (кроме локальной)
/// всегда, когда нет работающей службы, которая кладёт поверх разрешение.
///
/// Сеанс не динамический, а сами фильтры помечены постоянными: они
/// переживают и службу, и перезагрузку. Поэтому у них три свойства, каких
/// нет у остального: все они принадлежат нашему поставщику и только по
/// нему отыскиваются; каждый назван по одному приложению; и снять их все
/// можно отдельной командой, не поднимая службу.
pub struct Standing {
    engine: HANDLE,
}

unsafe impl Send for Standing {}

/// Что нужно сделать, чтобы от нынешних фильтров прийти к нужным: какие
/// снять и каким приложениям поставить набор заново.
///
/// `existing` — наши фильтры: номер и приложение из описания. Отдельно от
/// обращений к системе, чтобы проверять без прав администратора.
fn plan(existing: &[(u64, String)], desired: &[String]) -> (Vec<u64>, Vec<String>, usize) {
    let mut by_app: std::collections::BTreeMap<&str, Vec<u64>> = std::collections::BTreeMap::new();
    for (id, app) in existing {
        by_app.entry(app.as_str()).or_default().push(*id);
    }
    let mut delete = Vec::new();
    let mut kept = 0;
    for (app, ids) in &by_app {
        let wanted = desired.iter().any(|d| d == app);
        // Неполный или раздутый набор — не набор: его происхождение
        // неизвестно, и доверять ему как запрету нельзя.
        if wanted && ids.len() == FILTERS_PER_APP {
            kept += 1;
        } else {
            delete.extend(ids.iter().copied());
        }
    }
    let mut add: Vec<String> = Vec::new();
    for app in desired {
        let complete = by_app.get(app.as_str()).is_some_and(|ids| ids.len() == FILTERS_PER_APP);
        if !complete && !add.contains(app) {
            add.push(app.clone());
        }
    }
    (delete, add, kept)
}

impl Standing {
    /// Требует прав администратора.
    pub fn open() -> Result<Standing, String> {
        Ok(Standing { engine: open_engine(false)? })
    }

    /// Наши постоянные фильтры: номер и приложение, записанное в описании.
    fn ours(&self) -> Result<Vec<(u64, String)>, String> {
        let mut provider = PROVIDER;
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.providerKey = &mut provider;
        template.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        template.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        // Без условий подходят все фильтры слоя; сужает поставщик.
        template.actionMask = u32::MAX;

        let mut handle: HANDLE = std::ptr::null_mut();
        let code = unsafe { FwpmFilterCreateEnumHandle0(self.engine, &template, &mut handle) };
        if code != 0 {
            return Err(format!("перечисление фильтров не началось: {}", describe(code)));
        }
        let mut found = Vec::new();
        let mut failure = None;
        loop {
            const BATCH: u32 = 64;
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut count = 0u32;
            let code =
                unsafe { FwpmFilterEnum0(self.engine, handle, BATCH, &mut entries, &mut count) };
            if code != 0 {
                failure = Some(format!("перечисление фильтров оборвалось: {}", describe(code)));
                break;
            }
            for index in 0..count as usize {
                let filter = unsafe { &**entries.add(index) };
                // Шаблон шаблоном, а снимать чужое нельзя ни при каких
                // обстоятельствах: поставщик сверяется на каждом фильтре.
                let is_ours = !filter.providerKey.is_null()
                    && same_guid(unsafe { &*filter.providerKey }, &PROVIDER);
                if !is_ours {
                    continue;
                }
                let app = unsafe { from_wide_ptr(filter.displayData.description) };
                found.push((filter.filterId, app));
            }
            if !entries.is_null() {
                unsafe {
                    FwpmFreeMemory0(
                        &mut entries as *mut *mut *mut FWPM_FILTER0 as *mut *mut std::ffi::c_void,
                    )
                };
            }
            if count < BATCH {
                break;
            }
        }
        unsafe { FwpmFilterDestroyEnumHandle0(self.engine, handle) };
        match failure {
            Some(text) => Err(text),
            None => Ok(found),
        }
    }

    /// Приложения, на которых сейчас стоит постоянный запрет.
    pub fn apps(&self) -> Result<Vec<String>, String> {
        let mut apps: Vec<String> = self.ours()?.into_iter().map(|(_, app)| app).collect();
        apps.sort();
        apps.dedup();
        Ok(apps)
    }

    fn ensure_provider(&self) -> Result<(), String> {
        let mut name = wide("vpnsplit");
        let mut about = wide("Запреты приложениям из списка на время, пока служба vpnsplit не работает");
        let mut provider: FWPM_PROVIDER0 = unsafe { std::mem::zeroed() };
        provider.providerKey = PROVIDER;
        provider.displayData.name = name.as_mut_ptr();
        provider.displayData.description = about.as_mut_ptr();
        // Служба в поставщике намеренно не названа: с названной службой
        // Windows перестаёт применять его фильтры, когда служба отключена,
        // — а нам они нужны ровно тогда, когда службы нет.
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        let code = unsafe { FwpmProviderAdd0(self.engine, &provider, std::ptr::null_mut()) };
        if code != 0 && code != ALREADY_EXISTS {
            return Err(format!("поставщик не заведён: {}", describe(code)));
        }
        Ok(())
    }

    /// Приводит постоянные запреты в согласие со списком: снимает с тех,
    /// кого в нём больше нет, и ставит тем, кому ещё не стоит.
    ///
    /// Всё или ничего: правки идут одной транзакцией, и при сбое посреди
    /// неё прежнее состояние остаётся как было. Приложение, файла которого
    /// нет на диске, пропускается и называется в `failed` — это не сбой.
    pub fn sync(&self, apps: &[PathBuf]) -> Result<Change, String> {
        self.ensure_provider()?;
        let desired: Vec<String> = apps.iter().map(|exe| app_key(exe)).collect();
        let code = unsafe { FwpmTransactionBegin0(self.engine, 0) };
        if code != 0 {
            return Err(format!("транзакция не началась: {}", describe(code)));
        }
        let outcome = self.sync_inside(apps, &desired);
        match &outcome {
            Ok(_) => {
                let code = unsafe { FwpmTransactionCommit0(self.engine) };
                if code != 0 {
                    unsafe { FwpmTransactionAbort0(self.engine) };
                    return Err(format!("транзакция не завершилась: {}", describe(code)));
                }
            }
            Err(_) => {
                unsafe { FwpmTransactionAbort0(self.engine) };
            }
        }
        outcome
    }

    fn sync_inside(&self, apps: &[PathBuf], desired: &[String]) -> Result<Change, String> {
        // Перечисление — внутри той же транзакции: иначе между «посмотрел»
        // и «поправил» картина могла бы смениться.
        let existing = self.ours()?;
        let (delete, add, kept) = plan(&existing, desired);
        let mut change = Change { kept, ..Change::default() };
        for id in &delete {
            let code = unsafe { FwpmFilterDeleteById0(self.engine, *id) };
            if code != 0 {
                return Err(format!("фильтр {id} не снят: {}", describe(code)));
            }
        }
        let mut gone: Vec<String> = existing
            .iter()
            .filter(|(id, app)| delete.contains(id) && !desired.contains(app))
            .map(|(_, app)| app.clone())
            .collect();
        gone.sort();
        gone.dedup();
        change.removed = gone;

        for key in &add {
            let Some(exe) = apps.iter().find(|exe| app_key(exe) == *key) else { continue };
            let app = match AppId::of(exe) {
                Ok(app) => app,
                Err(e) => {
                    change.failed.push((exe.clone(), e));
                    continue;
                }
            };
            let name = short_name(exe);
            unsafe {
                add_block_set(
                    self.engine,
                    &app,
                    (WEIGHT_STANDING_BLOCK, &format!("vpnsplit: {name} без службы")),
                    (WEIGHT_STANDING_LOCAL, &format!("vpnsplit: {name} в локальную сеть без службы")),
                    Life::Persistent { app: key },
                )?;
            }
            change.added.push(exe.clone());
        }
        Ok(change)
    }

    /// Снимает все наши постоянные запреты. Это аварийный выход: служба
    /// сломана или удаляется, а приложения должны снова выйти в сеть.
    /// Возвращает, со скольких приложений запрет снят.
    pub fn clear(&self) -> Result<usize, String> {
        Ok(self.sync(&[])?.removed.len())
    }
}

impl Drop for Standing {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// Строка UTF-16 по указателю, до завершающего нуля. Пустой указатель —
/// пустая строка.
///
/// # Safety
/// Указатель либо пустой, либо ведёт на строку с завершающим нулём.
unsafe fn from_wide_ptr(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut length = 0;
    while *text.add(length) != 0 {
        length += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
}

/// Коды WFP — обычные коды Windows, но самые частые стоит назвать словами.
fn describe(code: u32) -> String {
    match code {
        5 => "отказано в доступе — нужны права администратора".to_owned(),
        0x8032_0003 => "такого фильтра нет".to_owned(),
        0x8032_0009 => "такой объект уже есть".to_owned(),
        0x8032_0016 => "несовместимое время жизни (постоянный объект из временного сеанса?)".to_owned(),
        1753 => "движок фильтрации не отвечает (служба BFE остановлена)".to_owned(),
        other => format!("код 0x{other:08X}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_cover_exactly_the_local_networks() {
        let masks: Vec<(u32, u32)> = local_masks().iter().map(|m| (m.addr, m.mask)).collect();
        // 127.0.0.0/8
        assert_eq!(masks[0], (0x7F00_0000, 0xFF00_0000));
        // 172.16.0.0/12 — ровно та граница, на которой легко ошибиться.
        assert_eq!(masks[2], (0xAC10_0000, 0xFFF0_0000));
        // 192.168.0.0/16
        assert_eq!(masks[3], (0xC0A8_0000, 0xFFFF_0000));
    }

    // Весь замысел — в порядке весов. Постоянный запрет слабее всего,
    // разрешение живой службы его перевешивает, запрет kill-switch
    // перевешивает разрешение, а локальная сеть открыта на обоих этажах.
    const _: () = assert!(WEIGHT_STANDING_BLOCK < WEIGHT_STANDING_LOCAL);
    const _: () = assert!(WEIGHT_STANDING_LOCAL < WEIGHT_ALIVE);
    const _: () = assert!(WEIGHT_ALIVE < WEIGHT_BLOCK);
    const _: () = assert!(WEIGHT_BLOCK < WEIGHT_PERMIT);
    // Вес в один байт — это номер диапазона, и диапазонов шестнадцать.
    const _: () = assert!(WEIGHT_PERMIT < 16);

    #[test]
    fn access_denied_is_explained_in_words() {
        assert!(describe(5).contains("администратора"));
        assert!(describe(0x1234).contains("0x00001234"));
    }

    fn full(app: &str, first: u64) -> Vec<(u64, String)> {
        (0..FILTERS_PER_APP as u64).map(|i| (first + i, app.to_owned())).collect()
    }

    #[test]
    fn a_complete_set_is_left_alone() {
        let existing = full("c:\\a.exe", 10);
        let (delete, add, kept) = plan(&existing, &["c:\\a.exe".to_owned()]);
        assert!(delete.is_empty() && add.is_empty());
        assert_eq!(kept, 1);
    }

    #[test]
    fn an_app_gone_from_the_list_loses_all_its_filters_and_only_they() {
        let mut existing = full("c:\\a.exe", 10);
        existing.extend(full("c:\\b.exe", 20));
        let (delete, add, kept) = plan(&existing, &["c:\\b.exe".to_owned()]);
        assert_eq!(delete, (10..10 + FILTERS_PER_APP as u64).collect::<Vec<_>>());
        assert!(add.is_empty());
        assert_eq!(kept, 1);
    }

    #[test]
    fn a_new_app_gets_a_set_and_is_asked_for_once() {
        let wanted = ["c:\\a.exe".to_owned(), "c:\\a.exe".to_owned()];
        let (delete, add, kept) = plan(&[], &wanted);
        assert!(delete.is_empty());
        assert_eq!(add, ["c:\\a.exe"]);
        assert_eq!(kept, 0);
    }

    #[test]
    fn a_broken_set_is_replaced_not_trusted() {
        // Осталось разрешение на локальную сеть без самого запрета — такой
        // «набор» выглядит как защита и не защищает.
        let mut existing = full("c:\\a.exe", 10);
        existing.remove(0);
        let (delete, add, kept) = plan(&existing, &["c:\\a.exe".to_owned()]);
        assert_eq!(delete.len(), FILTERS_PER_APP - 1);
        assert_eq!(add, ["c:\\a.exe"]);
        assert_eq!(kept, 0);
    }

    #[test]
    fn an_empty_list_clears_everything_of_ours() {
        let mut existing = full("c:\\a.exe", 10);
        existing.extend(full("c:\\b.exe", 20));
        let (delete, add, _) = plan(&existing, &[]);
        assert_eq!(delete.len(), 2 * FILTERS_PER_APP);
        assert!(add.is_empty());
    }

    #[test]
    fn a_filter_without_conditions_is_never_added() {
        // Движок здесь пустой: до обращения к нему дело дойти не должно.
        let refused = unsafe {
            add_filter(std::ptr::null_mut(), &[], FWP_ACTION_BLOCK, 2, "всё", Life::Dynamic)
        };
        assert!(refused.unwrap_err().contains("без условий"));
    }

    #[test]
    fn one_app_has_one_key_however_it_is_spelled() {
        assert_eq!(
            app_key(Path::new(r"C:\Program Files\Mozilla Firefox\firefox.exe")),
            app_key(Path::new(r"c:\program files\mozilla firefox\FIREFOX.EXE"))
        );
    }
}

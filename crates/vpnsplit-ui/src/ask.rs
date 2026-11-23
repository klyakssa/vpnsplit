//! Вопросы, на которые отвечают строкой: пароль закрытого ключа, логин с
//! паролем, имя подключения.
//!
//! У окна сообщения поля ввода нет, а заводить ради нескольких вопросов
//! файл ресурсов незачем: шаблон диалога собирается в памяти. Формат
//! шаблона старый и строгий — слова по шестнадцать бит, каждый элемент с
//! адреса, кратного четырём байтам; ошибёшься на слово — диалог просто не
//! появится, без объяснений.

use crate::win::{from_wide, wide};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DialogBoxIndirectParamW, EndDialog, GetDlgItemTextW, GetWindowLongPtrW, SetWindowLongPtrW,
    DLGTEMPLATE, GWLP_USERDATA, IDCANCEL, IDOK, WM_COMMAND, WM_INITDIALOG, WS_BORDER, WS_CAPTION,
    WS_CHILD, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

const DS_SETFONT: u32 = 0x40;
const DS_MODALFRAME: u32 = 0x80;
const DS_CENTER: u32 = 0x0800;
const ES_PASSWORD: u32 = 0x20;
const ES_AUTOHSCROLL: u32 = 0x80;
const BS_DEFPUSHBUTTON: u32 = 0x1;

/// Классы элементов в шаблоне называются числами.
const CLASS_BUTTON: u16 = 0x0080;
const CLASS_EDIT: u16 = 0x0081;
const CLASS_STATIC: u16 = 0x0082;

/// Номер первого поля ввода; остальные идут подряд.
const ID_EDIT: u16 = 100;
/// Длиннее ответов не бывает, а буфер нужен заранее.
const LIMIT: usize = 512;

/// Размеры в единицах диалога: они сами растут вместе со шрифтом и DPI.
const WIDTH: i16 = 230;
const MARGIN: i16 = 7;
const PROMPT_HEIGHT: i16 = 34;
const LABEL_HEIGHT: i16 = 9;
const EDIT_HEIGHT: i16 = 13;

/// Одно поле ввода.
#[derive(Clone, Copy)]
struct Field<'a> {
    /// Подпись над полем; пустая — поле без подписи.
    label: &'a str,
    /// Набранное не показывается.
    secret: bool,
    /// Что стоит в поле с самого начала.
    initial: &'a str,
}

fn words(text: &str) -> Vec<u16> {
    wide(text)
}

/// Один элемент шаблона. Начинается с адреса, кратного четырём байтам.
#[allow(clippy::too_many_arguments)]
fn control(out: &mut Vec<u16>, class: u16, id: u16, style: u32, x: i16, y: i16, w: i16, h: i16, text: &str) {
    if out.len() & 1 == 1 {
        out.push(0);
    }
    let style = style | WS_CHILD | WS_VISIBLE;
    out.extend([style as u16, (style >> 16) as u16, 0, 0]);
    out.extend([x as u16, y as u16, w as u16, h as u16, id]);
    out.extend([0xFFFF, class]);
    out.extend(words(text));
    // Дополнительных данных нет.
    out.push(0);
}

fn template(title: &str, prompt: &str, fields: &[Field]) -> Vec<u16> {
    let style = DS_SETFONT | DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    let inner = WIDTH - 2 * MARGIN;
    let labels = fields.iter().filter(|field| !field.label.is_empty()).count();
    let fields_height: i16 = fields
        .iter()
        .map(|field| EDIT_HEIGHT + 4 + if field.label.is_empty() { 0 } else { LABEL_HEIGHT + 1 })
        .sum();
    let buttons_y = MARGIN + PROMPT_HEIGHT + 4 + fields_height + 3;
    let height = buttons_y + 14 + MARGIN;

    let mut out = Vec::new();
    out.extend([style as u16, (style >> 16) as u16, 0, 0]);
    // Число элементов, положение (его заменит DS_CENTER) и размер.
    out.extend([(3 + fields.len() + labels) as u16, 0, 0, WIDTH as u16, height as u16]);
    // Меню нет, класс обычный.
    out.extend([0u16, 0]);
    out.extend(words(title));
    out.push(9);
    out.extend(words("Segoe UI"));

    control(&mut out, CLASS_STATIC, 0xFFFF, 0, MARGIN, MARGIN, inner, PROMPT_HEIGHT, prompt);
    // Поля — сразу за вопросом и раньше кнопок: фокус встаёт на первый
    // элемент, на котором можно остановиться, и это должно быть поле.
    let mut y = MARGIN + PROMPT_HEIGHT + 4;
    for (at, field) in fields.iter().enumerate() {
        if !field.label.is_empty() {
            control(&mut out, CLASS_STATIC, 0xFFFF, 0, MARGIN, y, inner, LABEL_HEIGHT, field.label);
            y += LABEL_HEIGHT + 1;
        }
        let secret = if field.secret { ES_PASSWORD } else { 0 };
        control(
            &mut out,
            CLASS_EDIT,
            ID_EDIT + at as u16,
            WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | secret,
            MARGIN,
            y,
            inner,
            EDIT_HEIGHT,
            field.initial,
        );
        y += EDIT_HEIGHT + 4;
    }
    let button = 50;
    control(
        &mut out,
        CLASS_BUTTON,
        IDOK as u16,
        WS_TABSTOP | BS_DEFPUSHBUTTON,
        WIDTH - MARGIN - 2 * button - 5,
        buttons_y,
        button,
        14,
        "ОК",
    );
    control(
        &mut out,
        CLASS_BUTTON,
        IDCANCEL as u16,
        WS_TABSTOP,
        WIDTH - MARGIN - button,
        buttons_y,
        button,
        14,
        "Отмена",
    );
    out
}

/// Куда диалог кладёт ответы: по строке на поле.
struct Answers {
    list: Vec<String>,
}

unsafe extern "system" fn procedure(dialog: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    match message {
        WM_INITDIALOG => {
            SetWindowLongPtrW(dialog, GWLP_USERDATA, lparam);
            // Единица — «фокус поставь сам»: он встанет на поле ввода,
            // первый элемент, на котором можно остановиться.
            1
        }
        WM_COMMAND => match (wparam & 0xFFFF) as i32 {
            IDOK => {
                let answers = GetWindowLongPtrW(dialog, GWLP_USERDATA) as *mut Answers;
                if !answers.is_null() {
                    let mut buffer = [0u16; LIMIT];
                    for (at, answer) in (*answers).list.iter_mut().enumerate() {
                        buffer.fill(0);
                        GetDlgItemTextW(dialog, ID_EDIT as i32 + at as i32, buffer.as_mut_ptr(), LIMIT as i32);
                        *answer = from_wide(&buffer);
                    }
                    // В буфере пароль: не оставлять его лежать в стеке.
                    buffer.fill(0);
                    std::hint::black_box(&buffer);
                }
                EndDialog(dialog, 1);
                1
            }
            IDCANCEL => {
                EndDialog(dialog, 0);
                1
            }
            _ => 0,
        },
        _ => 0,
    }
}

/// Показывает вопрос с полями. `None` — человек отказался отвечать.
fn ask(owner: HWND, title: &str, prompt: &str, fields: &[Field]) -> Option<Vec<String>> {
    let template = template(title, prompt, fields);
    let mut answers = Answers { list: vec![String::new(); fields.len()] };
    let outcome = unsafe {
        DialogBoxIndirectParamW(
            GetModuleHandleW(std::ptr::null()) as _,
            template.as_ptr() as *const DLGTEMPLATE,
            owner,
            Some(procedure),
            &mut answers as *mut Answers as LPARAM,
        )
    };
    (outcome == 1).then_some(answers.list)
}

/// Спрашивает пароль. `None` — человек отказался отвечать.
pub fn password(owner: HWND, title: &str, prompt: &str) -> Option<String> {
    ask(owner, title, prompt, &[Field { label: "", secret: true, initial: "" }])?.pop()
}

/// Спрашивает строку, которую видно, — с готовым ответом в поле.
pub fn text(owner: HWND, title: &str, prompt: &str, initial: &str) -> Option<String> {
    ask(owner, title, prompt, &[Field { label: "", secret: false, initial }])?.pop()
}

/// Спрашивает логин и пароль.
pub fn login(owner: HWND, title: &str, prompt: &str) -> Option<(String, String)> {
    let fields = [
        Field { label: "Логин:", secret: false, initial: "" },
        Field { label: "Пароль:", secret: true, initial: "" },
    ];
    let mut answers = ask(owner, title, prompt, &fields)?;
    let password = answers.pop()?;
    Some((answers.pop()?, password))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: [Field; 1] = [Field { label: "", secret: true, initial: "" }];
    const TWO: [Field; 2] = [
        Field { label: "Логин:", secret: false, initial: "" },
        Field { label: "Пароль:", secret: true, initial: "" },
    ];

    /// Элементы шаблона — по их приметам: `0xFFFF` и номер класса. Заодно
    /// проверяет, что каждый начинается с чётного слова.
    fn controls(out: &[u16], what: &str) -> Vec<u16> {
        let mut classes = Vec::new();
        for at in 9..out.len() - 1 {
            let class = out[at + 1];
            if out[at] == 0xFFFF && (CLASS_BUTTON..=CLASS_STATIC).contains(&class) {
                // До класса в элементе — девять слов: стиль, расширенный
                // стиль, четыре координаты и номер.
                let start = at - 9;
                assert_eq!(start % 2, 0, "элемент {} в «{what}» начинается с нечётного слова", classes.len());
                classes.push(class);
            }
        }
        classes
    }

    #[test]
    fn every_control_starts_on_a_four_byte_boundary() {
        // Нечётная длина заголовка и подписей — как раз тот случай, когда
        // выравнивание нужно; чётная — когда оно было бы лишним.
        for (title, prompt) in [("Пароль", "Введите пароль"), ("Пароль!", "x"), ("", "")] {
            assert_eq!(controls(&template(title, prompt, &ONE), title).len(), 4);
            // Вопрос, две подписи, два поля и две кнопки.
            assert_eq!(controls(&template(title, prompt, &TWO), title).len(), 7);
        }
        // И с готовым ответом в поле, чётной и нечётной длины.
        for initial in ["Работа", "Работа!"] {
            let named = [Field { label: "", secret: false, initial }];
            assert_eq!(controls(&template("Имя", "как назвать", &named), initial).len(), 4);
        }
    }

    #[test]
    fn the_header_counts_the_controls_and_carries_the_title() {
        let out = template("Пароль ключа", "вопрос", &ONE);
        assert_eq!(out[4], 4);
        let title = words("Пароль ключа");
        assert_eq!(&out[11..11 + title.len()], &title[..]);
        // Сразу за заголовком — размер шрифта.
        assert_eq!(out[11 + title.len()], 9);
        assert_eq!(template("Вход", "вопрос", &TWO)[4], 7);
    }

    #[test]
    fn fields_come_before_the_buttons_and_only_secrets_are_hidden() {
        let out = template("Вход", "вопрос", &TWO);
        // Порядок: вопрос, подпись, поле, подпись, поле, кнопки. Фокус
        // встаёт на первое поле, а Tab ведёт ко второму.
        assert_eq!(
            controls(&out, "Вход"),
            [CLASS_STATIC, CLASS_STATIC, CLASS_EDIT, CLASS_STATIC, CLASS_EDIT, CLASS_BUTTON, CLASS_BUTTON]
        );
        // Стиль поля — в двух словах перед координатами.
        let styles: Vec<u32> = (9..out.len() - 1)
            .filter(|at| out[*at] == 0xFFFF && out[at + 1] == CLASS_EDIT)
            .map(|at| out[at - 9] as u32 | (out[at - 8] as u32) << 16)
            .collect();
        assert_eq!(styles.len(), 2);
        assert_eq!(styles[0] & ES_PASSWORD, 0, "логин виден");
        assert_ne!(styles[1] & ES_PASSWORD, 0, "пароль — нет");
    }
}

//! Чтение имени из пакета DNS — ровно столько, сколько нужно, чтобы
//! сопоставить запрос на проводе с тем, кто его заказал.
//!
//! Полного разбора здесь нет намеренно: ни ответов, ни типов записей, ни
//! сжатия имён. Нужен один вопрос из одного запроса, а всё остальное —
//! лишний код в обработчике пакетов и лишний способ ошибиться на данных,
//! пришедших из сети.

/// Длина заголовка DNS: идентификатор, флаги и четыре счётчика.
const HEADER: usize = 12;

/// Имя из первого вопроса. `None`, если это не похоже на запрос с вопросом
/// или если данные обрываются.
///
/// `payload` — то, что идёт после заголовка UDP.
pub fn question_name(payload: &[u8]) -> Option<String> {
    if payload.len() < HEADER {
        return None;
    }
    // Старший бит второго слова флагов: 0 — запрос, 1 — ответ.
    if payload[2] & 0x80 != 0 {
        return None;
    }
    // Число вопросов.
    if u16::from_be_bytes([payload[4], payload[5]]) == 0 {
        return None;
    }

    let mut at = HEADER;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let length = *payload.get(at)? as usize;
        if length == 0 {
            break;
        }
        // Сжатие имён в вопросе запроса не встречается, и поддерживать его
        // здесь незачем: два старших бита ненулевые — значит это не длина.
        if length & 0xC0 != 0 {
            return None;
        }
        at += 1;
        let bytes = payload.get(at..at + length)?;
        labels.push(String::from_utf8_lossy(bytes).to_string());
        at += length;
        // Имя длиннее 255 байт недопустимо; заодно это защита от вечного
        // цикла на испорченных данных.
        if at > HEADER + 255 {
            return None;
        }
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

/// Имя локальной сети: его нельзя спрашивать у публичного сервера имён.
///
/// Такие имена знает только домашний роутер, и если увести их в туннель,
/// перестанут находиться принтер, телевизор и всё остальное в квартире.
/// Отказ здесь безопаснее ошибки в обратную сторону: имя уйдёт домой, как
/// уходило и раньше.
pub fn is_local(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_lowercase();
    // Одно слово без точек — короткое имя машины в сети.
    if !name.contains('.') {
        return true;
    }
    const LOCAL_SUFFIXES: [&str; 6] = [".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa"];
    if LOCAL_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
        return true;
    }
    // Обратные запросы: по адресу спрашивают имя, и для локальных сетей
    // ответ есть только у роутера.
    name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Запрос A-записи для указанного имени.
    fn query(name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[2] = 0x01; // стандартный запрос, рекурсия желательна
        bytes[5] = 1; // один вопрос
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&[0, 1, 0, 1]); // тип A, класс IN
        bytes
    }

    #[test]
    fn the_name_is_read_from_a_query() {
        let packet = query("api.ipify.org");
        assert_eq!(question_name(&packet).as_deref(), Some("api.ipify.org"));
    }

    #[test]
    fn a_single_label_works_too() {
        let packet = query("localhost");
        assert_eq!(question_name(&packet).as_deref(), Some("localhost"));
    }

    #[test]
    fn an_answer_is_not_a_question() {
        let mut packet = query("example.com");
        packet[2] |= 0x80; // это ответ
        assert_eq!(question_name(&packet), None);
    }

    #[test]
    fn a_query_without_questions_is_refused() {
        let mut packet = query("example.com");
        packet[5] = 0;
        assert_eq!(question_name(&packet), None);
    }

    #[test]
    fn truncated_data_does_not_panic() {
        let packet = query("example.com");
        for cut in 0..packet.len() {
            // Главное свойство: на любом обрезке — отказ, а не падение.
            let _ = question_name(&packet[..cut]);
        }
        assert_eq!(question_name(&[]), None);
        assert_eq!(question_name(&[0u8; 11]), None);
    }

    #[test]
    fn compression_in_a_question_is_refused_rather_than_guessed() {
        let mut packet = vec![0u8; HEADER];
        packet[2] = 0x01;
        packet[5] = 1;
        packet.push(0xC0); // указатель сжатия вместо длины
        packet.push(0x0C);
        assert_eq!(question_name(&packet), None);
    }

    #[test]
    fn local_names_stay_home() {
        for name in [
            "printer",
            "NAS",
            "tv.local",
            "router.lan",
            "mediaserver.home",
            "host.internal",
            "box.localdomain",
            "thing.home.arpa",
            "1.31.168.192.in-addr.arpa",
        ] {
            assert!(is_local(name), "{name} должно остаться дома");
        }
    }

    #[test]
    fn public_names_go_to_the_tunnel() {
        for name in [
            "api.ipify.org",
            "www.wikipedia.org",
            "github.com",
            "cdn.jsdelivr.net",
            "example.com.", // с точкой на конце — то же имя
            "localhost.example.com",
        ] {
            assert!(!is_local(name), "{name} должно уйти в туннель");
        }
    }

    #[test]
    fn a_name_that_never_ends_is_refused() {
        let mut packet = vec![0u8; HEADER];
        packet[2] = 0x01;
        packet[5] = 1;
        for _ in 0..100 {
            packet.push(3);
            packet.extend_from_slice(b"abc");
        }
        assert_eq!(question_name(&packet), None);
    }
}

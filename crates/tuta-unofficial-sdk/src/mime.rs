//! A decrypted [`Message`] as an RFC 5322 MIME message, so it reads through
//! the same parser as any other account's mail.
//!
//! The original Message-ID, In-Reply-To, References and List-Unsubscribe
//! headers are kept when the header block has them. Mail between Tuta
//! accounts has no header block, so its Message-ID is the one Tuta keeps for
//! it (the header's `message_id`): the id Tuta's own app answers it by. None
//! is ever made up.

use crate::mail::{Address, Attachment, Message};
use base64::{engine::general_purpose::STANDARD, Engine};

const BOUNDARY: &str = "=_tuta-unofficial-sdk-part";

/// Header text with any line break flattened: message data never gets to
/// start a header of its own.
fn header_safe(text: &str) -> String {
    text.chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

/// RFC 2047 encoded words for non-ASCII text, folded so no line runs long.
fn encode_words(text: &str) -> String {
    let text = header_safe(text);
    if text.is_ascii() {
        return text;
    }
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in text.chars() {
        if chunk.len() + c.len_utf8() > 45 {
            words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(&chunk)));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?b?{}?=", STANDARD.encode(&chunk)));
    }
    words.join("\r\n ")
}

/// A bare address, or `name <address>` with the name quoted or encoded.
fn format_address(address: &Address) -> String {
    let mailbox = header_safe(&address.address);
    let name = &address.name;
    if name.is_empty() {
        return mailbox;
    }
    let name = if !name.is_ascii() {
        encode_words(name)
    } else if name.contains(|c: char| "()<>@,:;.\"[]\\".contains(c)) {
        let escaped = header_safe(name).replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        header_safe(name)
    };
    format!("{name} <{mailbox}>")
}

/// A MIME type token pair, or the octet-stream fallback.
fn mime_type(value: Option<&str>) -> String {
    let is_token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    match value.and_then(|t| t.split_once('/')) {
        Some((main, sub)) if is_token(main) && is_token(sub) => {
            format!("{}/{}", main.to_ascii_lowercase(), sub.to_ascii_lowercase())
        }
        _ => "application/octet-stream".into(),
    }
}

/// Base64 body lines of at most 76 characters.
fn base64_lines(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 38 + 2);
    for line in encoded.as_bytes().chunks(76) {
        // Base64 output is ASCII.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push_str("\r\n");
    }
    out
}

/// A filename parameter, RFC 2231-encoded when it is not plain ASCII.
fn filename_parameter(name: &str) -> String {
    if name.is_ascii() && !name.contains(|c: char| c.is_ascii_control() || c == '"' || c == '\\') {
        return format!("filename=\"{name}\"");
    }
    let encoded: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("filename*=utf-8''{encoded}")
}

/// The first `name` header in an unparsed header block, unfolded.
fn header_value(block: &str, name: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for line in block.split('\n').map(|line| line.trim_end_matches('\r')) {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if let Some(value) = current.as_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if current.is_some() {
            return current;
        }
        if let Some((field, value)) = line.split_once(':') {
            if field.trim().eq_ignore_ascii_case(name) {
                current = Some(value.trim().to_string());
            }
        }
    }
    current
}

/// The days-since-epoch date as (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The Date header's form of milliseconds since the epoch, in UTC.
fn rfc2822_date(ms: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let seconds = ms / 1000;
    let days = (seconds / 86_400) as i64;
    let of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        DAYS[days.rem_euclid(7) as usize],
        day,
        MONTHS[month as usize - 1],
        year,
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

fn attachment_part(attachment: &Attachment) -> String {
    let filename = if attachment.name.is_empty() {
        "attachment"
    } else {
        attachment.name.as_str()
    };
    let mut part = format!(
        "Content-Type: {}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; {}\r\n",
        mime_type(attachment.mime_type.as_deref()),
        filename_parameter(&header_safe(filename)),
    );
    if let Some(cid) = &attachment.cid {
        let cid = header_safe(cid);
        let cid = cid.trim().trim_start_matches('<').trim_end_matches('>');
        if !cid.is_empty() {
            part.push_str(&format!("Content-ID: <{cid}>\r\n"));
        }
    }
    part.push_str("\r\n");
    part.push_str(&base64_lines(&attachment.data));
    part
}

/// The Message-ID Tuta keeps for the mail, when it is one: printable ASCII
/// without spaces or brackets, which it hands back bare.
fn kept_message_id(message_id: Option<&str>) -> Option<&str> {
    message_id.filter(|id| {
        !id.is_empty()
            && id.len() <= 998
            && id
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
    })
}

impl Message {
    /// The message as RFC 5322 MIME: the HTML body base64-encoded, and each
    /// attachment a part of a `multipart/mixed` beside it.
    pub fn to_mime(&self) -> Vec<u8> {
        let header = &self.header;
        let mut head = String::new();
        let mut put = |name: &str, value: &str| {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        };
        if !header.subject.is_empty() {
            put("Subject", &encode_words(&header.subject));
        }
        put("From", &format_address(&header.sender));
        put("Date", &rfc2822_date(header.date_ms));
        for (name, addresses) in [
            ("To", &self.to),
            ("Cc", &self.cc),
            ("Reply-To", &self.reply_to),
        ] {
            if !addresses.is_empty() {
                let formatted: Vec<String> = addresses.iter().map(format_address).collect();
                put(name, &formatted.join(", "));
            }
        }
        for name in [
            "Message-ID",
            "In-Reply-To",
            "References",
            "List-Unsubscribe",
            "List-Unsubscribe-Post",
        ] {
            if let Some(value) = header_value(&self.headers, name).filter(|v| !v.is_empty()) {
                put(name, &header_safe(&value));
            } else if name == "Message-ID" {
                if let Some(id) = kept_message_id(header.message_id.as_deref()) {
                    put(name, &format!("<{id}>"));
                }
            }
        }
        let html_part = format!(
            "Content-Type: text/html; charset=\"utf-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
            base64_lines(self.html.as_bytes())
        );
        let mut raw = head;
        raw.push_str("MIME-Version: 1.0\r\n");
        if self.attachments.is_empty() {
            raw.push_str(&html_part);
            return raw.into_bytes();
        }
        raw.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{BOUNDARY}\"\r\n\r\n"
        ));
        raw.push_str(&format!("--{BOUNDARY}\r\n{html_part}"));
        for attachment in &self.attachments {
            raw.push_str(&format!("--{BOUNDARY}\r\n"));
            raw.push_str(&attachment_part(attachment));
        }
        raw.push_str(&format!("--{BOUNDARY}--\r\n"));
        raw.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mail::MailHeader, Id};
    use mail_parser::MessageParser;

    fn address(name: &str, address: &str) -> Address {
        Address {
            name: name.into(),
            address: address.into(),
        }
    }

    fn message(headers: &str, message_id: Option<&str>, attachments: Vec<Attachment>) -> Message {
        Message {
            header: MailHeader {
                id: Id::parse("l/m").unwrap(),
                subject: "Grüße, Ada".into(),
                date_ms: 1_700_000_000_123,
                sender: address("Ada L.", "ada@tuta.com"),
                recipient: None,
                is_unread: false,
                confidential: true,
                conversation: "c".into(),
                message_id: message_id.map(str::to_string),
                has_attachments: !attachments.is_empty(),
                reply_type: 0,
            },
            html: "<p>hi</p>".into(),
            headers: headers.into(),
            to: vec![address("", "bo@example.org")],
            cc: Vec::new(),
            reply_to: vec![address("Ada", "ada+r@tuta.com")],
            attachments,
        }
    }

    #[test]
    fn dates_are_utc_rfc_2822() {
        assert_eq!(rfc2822_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(
            rfc2822_date(1_700_000_000_123),
            "Tue, 14 Nov 2023 22:13:20 +0000"
        );
        assert_eq!(
            rfc2822_date(951_782_400_000),
            "Tue, 29 Feb 2000 00:00:00 +0000"
        );
    }

    #[test]
    fn a_tuta_mail_reads_back_with_its_kept_message_id() {
        let raw = message("", Some("abc@tuta.com"), Vec::new()).to_mime();
        let parsed = MessageParser::default().parse(&raw).unwrap();
        assert_eq!(parsed.subject(), Some("Grüße, Ada"));
        assert_eq!(parsed.message_id(), Some("abc@tuta.com"));
        assert_eq!(
            parsed.from().unwrap().first().unwrap().address(),
            Some("ada@tuta.com")
        );
        assert_eq!(parsed.body_html(0).as_deref(), Some("<p>hi</p>"));
        assert_eq!(parsed.attachment_count(), 0);
    }

    #[test]
    fn original_threading_headers_win_and_attachments_are_parts() {
        let headers = "Message-ID: <orig@example.org>\r\nIn-Reply-To: <p@x>\r\nReferences: <r@x>\r\n <p@x>\r\nX-Other: 1\r\n";
        let attachments = vec![Attachment {
            name: "résumé.pdf".into(),
            mime_type: Some("Application/PDF".into()),
            cid: Some("<c1>".into()),
            data: vec![0, 1, 2, 3],
        }];
        let raw = message(headers, Some("kept@tuta.com"), attachments).to_mime();
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.contains("References: <r@x> <p@x>\r\n"));
        assert!(text.contains("Content-ID: <c1>\r\n"));
        assert!(text.contains("filename*=utf-8''r%C3%A9sum%C3%A9.pdf"));
        assert!(!text.contains("X-Other"));
        let parsed = MessageParser::default().parse(&raw).unwrap();
        assert_eq!(parsed.message_id(), Some("orig@example.org"));
        assert_eq!(parsed.attachment_count(), 1);
        let part = parsed.attachment(0).unwrap();
        assert_eq!(part.contents(), &[0, 1, 2, 3]);
    }

    #[test]
    fn header_injection_is_flattened() {
        let mut evil = message("", Some("bad id"), Vec::new());
        evil.header.subject = "x\r\nBcc: victim@example.org".into();
        let text = String::from_utf8(evil.to_mime()).unwrap();
        assert!(!text.contains("\r\nBcc:"));
        assert!(!text.contains("Message-ID"));
    }
}

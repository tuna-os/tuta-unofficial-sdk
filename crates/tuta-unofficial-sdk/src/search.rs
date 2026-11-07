//! Searching mail by scanning it, a bounded slice per call.
//!
//! Tuta has no server-side search on any plan: mail is end-to-end encrypted,
//! so the server cannot read a subject, and the official clients build their
//! search index on the device from mail they download and decrypt. This
//! crate keeps no index, so [`Session::search`] does what such an index
//! would be built from, in the open: it walks a folder newest first,
//! decrypts each mail's header (subject, sender, first recipient, date,
//! read flag), and downloads a body only when a criterion needs one. Each
//! call stops after [`SEARCH_SCAN_LIMIT`] mails, [`SEARCH_BODY_LIMIT`]
//! bodies, `limit` matches or [`SEARCH_TIME_BUDGET`], and hands back a
//! cursor to go on from. A caller that wants every match keeps calling
//! with the cursor until it comes back empty; one that keeps its own index
//! can use `sync` and `message` instead.
//!
//! Dates cost nothing to bound: a folder's entries are ordered by their
//! received date, so `before_ms` starts the walk at that date and
//! `after_ms` ends it there, without loading the mail outside.

use crate::{
    diag,
    error::api_code,
    ids::{id, Id},
    mail::{ListedMail, MailHeader},
    mailbox_ops::{self, IMPORTED_FOLDER_TYPE},
    thread, Error, Result, Session,
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tokio::time::Instant;
use tutabridge_tuta::{mail::MailExtensions, mail_set_entry_id};
use tutasdk::{
    date::DateTime,
    entities::generated::tutanota::{Mail, MailAddress, MailDetails, MailSet, MailSetEntry},
    CustomId, GeneratedId, ListLoadDirection,
};

/// The most matches one call returns.
pub const MAX_SEARCH_LIMIT: usize = 100;
/// The most mails one call examines.
pub const SEARCH_SCAN_LIMIT: usize = 500;
/// The most bodies one call downloads.
pub const SEARCH_BODY_LIMIT: usize = 50;
/// How long one call scans before it hands back its cursor; well inside the
/// helper protocol's 90-second limit.
pub const SEARCH_TIME_BUDGET: Duration = Duration::from_secs(30);
/// The longest text criterion, in characters.
pub const MAX_SEARCH_TEXT_CHARS: usize = 256;
/// Entries loaded per range request.
const ENTRY_PAGE: usize = 100;

/// What to look for. Every criterion given must hold; text criteria are
/// case-insensitive substrings. `keyword` looks in the subject, the sender,
/// the recipients and the body text; `recipient` in To, Cc and Bcc. Dates
/// are milliseconds since the epoch, `after_ms` inclusive and `before_ms`
/// exclusive, against the received date.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchQuery {
    pub keyword: Option<String>,
    pub subject: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub after_ms: Option<u64>,
    pub before_ms: Option<u64>,
    pub is_unread: Option<bool>,
}

/// A checked [`SearchQuery`] with its page size: what [`Session::search`]
/// runs.
#[derive(Clone, Debug)]
pub struct Search {
    keyword: Option<String>,
    subject: Option<String>,
    sender: Option<String>,
    recipient: Option<String>,
    after_ms: Option<u64>,
    before_ms: Option<u64>,
    is_unread: Option<bool>,
    limit: usize,
}

impl Search {
    /// At least one criterion and 1 to [`MAX_SEARCH_LIMIT`] matches; text
    /// that is blank or over [`MAX_SEARCH_TEXT_CHARS`], or `after_ms` not
    /// before `before_ms`, is [`Error::InvalidRequest`].
    pub fn new(query: SearchQuery, limit: usize) -> Result<Self> {
        if limit == 0 || limit > MAX_SEARCH_LIMIT {
            return Err(Error::InvalidPage);
        }
        if let (Some(after), Some(before)) = (query.after_ms, query.before_ms) {
            if after >= before {
                return Err(Error::InvalidRequest);
            }
        }
        let text = |value: Option<String>| -> Result<Option<String>> {
            let Some(value) = value else { return Ok(None) };
            let value = value.trim();
            if value.is_empty() || value.chars().count() > MAX_SEARCH_TEXT_CHARS {
                return Err(Error::InvalidRequest);
            }
            Ok(Some(fold(value)))
        };
        let search = Search {
            keyword: text(query.keyword)?,
            subject: text(query.subject)?,
            sender: text(query.sender)?,
            recipient: text(query.recipient)?,
            after_ms: query.after_ms,
            before_ms: query.before_ms,
            is_unread: query.is_unread,
            limit,
        };
        let has_criterion = search.keyword.is_some()
            || search.subject.is_some()
            || search.sender.is_some()
            || search.recipient.is_some()
            || search.after_ms.is_some()
            || search.before_ms.is_some()
            || search.is_unread.is_some();
        if !has_criterion {
            return Err(Error::InvalidRequest);
        }
        Ok(search)
    }

    /// The criteria a mail's header alone decides: `Some(false)` rules it
    /// out, `Some(true)` matches, `None` needs the body.
    fn on_header(&self, mail: &Mail) -> Option<bool> {
        let date = mail.receivedDate.as_millis();
        if self.after_ms.is_some_and(|after| date < after)
            || self.before_ms.is_some_and(|before| date >= before)
            || self.is_unread.is_some_and(|unread| unread != mail.unread)
        {
            return Some(false);
        }
        let subject = fold(&mail.subject);
        let sender = address_text(&mail.sender);
        if self.subject.as_ref().is_some_and(|s| !subject.contains(s))
            || self.sender.as_ref().is_some_and(|s| !sender.contains(s))
        {
            return Some(false);
        }
        let first_recipient = mail.firstRecipient.as_ref().map(address_text);
        let recipient_settled = match &self.recipient {
            None => true,
            Some(needle) => first_recipient.as_ref().is_some_and(|r| r.contains(needle)),
        };
        let keyword_settled = match &self.keyword {
            None => true,
            Some(needle) => {
                subject.contains(needle)
                    || sender.contains(needle)
                    || first_recipient.as_ref().is_some_and(|r| r.contains(needle))
            }
        };
        (recipient_settled && keyword_settled).then_some(true)
    }

    /// The criteria that needed the body, given it.
    fn on_details(&self, mail: &Mail, details: &MailDetails) -> bool {
        let recipients = &details.recipients;
        let recipient_text: Vec<String> = recipients
            .toRecipients
            .iter()
            .chain(&recipients.ccRecipients)
            .chain(&recipients.bccRecipients)
            .chain(mail.firstRecipient.as_ref())
            .map(address_text)
            .collect();
        if let Some(needle) = &self.recipient {
            if !recipient_text.iter().any(|r| r.contains(needle)) {
                return false;
            }
        }
        let Some(needle) = &self.keyword else {
            return true;
        };
        if fold(&mail.subject).contains(needle)
            || address_text(&mail.sender).contains(needle)
            || recipient_text.iter().any(|r| r.contains(needle))
        {
            return true;
        }
        let html = details
            .body
            .compressedText
            .as_deref()
            .or(details.body.text.as_deref())
            .unwrap_or_default();
        fold(&html_text(html)).contains(needle)
    }

    /// Where a folder's walk starts: just after `before_ms`, or at the top.
    fn first_entry(&self) -> CustomId {
        // The newest date an entry id holds: 32 bits of `ms >> 10`.
        let newest = u64::from(u32::MAX) << 10;
        let date = self.before_ms.map_or(newest, |before| before.min(newest));
        mail_set_entry_id::construct(DateTime::from_millis(date), &GeneratedId::max_id())
    }

    /// Whether an entry, by the date its id holds, is older than `after_ms`
    /// and so is every entry after it.
    fn is_past_end(&self, entry: &CustomId) -> bool {
        let Some(after) = self.after_ms else {
            return false;
        };
        match mail_set_entry_id::deconstruct(entry) {
            // The id keeps the date to 1024 ms below the real one.
            Ok((date, _)) => date.as_millis() + 1023 < after,
            Err(_) => false,
        }
    }
}

/// Where a search goes on from: the folder and the last entry examined. On
/// the wire it is an opaque string; hand it back unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchCursor {
    folder: Id,
    entry: String,
}

impl SearchCursor {
    /// A cursor as `search` handed it out; anything else is
    /// [`Error::InvalidRequest`].
    pub fn parse(value: &str) -> Result<Self> {
        let (folder, entry) = value.rsplit_once('/').ok_or(Error::InvalidRequest)?;
        let folder = Id::parse(folder).map_err(|_| Error::InvalidRequest)?;
        if entry.is_empty()
            || entry.len() > 64
            || !entry
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::InvalidRequest);
        }
        Ok(SearchCursor {
            folder,
            entry: entry.to_string(),
        })
    }

    /// The folder the search was in when it handed the cursor out.
    pub fn folder(&self) -> &Id {
        &self.folder
    }
}

impl std::fmt::Display for SearchCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.folder, self.entry)
    }
}

impl Serialize for SearchCursor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A match: the mail as `sync` lists it, and the folder it was found in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SearchHit {
    #[serde(flatten)]
    pub mail: ListedMail,
    pub folder: Id,
}

/// One call's matches, newest first within each folder, and where the next
/// call goes on from (None: the search is complete).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SearchPage {
    pub messages: Vec<SearchHit>,
    pub next_cursor: Option<SearchCursor>,
    /// How many mails this call examined.
    pub scanned: usize,
}

/// Lowercased for comparison.
fn fold(text: &str) -> String {
    text.to_lowercase()
}

fn address_text(address: &MailAddress) -> String {
    fold(&format!("{} {}", address.name, address.address))
}

/// The text of an HTML body, roughly: tags and the content of `style` and
/// `script` dropped, the common entities decoded, whitespace collapsed.
fn html_text(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open) = rest.find('<') {
        text.push_str(&rest[..open]);
        text.push(' ');
        let tag = &rest[open..];
        let lower: String = tag.chars().take(8).collect::<String>().to_ascii_lowercase();
        let skip_to = ["style", "script"]
            .iter()
            .find(|name| {
                lower[1..].starts_with(**name)
                    && lower[1 + name.len()..].starts_with(|c: char| c == '>' || c.is_whitespace())
            })
            .and_then(|name| {
                let close = format!("</{name}");
                tag.to_ascii_lowercase().find(&close)
            });
        let from = skip_to.unwrap_or(0);
        match tag[from..].find('>') {
            Some(end) => rest = &tag[from + end + 1..],
            None => {
                rest = "";
                break;
            }
        }
    }
    text.push_str(rest);
    let decoded = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Session {
    /// Search `folder` (a folder or a label), or with None every folder
    /// (not labels) in the mailbox's order, from `cursor` on: see the
    /// [module docs](crate::search) for what is scanned and the limits.
    pub async fn search(
        &self,
        folder: Option<&Id>,
        search: &Search,
        cursor: Option<&SearchCursor>,
    ) -> Result<SearchPage> {
        // A cursor from a search of another folder is not this search's.
        if let (Some(folder), Some(cursor)) = (folder, cursor) {
            if *folder != cursor.folder {
                return Err(Error::InvalidRequest);
            }
        }
        let started = Instant::now();
        let mailbox = mailbox_ops::load_mailbox(&self.sdk).await?;
        let label_ids: HashSet<String> = mailbox
            .sets
            .iter()
            .filter(|set| mailbox_ops::is_label(set))
            .filter_map(|set| set._id.as_ref().map(id))
            .collect();
        let mut targets: Vec<(Id, &MailSet)> = Vec::new();
        for set in &mailbox.sets {
            if !set._errors.is_empty() {
                continue;
            }
            let Some(set_id) = set._id.clone().map(Id::from_tuple) else {
                continue;
            };
            let wanted = match folder {
                Some(folder) => *folder == set_id,
                None => !mailbox_ops::is_label(set) && set.folderType != IMPORTED_FOLDER_TYPE,
            };
            if wanted {
                targets.push((set_id, set));
            }
        }
        if folder.is_some() && targets.is_empty() {
            return Err(Error::FolderNotFound);
        }
        let (mut index, mut resume_at) = match cursor {
            None => (0, None),
            Some(cursor) => {
                let index = targets
                    .iter()
                    .position(|(set_id, _)| *set_id == cursor.folder)
                    .ok_or(Error::FolderNotFound)?;
                (index, Some(CustomId(cursor.entry.clone())))
            }
        };
        let mut walk = Walk {
            session: self,
            search,
            started,
            scanned: 0,
            bodies: 0,
            hits: Vec::new(),
        };
        let mut next_cursor = None;
        while let Some((set_id, set)) = targets.get(index) {
            let start = resume_at.take().unwrap_or_else(|| search.first_entry());
            match walk.folder(set, start).await? {
                None => index += 1,
                Some(entry) => {
                    next_cursor = Some(SearchCursor {
                        folder: set_id.clone(),
                        entry,
                    });
                    break;
                }
            }
        }
        let scanned = walk.scanned;
        let hits = walk.hits;
        let mails: Vec<Mail> = hits.iter().map(|(_, mail)| mail.clone()).collect();
        let message_ids = thread::message_ids(&self.sdk, &mails).await;
        let mut messages = Vec::with_capacity(hits.len());
        for (folder, mail) in &hits {
            messages.push(SearchHit {
                mail: ListedMail {
                    header: MailHeader::of(mail, thread::message_id_of(&message_ids, mail))?,
                    labels: mailbox_ops::mail_labels(&mail.sets, &label_ids),
                },
                folder: folder.clone(),
            });
        }
        Ok(SearchPage {
            messages,
            next_cursor,
            scanned,
        })
    }
}

/// One call's progress across folders.
struct Walk<'a> {
    session: &'a Session,
    search: &'a Search,
    started: Instant,
    scanned: usize,
    bodies: usize,
    hits: Vec<(Id, Mail)>,
}

impl Walk<'_> {
    /// Walk one folder from `start` (exclusive), newest first. None: the
    /// folder is done; else the entry to go on after next time.
    async fn folder(&mut self, set: &MailSet, start: CustomId) -> Result<Option<String>> {
        let set_id = Id::from_tuple(set._id.clone().ok_or(Error::IncompleteResponse)?);
        let client = self.session.sdk.mail_facade().get_crypto_entity_client();
        // The last entry examined, or where the walk started.
        let mut resume = start.0;
        loop {
            let count = ENTRY_PAGE.min(SEARCH_SCAN_LIMIT - self.scanned);
            if count == 0 {
                return Ok(Some(resume));
            }
            let entries: Vec<MailSetEntry> = client
                .load_range(
                    &set.entries,
                    &CustomId(resume.clone()),
                    count,
                    ListLoadDirection::DESC,
                )
                .await
                .map_err(|error| {
                    diag::failed("search entries", &error);
                    api_code(error, Error::RequestFailed, Error::FolderNotFound)
                })?;
            let mut ids = Vec::with_capacity(entries.len());
            for entry in &entries {
                let entry_id = entry._id.as_ref().ok_or(Error::IncompleteResponse)?;
                if self.search.is_past_end(&entry_id.element_id) {
                    break;
                }
                ids.push((entry_id.element_id.0.clone(), entry.mail.clone()));
            }
            let reached_end = ids.len() < entries.len() || entries.len() < count;
            let mails = self.load_mails(&ids).await?;
            for (entry, mail_id) in ids {
                // A mail gone since its entry was listed, or undecryptable,
                // matches nothing.
                let matched = match mails.get(&id(&mail_id)) {
                    None => false,
                    Some(mail) => {
                        let matched = match self.search.on_header(mail) {
                            Some(matched) => matched,
                            // Out of bodies: this entry is examined again
                            // next time.
                            None if self.bodies == SEARCH_BODY_LIMIT => return Ok(Some(resume)),
                            None => {
                                self.bodies += 1;
                                match self.details(mail).await {
                                    Some(details) => self.search.on_details(mail, &details),
                                    None => false,
                                }
                            }
                        };
                        if matched {
                            self.hits.push((set_id.clone(), mail.clone()));
                        }
                        matched
                    }
                };
                self.scanned += 1;
                resume = entry;
                if (matched && self.hits.len() == self.search.limit)
                    || self.started.elapsed() >= SEARCH_TIME_BUDGET
                {
                    return Ok(Some(resume));
                }
            }
            if reached_end {
                return Ok(None);
            }
        }
    }

    /// The mails `ids` name, decrypted, by compound id; a mail that is gone
    /// or cannot be decrypted is left out.
    async fn load_mails(
        &self,
        ids: &[(String, tutasdk::IdTupleGenerated)],
    ) -> Result<HashMap<String, Mail>> {
        let client = self.session.sdk.mail_facade().get_crypto_entity_client();
        let mut lists: Vec<(GeneratedId, Vec<GeneratedId>)> = Vec::new();
        for (_, mail_id) in ids {
            match lists.iter_mut().find(|(list, _)| *list == mail_id.list_id) {
                Some((_, elements)) => elements.push(mail_id.element_id.clone()),
                None => lists.push((mail_id.list_id.clone(), vec![mail_id.element_id.clone()])),
            }
        }
        let mut mails = HashMap::new();
        for (list, elements) in lists {
            let loaded: Vec<Mail> =
                client
                    .load_multiple(&list, &elements)
                    .await
                    .map_err(|error| {
                        diag::failed("search mails", &error);
                        api_code(error, Error::RequestFailed, Error::RequestFailed)
                    })?;
            for mail in loaded {
                if !mail._errors.is_empty() {
                    continue;
                }
                if let Some(mail_id) = &mail._id {
                    mails.insert(id(mail_id), mail);
                }
            }
        }
        Ok(mails)
    }

    /// A mail's body and recipients; None when they cannot be read (the
    /// mail is then matched on its header alone, so it does not match).
    async fn details(&self, mail: &Mail) -> Option<MailDetails> {
        let extensions = MailExtensions::new(self.session.sdk.clone());
        let details = if mail.mailDetailsDraft.is_some() {
            extensions.load_mail_details_draft(mail).await
        } else if mail.mailDetails.is_some() {
            extensions.load_mail_details_blob(mail).await
        } else {
            return None;
        };
        match details {
            Ok(details) if details.body._errors.is_empty() => Some(details),
            Ok(_) => None,
            Err(error) => {
                diag::failed("search body", &error);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> SearchQuery {
        SearchQuery::default()
    }

    #[test]
    fn a_search_needs_a_criterion_and_a_sane_page() {
        assert_eq!(Search::new(query(), 10).err(), Some(Error::InvalidRequest));
        let keyword = SearchQuery {
            keyword: Some("x".into()),
            ..query()
        };
        assert_eq!(
            Search::new(keyword.clone(), 0).err(),
            Some(Error::InvalidPage)
        );
        assert_eq!(
            Search::new(keyword.clone(), MAX_SEARCH_LIMIT + 1).err(),
            Some(Error::InvalidPage)
        );
        assert!(Search::new(keyword, MAX_SEARCH_LIMIT).is_ok());
        for blank in ["", "   ", &"x".repeat(MAX_SEARCH_TEXT_CHARS + 1)] {
            let q = SearchQuery {
                subject: Some(blank.to_string()),
                ..query()
            };
            assert_eq!(Search::new(q, 10).err(), Some(Error::InvalidRequest));
        }
        let backwards = SearchQuery {
            after_ms: Some(10),
            before_ms: Some(10),
            ..query()
        };
        assert_eq!(
            Search::new(backwards, 10).err(),
            Some(Error::InvalidRequest)
        );
        let unread = SearchQuery {
            is_unread: Some(true),
            ..query()
        };
        assert!(Search::new(unread, 10).is_ok());
    }

    #[test]
    fn cursors_round_trip_and_refuse_junk() {
        let cursor = SearchCursor::parse("fl/fe/AbC-_9").unwrap();
        assert_eq!(cursor.folder, Id::parse("fl/fe").unwrap());
        assert_eq!(cursor.to_string(), "fl/fe/AbC-_9");
        for junk in ["", "fl/fe", "fl/fe/", "fl/fe/a b", "fe/x", "fl/fe/a/b/c"] {
            assert_eq!(
                SearchCursor::parse(junk).err(),
                Some(Error::InvalidRequest),
                "{junk}"
            );
        }
    }

    #[test]
    fn the_walk_starts_at_the_date_bound() {
        let search = |before_ms| {
            Search::new(
                SearchQuery {
                    before_ms,
                    is_unread: Some(true),
                    ..query()
                },
                10,
            )
            .unwrap()
        };
        let top = search(None).first_entry();
        let (date, mail) = mail_set_entry_id::deconstruct(&top).unwrap();
        assert_eq!(date.as_millis(), u64::from(u32::MAX) << 10);
        assert_eq!(mail, GeneratedId::max_id());
        let bounded = search(Some(1_700_000_000_000)).first_entry();
        let (date, _) = mail_set_entry_id::deconstruct(&bounded).unwrap();
        assert_eq!(date.as_millis(), 1_700_000_000_000 >> 10 << 10);
    }

    #[test]
    fn entries_older_than_after_end_the_walk() {
        let search = Search::new(
            SearchQuery {
                after_ms: Some(1_700_000_000_500),
                ..query()
            },
            10,
        )
        .unwrap();
        let entry =
            |ms| mail_set_entry_id::construct(DateTime::from_millis(ms), &GeneratedId::max_id());
        assert!(!search.is_past_end(&entry(1_700_000_000_500)));
        // Same 1024 ms bucket: the id cannot tell it is older.
        assert!(!search.is_past_end(&entry(1_700_000_000_000)));
        assert!(search.is_past_end(&entry(1_699_999_999_000)));
    }

    #[test]
    fn html_bodies_are_searched_as_text() {
        let html = "<html><head><style>p { color: red }</style><script type=x>var secret = 1</script></head>\
                    <body><p>Hello&nbsp;<b>Ada</b> &amp; Bo</p><STYLE>.x{}</STYLE>bye</body></html>";
        assert_eq!(html_text(html), "Hello Ada & Bo bye");
        assert_eq!(html_text("a <unterminated"), "a");
        assert_eq!(html_text("plain"), "plain");
    }

    #[test]
    fn text_criteria_fold_case() {
        let search = Search::new(
            SearchQuery {
                keyword: Some("  GRÜSSE ".into()),
                ..query()
            },
            1,
        )
        .unwrap();
        assert_eq!(search.keyword.as_deref(), Some("grüsse"));
    }
}

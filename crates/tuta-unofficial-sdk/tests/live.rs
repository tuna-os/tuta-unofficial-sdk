//! Live tests against Tuta's servers, ignored by default. One run signs in
//! once and sends one mail; everything it creates is deleted again and its
//! session is closed.
//!
//! ```sh
//! TUTA_LIVE=1 TUTA_LIVE_EMAIL=... TUTA_LIVE_PASSWORD=... TUTA_LIVE_TOTP=... \
//!     cargo test -p tuta-unofficial-sdk --test live -- --ignored --nocapture
//! ```
//!
//! `TUTA_LIVE_TOTP` is only needed for an account with a second factor.
//! Use a test account: the run reads the Inbox and sends to itself.

use mail_parser::MessageParser;
use secrecy::SecretString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tuta_unofficial_sdk::{
    contacts::Passwords,
    drafts::{self, DraftRequest},
    Client, FolderRole, Id, Outcome, OutgoingAttachment, Page, Recipient, SendRequest, Session,
    Thread, WatchEvent,
};

type Check = Result<(), String>;

struct Live {
    email: String,
    password: SecretString,
    totp: Option<String>,
}

fn live() -> Option<Live> {
    if std::env::var("TUTA_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: set TUTA_LIVE=1 and TUTA_LIVE_EMAIL/PASSWORD[/TOTP]");
        return None;
    }
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    Some(Live {
        email: var("TUTA_LIVE_EMAIL"),
        password: SecretString::from(var("TUTA_LIVE_PASSWORD")),
        totp: std::env::var("TUTA_LIVE_TOTP")
            .ok()
            .filter(|t| !t.is_empty()),
    })
}

fn check(condition: bool, what: &str) -> Check {
    if condition {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

fn fail<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> String {
    move |error| format!("{what}: {error}")
}

/// What the run created, removed again whatever happened.
#[derive(Default)]
struct Created {
    mails: Vec<Id>,
    draft: Option<Id>,
}

async fn next_event(
    watch: &mut tuta_unofficial_sdk::Watch,
    within: Duration,
) -> Result<WatchEvent, String> {
    let next = std::future::poll_fn(|cx| {
        futures_core::Stream::poll_next(std::pin::Pin::new(&mut *watch), cx)
    });
    match tokio::time::timeout(within, next).await {
        Ok(Some(Ok(event))) => Ok(event),
        Ok(Some(Err(error))) => Err(format!("watch: {error}")),
        Ok(None) => Err("watch ended".into()),
        Err(_) => Err("watch: no event in time".into()),
    }
}

async fn run(client: &Client, session: &Session, email: &str, created: &mut Created) -> Check {
    // Folders, labels, a first page.
    let folders = session.folders().await.map_err(fail("folders"))?;
    let role = |wanted: FolderRole| {
        folders
            .iter()
            .find(|folder| folder.role == wanted)
            .map(|folder| folder.id.clone())
            .ok_or(format!("no {wanted:?} folder"))
    };
    let (inbox, trash) = (role(FolderRole::Inbox)?, role(FolderRole::Trash)?);
    role(FolderRole::Sent)?;
    session.labels().await.map_err(fail("labels"))?;
    let page = session
        .sync(None, Page::new(5, 0).unwrap())
        .await
        .map_err(fail("sync"))?;
    check(page.folder == inbox, "sync lists the Inbox by default")?;
    check(
        page.all_ids
            .as_ref()
            .is_some_and(|ids| ids.len() == page.exists),
        "the first page lists every id",
    )?;

    // The saved session resumes.
    let resumed = Session::resume(client, session.saved().clone())
        .await
        .map_err(fail("resume"))?;
    check(
        resumed.login() == email,
        "the resumed session is the same account",
    )?;

    // A draft is created, updated in place and discarded.
    let token = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let me = || vec![Recipient::new("", email)];
    let mut draft = DraftRequest {
        draft: None,
        sender: email.to_string(),
        sender_name: String::new(),
        to: me(),
        cc: Vec::new(),
        bcc: Vec::new(),
        reply_tos: Vec::new(),
        subject: format!("tuta-unofficial-sdk draft {token}"),
        body_html: "<p>draft</p>".into(),
        confidential: true,
        attachments: Vec::new(),
        thread: Thread::default(),
    };
    let draft_id = drafts::save(session, &draft)
        .await
        .map_err(fail("draft save"))?;
    created.draft = Some(draft_id.clone());
    draft.draft = Some(draft_id.clone());
    draft.body_html = "<p>draft, updated</p>".into();
    let updated = drafts::save(session, &draft)
        .await
        .map_err(fail("draft update"))?;
    check(updated == draft_id, "an update keeps the draft's id")?;
    drafts::delete(session, &draft_id)
        .await
        .map_err(fail("draft delete"))?;
    created.draft = None;
    drafts::delete(session, &draft_id)
        .await
        .map_err(fail("draft delete is idempotent"))?;

    // A confidential send to self, watched arriving.
    let mut watch = session.watch().await.map_err(fail("watch"))?;
    check(
        next_event(&mut watch, Duration::from_secs(30)).await? == WatchEvent::Ready,
        "the watch starts with ready",
    )?;
    let subject = format!("tuta-unofficial-sdk live {token}");
    let outcome = session
        .send_within(
            SendRequest {
                sender: email.to_string(),
                sender_name: "tuta-unofficial-sdk".into(),
                to: me(),
                cc: Vec::new(),
                bcc: Vec::new(),
                reply_tos: Vec::new(),
                subject: subject.clone(),
                body_html: format!("<p>live {token}</p>"),
                confidential: true,
                ordinary_confirmed: false,
                passwords: Passwords::new(),
                attachments: vec![OutgoingAttachment {
                    name: "token.txt".into(),
                    mime_type: "text/plain".into(),
                    cid: None,
                    data: token.clone().into_bytes(),
                }],
                thread: Thread::default(),
            },
            Duration::from_secs(90),
        )
        .await
        .map_err(fail("send"))?;
    if let Some(sent) = &outcome.sent_mail {
        created.mails.push(sent.clone());
    }
    check(
        outcome.confidential == Some(true),
        "the send is confidential",
    )?;
    check(outcome.internal_recipients == Some(1), "one Tuta recipient")?;
    check(
        outcome
            .recipients
            .as_ref()
            .is_some_and(|keys| keys.len() == 1),
        "the recipient's key is reported",
    )?;
    check(
        outcome
            .secure_external
            .as_ref()
            .is_some_and(|external| external.is_empty()),
        "nobody outside Tuta",
    )?;
    check(
        outcome.contacts_saved == Some(true),
        "no contact write failed",
    )?;
    check(outcome.parent_marked.is_none(), "new mail has no parent")?;
    let sent = outcome.sent_mail.clone().ok_or("the sent copy's id")?;

    let mut saw_mail = false;
    for _ in 0..10 {
        match next_event(&mut watch, Duration::from_secs(30)).await? {
            WatchEvent::MailChanged { .. } => {
                saw_mail = true;
                break;
            }
            _ => continue,
        }
    }
    watch.close().await;
    check(saw_mail, "the watch reports the new mail")?;

    // The received copy decrypts through the bucket key.
    let mut received = None;
    for _ in 0..10 {
        let page = session
            .sync(Some(&inbox), Page::new(20, 0).unwrap())
            .await
            .map_err(fail("sync inbox"))?;
        received = page
            .messages
            .iter()
            .find(|mail| mail.header.subject == subject && mail.header.id != sent)
            .map(|mail| mail.header.clone());
        if received.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let received = received.ok_or("the mail arrived in the Inbox")?;
    created.mails.push(received.id.clone());
    check(received.confidential, "the received copy is confidential")?;
    let message = session
        .message(&received.id)
        .await
        .map_err(fail("message"))?;
    check(
        message.html.contains(&format!("live {token}")),
        "the body decrypts",
    )?;
    check(
        message.attachments.len() == 1 && message.attachments[0].data == token.as_bytes(),
        "the attachment decrypts",
    )?;
    let mime = message.to_mime();
    let parsed = MessageParser::default()
        .parse(&mime)
        .ok_or("the MIME form parses")?;
    check(
        parsed.subject() == Some(subject.as_str()),
        "the MIME form keeps the subject",
    )?;
    check(
        message.header.message_id.is_some(),
        "the mail has its Message-ID",
    )?;

    let read = session
        .mark_read(std::slice::from_ref(&received.id), true)
        .await
        .map_err(fail("mark read"))?;
    check(read[0].code == Outcome::Applied, "mark read applies")?;

    // Both copies go to Trash, then for good.
    clean_up(session, &trash, created).await
}

async fn clean_up(session: &Session, trash: &Id, created: &mut Created) -> Check {
    if let Some(draft) = created.draft.take() {
        drafts::delete(session, &draft)
            .await
            .map_err(fail("draft clean-up"))?;
    }
    if created.mails.is_empty() {
        return Ok(());
    }
    let moved = session
        .move_mail(&created.mails, trash)
        .await
        .map_err(fail("move to trash"))?;
    check(
        moved.iter().all(|row| row.code == Outcome::Applied),
        "both copies moved to Trash",
    )?;
    let deleted = session
        .delete(&created.mails, trash)
        .await
        .map_err(fail("delete"))?;
    check(
        deleted.iter().all(|row| row.code == Outcome::Applied),
        "both copies deleted",
    )?;
    created.mails.clear();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "talks to Tuta's servers: set TUTA_LIVE=1 and the TUTA_LIVE_* credentials"]
async fn login_sync_confidential_send_to_self_and_clean_up() {
    let Some(live) = live() else { return };
    let client = Client::new()
        .unwrap()
        .client_name("tuta-unofficial-sdk live test");
    let session = client
        .login(&live.email, &live.password, live.totp.as_deref())
        .await
        .expect("login");
    let mut created = Created::default();
    let outcome = run(&client, &session, &live.email, &mut created).await;
    // Whatever failed, remove what was created and close the session.
    let leftovers = match session.folders().await {
        Ok(folders) => match folders.iter().find(|f| f.role == FolderRole::Trash) {
            Some(trash) => clean_up(&session, &trash.id, &mut created).await,
            None => Err("no Trash to clean up into".into()),
        },
        Err(error) => Err(format!("folders for clean-up: {error}")),
    };
    let revoked = session.revoke().await;
    outcome.unwrap();
    leftovers.unwrap();
    revoked.expect("revoke");
}

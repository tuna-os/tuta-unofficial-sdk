//! List the folders of a Tuta account and read the newest mail in its Inbox.
//!
//! ```sh
//! TUTA_EMAIL=ada@tuta.com cargo run --example read_mail
//! ```
//!
//! The password is read from the first line of stdin (or `TUTA_PASSWORD`),
//! a TOTP code from `TUTA_TOTP` when the account has one. The session is
//! closed again at the end, so the example leaves nothing behind.

use secrecy::SecretString;
use std::io::BufRead;
use tuta_unofficial_sdk::{Client, Page};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let email = std::env::var("TUTA_EMAIL").map_err(|_| "set TUTA_EMAIL")?;
    let password = match std::env::var("TUTA_PASSWORD") {
        Ok(password) => password,
        Err(_) => {
            eprintln!("password (one line on stdin):");
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };
    let password = SecretString::from(password);
    let totp = std::env::var("TUTA_TOTP").ok();

    let client = Client::new()?.client_name("tuta-unofficial-sdk example");
    let session = client.login(&email, &password, totp.as_deref()).await?;

    println!("Folders:");
    for folder in session.folders().await? {
        println!("  {:<10} {}", format!("{:?}", folder.role), folder.label);
    }

    let page = session.sync(None, Page::new(1, 0)?).await?;
    println!("Inbox holds {} mail(s)", page.exists);
    if let Some(newest) = page.messages.first() {
        let message = session.message(&newest.header.id).await?;
        println!(
            "Newest: {:?} from {} ({} attachment(s), {})",
            message.header.subject,
            message.header.sender.address,
            message.attachments.len(),
            if message.header.confidential {
                "end-to-end encrypted"
            } else {
                "not end-to-end encrypted"
            }
        );
        let mime = message.to_mime();
        println!("As MIME: {} bytes", mime.len());
    }

    session.revoke().await?;
    Ok(())
}

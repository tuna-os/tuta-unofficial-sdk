//! Passwords for password-protected ("secure external") mail to recipients
//! outside Tuta, and the contacts Tuta keeps them on.
//!
//! The official client reads a recipient's password from their contact's
//! `presharedPassword` and writes it back there when a send changed it
//! (`SendMailModel.updateContacts`), so every Tuta app the user signs in to
//! offers the same password next time. This crate does the same, through
//! the SDK's `ContactFacade` (`sdk-patches/04-secure-external-recipient.patch`).
//!
//! Passwords are secrets: they are held in `Zeroizing` strings or
//! `SecretString`s, have no Debug form, and never reach the diagnostics.

use crate::{
    diag,
    send::{classify_recipients, valid_address, RecipientKind},
    Error, Result, Session,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use tutasdk::{
    entities::generated::tutanota::{Contact, ContactMailAddress},
    ApiCallError, GeneratedId, LoggedInSdk,
};
use zeroize::Zeroizing;

/// The most addresses one [`passwords`] or [`store_passwords`] takes: a
/// composer's recipients, not an address book.
pub const MAX_ADDRESSES: usize = 100;
/// TS `ContactAddressType.OTHER`, what `createNewContact` files an address as.
const CONTACT_ADDRESS_OTHER: i64 = 2;

/// Passwords by recipient address (the protocol's `passwords` object).
/// Addresses match ignoring case and surrounding space; passwords are
/// trimmed, and a blank one counts as missing.
#[derive(Default)]
pub struct Passwords(Vec<(String, Zeroizing<String>)>);

impl fmt::Debug for Passwords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Passwords({} redacted)", self.0.len())
    }
}

impl<'de> Deserialize<'de> for Passwords {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct PasswordMap;
        impl<'de> Visitor<'de> for PasswordMap {
            type Value = Passwords;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object of address to password")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Passwords, A::Error> {
                let mut passwords = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((address, password)) = map.next_entry::<String, String>()? {
                    // Moved, not copied: the only plaintext copy is the
                    // zeroizing one.
                    passwords.push((address, Zeroizing::new(password)));
                }
                Ok(Passwords(passwords))
            }
        }
        deserializer.deserialize_map(PasswordMap)
    }
}

impl Passwords {
    /// No passwords.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `address`'s password. The string is moved in and zeroed on drop.
    pub fn insert(&mut self, address: impl Into<String>, password: SecretString) {
        self.0.push((
            address.into(),
            Zeroizing::new(password.expose_secret().to_string()),
        ));
    }

    /// The password for `address`, trimmed as the official client trims it
    /// before use; None when there is none or it is blank. Addresses match
    /// ignoring case and surrounding space.
    pub fn get(&self, address: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| same_address(key, address))
            .map(|(_, password)| password.trim())
            .filter(|password| !password.is_empty())
    }

    /// Every address given, blank passwords included.
    pub fn addresses(&self) -> impl ExactSizeIterator<Item = &str> {
        self.0.iter().map(|(address, _)| address.as_str())
    }

    /// Whether no address has a non-blank password.
    pub fn is_empty(&self) -> bool {
        self.entries().next().is_none()
    }

    fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(address, password)| (address.as_str(), password.trim()))
            .filter(|(_, password)| !password.is_empty())
    }
}

fn same_address(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The first readable contact listing `address`, as the official client's
/// `ContactModel.searchForContact` resolves a recipient.
fn contact_for<'a>(contacts: &'a [Contact], address: &str) -> Option<&'a Contact> {
    contacts.iter().find(|contact| {
        contact._errors.is_empty()
            && contact
                .mailAddresses
                .iter()
                .any(|entry| same_address(&entry.address, address))
    })
}

fn stored_password(contact: &Contact) -> Option<&str> {
    contact
        .presharedPassword
        .as_deref()
        .filter(|password| !password.is_empty())
}

fn transport_or(error: &ApiCallError, code: Error) -> Error {
    match error {
        ApiCallError::RestClient { .. } => Error::TransportFailed,
        _ => code,
    }
}

async fn load_contacts(sdk: &LoggedInSdk) -> Result<Vec<Contact>> {
    sdk.contact_facade
        .load_all_user_contacts()
        .await
        .map_err(|error| {
            diag::failed("contact load", &error);
            transport_or(&error, Error::RequestFailed)
        })
}

/// TS `fullNameToFirstAndLastName`, or `mailAddressToFirstAndLastName` when
/// the recipient has no name: the first word, then the rest.
fn first_and_last_name(name: &str, address: &str) -> (String, String) {
    let name = name.trim();
    if !name.is_empty() {
        return match name.split_once(' ') {
            Some((first, last)) => (first.to_string(), last.to_string()),
            None => (name.to_string(), String::new()),
        };
    }
    let local = address.split('@').next().unwrap_or_default();
    let separator = ['.', '_', '-']
        .into_iter()
        .find(|separator| local.contains(*separator));
    let mut parts: Vec<String> = match separator {
        Some(separator) => local.split(separator).map(capitalized).collect(),
        None => vec![capitalized(local)],
    };
    let first = parts.remove(0);
    (first, parts.join(" "))
}

fn capitalized(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// TS `createNewContact` with the password set, as `updateContacts` stores a
/// new confidential external recipient.
fn new_contact(address: &str, name: &str, password: &str) -> Contact {
    let (first_name, last_name) = first_and_last_name(name, address);
    Contact {
        _id: None,
        _permissions: GeneratedId::min_id(),
        _format: 0,
        _ownerEncSessionKey: None,
        firstName: first_name,
        lastName: last_name,
        company: String::new(),
        role: String::new(),
        oldBirthdayDate: None,
        comment: String::new(),
        presharedPassword: Some(password.to_string()),
        _ownerGroup: None,
        nickname: None,
        title: None,
        birthdayIso: None,
        middleName: None,
        nameSuffix: None,
        phoneticFirst: None,
        phoneticMiddle: None,
        phoneticLast: None,
        department: None,
        _ownerKeyVersion: None,
        _kdfNonce: None,
        mailAddresses: vec![ContactMailAddress {
            _id: None,
            r#type: CONTACT_ADDRESS_OTHER,
            address: address.to_string(),
            customTypeName: String::new(),
            _errors: Default::default(),
        }],
        phoneNumbers: Vec::new(),
        addresses: Vec::new(),
        socialIds: Vec::new(),
        oldBirthdayAggregate: None,
        photo: None,
        customDate: Vec::new(),
        websites: Vec::new(),
        relationships: Vec::new(),
        messengerHandles: Vec::new(),
        pronouns: Vec::new(),
        _errors: Default::default(),
    }
}

/// One password to keep on a contact: the address, the recipient's name for
/// a new contact, the password.
struct PasswordWrite<'a> {
    address: &'a str,
    name: &'a str,
    password: &'a str,
}

/// What `save` does for one address, given the contacts there are.
#[derive(Debug, PartialEq, Eq)]
enum ContactWrite {
    Unchanged,
    Update(usize),
    Create,
}

fn contact_write(contacts: &[Contact], address: &str, password: &str) -> ContactWrite {
    match contact_for(contacts, address) {
        Some(contact) if stored_password(contact) == Some(password) => ContactWrite::Unchanged,
        Some(contact) => ContactWrite::Update(
            contacts
                .iter()
                .position(|c| std::ptr::eq(c, contact))
                .expect("a contact found in the list"),
        ),
        None => ContactWrite::Create,
    }
}

/// Keep each password on the recipient's contact: update one that holds a
/// different password, create one where the address has none. Every write
/// is attempted; the first failure's code comes back.
async fn save(sdk: &LoggedInSdk, entries: &[PasswordWrite<'_>]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let contacts = load_contacts(sdk).await?;
    let mut outcome = Ok(());
    for entry in entries {
        let written = match contact_write(&contacts, entry.address, entry.password) {
            ContactWrite::Unchanged => continue,
            ContactWrite::Update(index) => sdk
                .contact_facade
                .set_preshared_password(&contacts[index], entry.password)
                .await
                .map_err(|error| {
                    diag::failed("contact password (Contact patch)", &error);
                    transport_or(&error, Error::ContactSaveFailed)
                }),
            ContactWrite::Create => sdk
                .contact_facade
                .create_contact(new_contact(entry.address, entry.name, entry.password))
                .await
                .map(|_| ())
                .map_err(|error| {
                    diag::failed("contact create", &error);
                    transport_or(&error, Error::ContactSaveFailed)
                }),
        };
        if outcome.is_ok() {
            outcome = written;
        }
    }
    outcome
}

/// Keep the password of every recipient a send reached password-protected
/// (`sent_to`), the way `save` does; `recipients` pairs each address of the
/// mail with its display name, which names a new contact.
pub(crate) async fn save_for_sent(
    sdk: &LoggedInSdk,
    sent_to: &[String],
    passwords: &Passwords,
    recipients: &[(&str, &str)],
) -> Result<()> {
    let entries: Vec<PasswordWrite> = sent_to
        .iter()
        .filter_map(|address| {
            Some(PasswordWrite {
                address,
                name: recipients
                    .iter()
                    .find(|(candidate, _)| same_address(candidate, address))
                    .map_or("", |(_, name)| name),
                password: passwords.get(address)?,
            })
        })
        .collect();
    save(sdk, &entries).await
}

/// Keep every non-blank password on its address's contact, without sending.
pub(crate) async fn save_all(sdk: &LoggedInSdk, passwords: &Passwords) -> Result<()> {
    let entries: Vec<PasswordWrite> = passwords
        .entries()
        .map(|(address, password)| PasswordWrite {
            address,
            name: "",
            password,
        })
        .collect();
    save(sdk, &entries).await
}

/// One address as a composer needs it: whether it is outside Tuta (None when
/// the lookup failed) and the password its contact keeps (None for a Tuta
/// address or when none is kept).
pub struct ContactPassword {
    pub address: String,
    pub external: Option<bool>,
    pub password: Option<SecretString>,
}

impl fmt::Debug for ContactPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactPassword")
            .field("external", &self.external)
            .field("has_password", &self.password.is_some())
            .finish_non_exhaustive()
    }
}

impl Serialize for ContactPassword {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Row<'a> {
            address: &'a str,
            external: Option<bool>,
            password: Option<&'a str>,
        }
        Row {
            address: &self.address,
            external: self.external,
            password: self.password.as_ref().map(|p| p.expose_secret()),
        }
        .serialize(serializer)
    }
}

/// `ContactPassword` for each distinct address, in the given order.
async fn recipient_passwords(
    sdk: &LoggedInSdk,
    addresses: &[String],
) -> Result<Vec<ContactPassword>> {
    let addresses = crate::delivery::unique_addresses(addresses);
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let kinds = classify_recipients(sdk, &addresses).await;
    let contacts = load_contacts(sdk).await?;
    Ok(passwords_of(addresses, &kinds, &contacts))
}

fn passwords_of(
    addresses: Vec<String>,
    kinds: &[RecipientKind],
    contacts: &[Contact],
) -> Vec<ContactPassword> {
    addresses
        .into_iter()
        .zip(kinds)
        .map(|(address, kind)| {
            let external = match kind {
                RecipientKind::Internal => Some(false),
                RecipientKind::External => Some(true),
                RecipientKind::Unknown(_) => None,
            };
            let password = (external != Some(false))
                .then(|| contact_for(contacts, &address).and_then(stored_password))
                .flatten()
                .map(|password| SecretString::from(password.to_string()));
            ContactPassword {
                address,
                external,
                password,
            }
        })
        .collect()
}

/// The checks [`passwords`] and [`store_passwords`] make before any I/O: at
/// most [`MAX_ADDRESSES`] ([`Error::InvalidBatch`]), each one an address
/// ([`Error::InvalidRecipient`]).
pub fn check_addresses<'a>(addresses: impl ExactSizeIterator<Item = &'a str>) -> Result<()> {
    if addresses.len() > MAX_ADDRESSES {
        return Err(Error::InvalidBatch);
    }
    let mut addresses = addresses;
    if addresses.any(|address| !valid_address(address)) {
        return Err(Error::InvalidRecipient);
    }
    Ok(())
}

/// Per distinct address, in request order: whether it is outside Tuta and
/// the password its contact keeps, so a composer can fill passwords in.
pub async fn passwords(session: &Session, addresses: &[String]) -> Result<Vec<ContactPassword>> {
    check_addresses(addresses.iter().map(String::as_str))?;
    recipient_passwords(&session.sdk, addresses).await
}

/// Keep every non-blank password on its address's contact without
/// sending, for a send that is queued for later: a contact holding another
/// password is updated, an address without a contact gets a new one. A
/// blank password is skipped: it never clears one.
pub async fn store_passwords(session: &Session, passwords: &Passwords) -> Result<()> {
    check_addresses(passwords.addresses())?;
    save_all(&session.sdk, passwords).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use tutasdk::IdTupleGenerated;

    fn passwords(json: &str) -> Passwords {
        serde_json::from_str(json).unwrap()
    }

    fn contact(addresses: &[&str], password: Option<&str>) -> Contact {
        let mut contact = new_contact(addresses[0], "", password.unwrap_or_default());
        contact.presharedPassword = password.map(str::to_string);
        contact._id = Some(IdTupleGenerated::new(
            GeneratedId("list".into()),
            GeneratedId(addresses[0].into()),
        ));
        contact.mailAddresses = addresses
            .iter()
            .map(|address| ContactMailAddress {
                address: address.to_string(),
                ..contact.mailAddresses[0].clone()
            })
            .collect();
        contact
    }

    #[test]
    fn passwords_match_addresses_loosely_and_are_trimmed() {
        let passwords =
            passwords(r#"{"Ext@Example.org":"  s3cret pass ","blank@example.org":"   "}"#);
        assert_eq!(passwords.get("ext@example.org"), Some("s3cret pass"));
        assert_eq!(passwords.get(" EXT@example.ORG "), Some("s3cret pass"));
        assert_eq!(passwords.get("blank@example.org"), None);
        assert_eq!(passwords.get("other@example.org"), None);
        assert_eq!(
            passwords.entries().collect::<Vec<_>>(),
            [("Ext@Example.org", "s3cret pass")]
        );
    }

    #[test]
    fn passwords_never_show_in_debug_output() {
        let passwords = passwords(r#"{"ext@example.org":"hunter2"}"#);
        let printed = format!("{passwords:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(!printed.contains("ext@"), "{printed}");
    }

    #[test]
    fn passwords_must_be_an_object_of_strings() {
        for json in [r#"["a"]"#, r#"{"a@b.c":1}"#, r#""x""#] {
            assert!(serde_json::from_str::<Passwords>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn a_new_contact_is_named_as_the_official_client_names_it() {
        assert_eq!(
            first_and_last_name("Ada King Lovelace", "x@y.z"),
            ("Ada".into(), "King Lovelace".into())
        );
        assert_eq!(
            first_and_last_name(" Ada ", "x@y.z"),
            ("Ada".into(), "".into())
        );
        assert_eq!(
            first_and_last_name("", "ada.king.lovelace@example.org"),
            ("Ada".into(), "King Lovelace".into())
        );
        assert_eq!(
            first_and_last_name("", "ada_king@example.org"),
            ("Ada".into(), "King".into())
        );
        assert_eq!(
            first_and_last_name("", "ada@example.org"),
            ("Ada".into(), "".into())
        );
        let contact = new_contact("ada@example.org", "", "pw");
        assert_eq!(contact.presharedPassword.as_deref(), Some("pw"));
        assert_eq!(contact.mailAddresses.len(), 1);
        assert_eq!(contact.mailAddresses[0].address, "ada@example.org");
        assert_eq!(contact.mailAddresses[0].r#type, CONTACT_ADDRESS_OTHER);
    }

    #[test]
    fn a_contact_is_written_only_when_its_password_differs_or_it_is_missing() {
        let contacts = [
            contact(&["first@example.org"], None),
            contact(&["home@example.org", "Work@Example.org"], Some("same")),
        ];
        assert_eq!(
            contact_write(&contacts, "work@example.org", "same"),
            ContactWrite::Unchanged
        );
        assert_eq!(
            contact_write(&contacts, "work@example.org", "changed"),
            ContactWrite::Update(1)
        );
        assert_eq!(
            contact_write(&contacts, "first@example.org", "new"),
            ContactWrite::Update(0)
        );
        assert_eq!(
            contact_write(&contacts, "nobody@example.org", "new"),
            ContactWrite::Create
        );
    }

    #[test]
    fn rows_report_kind_and_a_stored_password_only_outside_tuta() {
        let addresses = [
            "ext@example.org".to_string(),
            "friend@tuta.com".to_string(),
            "unknown@example.org".to_string(),
            "none@example.org".to_string(),
        ];
        let kinds = [
            RecipientKind::External,
            RecipientKind::Internal,
            RecipientKind::Unknown(Error::TransportFailed),
            RecipientKind::External,
        ];
        let contacts = [
            contact(&["Ext@example.org"], Some("pw1")),
            contact(&["friend@tuta.com"], Some("ignored")),
            contact(&["unknown@example.org"], Some("pw3")),
            contact(&["none@example.org"], Some("")),
        ];
        let rows: Vec<Value> = passwords_of(addresses.to_vec(), &kinds, &contacts)
            .iter()
            .map(|row| serde_json::to_value(row).unwrap())
            .collect();
        assert_eq!(
            rows,
            [
                json!({"address": "ext@example.org", "external": true, "password": "pw1"}),
                json!({"address": "friend@tuta.com", "external": false, "password": null}),
                json!({"address": "unknown@example.org", "external": null, "password": "pw3"}),
                json!({"address": "none@example.org", "external": true, "password": null}),
            ]
        );
    }

    #[test]
    fn address_lists_are_bounded_and_well_formed() {
        assert_eq!(check_addresses(["a@b.c"].into_iter()), Ok(()));
        assert_eq!(
            check_addresses(["a@b.c", "nope"].into_iter()),
            Err(Error::InvalidRecipient)
        );
        let many = vec!["a@b.c"; MAX_ADDRESSES + 1];
        assert_eq!(check_addresses(many.into_iter()), Err(Error::InvalidBatch));
    }
}

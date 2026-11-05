//! Passwords for password-protected ("secure external") mail to recipients
//! outside Tuta, and the contacts Tuta keeps them on.
//!
//! The official client reads a recipient's password from their contact's
//! `presharedPassword` and writes it back there when a send changed it
//! (`SendMailModel.updateContacts`), so every Tuta app the user signs in to
//! offers the same password next time. The helper does the same, through the
//! SDK's `ContactFacade` (`sdk-patches/04-secure-external-recipient.patch`).
//!
//! Passwords are secrets: they are held in `Zeroizing` strings, have no Debug
//! form, and never reach the diagnostics.

use crate::{classify_recipients, diag, resume, valid_address, RecipientKind, Result, Session};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use std::fmt;
use tutasdk::{
    entities::generated::tutanota::{Contact, ContactMailAddress},
    ApiCallError, GeneratedId, LoggedInSdk, Sdk,
};
use zeroize::Zeroizing;

/// The most addresses one `contact_passwords` or `store_contact_passwords`
/// takes: a composer's recipients, not an address book.
const MAX_ADDRESSES: usize = 100;
/// TS `ContactAddressType.OTHER`, what `createNewContact` files an address as.
const CONTACT_ADDRESS_OTHER: i64 = 2;

/// Passwords by recipient address, as a request's `passwords` object.
#[derive(Default)]
pub(crate) struct Passwords(Vec<(String, Zeroizing<String>)>);

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
    /// The password for `address`, trimmed as the official client trims it
    /// before use; None when there is none or it is blank. Addresses match
    /// ignoring case and surrounding space.
    pub(crate) fn get(&self, address: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| same_address(key, address))
            .map(|(_, password)| password.trim())
            .filter(|password| !password.is_empty())
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

fn transport_or(error: &ApiCallError, code: &'static str) -> &'static str {
    match error {
        ApiCallError::RestClient { .. } => "transport_failed",
        _ => code,
    }
}

async fn load_contacts(sdk: &LoggedInSdk) -> Result<Vec<Contact>> {
    sdk.contact_facade
        .load_all_user_contacts()
        .await
        .map_err(|error| {
            diag::failed("contact load", &error);
            transport_or(&error, "request_failed")
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
pub(crate) struct ContactPassword<'a> {
    pub(crate) address: &'a str,
    pub(crate) name: &'a str,
    pub(crate) password: &'a str,
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
pub(crate) async fn save(sdk: &LoggedInSdk, entries: &[ContactPassword<'_>]) -> Result<()> {
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
                    transport_or(&error, "contact_save_failed")
                }),
            ContactWrite::Create => sdk
                .contact_facade
                .create_contact(new_contact(entry.address, entry.name, entry.password))
                .await
                .map(|_| ())
                .map_err(|error| {
                    diag::failed("contact create", &error);
                    transport_or(&error, "contact_save_failed")
                }),
        };
        if outcome.is_ok() {
            outcome = written;
        }
    }
    outcome
}

fn check_addresses<'a>(addresses: impl ExactSizeIterator<Item = &'a str>) -> Result<()> {
    if addresses.len() > MAX_ADDRESSES {
        return Err("invalid_batch");
    }
    let mut addresses = addresses;
    if addresses.any(|address| !valid_address(address)) {
        return Err("invalid_recipient");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactPasswords {
    session: Session,
    addresses: Vec<String>,
}

/// Each address once, in request order: whether it is outside Tuta (null
/// when the lookup failed) and the password its contact keeps (null for a
/// Tuta address or when none is kept), so a composer can fill it in.
pub(crate) async fn contact_passwords(sdk: &Sdk, request: ContactPasswords) -> Result<Value> {
    check_addresses(request.addresses.iter().map(String::as_str))?;
    let addresses = crate::delivery::unique_addresses(&request.addresses);
    if addresses.is_empty() {
        return Ok(json!({"recipients": []}));
    }
    let sdk = resume(sdk, request.session).await?;
    let kinds = classify_recipients(&sdk, &addresses).await;
    let contacts = load_contacts(&sdk).await?;
    Ok(json!({"recipients": recipient_rows(&addresses, &kinds, &contacts)}))
}

fn recipient_rows(
    addresses: &[String],
    kinds: &[RecipientKind],
    contacts: &[Contact],
) -> Vec<Value> {
    addresses
        .iter()
        .zip(kinds)
        .map(|(address, kind)| {
            let external = match kind {
                RecipientKind::Internal => Some(false),
                RecipientKind::External => Some(true),
                RecipientKind::Unknown(_) => None,
            };
            let password = (external != Some(false))
                .then(|| contact_for(contacts, address).and_then(stored_password))
                .flatten();
            json!({"address": address, "external": external, "password": password})
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreContactPasswords {
    session: Session,
    passwords: Passwords,
}

/// Keep passwords on contacts without sending, for a send that is queued
/// rather than sent now. A blank password is skipped: it never clears one.
pub(crate) async fn store_contact_passwords(
    sdk: &Sdk,
    request: StoreContactPasswords,
) -> Result<Value> {
    check_addresses(
        request
            .passwords
            .0
            .iter()
            .map(|(address, _)| address.as_str()),
    )?;
    let entries: Vec<ContactPassword> = request
        .passwords
        .entries()
        .map(|(address, password)| ContactPassword {
            address,
            name: "",
            password,
        })
        .collect();
    if entries.is_empty() {
        return Ok(json!({}));
    }
    let sdk = resume(sdk, request.session).await?;
    save(&sdk, &entries).await?;
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            RecipientKind::Unknown("transport_failed"),
            RecipientKind::External,
        ];
        let contacts = [
            contact(&["Ext@example.org"], Some("pw1")),
            contact(&["friend@tuta.com"], Some("ignored")),
            contact(&["unknown@example.org"], Some("pw3")),
            contact(&["none@example.org"], Some("")),
        ];
        let rows = recipient_rows(&addresses, &kinds, &contacts);
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
            Err("invalid_recipient")
        );
        let many = vec!["a@b.c"; MAX_ADDRESSES + 1];
        assert_eq!(check_addresses(many.into_iter()), Err("invalid_batch"));
    }
}

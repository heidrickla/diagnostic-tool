//! The page fixtures below are assumed layouts, not captures: Microsoft's help pages
//! ("Find your BitLocker recovery key", "Manage your work or school account connected devices")
//! name the steps (sign in, find the key ID, "View BitLocker Keys") but show the pages only
//! as screenshots. They are written as `document.body.innerText` would give such pages:
//! a table becomes tab-separated lines, a panel becomes one value per line. The reader is
//! built not to depend on the labels, only on keys sitting beside their IDs.
use super::*;
use std::sync::atomic::AtomicBool;

// Valid keys: every group is a multiple of 11 no larger than 720885.
const KEY_A: &str = "111111-222222-333333-444444-555555-666666-000000-121121";
const KEY_B: &str = "100001-200002-300003-400004-500005-600006-700007-088088";
const KEY_C: &str = "654654-123453-000011-720885-000022-010010-033033-044044";
const ID_A: &str = "5A1B2C3D-1111-2222-3333-444455556666";
const ID_B: &str = "9E8F7A6B-AAAA-BBBB-CCCC-DDDDEEEEFFFF";
const ID_C: &str = "0C0C0C0C-1234-5678-9ABC-DEF012345678";

/// Personal account page (account.microsoft.com/devices/recoverykey), assumed layout: a table
/// with the first eight characters of each key ID.
fn personal_page() -> String {
    format!(
        "Microsoft account\nYour info\nPrivacy\nSecurity\nDevices\n\
         BitLocker recovery keys\n\
         Your BitLocker recovery key can help you get back into your PC.\n\
         Device name\tKey ID\tRecovery key\tDrive\tKey upload date\n\
         DESKTOP-7K2M9QX\t5A1B2C3D\t{KEY_A}\tOS Volume\t3/14/2025\n\
         LAPTOP-4F5E6D7C\t9E8F7A6B\t{KEY_B}\tOS Volume\t11/2/2024\n\
         Delete\nHelp\nPrivacy & cookies  Terms of use  (c) Microsoft 2026\n"
    )
}

/// Work or school page (myaccount.microsoft.com, Devices, a device's "View BitLocker Keys"),
/// assumed layout: a panel with the whole key ID, one value per line, after the device's
/// own ID (also a GUID).
fn work_page() -> String {
    format!(
        "My Account\nOverview\nSecurity info\nDevices\nPassword\nOrganizations\n\
         Devices\nDisable a lost device and review your connected devices.\n\
         CONTOSO-LT-0042\nWindows\nDevice ID\n{}\nObject ID\n{}\n\
         BitLocker Keys\n\
         BitLocker Key ID\n{ID_A}\nRecovery Key\n{KEY_A}\nDrive Type\nOperating system drive\n\
         BitLocker Key ID\n{ID_C}\nRecovery Key\n{KEY_C}\nDrive Type\nFixed data drive\n\
         Close\n",
        "11112222-3333-4444-5555-666677778888", "AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111"
    )
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn found(read: PageRead) -> String {
    match read {
        PageRead::Found(key) => key.as_str().to_string(),
        other => panic!("expected a key, got {other:?}"),
    }
}

#[test]
fn the_personal_page_gives_the_key_for_the_recovery_screen_id() {
    let page = personal_page();
    assert_eq!(found(read_page(&page, &ids(&["5A1B2C3D"]))), KEY_A);
    assert_eq!(found(read_page(&page, &ids(&["9e8f7a6b"]))), KEY_B);
    // The drive's whole protector GUID matches the eight characters the page shows.
    assert_eq!(found(read_page(&page, &ids(&[ID_B]))), KEY_B);
    assert_eq!(
        found(read_page(&page, &ids(&[&format!("{{{ID_A}}}")]))),
        KEY_A
    ); // Two of the drive's IDs listed: the first one asked for gives the key.
    assert_eq!(
        found(read_page(&page, &ids(&["9E8F7A6B", "5A1B2C3D"]))),
        KEY_B
    );
}

#[test]
fn the_work_page_gives_the_key_for_the_whole_id_past_the_device_ids() {
    let page = work_page();
    assert_eq!(found(read_page(&page, &ids(&[ID_A]))), KEY_A);
    assert_eq!(found(read_page(&page, &ids(&["0C0C0C0C"]))), KEY_C);
    // A whole GUID that shares only the first eight characters is a different key.
    let near = "5A1B2C3D-0000-0000-0000-000000000000";
    assert!(matches!(
        read_page(&page, &ids(&[near])),
        PageRead::NotListed { keys: 2 }
    ));
}

#[test]
fn a_page_without_the_wanted_id_says_how_many_keys_it_lists() {
    assert!(matches!(
        read_page(&personal_page(), &ids(&["0C0C0C0C"])),
        PageRead::NotListed { keys: 2 }
    ));
    assert!(matches!(
        read_page(&personal_page(), &[]),
        PageRead::NotListed { keys: 2 }
    ));
}

#[test]
fn a_page_without_keys_is_not_understood() {
    let signed_out = "Sign in\nEmail, phone, or Skype\nNo account? Create one!\nNext\n5A1B2C3D";
    assert!(matches!(
        read_page(signed_out, &ids(&["5A1B2C3D"])),
        PageRead::NotUnderstood
    ));
}

#[test]
fn a_layout_with_the_key_before_its_id_is_read_that_way() {
    let page = format!(
        "Recovery key\n{KEY_A}\nKey ID\n5A1B2C3D\n\nRecovery key\n{KEY_B}\nKey ID\n9E8F7A6B\n"
    );
    assert_eq!(found(read_page(&page, &ids(&["9E8F7A6B"]))), KEY_B);
    assert_eq!(found(read_page(&page, &ids(&["5A1B2C3D"]))), KEY_A);
}

#[test]
fn an_id_between_two_keys_with_no_clear_order_is_not_guessed() {
    let page = format!("{KEY_A}\n5A1B2C3D\n{KEY_B}\n");
    assert!(matches!(
        read_page(&page, &ids(&["5A1B2C3D"])),
        PageRead::NotUnderstood
    ));
    // One key beside the ID, nothing on the other side: that key.
    let page = format!("Key ID 5A1B2C3D\n{KEY_A}\n");
    assert_eq!(found(read_page(&page, &ids(&["5A1B2C3D"]))), KEY_A);
}

#[test]
fn only_real_recovery_keys_are_read() {
    // A group that is not a multiple of 11, and one past 65535 * 11.
    let bad_check = "123456-222222-333333-444444-555555-666666-000000-121121";
    let too_big = "999999-222222-333333-444444-555555-666666-000000-121121";
    // Nine groups: no key is read out of the middle of it.
    let nine = format!("{KEY_A}-111111");
    let seven = "111111-222222-333333-444444-555555-666666-000000";
    let long_group = "1111111-222222-333333-444444-555555-666666-000000-121121";
    for text in [bad_check, too_big, nine.as_str(), seven, long_group] {
        let page = format!("Key ID 5A1B2C3D\n{text}\n");
        assert!(
            matches!(
                read_page(&page, &ids(&["5A1B2C3D"])),
                PageRead::NotUnderstood
            ),
            "{text}"
        );
    }
}

#[test]
fn keys_written_with_spaces_or_typographic_hyphens_are_read() {
    let spaced = KEY_A.replace('-', " ");
    let nbsp = KEY_A.replace('-', "\u{a0}");
    let hyphen = KEY_A.replace('-', "\u{2011}");
    for text in [spaced, nbsp, hyphen] {
        let page = format!("5A1B2C3D {text}");
        assert_eq!(found(read_page(&page, &ids(&["5A1B2C3D"]))), KEY_A);
    }
}

#[test]
fn device_names_and_words_are_not_taken_for_key_ids() {
    let found = find_key_ids("LAPTOP-4F5E6D7C DEADBEEFS xDEADBEEF DEADBEEF_1 1A2B3C4D-x");
    assert!(found.is_empty(), "{found:?}");
    let found = find_key_ids("(1A2B3C4D) {5A1B2C3D-1111-2222-3333-444455556666}");
    let prefixes: Vec<&str> = found.iter().map(|(_, id)| id.prefix.as_str()).collect();
    assert_eq!(prefixes, ["1A2B3C4D", "5A1B2C3D"]);
    assert!(found[1].1.full.is_some());
}

#[test]
fn key_ids_are_read_as_people_and_windows_write_them() {
    let short = KeyId::parse(" 5a1b2c3d ").expect("eight hex digits");
    assert_eq!(short.prefix, "5A1B2C3D");
    assert_eq!(short.full, None);
    let full = KeyId::parse(&format!("{{{}}}", ID_A.to_lowercase())).expect("a GUID");
    assert_eq!(full.full.as_deref(), Some(ID_A));
    assert!(short.matches(&full) && full.matches(&short));
    for bad in ["", "5A1B2C3", "5A1B2C3G", "5A1B2C3D-1111", "not an id"] {
        assert_eq!(KeyId::parse(bad), None, "{bad}");
    }
}

#[test]
fn a_secret_key_never_prints_its_digits() {
    let page = format!("5A1B2C3D {KEY_A}");
    let PageRead::Found(key) = read_page(&page, &ids(&["5A1B2C3D"])) else {
        panic!("no key");
    };
    let shown = format!(
        "{key:?} {:?}",
        PageRead::Found(SecretKey::from_groups(&[11; 8]))
    );
    assert_eq!(
        shown,
        "SecretKey(48 digits, hidden) Found(SecretKey(48 digits, hidden))"
    );
    assert_eq!(&key.as_str()[KEY_LEN - 6..], "121121");
}

#[test]
fn scrub_zeroes_a_buffer() {
    let mut buffer = *b"111111-222222";
    scrub(&mut buffer);
    assert_eq!(buffer, [0u8; 13]);
    let mut wide = [0x31u16; 6];
    scrub_wide(&mut wide);
    assert_eq!(wide, [0u16; 6]);
}

#[test]
fn script_results_are_decoded_from_json_strings() {
    let text = decode_script_string(r#""Key ID\t5A1B2C3D\n\"quoted\" \\ \/ \u00e9 \ud83d\ude00""#)
        .expect("a JSON string");
    assert_eq!(
        text.as_str(),
        "Key ID\t5A1B2C3D\n\"quoted\" \\ / \u{e9} \u{1F600}"
    );
    assert!(decode_script_string("null").is_none());
    assert!(decode_script_string(r#""bad \x escape""#).is_none());
    assert!(decode_script_string(r#""lone \ud83d surrogate""#).is_none());
}

#[test]
fn the_sign_in_window_keeps_to_microsoft_hosts() {
    for allowed in [
        "https://login.live.com/oauth20_authorize.srf?client_id=x",
        "https://account.microsoft.com/devices/recoverykey",
        "https://LOGIN.MICROSOFTONLINE.COM/common/oauth2/v2.0/authorize",
        "https://myaccount.microsoft.com:443/device-list",
        "https://login.live.com./ppsecure/post.srf",
        "https://account.live.com/proofs/Add",
        "about:blank",
    ] {
        assert_eq!(navigation_allowed(allowed), Ok(()), "{allowed}");
    }
    let refused = [
        ("https://www.example.com/", "www.example.com"),
        (
            "https://login.live.com.example.com/",
            "login.live.com.example.com",
        ),
        ("https://evil-login.live.com/", "evil-login.live.com"),
        (
            "https://login.live.com@example.com/",
            "an address with a user name or an unusual port",
        ),
        (
            "https://login.live.com:8443/",
            "an address with a user name or an unusual port",
        ),
        ("http://login.live.com/", "an address starting http:"),
        ("javascript:alert(1)", "an address starting javascript:"),
        ("data:text/html,hi", "an address starting data:"),
        ("file:///C:/Windows/win.ini", "an address starting file:"),
        ("", "an address that is not https"),
    ];
    for (uri, why) in refused {
        assert_eq!(navigation_allowed(uri), Err(why.to_string()), "{uri}");
    }
    assert_eq!(
        host_of("https://login.live.com/ppsecure/post.srf?code=secret"),
        "login.live.com"
    );
}

#[test]
fn the_key_page_is_known_by_host_and_path() {
    assert!(Account::Personal.is_key_page("https://account.microsoft.com/devices/recoverykey"));
    assert!(Account::Personal.is_key_page(
        "https://account.microsoft.com/devices/RecoveryKey?refd=account.microsoft.com"
    ));
    assert!(!Account::Personal.is_key_page("https://account.microsoft.com/devices"));
    assert!(!Account::Personal.is_key_page("https://login.live.com/devices/recoverykey"));
    assert!(Account::WorkOrSchool.is_key_page("https://myaccount.microsoft.com/device-list"));
    assert!(!Account::WorkOrSchool.is_key_page("https://myaccount.microsoft.com/"));
    for account in [Account::Personal, Account::WorkOrSchool] {
        assert_eq!(navigation_allowed(account.start_url()), Ok(()));
        assert!(account.is_key_page(account.start_url()));
    }
}

/// A key file as the BitLocker wizard's "Save to a file" writes it (assumed from its known
/// wording; UTF-16 with a byte order mark, CRLF lines).
fn key_file_text(id: &str, key: &str) -> String {
    format!(
        "BitLocker Drive Encryption recovery key \r\n\r\n\
         To verify that this is the correct recovery key, compare the start of the following \
         identifier with the identifier value displayed on your PC.\r\n\r\n\
         Identifier:\r\n\r\n\t{id}\r\n\r\n\
         If the above identifier matches the one displayed by your PC, then use the following \
         key to unlock your drive.\r\n\r\n\
         Recovery Key:\r\n\r\n\t{key}\r\n\r\n\
         If the above identifier doesn't match the one displayed by your PC, then this isn't \
         the right key to unlock your drive.\r\n\
         Try another recovery key, or refer to https://go.microsoft.com/fwlink/?LinkID=260589 \
         for additional assistance.\r\n"
    )
}

fn utf16_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

#[test]
fn key_file_names_give_their_key_id() {
    let id = key_file_id(&format!("BitLocker Recovery Key {ID_A}.TXT")).expect("a key file");
    assert_eq!(id.full.as_deref(), Some(ID_A));
    for name in [
        format!("bitlocker recovery key {}.txt", ID_A.to_lowercase()),
        format!("BitLocker Recovery Key {ID_A} (1).TXT"),
        format!("BitLocker Recovery Key {{{ID_A}}}.TXT"),
    ] {
        assert!(key_file_id(&name).is_some(), "{name}");
    }
    for name in [
        format!("BitLocker Recovery Key {ID_A}.TXT.lnk"),
        format!("BitLocker Recovery Key {ID_A} copy.TXT"),
        "BitLocker Recovery Key 5A1B2C3D.TXT".to_string(),
        format!("{ID_A}.BEK"),
    ] {
        assert!(key_file_id(&name).is_none(), "{name}");
    }
}

#[test]
fn key_files_are_read_in_utf16_and_utf8() {
    let id = KeyId::parse(ID_A).expect("id");
    let text = key_file_text(ID_A, KEY_A);
    let key = read_key_file(&utf16_with_bom(&text), &id).expect("UTF-16 file");
    assert_eq!(key.as_str(), KEY_A);
    let key = read_key_file(text.as_bytes(), &id).expect("UTF-8 file");
    assert_eq!(key.as_str(), KEY_A);
    // A file whose stated identifier is not the one in its name is not trusted.
    let other = key_file_text(ID_B, KEY_B);
    assert!(read_key_file(&utf16_with_bom(&other), &id).is_none());
    // A damaged key is not returned.
    let damaged = key_file_text(ID_A, &KEY_A.replace("121121", "121122"));
    assert!(read_key_file(&utf16_with_bom(&damaged), &id).is_none());
}

/// A folder tree with key files at three depths and one damaged file, removed on drop.
struct KeyTree(PathBuf);

impl KeyTree {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("keylookup-{tag}-{}", std::process::id()));
        let deep = root.join("Users").join("Documents");
        let too_deep = deep.join("Old");
        std::fs::create_dir_all(&too_deep).expect("folders");
        let write = |folder: &Path, id: &str, key: &str| {
            let path = folder.join(format!("BitLocker Recovery Key {id}.TXT"));
            std::fs::write(&path, utf16_with_bom(&key_file_text(id, key))).expect("write");
        };
        write(&deep, ID_A, KEY_A);
        write(&root, ID_B, KEY_B);
        write(&too_deep, ID_C, KEY_C);
        // Named for a wanted ID, but its key is damaged.
        let damaged = key_file_text("0C0C0C0C-0000-0000-0000-000000000000", "1-2");
        let name = "BitLocker Recovery Key 0C0C0C0C-0000-0000-0000-000000000000.TXT";
        std::fs::write(root.join(name), utf16_with_bom(&damaged)).expect("write");
        KeyTree(root)
    }

    fn options(&self, depth: usize) -> KeyFileSearchOptions {
        KeyFileSearchOptions {
            key_ids: ids(&[ID_A, "0C0C0C0C"]),
            folders: vec![self.0.clone()],
            search_drives: false,
            folder_depth: depth,
            ..Default::default()
        }
    }
}

impl Drop for KeyTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_folder_search_finds_wanted_key_files_to_its_depth() {
    let tree = KeyTree::new("depth");
    let mut events = Vec::new();
    let cancel = AtomicBool::new(false);
    let result =
        search_key_files(&tree.options(2), &mut |e| events.push(e.clone()), &cancel).expect("ok");
    assert_eq!(result.stop, SearchStop::Finished);
    assert_eq!(result.keys.len(), 1, "{result:?}");
    assert_eq!(result.keys[0].key.as_str(), KEY_A);
    assert_eq!(result.found[0].key_id, ID_A);
    assert_eq!(result.unusable.len(), 1, "{result:?}");
    assert_eq!(result.roots_searched, vec![tree.0.clone()]);
    assert!(events.contains(&KeyFileEvent::Searching {
        root: tree.0.clone()
    }));
    assert!(events
        .iter()
        .any(|e| matches!(e, KeyFileEvent::Found { key_id, .. } if key_id == ID_A)));
    // The serialized result and events carry paths and IDs, never a key.
    let json = serde_json::to_string(&result).expect("serializes");
    let events_json = serde_json::to_string(&events).expect("serializes");
    for text in [&json, &events_json] {
        assert!(!text.contains("111111"), "{text}");
        assert!(!text.contains("654654"), "{text}");
    }
    let deeper = search_key_files(&tree.options(3), &mut |_| {}, &cancel).expect("ok");
    assert_eq!(deeper.keys.len(), 2);
}

#[test]
fn a_cancelled_search_says_so() {
    let tree = KeyTree::new("cancel");
    let result =
        search_key_files(&tree.options(2), &mut |_| {}, &AtomicBool::new(true)).expect("ok");
    assert_eq!(result.stop, SearchStop::Cancelled);
}

#[test]
fn search_options_out_of_bounds_are_refused() {
    let good = KeyFileSearchOptions {
        key_ids: ids(&["5A1B2C3D"]),
        ..Default::default()
    };
    assert!(good.check().is_ok());
    let cases = [
        KeyFileSearchOptions {
            key_ids: ids(&["nope"]),
            ..good.clone()
        },
        KeyFileSearchOptions {
            key_ids: vec!["5A1B2C3D".to_string(); 17],
            ..good.clone()
        },
        KeyFileSearchOptions {
            drive_depth: 3,
            ..good.clone()
        },
        KeyFileSearchOptions {
            folder_depth: 9,
            ..good.clone()
        },
        KeyFileSearchOptions {
            time_limit_secs: 0,
            ..good.clone()
        },
        KeyFileSearchOptions {
            entry_limit: 0,
            ..good.clone()
        },
        KeyFileSearchOptions {
            search_drives: false,
            ..good.clone()
        },
    ];
    for options in cases {
        let refused = search_key_files(&options, &mut |_| {}, &AtomicBool::new(false));
        assert!(refused.is_err(), "{options:?}");
    }
    // An agent's options: unknown fields are refused, missing ones take the defaults.
    let parsed: KeyFileSearchOptions =
        serde_json::from_str(r#"{"key_ids":["5A1B2C3D"],"folder_depth":4}"#).expect("parses");
    assert_eq!(parsed.folder_depth, 4);
    assert_eq!(parsed.drive_depth, 2);
    assert!(serde_json::from_str::<KeyFileSearchOptions>(r#"{"key_ids":[],"depth":1}"#).is_err());
}

fn sign_in(account: Account) -> SignIn {
    let mut sign_in = SignIn::new(&SignInOptions {
        key_ids: ids(&[ID_A, "5a1b2c3d", "9E8F7A6B"]),
        account: None,
    })
    .expect("options");
    sign_in.choose(account);
    sign_in
}

#[test]
fn the_sign_in_step_names_the_key_ids_to_look_for() {
    let mut step = sign_in(Account::Personal);
    assert_eq!(step.shown_ids(), "5A1B2C3D or 9E8F7A6B");
    let not_listed = format!("Key ID 0C0C0C0C {KEY_C}");
    let ReadStep::Tell(text) = step.page_text_after(Some(&not_listed), Duration::ZERO) else {
        panic!("a message");
    };
    assert!(
        text.contains("one recovery key, none with key ID 5A1B2C3D or 9E8F7A6B"),
        "{text}"
    );
    // Said once; the page keeps being read.
    assert_eq!(
        step.page_text_after(Some(&not_listed), Duration::ZERO),
        ReadStep::Wait
    );
}

#[test]
fn an_unreadable_key_page_waits_for_the_grace_then_says_copy_by_hand() {
    let mut step = sign_in(Account::WorkOrSchool);
    assert_eq!(
        step.page_text_after(Some("Loading"), Duration::from_secs(2)),
        ReadStep::Wait
    );
    let ReadStep::Tell(text) = step.page_text_after(None, READ_GRACE) else {
        panic!("a message");
    };
    assert!(text.contains("starts with 5A1B2C3D or 9E8F7A6B"), "{text}");
    let result = step.finish(true);
    assert_eq!(result.outcome, SignInOutcome::NotUnderstood);
    assert!(result.key.is_none());
}

#[test]
fn a_read_key_goes_to_the_result_but_never_into_its_serialized_form() {
    let mut step = sign_in(Account::Personal);
    assert_eq!(
        step.navigation("https://login.live.com/oauth20_authorize.srf?code=x", false),
        Ok(())
    );
    let refused = step.navigation("https://www.example.com/", false);
    assert!(refused
        .unwrap_err()
        .contains("www.example.com was not opened"));
    assert_eq!(step.should_read("https://login.live.com/"), (false, None));
    assert_eq!(
        step.should_read(Account::Personal.start_url()),
        (true, Some("Reading the recovery key page."))
    );
    // Microsoft sends the key page on to sign in first: the window says so.
    assert_eq!(
        step.should_read("https://login.live.com/oauth20_authorize.srf"),
        (false, Some(SIGNING_IN))
    );
    assert_eq!(step.should_read("https://login.live.com/"), (false, None));
    assert_eq!(
        step.should_read(Account::Personal.start_url()),
        (true, Some("Reading the recovery key page."))
    );
    assert_eq!(
        step.page_text_after(Some(&personal_page()), Duration::ZERO),
        ReadStep::Done
    );
    let events = step.take_events();
    assert_eq!(events.last(), Some(&SignInEvent::KeyRead));
    let result = step.finish(true);
    assert_eq!(result.outcome, SignInOutcome::KeyRead);
    assert_eq!(result.key.as_ref().map(SecretKey::as_str), Some(KEY_A));
    assert_eq!(result.hosts_opened, ["login.live.com"]);
    assert_eq!(result.hosts_refused, ["www.example.com"]);
    let json = serde_json::to_string(&result).expect("serializes");
    assert!(!json.contains("111111"), "{json}");
    assert!(json.contains(r#""outcome":{"kind":"key_read"}"#), "{json}");
    assert!(!serde_json::to_string(&events)
        .expect("events")
        .contains("111111"));
}

#[test]
fn a_refused_page_on_a_work_account_names_company_sign_in() {
    let mut work = sign_in(Account::WorkOrSchool);
    let text = work
        .navigation("https://adfs.contoso.com/", false)
        .unwrap_err();
    assert!(text.contains("company page"), "{text}");
    let mut personal = sign_in(Account::Personal);
    let text = personal
        .new_window("https://adfs.contoso.com/")
        .unwrap_err();
    assert!(!text.contains("company page"), "{text}");
    assert_eq!(
        personal.new_window("https://account.microsoft.com/"),
        Ok(())
    );
    assert_eq!(personal.finish(true).outcome, SignInOutcome::Cancelled);
}

#[test]
fn sign_in_options_need_a_key_id() {
    assert!(SignIn::new(&SignInOptions::default()).is_err());
    let parsed: SignInOptions =
        serde_json::from_str(r#"{"key_ids":["5A1B2C3D"],"account":"work_or_school"}"#)
            .expect("parses");
    assert_eq!(parsed.account, Some(Account::WorkOrSchool));
}

#[test]
fn sign_in_folders_are_new_and_named_for_the_sweep() {
    let folder = new_sign_in_folder().expect("a folder");
    let name = folder
        .file_name()
        .expect("name")
        .to_string_lossy()
        .to_string();
    assert!(is_sign_in_folder_name(&name), "{name}");
    assert!(std::fs::read_dir(&folder).expect("empty").next().is_none());
    std::fs::remove_dir(&folder).expect("clean up");
    for other in [
        "DiagnosticTool-signin-",
        "DiagnosticTool-signin-0123456789abcdeg",
        "DiagnosticTool-signin-0123456789abcdef0",
        "Other-0123456789abcdef",
    ] {
        assert!(!is_sign_in_folder_name(other), "{other}");
    }
}

/// The guard: each buffer that holds a recovery key asks Windows to leave it out of dumps
/// of this process while it lives (the typed key, a key found in a file or on the account
/// page, the page and file text it was read from), and takes the request back after the
/// buffer is zeroed and before it is freed (the shield is declared before the text).
#[test]
fn key_buffers_ask_to_be_left_out_of_dumps() {
    let id = KeyId::parse(ID_A).expect("id");
    let key = read_key_file(key_file_text(ID_A, KEY_A).as_bytes(), &id).expect("key");
    assert!(key.shielded());
    assert!(ScrubbedText::with_capacity(64).shielded());
    let mut grown = ScrubbedText::with_capacity(1);
    for c in "page text longer than its first buffer".chars() {
        grown.push(c);
    }
    assert!(grown.shielded());
    let page = decode_script_string(r#""Key ID 5A1B2C3D""#).expect("page text");
    assert!(page.shielded());
    assert!(crate::recovery::bitlocker::KeyText::new(KEY_A.to_string()).shielded());
    let buffer = [1u8; 64];
    assert!(DumpShield::over(buffer.as_ptr(), buffer.len()).is_some());
    assert!(DumpShield::over(buffer.as_ptr(), 0).is_none());

    let shield_first = |code: &str, type_line: &str| {
        let at = code.find(type_line).expect(type_line);
        let body = &code[at..at + code[at..].find("\n}\n").unwrap()];
        let shield = body.find("shield: Option<DumpShield>,").expect(type_line);
        let text = body.find("text: ").expect(type_line);
        assert!(shield < text, "{type_line}");
    };
    let lookup = include_str!("../keylookup.rs");
    shield_first(lookup, "pub struct ScrubbedText {");
    shield_first(lookup, "pub struct SecretKey {");
    let bitlocker = include_str!("../bitlocker.rs");
    shield_first(bitlocker, "pub struct KeyText {");
    shield_first(bitlocker, "pub struct RecoveryKey {");
    // A key file is read only into `SecretBytes`, shielded before a byte is read and zeroed
    // whole when dropped, on every path.
    let code = lookup.split("#[cfg(test)]").next().unwrap();
    assert!(
        !code.contains("std::fs::read("),
        "a key file read into a plain buffer"
    );
    let try_file = &code[code.find("fn try_key_file(").unwrap()..];
    let try_file = &try_file[..try_file.find("\n}\n").unwrap()];
    assert!(try_file.contains("SecretBytes::read_to_end(&mut file, KEY_FILE_LIMIT as usize)"));
    assert!(try_file.contains("read_key_file(bytes.as_slice(), &id)"));
    let read = &code[code.find("    pub fn read_to_end(").unwrap()..];
    assert!(
        read.find("DumpShield::over(bytes.as_ptr()").unwrap() < read.find("reader.read(").unwrap()
    );
    let bytes = &code[code.find("pub struct SecretBytes {").unwrap()..];
    let bytes = &bytes[..bytes.find("\n}\n").unwrap()];
    assert!(
        bytes.find("_shield: Option<DumpShield>,").unwrap() < bytes.find("bytes: Vec<u8>").unwrap()
    );
    let drop_code = &code[code.find("impl Drop for SecretBytes").unwrap()..];
    let drop_code = &drop_code[..drop_code.find("\n}\n").unwrap()];
    assert!(drop_code.contains("self.bytes.resize(self.bytes.capacity(), 0);"));
}

/// The guard: a folder the key file search cannot read is counted and named, never passed
/// over as searched with nothing found.
#[test]
fn a_folder_that_cannot_be_read_is_said() {
    let missing =
        std::env::temp_dir().join(format!("diagtool-no-such-folder-{}", std::process::id()));
    let options = KeyFileSearchOptions {
        key_ids: ids(&[ID_A]),
        folders: vec![missing.clone()],
        search_drives: false,
        ..Default::default()
    };
    let mut events = Vec::new();
    let result = search_key_files(
        &options,
        &mut |e| events.push(e.clone()),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(result.unreadable_count, 1, "{result:?}");
    assert_eq!(result.unreadable[0].0, missing);
    assert!(events
        .iter()
        .any(|e| matches!(e, KeyFileEvent::Unreadable { .. })));
}

/// The guard: a refusal the browser did not take ends the sign-in: nothing more is read
/// and no key is given, even one read before.
#[test]
fn a_refusal_that_did_not_take_ends_the_sign_in() {
    let mut step = sign_in(Account::Personal);
    let text = step.could_not_refuse("a download");
    assert!(text.contains("could not refuse a download"), "{text}");
    assert!(step.broken());
    assert_eq!(
        step.should_read(Account::Personal.start_url()),
        (false, None),
        "the key page is not read once a refusal did not take"
    );
    let result = step.finish(true);
    assert!(
        matches!(result.outcome, SignInOutcome::Unavailable { .. }),
        "{:?}",
        result.outcome
    );
    assert!(result.key.is_none());
}

/// The guard: the exclusion from crash dumps lives as long as any key it covers. Each key
/// found, in a search result, a sign-in result or held by a caller after the lookup
/// returned, and each typed or parsed key, holds a share of it; a search thread still
/// running past the time limit holds one until it ends.
#[test]
fn every_key_holds_the_exclusion_while_it_lives() {
    use crate::tools::crash_dumps::keep_out_of_dumps;
    let held = keep_out_of_dumps().unwrap();
    let id = KeyId::parse(ID_A).expect("id");
    let key = read_key_file(key_file_text(ID_A, KEY_A).as_bytes(), &id).expect("key");
    assert!(key.exclusion().unwrap().same(&held));
    let typed = crate::recovery::bitlocker::KeyText::new(KEY_A.to_string());
    assert!(typed.exclusion().unwrap().same(&held));
    let page = format!("Key ID: {ID_A}\nRecovery key: {KEY_A}\n");
    let read = read_page(&page, &[ID_A.to_string()]);
    let PageRead::Found(from_page) = read else {
        panic!("no key read from the page")
    };
    assert!(from_page.exclusion().unwrap().same(&held));
    drop(held);
    // The lookup returned and dropped its own share; the key still holds the same one.
    let tree = KeyTree::new("share");
    let result =
        search_key_files(&tree.options(2), &mut |_| {}, &AtomicBool::new(false)).expect("ok");
    let later = keep_out_of_dumps().unwrap();
    assert!(result.keys[0].key.exclusion().unwrap().same(&later));
    assert!(key.exclusion().unwrap().same(&later));

    let code = include_str!("../keylookup.rs");
    let search = &code[code.find("pub fn search_key_files(").unwrap()..];
    let spawn = &search[search.find(".spawn(move || {").unwrap()..];
    let spawn = &spawn[..spawn.find("});").unwrap()];
    assert!(
        spawn.contains("drop(share);"),
        "each search thread holds a share to its end"
    );
    let bitlocker = include_str!("../bitlocker.rs");
    let parse = &bitlocker[bitlocker.find("pub fn parse(typed: &str)").unwrap()..];
    assert!(parse.contains("_dumps: crate::tools::crash_dumps::exclusion_share(),"));
}

/// The test binary's allocator, which looks at one watched block as it is freed: whether
/// every byte of it is zero then. The block is still the program's while it is looked at,
/// so this observes what a freed key buffer leaves behind without reading freed memory.
pub(crate) mod zero_watch {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    static WATCHED: AtomicUsize = AtomicUsize::new(0);
    /// 0 not freed yet, 1 freed all zero, 2 freed holding a byte that is not zero.
    static FREED: AtomicU8 = AtomicU8::new(0);
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub struct Watch;

    // SAFETY: every call is passed to the system allocator unchanged; the watched block is
    // only read, within its layout, before it is passed on to be freed.
    unsafe impl GlobalAlloc for Watch {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: as the caller's contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
            if !block.is_null() && block as usize == WATCHED.load(Ordering::SeqCst) {
                // SAFETY: the block is allocated with `layout` until freed just below.
                let zero = (0..layout.size()).all(|i| unsafe { block.add(i).read_volatile() } == 0);
                FREED.store(if zero { 1 } else { 2 }, Ordering::SeqCst);
                WATCHED.store(0, Ordering::SeqCst);
            }
            // SAFETY: as the caller's contract.
            unsafe { System.dealloc(block, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Watch = Watch;

    /// Whether the block at `block` holds only zeros when `free` frees it. Panics when
    /// `free` does not free it.
    pub fn freed_zeroed(block: *const u8, free: impl FnOnce()) -> bool {
        let _one = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        FREED.store(0, Ordering::SeqCst);
        WATCHED.store(block as usize, Ordering::SeqCst);
        free();
        WATCHED.store(0, Ordering::SeqCst);
        match FREED.load(Ordering::SeqCst) {
            1 => true,
            2 => false,
            _ => panic!("the watched block was not freed"),
        }
    }
}

/// The guard: each key type's memory holds only zeros when it is freed, its spare capacity
/// included. A plain buffer, freed the same way, does not: the watch sees key bytes.
#[test]
fn key_buffers_hold_only_zeros_when_freed() {
    let plain = KEY_A.as_bytes().to_vec();
    assert!(!zero_watch::freed_zeroed(plain.as_ptr(), || drop(plain)));

    let key = find_keys(KEY_A).remove(0).1;
    let at = key.text.as_ptr();
    assert!(zero_watch::freed_zeroed(at, || drop(key)));

    let mut text = ScrubbedText::with_capacity(128);
    for c in KEY_A.chars() {
        text.push(c);
    }
    let at = text.text.as_ptr();
    assert!(zero_watch::freed_zeroed(at, || drop(text)));

    let bytes = SecretBytes::read_to_end(&mut KEY_A.as_bytes(), 1024).unwrap();
    assert_eq!(bytes.as_slice(), KEY_A.as_bytes());
    let at = bytes.as_slice().as_ptr();
    assert!(zero_watch::freed_zeroed(at, || drop(bytes)));
}

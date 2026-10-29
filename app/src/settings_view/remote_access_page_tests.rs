use super::*;

#[test]
fn page_is_unavailable_without_stub_server() {
    // The unit-test process never enables the offline stub server, so the page stays hidden.
    assert!(!is_remote_access_available());
}

#[test]
fn section_slug_roundtrips() {
    let section = SettingsSection::RemoteAccess;
    assert_eq!(SettingsSection::from_slug(&section.to_string()), Some(section));
}

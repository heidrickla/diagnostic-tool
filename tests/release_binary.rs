//! Checks on the built DiagnosticTool.exe itself: what it imports and what it embeds.
#![cfg(windows)]

#[path = "../xtask/src/pe.rs"]
mod pe;

fn exe_bytes() -> Vec<u8> {
    let path = env!("CARGO_BIN_EXE_DiagnosticTool");
    std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

#[test]
fn gui_exe_imports_no_c_runtime_dll() {
    let bytes = exe_bytes();
    let image = pe::Pe::parse(&bytes).expect("DiagnosticTool.exe parses as PE");
    let imports = image.imported_dlls().expect("import table reads");
    assert!(
        imports
            .iter()
            .any(|d| d.eq_ignore_ascii_case("kernel32.dll")),
        "import table read nothing useful: {imports:?}"
    );
    let crt: Vec<_> = imports.iter().filter(|d| pe::is_crt_dll(d)).collect();
    assert!(crt.is_empty(), "C runtime DLLs imported: {crt:?}");
}

#[test]
fn gui_exe_records_pdb_by_file_name_only() {
    let bytes = exe_bytes();
    let image = pe::Pe::parse(&bytes).expect("DiagnosticTool.exe parses as PE");
    let pdb = image.pdb_path().expect("debug directory reads");
    let pdb = pdb.expect("a CodeView entry names the PDB");
    assert!(
        !pdb.contains(['\\', '/', ':']),
        "PDB path carries a directory: {pdb}"
    );
}

#[test]
fn gui_exe_is_linked_reproducibly() {
    let bytes = exe_bytes();
    let image = pe::Pe::parse(&bytes).expect("DiagnosticTool.exe parses as PE");
    let kinds: Vec<u32> = image
        .debug_entries()
        .expect("debug directory reads")
        .iter()
        .map(|e| e.kind)
        .collect();
    assert!(
        kinds.contains(&pe::DEBUG_TYPE_REPRO),
        "no REPRO debug entry, so /Brepro was not applied: {kinds:?}"
    );
}

#[test]
fn gui_exe_resolves_imports_from_system32_only() {
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x800;
    let bytes = exe_bytes();
    let image = pe::Pe::parse(&bytes).expect("DiagnosticTool.exe parses as PE");
    let flags = image
        .dependent_load_flags()
        .expect("load configuration reads");
    assert_eq!(
        flags,
        Some(LOAD_LIBRARY_SEARCH_SYSTEM32),
        "DependentLoadFlags lets the application directory supply imports"
    );
}

#[test]
fn gui_exe_embeds_manifest_version_and_icon_resources() {
    let bytes = exe_bytes();
    let image = pe::Pe::parse(&bytes).expect("DiagnosticTool.exe parses as PE");
    for (kind, name) in [
        (pe::RT_MANIFEST, "manifest"),
        (pe::RT_VERSION, "version"),
        (pe::RT_ICON_GROUP, "icon group"),
    ] {
        let present = image.has_resource(kind, 1).expect("resource tree reads");
        assert!(present, "no {name} resource with id 1");
    }
}

#[test]
fn gui_exe_manifest_declares_per_monitor_v2() {
    let bytes = exe_bytes();
    let needle = b">PerMonitorV2</dpiAwareness>";
    assert!(
        bytes.windows(needle.len()).any(|w| w == needle),
        "no PerMonitorV2 dpiAwareness in the embedded manifest"
    );
}

#[test]
fn gui_exe_version_resource_carries_package_version() {
    let bytes = exe_bytes();
    let wide: Vec<u8> = env!("CARGO_PKG_VERSION")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(
        bytes.windows(wide.len()).any(|w| w == wide),
        "no UTF-16LE {} string, so VERSIONINFO is missing",
        env!("CARGO_PKG_VERSION")
    );
}

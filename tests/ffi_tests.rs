use std::ffi::{c_char, CStr, CString};

#[test]
fn ffi_version_matches_constants() {
    let version = wiretap_rs::constants::VERSION.trim_start_matches('v');
    let parts: Vec<u32> = version
        .split('.')
        .map(|part| part.parse::<u32>().expect("numeric version part"))
        .collect();
    assert_eq!(parts.len(), 3, "version must have major.minor.patch");
    assert_eq!(
        wiretap_rs::ffi::wiretap_version_major(),
        parts[0],
        "major version mismatch"
    );
    assert_eq!(
        wiretap_rs::ffi::wiretap_version_minor(),
        parts[1],
        "minor version mismatch"
    );
    assert_eq!(
        wiretap_rs::ffi::wiretap_version_patch(),
        parts[2],
        "patch version mismatch"
    );
}

#[test]
fn ffi_run_argv_handles_invalid_pointer_input() {
    let rc = wiretap_rs::ffi::wiretap_run_argv(1, std::ptr::null());
    assert_eq!(rc, 2);

    let error_ptr = wiretap_rs::ffi::wiretap_last_error_message();
    assert!(!error_ptr.is_null());
    let message = unsafe { CStr::from_ptr(error_ptr) }
        .to_string_lossy()
        .to_string();
    unsafe { wiretap_rs::ffi::wiretap_string_free(error_ptr) };
    assert!(message.contains("argv"));
}

#[test]
fn ffi_run_argv_reports_utf8_errors() {
    let arg0 = CString::new("wiretap-rs").expect("arg0");
    let invalid_utf8 = [0xff_u8, 0x00_u8];
    let argv = [arg0.as_ptr(), invalid_utf8.as_ptr() as *const c_char];
    let rc = wiretap_rs::ffi::wiretap_run_argv(argv.len() as i32, argv.as_ptr());
    assert_eq!(rc, 2);

    let error_ptr = wiretap_rs::ffi::wiretap_last_error_message();
    assert!(!error_ptr.is_null());
    let message = unsafe { CStr::from_ptr(error_ptr) }
        .to_string_lossy()
        .to_string();
    unsafe { wiretap_rs::ffi::wiretap_string_free(error_ptr) };
    assert!(message.contains("UTF-8"));
}

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::ptr;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = Some(message.into());
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = None;
    });
}

fn version_triplet() -> (u32, u32, u32) {
    let version = crate::constants::VERSION.trim_start_matches('v');
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

fn argv_from_raw(argc: c_int, argv: *const *const c_char) -> Result<Vec<String>, String> {
    if argc <= 0 {
        return Err("argc must be greater than 0".to_string());
    }
    if argv.is_null() {
        return Err("argv must not be null".to_string());
    }

    let mut args = Vec::with_capacity(argc as usize);
    for index in 0..argc {
        let ptr = unsafe { *argv.add(index as usize) };
        if ptr.is_null() {
            return Err(format!("argv[{index}] must not be null"));
        }
        let arg = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .map_err(|_| format!("argv[{index}] is not valid UTF-8"))?
            .to_string();
        args.push(arg);
    }
    Ok(args)
}

#[no_mangle]
pub extern "C" fn wiretap_run_argv(argc: c_int, argv: *const *const c_char) -> c_int {
    let args = match argv_from_raw(argc, argv) {
        Ok(args) => args,
        Err(message) => {
            set_last_error(message);
            return 2;
        }
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::cli::run_with_args(&args)
    }));

    match result {
        Ok(Ok(())) => {
            clear_last_error();
            0
        }
        Ok(Err(err)) => {
            set_last_error(err.to_string());
            1
        }
        Err(_) => {
            set_last_error("wiretap panicked while executing command");
            3
        }
    }
}

#[no_mangle]
pub extern "C" fn wiretap_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|last| {
        let message = last.borrow().clone();
        let Some(message) = message else {
            return ptr::null_mut();
        };
        let sanitized = message.replace('\0', " ");
        CString::new(sanitized)
            .map(CString::into_raw)
            .unwrap_or(ptr::null_mut())
    })
}

#[no_mangle]
pub unsafe extern "C" fn wiretap_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}

#[no_mangle]
pub extern "C" fn wiretap_version_major() -> u32 {
    version_triplet().0
}

#[no_mangle]
pub extern "C" fn wiretap_version_minor() -> u32 {
    version_triplet().1
}

#[no_mangle]
pub extern "C" fn wiretap_version_patch() -> u32 {
    version_triplet().2
}

#[cfg(test)]
mod tests {
    use super::{wiretap_last_error_message, wiretap_run_argv, wiretap_string_free};
    use std::ffi::{c_char, CStr, CString};

    #[test]
    fn ffi_run_argv_accepts_version_command() {
        let arg0 = CString::new("wiretap-rs").expect("arg0");
        let arg1 = CString::new("--version").expect("arg1");
        let argv = [arg0.as_ptr(), arg1.as_ptr()];
        assert_eq!(wiretap_run_argv(argv.len() as i32, argv.as_ptr()), 0);
    }

    #[test]
    fn ffi_run_argv_rejects_invalid_utf8() {
        let arg0 = CString::new("wiretap-rs").expect("arg0");
        let invalid_utf8 = [0xff_u8, 0x00_u8];
        let argv = [arg0.as_ptr(), invalid_utf8.as_ptr() as *const c_char];
        assert_eq!(wiretap_run_argv(argv.len() as i32, argv.as_ptr()), 2);

        let error_ptr = wiretap_last_error_message();
        assert!(!error_ptr.is_null());
        let message = unsafe { CStr::from_ptr(error_ptr) }
            .to_string_lossy()
            .to_string();
        unsafe { wiretap_string_free(error_ptr) };
        assert!(message.contains("UTF-8"));
    }

    #[test]
    fn ffi_run_argv_surfaces_cli_errors() {
        let arg0 = CString::new("wiretap-rs").expect("arg0");
        let arg1 = CString::new("definitely-not-a-command").expect("arg1");
        let argv = [arg0.as_ptr(), arg1.as_ptr()];
        assert_eq!(wiretap_run_argv(argv.len() as i32, argv.as_ptr()), 1);

        let error_ptr = wiretap_last_error_message();
        assert!(!error_ptr.is_null());
        let message = unsafe { CStr::from_ptr(error_ptr) }
            .to_string_lossy()
            .to_string();
        unsafe { wiretap_string_free(error_ptr) };
        assert!(!message.is_empty());
    }
}

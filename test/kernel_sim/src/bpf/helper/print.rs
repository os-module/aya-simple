use core::{
    ffi::{c_char, c_int},
    fmt::Write,
};

use printf_compat::{format, output};

/// Printf according to the format string, function will return the number of bytes written(including '\0')
pub unsafe extern "C" fn printf(w: &mut impl Write, str: *const c_char, mut args: ...) -> c_int {
    let bytes_written = format(str, args.as_va_list(), output::fmt_write(w));
    bytes_written + 1
}

/// Printf with '\n' at the end, function will return the number of bytes written(including '\n' and '\0')
pub unsafe extern "C" fn printf_with(
    w: &mut impl Write,
    str: *const c_char,
    mut args: ...
) -> c_int {
    let str = core::ffi::CStr::from_ptr(str).to_str().unwrap().as_bytes();
    let bytes_written = if str.ends_with(b"\n") {
        format(str.as_ptr() as _, args.as_va_list(), output::fmt_write(w))
    } else {
        let mut bytes_written = format(str.as_ptr() as _, args.as_va_list(), output::fmt_write(w));
        w.write_str("\n").unwrap();
        bytes_written += 1;
        bytes_written
    };
    bytes_written + 1
}
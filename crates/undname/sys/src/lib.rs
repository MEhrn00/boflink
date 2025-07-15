#![allow(non_camel_case_types, non_snake_case)]

pub type malloc_func_t = unsafe extern "C" fn(usize) -> *mut std::ffi::c_void;
pub type free_func_t = unsafe extern "C" fn(*mut std::ffi::c_void);

#[cfg(windows)]
#[cfg_attr(target_env = "msvc", link(name = "vcruntime", kind = "dylib"))]
#[cfg_attr(target_env = "gnu", link(name = "msvcrt", kind = "dylib"))]
#[cfg_attr(
    not(any(target_env = "msvc", target_env = "gnu")),
    link(name = "VCRUNTIME140", kind = "raw-dylib")
)]
unsafe extern "C" {
    pub fn __unDNameEx(
        buffer: *mut std::ffi::c_char,
        mangled: *const std::ffi::c_char,
        buflen: std::ffi::c_int,
        memget: malloc_func_t,
        memfree: free_func_t,
        unknown: *const std::ffi::c_void,
        flags: std::ffi::c_uint,
    ) -> *mut std::ffi::c_char;
}

#[cfg(not(windows))]
#[allow(clippy::missing_safety_doc, unused_variables)]
pub unsafe extern "C" fn __unDNameEx(
    buffer: *mut std::ffi::c_char,
    mangled: *const std::ffi::c_char,
    buflen: std::ffi::c_int,
    memget: malloc_func_t,
    memfree: free_func_t,
    unknown: *const std::ffi::c_void,
    flags: std::ffi::c_uint,
) -> *mut std::ffi::c_char {
    unimplemented!("__unDNameEx is not implemented for non-Windows targets");
}

pub use windows_sys::Win32::System::Diagnostics::Debug::{
    UNDNAME_32_BIT_DECODE, UNDNAME_COMPLETE, UNDNAME_NAME_ONLY, UNDNAME_NO_ACCESS_SPECIFIERS,
    UNDNAME_NO_ALLOCATION_LANGUAGE, UNDNAME_NO_ALLOCATION_MODEL, UNDNAME_NO_ARGUMENTS,
    UNDNAME_NO_CV_THISTYPE, UNDNAME_NO_FUNCTION_RETURNS, UNDNAME_NO_LEADING_UNDERSCORES,
    UNDNAME_NO_MEMBER_TYPE, UNDNAME_NO_MS_KEYWORDS, UNDNAME_NO_MS_THISTYPE,
    UNDNAME_NO_RETURN_UDT_MODEL, UNDNAME_NO_SPECIAL_SYMS, UNDNAME_NO_THISTYPE,
    UNDNAME_NO_THROW_SIGNATURES,
};

use std::ffi::{CStr, CString, FromBytesWithNulError};

#[cfg(feature = "sys")]
pub use undname_sys as sys;

mod error;
mod memproxy;

pub use error::Error;

/// Mask for passing the undname flags to [`undname_sys::__unDNameEx`].
///
/// undname.exe will unset bit 15 when calling `__unDNameEx`.
const UNDNAME_FLAGS_MASK: u32 = !(1 << 14);

/// Flags for customizing symbol demangling.
///
/// Constants are not fully documented in the Windows API docs https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-undecoratesymbolname.
///
/// Thankfully, MS decided to document them here https://github.com/microsoft/deoptexplorer-vscode/blob/9a6bc239bf88a6c26a52a517d41e1a00e1d96353/src/platforms/win32/api/dbghelp.ts#L529 :).
///
/// The UNDNAME_NO_MS_THISTYPE is wrong though and should be 0x60.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UndnameFlags(u32);

impl std::default::Default for UndnameFlags {
    fn default() -> Self {
        Self::Complete
    }
}

bitflags::bitflags! {
    impl UndnameFlags: u32 {
        /// Enable full undecoration.
        const Complete = undname_sys::UNDNAME_COMPLETE;

        /// Remove leading underscores from Microsoft keywords.
        const NoLeadingUnderscores = 0x0001;

        /// Disable expansion of Microsoft keywords.
        const NoMsKeywords = undname_sys::UNDNAME_NO_MS_KEYWORDS;

        /// Disable expansion of return types for primary declarations.
        const NoFunctionReturns = undname_sys::UNDNAME_NO_FUNCTION_RETURNS;

        /// Disable expansion of the declaration model.
        const NoAllocationModel = undname_sys::UNDNAME_NO_ALLOCATION_MODEL;

        /// Disable expansion of the declaration language specifier.
        const NoAllocationLanguage = undname_sys::UNDNAME_NO_ALLOCATION_LANGUAGE;

        /// Disable all modifiers on the 'this' type.
        const NoThistype = undname_sys::UNDNAME_NO_THISTYPE;

        /// Disable expansion of access specifiers for members.
        const NoAccessSpecifiers = undname_sys::UNDNAME_NO_ACCESS_SPECIFIERS;

        /// Disable expansion of throw-signatures for functions and pointers to functions.
        const NoThrowSignatures = undname_sys::UNDNAME_NO_THROW_SIGNATURES;

        /// Disable expansion of the static or virtual attribute of members.
        const NoMemberType = undname_sys::UNDNAME_NO_MEMBER_TYPE;

        /// Disable expansion of the Microsoft model for user-defined type returns.
        const NoReturnUdtModel = undname_sys::UNDNAME_NO_RETURN_UDT_MODEL;

        /// Undecorate 32-bit decorated names.
        const ThirtyTwoBitDecode = undname_sys::UNDNAME_32_BIT_DECODE;

        /// Undecorate only the name for primary declaration. Returns [scope::]name. Does expand template parameters.
        const NameOnly = undname_sys::UNDNAME_NAME_ONLY;

        /// Do not undecorate function arguments.
        const NoArguments = undname_sys::UNDNAME_NO_ARGUMENTS;

        /// Disable enum/class/struct/union prefix.
        const NoTypePrefix = 0x8000;

        /// Disable expansion of __ptr64 keyword.
        const NoPtr64Expansion = 0x20000;
    }
}

/// Demangle the specified mangled symbol.
pub fn undname(mangled: impl AsRef<str>, flags: UndnameFlags) -> Result<String, Error> {
    match std::ffi::CStr::from_bytes_with_nul(mangled.as_ref().as_bytes()) {
        Ok(mangled) => undname_cstr(mangled, flags),
        Err(FromBytesWithNulError::NotNulTerminated) => {
            let mangled = CString::new(mangled.as_ref().as_bytes()).map_err(|e| {
                Error::MangledInteriorNul {
                    position: e.nul_position(),
                }
            })?;

            undname_cstr(mangled, flags)
        }
        Err(FromBytesWithNulError::InteriorNul { position }) => {
            Err(Error::MangledInteriorNul { position })
        }
    }
    .and_then(|demangled| {
        demangled
            .into_string()
            .map_err(|e| Error::Utf8(e.utf8_error()))
    })
}

/// Demangle the specified mangled symbol.
pub fn undname_cstr(mangled: impl AsRef<CStr>, flags: UndnameFlags) -> Result<CString, Error> {
    let demangled_ptr = unsafe {
        undname_sys::__unDNameEx(
            std::ptr::null_mut(),
            mangled.as_ref().as_ptr(),
            0,
            memproxy::memget_callback,
            memproxy::memfree_callback,
            std::ptr::null(),
            flags.bits() & UNDNAME_FLAGS_MASK,
        )
    };

    if demangled_ptr.is_null() {
        return Err(Error::FFINull);
    }

    let demangled_cstr = unsafe { CStr::from_ptr(demangled_ptr) };
    let demangled = demangled_cstr.to_owned();

    unsafe {
        memproxy::memfree_callback(demangled_ptr.cast());
    }

    Ok(demangled)
}

#[cfg(windows)]
#[cfg(test)]
mod tests_windows {
    use std::ffi::CStr;

    use super::{UndnameFlags, undname, undname_cstr};

    #[test]
    fn demangle_cstr() {
        const TESTS: &[(&CStr, &str)] = &[
            (c"??$f@W4Bar@@@@YAXH@Z", "void __cdecl f<enum Bar>(int)"),
            (
                c"??$foo@H$$A6AXN@ZH@@YAXXZ",
                "void __cdecl foo<int,void __cdecl(double),int>(void)",
            ),
            (
                c"??6@YA?AUA@@AEBU0@0@Z",
                "struct A __cdecl operator<<(struct A const &,struct A const &)",
            ),
            (
                c"??H@YA?AUA@@AEAU0@0@Z",
                "struct A __cdecl operator+(struct A &,struct A &)",
            ),
            (
                c"??L@YA?AUA@@U0@0@Z",
                "struct A __cdecl operator%(struct A,struct A)",
            ),
            (c"?asdf@@YAXW4Bar@@@Z", "void __cdecl asdf(enum Bar)"),
            (
                c"?bar@?$Foo@$$BY03H@@QEAAXXZ",
                "public: void __cdecl Foo<int [4]>::bar(void)",
            ),
            (c"?f@@YAXH@Z", "void __cdecl f(int)"),
            (c"?f@ns@@YAXXZ", "void __cdecl ns::f(void)"),
        ];

        for (symbol, expected) in TESTS {
            let result = undname_cstr(symbol, UndnameFlags::NoPtr64Expansion)
                .unwrap_or_else(|e| panic!("Could not demangle {symbol:?}: {e}"));

            let result_str = result.to_str().expect("Could not convert result to UTF8");
            assert_eq!(
                result_str, *expected,
                "demangled string {symbol:?} does not match {expected}"
            );
        }
    }

    #[test]
    fn demangle_str_null() {
        const TESTS: &[(&str, &str)] = &[
            ("??$f@W4Bar@@@@YAXH@Z\0", "void __cdecl f<enum Bar>(int)"),
            (
                "??$foo@H$$A6AXN@ZH@@YAXXZ\0",
                "void __cdecl foo<int,void __cdecl(double),int>(void)",
            ),
            (
                "??6@YA?AUA@@AEBU0@0@Z\0",
                "struct A __cdecl operator<<(struct A const &,struct A const &)",
            ),
            (
                "??H@YA?AUA@@AEAU0@0@Z\0",
                "struct A __cdecl operator+(struct A &,struct A &)",
            ),
            (
                "??L@YA?AUA@@U0@0@Z\0",
                "struct A __cdecl operator%(struct A,struct A)",
            ),
            ("?asdf@@YAXW4Bar@@@Z\0", "void __cdecl asdf(enum Bar)"),
            (
                "?bar@?$Foo@$$BY03H@@QEAAXXZ\0",
                "public: void __cdecl Foo<int [4]>::bar(void)",
            ),
            ("?f@@YAXH@Z\0", "void __cdecl f(int)"),
            ("?f@ns@@YAXXZ\0", "void __cdecl ns::f(void)"),
        ];

        for (symbol, expected) in TESTS {
            let result = undname(symbol, UndnameFlags::NoPtr64Expansion)
                .unwrap_or_else(|e| panic!("Could not demangle {symbol:?}: {e}"));

            assert_eq!(
                result.as_str(),
                *expected,
                "demangled string {symbol:?} does not match {expected}"
            );
        }
    }

    #[test]
    fn demangle_str_nonnull() {
        const TESTS: &[(&str, &str)] = &[
            ("??$f@W4Bar@@@@YAXH@Z", "void __cdecl f<enum Bar>(int)"),
            (
                "??$foo@H$$A6AXN@ZH@@YAXXZ",
                "void __cdecl foo<int,void __cdecl(double),int>(void)",
            ),
            (
                "??6@YA?AUA@@AEBU0@0@Z",
                "struct A __cdecl operator<<(struct A const &,struct A const &)",
            ),
            (
                "??H@YA?AUA@@AEAU0@0@Z",
                "struct A __cdecl operator+(struct A &,struct A &)",
            ),
            (
                "??L@YA?AUA@@U0@0@Z",
                "struct A __cdecl operator%(struct A,struct A)",
            ),
            ("?asdf@@YAXW4Bar@@@Z", "void __cdecl asdf(enum Bar)"),
            (
                "?bar@?$Foo@$$BY03H@@QEAAXXZ",
                "public: void __cdecl Foo<int [4]>::bar(void)",
            ),
            ("?f@@YAXH@Z", "void __cdecl f(int)"),
            ("?f@ns@@YAXXZ", "void __cdecl ns::f(void)"),
        ];

        for (symbol, expected) in TESTS {
            let result = undname(symbol, UndnameFlags::NoPtr64Expansion)
                .unwrap_or_else(|e| panic!("Could not demangle {symbol:?}: {e}"));

            assert_eq!(
                result.as_str(),
                *expected,
                "demangled string {symbol:?} does not match {expected}"
            );
        }
    }
}

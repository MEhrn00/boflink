use std::{
    ffi::{CStr, CString, FromBytesWithNulError},
    {alloc::Layout, mem::MaybeUninit},
};

use windows::Win32::System::Diagnostics::Debug::{
    UNDNAME_32_BIT_DECODE, UNDNAME_COMPLETE, UNDNAME_NAME_ONLY, UNDNAME_NO_ACCESS_SPECIFIERS,
    UNDNAME_NO_ALLOCATION_LANGUAGE, UNDNAME_NO_ALLOCATION_MODEL, UNDNAME_NO_ARGUMENTS,
    UNDNAME_NO_FUNCTION_RETURNS, UNDNAME_NO_MEMBER_TYPE, UNDNAME_NO_MS_KEYWORDS,
    UNDNAME_NO_RETURN_UDT_MODEL, UNDNAME_NO_THISTYPE, UNDNAME_NO_THROW_SIGNATURES,
};

#[cfg_attr(target_env = "msvc", link(name = "vcruntime", kind = "dylib"))]
#[cfg_attr(target_env = "gnu", link(name = "msvcrt", kind = "dylib"))]
#[cfg_attr(
    not(any(target_env = "msvc", target_env = "gnu")),
    link(name = "VCRUNTIME140", kind = "raw-dylib")
)]
#[allow(non_camel_case_types, non_snake_case)]
unsafe extern "system" {
    pub fn __unDNameEx(
        buffer: *mut std::ffi::c_char,
        mangled: *const std::ffi::c_char,
        buflen: std::ffi::c_int,
        memget: unsafe extern "system" fn(usize) -> *mut std::ffi::c_void,
        memfree: unsafe extern "system" fn(*mut std::ffi::c_void),
        unknown: *const std::ffi::c_void,
        flags: std::ffi::c_uint,
    ) -> *mut std::ffi::c_char;
}

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
        const Complete = UNDNAME_COMPLETE;

        /// Remove leading underscores from Microsoft keywords.
        const NoLeadingUnderscores = 0x0001;

        /// Disable expansion of Microsoft keywords.
        const NoMsKeywords = UNDNAME_NO_MS_KEYWORDS;

        /// Disable expansion of return types for primary declarations.
        const NoFunctionReturns = UNDNAME_NO_FUNCTION_RETURNS;

        /// Disable expansion of the declaration model.
        const NoAllocationModel = UNDNAME_NO_ALLOCATION_MODEL;

        /// Disable expansion of the declaration language specifier.
        const NoAllocationLanguage = UNDNAME_NO_ALLOCATION_LANGUAGE;

        /// Disable all modifiers on the 'this' type.
        const NoThistype = UNDNAME_NO_THISTYPE;

        /// Disable expansion of access specifiers for members.
        const NoAccessSpecifiers = UNDNAME_NO_ACCESS_SPECIFIERS;

        /// Disable expansion of throw-signatures for functions and pointers to functions.
        const NoThrowSignatures = UNDNAME_NO_THROW_SIGNATURES;

        /// Disable expansion of the static or virtual attribute of members.
        const NoMemberType = UNDNAME_NO_MEMBER_TYPE;

        /// Disable expansion of the Microsoft model for user-defined type returns.
        const NoReturnUdtModel = UNDNAME_NO_RETURN_UDT_MODEL;

        /// Undecorate 32-bit decorated names.
        const ThirtyTwoBitDecode = UNDNAME_32_BIT_DECODE;

        /// Undecorate only the name for primary declaration. Returns [scope::]name. Does expand template parameters.
        const NameOnly = UNDNAME_NAME_ONLY;

        /// Do not undecorate function arguments.
        const NoArguments = UNDNAME_NO_ARGUMENTS;

        /// Disable enum/class/struct/union prefix.
        const NoTypePrefix = 0x8000;

        /// Disable expansion of __ptr64 keyword.
        const NoPtr64Expansion = 0x20000;
    }
}

/// Demangle the specified mangled symbol.
pub fn undname_demangle(mangled: impl AsRef<str>, flags: UndnameFlags) -> Result<String, Error> {
    match std::ffi::CStr::from_bytes_with_nul(mangled.as_ref().as_bytes()) {
        Ok(mangled) => undname_demangle_cstr(mangled, flags),
        Err(FromBytesWithNulError::NotNulTerminated) => {
            let mangled =
                CString::new(mangled.as_ref().as_bytes()).map_err(|_| Error::MangledInteriorNul)?;

            undname_demangle_cstr(mangled, flags)
        }
        Err(FromBytesWithNulError::InteriorNul { .. }) => Err(Error::MangledInteriorNul),
    }
    .and_then(|demangled| {
        demangled
            .into_string()
            .map_err(|e| Error::Utf8(e.utf8_error()))
    })
}

/// Demangle the specified mangled symbol.
pub fn undname_demangle_cstr(
    mangled: impl AsRef<CStr>,
    flags: UndnameFlags,
) -> Result<CString, Error> {
    let demangled_ptr = unsafe {
        __unDNameEx(
            std::ptr::null_mut(),
            mangled.as_ref().as_ptr(),
            0,
            memget_callback,
            memfree_callback,
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
        memfree_callback(demangled_ptr.cast());
    }

    Ok(demangled)
}

#[derive(Debug)]
pub enum Error {
    MangledInteriorNul,
    Utf8(std::str::Utf8Error),
    FFINull,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MangledInteriorNul => {
                write!(f, "mangled string contains an interior nul byte")
            }
            Self::Utf8(e) => write!(f, "demangled string is invalid UTF-8 {e}"),
            Self::FFINull => write!(f, "FFI returned NULL"),
        }
    }
}

impl std::error::Error for Error {}

/// A memory chunk for memget/memfree operations
#[repr(C)]
struct MemChunk<T: ?Sized> {
    /// The total size of this chunk allocation.
    size: usize,

    /// The chunk data.
    data: T,
}

/// Callback function for [`undname_sys::__unDName`] memget.
///
/// # Safety
/// This should NEVER be called outside of the
/// [`undname_sys::__unDName`] context.
unsafe extern "system" fn memget_callback(size: usize) -> *mut std::ffi::c_void {
    let mut alloc_size = size;
    if alloc_size == 0 {
        alloc_size = 1;
    }

    let size_needed = std::mem::size_of::<MemChunk<()>>() + alloc_size;
    if isize::try_from(size_needed).is_err() {
        // SAFETY: This layout is only used for propogating the layout error.
        std::alloc::handle_alloc_error(unsafe {
            Layout::from_size_align_unchecked(
                isize::MAX as usize,
                std::mem::align_of::<MemChunk<()>>(),
            )
        });
    }

    // Get the layout needed for the chunk
    // SAFETY: `_unchecked` is used for performance.
    // - The size needed is checked if it will overflow an isize.
    // - The alignment should always be correct since it is from the compiler.
    let chunk_layout = unsafe {
        Layout::from_size_align_unchecked(size_needed, std::mem::align_of::<MemChunk<()>>())
    };

    // Pad alignment
    let chunk_layout = chunk_layout.pad_to_align();

    // SAFETY: Requires check for NULL pointer on failed allocation.
    let chunk_alc = unsafe { std::alloc::alloc(chunk_layout) };
    if chunk_alc.is_null() {
        std::alloc::handle_alloc_error(chunk_layout);
    }

    let chunk_ptr: *mut MemChunk<[MaybeUninit<u8>; 1]> = chunk_alc.cast();
    // SAFETY: Pointer is non-NULL and properly aligned.
    unsafe { (*chunk_ptr).size = chunk_layout.size() };

    // SAFETY:
    // - chunk_ptr is non-NULL.
    // - Access to the data field is properly aligned
    // - data field is uninitialized and should not be dereferenced!!!
    let data_ptr = unsafe { std::ptr::addr_of_mut!((*chunk_ptr).data) };

    data_ptr.cast()
}

/// Callback function for [`undname_sys::__unDName`]` memfree.
///
/// # Safety
/// This function should NEVER be called outside of the
/// [`undname_sys::__unDName`] context.
unsafe extern "system" fn memfree_callback(ptr: *mut std::ffi::c_void) {
    if ptr.is_null() {
        return;
    }

    let data_ptr: *mut [MaybeUninit<u8>; 1] = ptr.cast();

    // SAFETY: This is wildly unsafe lmao.
    let chunk_ptr: *mut MemChunk<[MaybeUninit<u8>; 1]> = unsafe {
        data_ptr
            .byte_sub(std::mem::offset_of!(MemChunk<()>, data))
            .cast()
    };

    if chunk_ptr.is_null() || !chunk_ptr.is_aligned() {
        panic!("Called memfree_callback on invalid pointer");
    }

    // SAFETY: chunk_ptr is not NULL and properly aligned to read from.
    let chunk_size = unsafe { (*chunk_ptr).size };

    if isize::try_from(chunk_size).is_err() {
        panic!("memfree_callback chunk size overflows an isize");
    }

    // SAFETY:
    // - The chunk size has been checked if it will overflow an isize.
    // - The alignment should always be correct since it is from the compiler.
    let chunk_layout = unsafe {
        Layout::from_size_align_unchecked(chunk_size, std::mem::size_of::<MemChunk<()>>())
    };

    // SAFETY: Assuming that this function was called correctly, the dealloc
    // here should be fine. If it was not called correctly, then RIP o7
    unsafe { std::alloc::dealloc(chunk_ptr.cast(), chunk_layout) }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::{
        UndnameFlags, memfree_callback, memget_callback, undname_demangle, undname_demangle_cstr,
    };

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
            let result = undname_demangle_cstr(symbol, UndnameFlags::NoPtr64Expansion)
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
            let result = undname_demangle(symbol, UndnameFlags::NoPtr64Expansion)
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
            let result = undname_demangle(symbol, UndnameFlags::NoPtr64Expansion)
                .unwrap_or_else(|e| panic!("Could not demangle {symbol:?}: {e}"));

            assert_eq!(
                result.as_str(),
                *expected,
                "demangled string {symbol:?} does not match {expected}"
            );
        }
    }

    fn run_allocation_tests(alloc_range: impl Iterator<Item = usize>) {
        for alloc_size in alloc_range {
            let ptr = unsafe { memget_callback(alloc_size) };

            assert!(
                !ptr.is_null(),
                "memget_callback for {alloc_size} returned a NULL pointer"
            );

            unsafe {
                memfree_callback(ptr);
            }
        }
    }

    #[test]
    fn memget_alloc_zero() {
        let ptr = unsafe { memget_callback(0) };

        assert!(
            !ptr.is_null(),
            "memget_callback allocation for size 0 should return a non-NULL pointer"
        );

        unsafe {
            memfree_callback(ptr);
        }
    }

    #[test]
    fn memget_small_allocations() {
        run_allocation_tests((1..=0x250).step_by(10));
    }

    #[test]
    fn memget_medium_allocations() {
        run_allocation_tests((0x250..=0x500).step_by(10));
    }

    #[test]
    fn memget_large_allocations() {
        run_allocation_tests((0x500..=0x900).step_by(10));
    }

    #[test]
    fn memget_page_boundaries() {
        run_allocation_tests(
            [
                0xfff, 0x1000, 0x1001, 0x1fff, 0x2000, 0x2001, 0x2fff, 0x3000, 0x3001,
            ]
            .into_iter(),
        );
    }
}

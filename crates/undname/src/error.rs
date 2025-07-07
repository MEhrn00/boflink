#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mangled string contains an interior nul byte")]
    MangledInteriorNul { position: usize },

    #[error("demangled string is invalid UTF-8 {0}")]
    Utf8(std::str::Utf8Error),

    #[error("FFI returned NULL")]
    FFINull,
}

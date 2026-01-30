use std::path::Path;

/// A COFF node.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct CoffNode<'data> {
    /// The path on disk.
    file_path: &'data Path,

    /// The member path.
    member_path: Option<&'data Path>,
}

impl<'data> CoffNode<'data> {
    pub const fn new(file_path: &'data Path, member_path: Option<&'data Path>) -> CoffNode<'data> {
        Self {
            file_path,
            member_path,
        }
    }

    /// Returns a [`CoffNodeShortName`] for displaying a shortened version of
    /// the COFF name.
    pub fn short_name(&self) -> CoffNodeShortName<'_, 'data> {
        CoffNodeShortName(self)
    }
}

impl std::fmt::Display for CoffNode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(member_path) = self.member_path {
            write!(f, "{}({})", self.file_path.display(), member_path.display())
        } else {
            write!(f, "{}", self.file_path.display())
        }
    }
}

/// Used for writing out a shortened version of a [`CoffNode`].
#[derive(Debug)]
pub struct CoffNodeShortName<'b, 'data>(&'b CoffNode<'data>);

impl std::fmt::Display for CoffNodeShortName<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(member_path) = self.0.member_path {
            write!(
                f,
                "{}({})",
                self.0.file_path.file_name().unwrap().to_string_lossy(),
                member_path.file_name().unwrap().to_string_lossy(),
            )
        } else {
            write!(
                f,
                "{}",
                self.0.file_path.file_name().unwrap().to_string_lossy()
            )
        }
    }
}

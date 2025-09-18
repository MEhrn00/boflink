use std::collections::HashMap;

use longnames::ArchiveMemberName;
use typed_arena::Arena;

mod armap;
mod gnu;
mod longnames;
mod msvc;
mod sorted_armap;

pub use gnu::GnuArchiveVariant;
pub use msvc::MsvcArchiveVariant;

pub trait ByteSize {
    fn byte_size(&self) -> usize;
}

trait MemberSize {
    fn member_data_size(&self) -> usize;

    fn member_size(&self) -> usize {
        let size = std::mem::size_of::<object::archive::Header>() + self.member_data_size();
        if !size.is_multiple_of(2) {
            size + 1
        } else {
            size
        }
    }
}

fn make_archive_member_buffer(
    name: &ArchiveMemberName,
    metadata: &ArchiveMemberMetadata,
    member: &impl MemberSize,
) -> Vec<u8> {
    use object::archive::Header;
    use std::mem::offset_of;

    let mut buffer = Vec::with_capacity(member.member_size());
    buffer.extend(name.to_name_array());

    // Pad to the date field
    buffer.resize(offset_of!(Header, date), b' ');

    let mut strbuf = String::with_capacity(12);

    if let Some(date_val) = metadata.date {
        make_ascii_base10(&mut strbuf, date_val);
        buffer.extend(strbuf.as_bytes());
    }

    // Pad to the uid field
    buffer.resize(offset_of!(Header, uid), b' ');

    if let Some(uid_val) = metadata.uid {
        make_ascii_base10(&mut strbuf, uid_val);
        buffer.extend(strbuf.as_bytes());
    }

    // Pad to the gid field
    buffer.resize(offset_of!(Header, gid), b' ');

    if let Some(gid_val) = metadata.gid {
        make_ascii_base10(&mut strbuf, gid_val);
        buffer.extend(strbuf.as_bytes());
    }

    // Pad to the mode field
    buffer.resize(offset_of!(Header, mode), b' ');

    if let Some(mode_val) = metadata.mode {
        make_ascii_base10(&mut strbuf, mode_val);
        buffer.extend(strbuf.as_bytes());
    }

    // Pad to the size field
    buffer.resize(offset_of!(Header, size), b' ');

    make_ascii_base10(&mut strbuf, member.member_data_size() as u64);
    buffer.extend(strbuf.as_bytes());

    // Pad to the terminator field
    buffer.resize(offset_of!(Header, terminator), b' ');

    buffer.extend(object::archive::TERMINATOR);

    buffer
}

pub trait ArchiveVariant: Default + ByteSize {
    fn add_exported_symbol(&mut self, member: ArchiveMemberIndex, symbol: impl AsRef<str>);
    fn add_long_name(&mut self, name: impl Into<String>) -> ArchiveMemberName;
    fn build(self, archive_map: HashMap<ArchiveMemberIndex, usize>) -> Vec<u8>;
}

#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ArchiveMemberIndex(pub(self) usize);

#[derive(Default)]
struct ArchiveMemberMetadata {
    date: Option<u64>,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
}

struct ArchiveMemberBuilder {
    name: ArchiveMemberName,
    meta: ArchiveMemberMetadata,
    data: Vec<u8>,
}

impl ArchiveMemberBuilder {
    fn new(name: ArchiveMemberName, data: Vec<u8>) -> ArchiveMemberBuilder {
        Self {
            name,
            data,
            meta: ArchiveMemberMetadata::default(),
        }
    }

    // Builds this member
    fn build(mut self) -> Vec<u8> {
        let mut buffer = make_archive_member_buffer(&self.name, &self.meta, &self);
        buffer.append(&mut self.data);
        if !buffer.len().is_multiple_of(2) {
            buffer.push(b'\n');
        }

        buffer
    }
}

impl MemberSize for ArchiveMemberBuilder {
    fn member_data_size(&self) -> usize {
        self.data.len()
    }
}

/// Converts an integer value to base 10 ascii using the specified string buffer
fn make_ascii_base10(s: &mut String, v: impl Into<u64>) {
    s.clear();

    let v = v.into();

    let mut n = 0;

    while v / 10u64.pow(n + 1) != 0 {
        n += 1;
    }

    for e in (0..=n).rev() {
        let num = ((v / 10u64.pow(e)) % 10) as u32;
        s.push(char::from_digit(num, 10).unwrap());
    }
}

pub struct ArchiveBuilder<V: ArchiveVariant> {
    /// The archive variant
    variant: V,

    /// The members in the archive
    members: Arena<ArchiveMemberBuilder>,
}

impl<V: ArchiveVariant> ArchiveBuilder<V> {
    /// Create a new [`ArchiveBuilder`] for the specified number of members.
    ///
    /// This excludes linker members (armap, longnames, etc.).
    pub fn with_capacity(members: usize) -> ArchiveBuilder<V> {
        Self {
            variant: V::default(),
            members: Arena::with_capacity(members),
        }
    }

    /// Adds a member to the archive.
    ///
    /// Returns an [`ArchiveMemberAccessor`] for modifying the inserted member
    /// metadata.
    pub fn add_member(
        &mut self,
        name: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> ArchiveMemberAccessor<'_, V> {
        let archive_index = self.members.len();

        ArchiveMemberAccessor {
            index: ArchiveMemberIndex(archive_index),
            member: self.members.alloc(ArchiveMemberBuilder::new(
                self.variant.add_long_name(name),
                data.into(),
            )),
            variant: &mut self.variant,
        }
    }

    /// Build the archive
    pub fn build(mut self) -> Vec<u8> {
        // Calculate the buffer size needed for building the archive
        let mut buffer_size = object::archive::MAGIC.len() + self.variant.byte_size();

        // Create the map of archive members to their file offsets
        let mut archive_map = HashMap::with_capacity(self.members.len());
        for (member_idx, member) in self.members.iter_mut().enumerate() {
            archive_map.insert(ArchiveMemberIndex(member_idx), buffer_size);
            buffer_size += member.member_size();
        }

        // Build the archive

        let mut buffer = Vec::with_capacity(buffer_size);
        // Add the signature
        buffer.extend(object::archive::MAGIC);
        // Add the variant members
        buffer.append(&mut self.variant.build(archive_map));

        // Add the rest of the members
        let members = self.members.into_vec();
        for member in members {
            buffer.append(&mut member.build());
        }

        buffer
    }
}

impl ArchiveBuilder<MsvcArchiveVariant> {
    pub fn msvc_archive_with_capacity(members: usize) -> ArchiveBuilder<MsvcArchiveVariant> {
        Self::with_capacity(members)
    }
}

impl ArchiveBuilder<GnuArchiveVariant> {
    pub fn gnu_archive_with_capacity(members: usize) -> ArchiveBuilder<GnuArchiveVariant> {
        Self::with_capacity(members)
    }
}

/// Accessor for modifying metadata of an archive member.
pub struct ArchiveMemberAccessor<'a, V: ArchiveVariant> {
    /// The archive index
    index: ArchiveMemberIndex,

    /// The archive member
    member: &'a mut ArchiveMemberBuilder,

    /// The archive variant
    variant: &'a mut V,
}

impl<V: ArchiveVariant> ArchiveMemberAccessor<'_, V> {
    /// Adds a symbol export to this archive member in the symbol table
    pub fn export(&mut self, symbol: impl AsRef<str>) {
        self.variant.add_exported_symbol(self.index, symbol);
    }

    /// Adds the list of exports to the archive symbol table for this member
    pub fn exports<I, S>(&mut self, symbols: I)
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        for symbol in symbols {
            self.variant.add_exported_symbol(self.index, symbol);
        }
    }

    /// Sets the date timestamp in the archive header to the specified value
    pub fn date(&mut self, ts: u64) {
        self.member.meta.date = Some(ts);
    }

    /// Sets the user id value to the specified value
    pub fn uid(&mut self, uid: u32) {
        self.member.meta.uid = Some(uid);
    }

    /// Sets the group id value to the specified value
    pub fn gid(&mut self, gid: u32) {
        self.member.meta.gid = Some(gid);
    }

    /// Sets the mode to the specified value
    pub fn mode(&mut self, mode: u32) {
        self.member.meta.mode = Some(mode);
    }
}

#[cfg(test)]
mod tests {
    use super::make_ascii_base10;

    #[test]
    fn make_ascii_int() {
        const TESTS: &[(u64, &str)] = &[(123, "123"), (848193, "848193"), (0, "0")];

        for (v, expected) in TESTS {
            let mut value = String::with_capacity(expected.len());
            make_ascii_base10(&mut value, *v);
            assert_eq!(
                value, *expected,
                "integer value should have been converted into ASCII"
            );
        }
    }
}

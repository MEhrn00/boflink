use std::sync::{Mutex, RwLock};

use indexmap::IndexMap;

use crate::{
    coff::{ComdatSelection, StorageClass, SymbolIndex, SymbolSectionNumber},
    inputs::ObjectFileId,
    syncpool::BumpBox,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(usize);

impl SymbolId {
    pub const fn new(idx: usize) -> Self {
        Self(idx)
    }

    const fn index(self) -> usize {
        self.0
    }
}

#[derive(Debug)]
pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub value: u32,
    pub section: SymbolSectionNumber,
    pub typ: u16,
    pub storage_class: StorageClass,
    pub owner: ObjectFileId,
    pub table_index: SymbolIndex,
    pub selection: Option<ComdatSelection>,
}

#[derive(Debug)]
pub struct SymbolMap<'a> {
    map: RwLock<IndexMap<&'a [u8], Mutex<BumpBox<'a, Symbol<'a>>>>>,
}

impl<'a> SymbolMap<'a> {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(IndexMap::new()),
        }
    }
}

//! Concurrent [`IndexMap`] used for object interning.
//!
//! This allows inserting a keyed item by hash returning an index for later retrieval.
//! The main purpose this is for doing string interning https://en.wikipedia.org/wiki/String_interning
//! when using hash maps. Retrieving an item by its index is a lot quicker than
//! doing a regular hash map lookup.
//!
//! An indexmap is used internally but insertion order is not retained.
use std::{
    hash::{BuildHasher, Hash, Hasher, RandomState},
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr::NonNull,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use crossbeam_utils::CachePadded;
use indexmap::IndexMap;
use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};

/// Index value returned for retrieving items later
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Index {
    slot: usize,
    index: usize,
}

impl Index {
    pub const fn slot(&self) -> usize {
        self.slot
    }

    pub const fn index(&self) -> usize {
        self.index
    }
}

pub struct ConcurrentIndexMap<K, V, S = RandomState> {
    hash_builder: S,
    slots: Box<[CachePadded<RwLock<IndexMap<K, V, S>>>]>,
}

impl<K, V> ConcurrentIndexMap<K, V, RandomState> {
    #[allow(unused)]
    pub fn new() -> Self {
        Self::with_hasher(RandomState::default())
    }

    #[allow(unused)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_hasher(capacity, RandomState::default())
    }

    pub fn with_slot_count(count: usize) -> Self {
        Self::with_capacity_hasher_and_slot_count(0, RandomState::default(), count)
    }

    #[allow(unused)]
    pub fn with_capacity_and_slot_count(capacity: usize, slot_count: usize) -> Self {
        Self::with_capacity_hasher_and_slot_count(capacity, RandomState::default(), slot_count)
    }
}

impl<K, V, S: Clone> ConcurrentIndexMap<K, V, S> {
    pub fn with_hasher(hasher: S) -> Self {
        Self::with_capacity_and_hasher(0, hasher)
    }

    pub fn with_capacity_and_hasher(capacity: usize, hasher: S) -> Self {
        Self::with_capacity_hasher_and_slot_count(
            capacity,
            hasher,
            std::thread::available_parallelism()
                .map(|amt| amt.get().next_power_of_two())
                .unwrap_or(4),
        )
    }

    #[allow(unused)]
    pub fn with_hasher_and_slot_count(hasher: S, slot_count: usize) -> Self {
        Self::with_capacity_hasher_and_slot_count(0, hasher, slot_count)
    }

    pub fn with_capacity_hasher_and_slot_count(
        mut capacity: usize,
        hasher: S,
        slot_count: usize,
    ) -> Self {
        assert!(slot_count > 1);
        assert!(slot_count.is_power_of_two());

        // Distribute initial capacity evenly among slots
        if capacity > 0 {
            capacity = capacity.next_multiple_of(slot_count);
        }

        capacity = capacity / slot_count;

        Self {
            hash_builder: hasher.clone(),
            slots: (0..slot_count)
                .map(|_| {
                    CachePadded::new(RwLock::new(IndexMap::with_capacity_and_hasher(
                        capacity,
                        hasher.clone(),
                    )))
                })
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.slots
            .iter()
            .fold(0, |acc, slot| acc + slot.read().unwrap().len())
    }
}

impl<K: Send + Sync, V: Send + Sync, S: Send + Sync> ConcurrentIndexMap<K, V, S> {
    #[allow(unused)]
    pub fn par_for_each_value(&self, f: impl Fn(&V) + Send + Sync) {
        self.slots.par_iter().for_each(|slot| {
            let slot = slot.read().unwrap();
            slot.par_values().for_each(&f);
        });
    }

    pub fn par_for_each_value_mut(&mut self, f: impl Fn(&mut V) + Send + Sync) {
        self.slots.par_iter_mut().for_each(|slot| {
            let slot = slot.get_mut().unwrap();
            slot.par_values_mut().for_each(&f);
        });
    }
}

impl<K, V, S> ConcurrentIndexMap<K, V, S>
where
    K: Hash + Eq,
    S: BuildHasher,
{
    /// Inserts a key-value pair.
    ///
    /// Returns `(Index, Some(_))` with the previous value if the key already
    /// contained a value or `(Index, None)` if the value was newly inserted.
    #[allow(unused)]
    pub fn insert(&self, key: K, value: V) -> (Index, Option<V>) {
        match self.entry(key) {
            Entry::Occupied(mut entry) => {
                let value = entry.insert(value);
                (entry.index(), Some(value))
            }
            Entry::Vacant(entry) => {
                let entry = entry.insert_entry(value);
                (entry.index(), None)
            }
        }
    }

    /// Gets a read reference to the entry at `index`
    pub fn get(&self, index: Index) -> Option<Ref<'_, K, V, S>> {
        let slot = self.slots[index.slot()].read().unwrap();
        let (key, value) = slot.get_index(index.index())?;
        Some(Ref {
            key: NonNull::from(key),
            value: NonNull::from(value),
            _guard: slot,
        })
    }

    /// Gets a write reference to the entry at `index`.
    ///
    /// # Notes
    /// This will acquire a write lock on the slot that the entry is located in
    #[allow(unused)]
    pub fn get_mut(&self, index: Index) -> Option<RefMut<'_, K, V, S>> {
        let mut slot = self.slots[index.slot()].write().unwrap();
        let (key, value) = slot.get_index_mut(index.index())?;
        Some(RefMut {
            key: NonNull::from(key),
            value: NonNull::from(value),
            _guard: slot,
            _invariant: PhantomData,
        })
    }

    /// Concurrent entry API for inserting/modifying an element by looking up
    /// its key.
    ///
    /// # Notes
    /// This will acquire a write lock on the slot that the entry is located in.
    pub fn entry(&self, key: K) -> Entry<'_, K, V, S> {
        let slot_idx = self.compute_slot(&key);
        let map = &self.slots[slot_idx];
        let mut guard = map.write().unwrap();
        match guard.entry(key) {
            indexmap::map::Entry::Vacant(entry) => Entry::Vacant(VacantEntry {
                index: Index {
                    slot: slot_idx,
                    index: entry.index(),
                },
                key: entry.into_key(),
                map: guard,
            }),
            indexmap::map::Entry::Occupied(entry) => Entry::Occupied(OccupiedEntry {
                index: Index {
                    slot: slot_idx,
                    index: entry.index(),
                },
                map: guard,
            }),
        }
    }

    /// Entry API that operates on an exclusive reference to the map.
    ///
    /// This allows bypassing read/write locks when accessing values.
    pub fn exclusive_entry(&mut self, key: K) -> ExclusiveEntry<'_, K, V> {
        let slot_idx = self.compute_slot(&key);
        let slot = self.slots[slot_idx].get_mut().unwrap();
        match slot.entry(key) {
            indexmap::map::Entry::Occupied(entry) => {
                ExclusiveEntry::Occupied(ExclusiveOccupiedEntry {
                    slot: slot_idx,
                    entry,
                })
            }
            indexmap::map::Entry::Vacant(entry) => ExclusiveEntry::Vacant(ExclusiveVacantEntry {
                slot: slot_idx,
                entry,
            }),
        }
    }

    /// Get an exclusive reference to the key-value pair at `index`.
    pub fn get_exclusive(&mut self, index: Index) -> Option<(&K, &mut V)> {
        let slot = self.slots[index.slot()].get_mut().unwrap();
        slot.get_index_mut(index.index())
    }

    /// Get an exclusive reference to the value at `index`.
    pub fn get_exclusive_value(&mut self, index: Index) -> Option<&mut V> {
        self.get_exclusive(index).map(|(_, v)| v)
    }

    fn compute_slot(&self, key: &K) -> usize {
        let mut state = self.hash_builder.build_hasher();
        key.hash(&mut state);
        state.finish() as usize % self.slots.len()
    }
}

impl<K, V, S> Default for ConcurrentIndexMap<K, V, S>
where
    K: Eq + Hash,
    S: Default + BuildHasher + Clone,
{
    fn default() -> Self {
        Self::with_hasher(Default::default())
    }
}

impl<K, V, S> std::fmt::Debug for ConcurrentIndexMap<K, V, S>
where
    K: std::fmt::Debug,
    V: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_map = f.debug_map();

        for slot in self.slots.iter() {
            if let Ok(map) = slot.read() {
                map.iter().for_each(|(k, v)| {
                    debug_map.entry(k, v);
                });
            }
        }

        debug_map.finish()
    }
}

pub enum Entry<'a, K, V, S = RandomState> {
    Occupied(OccupiedEntry<'a, K, V, S>),
    Vacant(VacantEntry<'a, K, V, S>),
}

impl<'a, K, V, S> Entry<'a, K, V, S> {
    pub fn index(&self) -> Index {
        match self {
            Self::Occupied(entry) => entry.index(),
            Self::Vacant(entry) => entry.index(),
        }
    }
}

impl<'a, K, V, S> Entry<'a, K, V, S>
where
    K: Hash + Eq,
    S: BuildHasher,
{
    #[allow(unused)]
    pub fn insert_entry(self, value: V) -> OccupiedEntry<'a, K, V, S> {
        match self {
            Self::Occupied(mut entry) => {
                entry.insert(value);
                entry
            }
            Self::Vacant(entry) => entry.insert_entry(value),
        }
    }

    pub fn or_insert_with(self, f: impl FnOnce() -> V) -> RefMut<'a, K, V, S> {
        match self {
            Self::Occupied(entry) => entry.into_mut(),
            Self::Vacant(entry) => entry.insert(f()),
        }
    }
}

pub struct OccupiedEntry<'a, K, V, S = RandomState> {
    index: Index,
    map: RwLockWriteGuard<'a, IndexMap<K, V, S>>,
}

impl<'a, K, V, S> OccupiedEntry<'a, K, V, S> {
    pub fn index(&self) -> Index {
        self.index
    }
}

impl<'a, K, V, S> OccupiedEntry<'a, K, V, S>
where
    K: Hash + Eq,
    S: BuildHasher,
{
    pub fn insert(&mut self, value: V) -> V {
        let mut entry = self.map.get_index_entry(self.index.index).unwrap();
        entry.insert(value)
    }

    pub fn into_mut(mut self) -> RefMut<'a, K, V, S> {
        let entry = self.map.get_index_entry(self.index.index).unwrap();
        let key = NonNull::from(entry.key());
        let value = NonNull::from(entry.into_mut());
        RefMut {
            key,
            value,
            _guard: self.map,
            _invariant: PhantomData,
        }
    }
}

pub struct VacantEntry<'a, K, V, S = RandomState> {
    index: Index,
    key: K,
    map: RwLockWriteGuard<'a, IndexMap<K, V, S>>,
}

impl<'a, K, V, S> VacantEntry<'a, K, V, S> {
    pub fn index(&self) -> Index {
        self.index
    }

    #[allow(unused)]
    pub fn key(&self) -> &K {
        &self.key
    }

    #[allow(unused)]
    pub fn into_key(self) -> K {
        self.key
    }
}

impl<'a, K, V, S> VacantEntry<'a, K, V, S>
where
    K: Hash + Eq,
    S: BuildHasher,
{
    pub fn insert_entry(mut self, value: V) -> OccupiedEntry<'a, K, V, S> {
        let entry = self.map.entry(self.key);
        entry.insert_entry(value);
        OccupiedEntry {
            index: self.index,
            map: self.map,
        }
    }

    pub fn insert(mut self, value: V) -> RefMut<'a, K, V, S> {
        let entry = self.map.entry(self.key);
        let entry = entry.insert_entry(value);
        let key = NonNull::from(entry.key());
        let value = NonNull::from(entry.into_mut());
        RefMut {
            key,
            value,
            _guard: self.map,
            _invariant: PhantomData,
        }
    }
}

pub enum ExclusiveEntry<'a, K, V> {
    Occupied(ExclusiveOccupiedEntry<'a, K, V>),
    Vacant(ExclusiveVacantEntry<'a, K, V>),
}

impl<'a, K, V> ExclusiveEntry<'a, K, V> {
    #[allow(unused)]
    pub fn index(&self) -> Index {
        match self {
            Self::Occupied(entry) => entry.index(),
            Self::Vacant(entry) => entry.index(),
        }
    }
}

impl<'a, K, V> ExclusiveEntry<'a, K, V> {
    #[allow(unused)]
    pub fn insert_entry(self, value: V) -> ExclusiveOccupiedEntry<'a, K, V> {
        match self {
            Self::Occupied(mut entry) => {
                entry.insert(value);
                entry
            }
            Self::Vacant(entry) => entry.insert_entry(value),
        }
    }

    #[allow(unused)]
    pub fn or_insert_with(self, f: impl FnOnce() -> V) -> &'a mut V {
        match self {
            Self::Occupied(entry) => entry.into_mut(),
            Self::Vacant(entry) => entry.insert(f()),
        }
    }
}

pub struct ExclusiveOccupiedEntry<'a, K, V> {
    slot: usize,
    entry: indexmap::map::OccupiedEntry<'a, K, V>,
}

impl<'a, K, V> ExclusiveOccupiedEntry<'a, K, V> {
    pub fn index(&self) -> Index {
        Index {
            slot: self.slot,
            index: self.entry.index(),
        }
    }

    pub fn insert(&mut self, value: V) -> V {
        self.entry.insert(value)
    }

    pub fn into_mut(self) -> &'a mut V {
        self.entry.into_mut()
    }
}

pub struct ExclusiveVacantEntry<'a, K, V> {
    slot: usize,
    entry: indexmap::map::VacantEntry<'a, K, V>,
}

impl<'a, K, V> ExclusiveVacantEntry<'a, K, V> {
    pub fn index(&self) -> Index {
        Index {
            slot: self.slot,
            index: self.entry.index(),
        }
    }

    pub fn key(&self) -> &K {
        self.entry.key()
    }

    #[allow(unused)]
    pub fn into_key(self) -> K {
        self.entry.into_key()
    }

    pub fn insert_entry(self, value: V) -> ExclusiveOccupiedEntry<'a, K, V> {
        ExclusiveOccupiedEntry {
            slot: self.slot,
            entry: self.entry.insert_entry(value),
        }
    }

    pub fn insert(self, value: V) -> &'a mut V {
        self.entry.insert(value)
    }
}

pub struct RefMut<'a, K, V, S = RandomState> {
    key: NonNull<K>,
    value: NonNull<V>,
    _guard: RwLockWriteGuard<'a, IndexMap<K, V, S>>,
    _invariant: PhantomData<&'a mut V>,
}

impl<'a, K, V, S> RefMut<'a, K, V, S> {
    #[allow(unused)]
    pub fn key(&self) -> &K {
        self.pair().0
    }

    pub fn value(&self) -> &V {
        self.pair().1
    }

    pub fn value_mut(&mut self) -> &mut V {
        self.pair_mut().1
    }

    pub fn pair(&self) -> (&K, &V) {
        unsafe { (self.key.as_ref(), self.value.as_ref()) }
    }

    pub fn pair_mut(&mut self) -> (&K, &mut V) {
        // SAFETY: write guard over the slot with the entry ensures that the key
        // and value pointers stay valid. Value can be mutable since the returned
        // lifetime is bound to `&mut self`, it is invariant over V and it was
        // derived from a mutable reference to the index map entry value.
        unsafe { (self.key.as_ref(), self.value.as_mut()) }
    }
}

impl<'a, K, V, S> Deref for RefMut<'a, K, V, S> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        self.value()
    }
}

impl<'a, K, V, S> DerefMut for RefMut<'a, K, V, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value_mut()
    }
}

pub struct Ref<'a, K, V, S = RandomState> {
    key: NonNull<K>,
    value: NonNull<V>,
    _guard: RwLockReadGuard<'a, IndexMap<K, V, S>>,
}

impl<'a, K, V, S> Ref<'a, K, V, S> {
    pub fn key(&self) -> &K {
        self.pair().0
    }

    pub fn value(&self) -> &V {
        self.pair().1
    }

    pub fn pair(&self) -> (&K, &V) {
        // SAFETY: read guard over the slot with the entry ensures that the key
        // and value pointers stay valid. Value cannot be turned into a `&mut V`
        // because it was not acquired through a mutable reference.
        unsafe { (self.key.as_ref(), self.value.as_ref()) }
    }
}

impl<'a, K, V, S> Deref for Ref<'a, K, V, S> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        self.value()
    }
}

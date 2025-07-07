//! Proxy functions for [`undname_sys::__unDName`] mem callbacks.

use std::{alloc::Layout, mem::MaybeUninit};

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
pub unsafe extern "C" fn memget_callback(size: usize) -> *mut std::ffi::c_void {
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
pub unsafe extern "C" fn memfree_callback(ptr: *mut std::ffi::c_void) {
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
    use super::{memfree_callback, memget_callback};

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
    fn alloc_zero() {
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
    fn small_allocations() {
        run_allocation_tests((1..=0x250).step_by(10));
    }

    #[test]
    fn medium_allocations() {
        run_allocation_tests((0x250..=0x500).step_by(10));
    }

    #[test]
    fn large_allocations() {
        run_allocation_tests((0x500..=0x900).step_by(10));
    }

    #[test]
    fn page_boundaries() {
        run_allocation_tests(
            [
                0xfff, 0x1000, 0x1001, 0x1fff, 0x2000, 0x2001, 0x2fff, 0x3000, 0x3001,
            ]
            .into_iter(),
        );
    }
}

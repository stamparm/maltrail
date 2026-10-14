//! Where the trail store's big arrays live: the heap, or a file-backed shared mapping.
//!
//! The store is ~120 MB at 1.9 M trails. On the heap that is anonymous memory, which a box without
//! swap can only get back by killing the process - on a 221 MB Raspberry Pi the kernel's OOM killer
//! did exactly that, and a reload (which builds the new store while the old one is still serving)
//! needed twice as much. In a `MAP_SHARED` mapping of a file the same bytes are page cache: the
//! kernel writes them back once and can then drop and re-read them under pressure like any other
//! file page, so the store costs what the box can spare rather than all of it at once.
//!
//! The mapping is not a cache. Every load builds a fresh store into a fresh file, which is unlinked
//! the moment it is created - nothing on disk can go stale, outlive the process, or be read by
//! the next load, so there is no question of it holding a whitelist or a trail set other than the
//! one this load was given. Space is reserved with `posix_fallocate` before anything is mapped:
//! writing a page of a sparse file on a full disk is a SIGBUS, and a sensor must not die of that.
//! Anything that fails - no directory, no space, no `mmap` - falls back to the heap, which is what
//! the store always used.

use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;

/// Types a region can hold: `Copy`, no `Drop`, and every byte written before it is read (a region
/// is always created filled), so viewing mapped memory as `[T]` is sound.
///
/// # Safety
/// Implement only for plain-old-data types without padding-dependent invariants.
pub unsafe trait Pod: Copy + 'static {}

unsafe impl Pod for u8 {}
unsafe impl Pod for u64 {}

/// Where to put file-backed regions. `None` everywhere means the heap.
#[derive(Clone)]
pub struct Spill {
    // only Linux maps; elsewhere every region is on the heap
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    dir: Arc<PathBuf>,
}

impl Spill {
    pub fn new(dir: PathBuf) -> Spill {
        Spill { dir: Arc::new(dir) }
    }

    #[cfg(target_os = "linux")]
    fn map(&self, bytes: usize) -> Option<*mut u8> {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);

        if bytes == 0 {
            return None;
        }
        let name = format!(".maltrail-trails-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
        let path = self.dir.join(name);
        let mut cpath = path.as_os_str().as_bytes().to_vec();
        cpath.push(0);
        unsafe {
            let fd = libc::open(
                cpath.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            );
            if fd < 0 {
                return None;
            }
            // Unlinked at once: the mapping keeps the inode alive, and nothing is left behind by
            // any way this process can end.
            libc::unlink(cpath.as_ptr() as *const libc::c_char);
            let ptr = if libc::posix_fallocate(fd, 0, bytes as libc::off_t) == 0 {
                libc::mmap(std::ptr::null_mut(), bytes, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0)
            } else {
                libc::MAP_FAILED
            };
            libc::close(fd);
            if ptr == libc::MAP_FAILED {
                None
            } else {
                Some(ptr as *mut u8)
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn map(&self, _bytes: usize) -> Option<*mut u8> {
        None
    }
}

enum Backing<T> {
    /// Held only to own (and eventually free) the memory `ptr` points into.
    #[allow(dead_code)]
    Heap(Vec<T>),
    // read only by the Linux unmap/msync paths; elsewhere nothing is ever mapped
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Mapped { bytes: usize },
}

/// A fixed-length array of `T`, on the heap or file-backed (see the module doc).
pub struct Region<T: Pod> {
    ptr: *mut T,
    len: usize,
    backing: Backing<T>,
    _marker: PhantomData<T>,
}

// The region owns its memory exclusively, exactly like the `Vec` it replaces.
unsafe impl<T: Pod + Send> Send for Region<T> {}
unsafe impl<T: Pod + Sync> Sync for Region<T> {}

impl<T: Pod> Region<T> {
    pub fn filled(len: usize, value: T, spill: Option<&Spill>) -> Region<T> {
        let bytes = len.saturating_mul(std::mem::size_of::<T>());
        if let Some(raw) = spill.and_then(|s| s.map(bytes)) {
            let ptr = raw as *mut T;
            // A fresh mapping of a fallocated file reads as zeroes; writing zeroes over it would
            // only dirty every page for nothing.
            // SAFETY: viewing a `Pod` value as its bytes.
            let zero = unsafe { std::slice::from_raw_parts(&value as *const T as *const u8, std::mem::size_of::<T>()) }
                .iter()
                .all(|b| *b == 0);
            if !zero {
                for i in 0..len {
                    // SAFETY: `ptr` maps `len` elements, page-aligned (so aligned for any `T` here).
                    unsafe { ptr.add(i).write(value) };
                }
            }
            return Region { ptr, len, backing: Backing::Mapped { bytes }, _marker: PhantomData };
        }
        let mut v = vec![value; len];
        let ptr = v.as_mut_ptr();
        Region { ptr, len, backing: Backing::Heap(v), _marker: PhantomData }
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self.backing, Backing::Mapped { .. })
    }

    /// Start writing the dirty pages back now, so they are reclaimable by the time the kernel wants
    /// them rather than only after it has waited for the writeback.
    pub fn flush_async(&self) {
        #[cfg(target_os = "linux")]
        if let Backing::Mapped { bytes } = self.backing {
            unsafe { libc::msync(self.ptr as *mut libc::c_void, bytes, libc::MS_ASYNC) };
        }
    }
}

impl<T: Pod> std::ops::Deref for Region<T> {
    type Target = [T];
    #[inline]
    fn deref(&self) -> &[T] {
        // SAFETY: `ptr` points at `len` initialised elements owned by this region.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T: Pod> std::ops::DerefMut for Region<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as above, and `&mut self` is exclusive.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl<T: Pod> Drop for Region<T> {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Backing::Mapped { bytes } = self.backing {
            unsafe { libc::munmap(self.ptr as *mut libc::c_void, bytes) };
        }
    }
}

/// The key-text arena: append-only bytes. File-backed, it is sized up front to an upper bound (a
/// mapped page that is never written costs nothing) and copied into a bigger region in the rare
/// case the bound was wrong.
pub enum Arena {
    Heap(Vec<u8>),
    Mapped { region: Region<u8>, used: usize, spill: Spill },
}

impl Arena {
    pub fn with_capacity(capacity: usize, spill: Option<&Spill>) -> Arena {
        if let Some(spill) = spill {
            let region = Region::filled(capacity.max(4096), 0u8, Some(spill));
            if region.is_mapped() {
                return Arena::Mapped { region, used: 0, spill: spill.clone() };
            }
        }
        Arena::Heap(Vec::with_capacity(capacity))
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Arena::Heap(v) => v.len(),
            Arena::Mapped { used, .. } => *used,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        match self {
            Arena::Heap(v) => v.extend_from_slice(data),
            Arena::Mapped { region, used, spill } => {
                if *used + data.len() > region.len() {
                    let mut bigger = Region::filled((region.len() * 2).max(*used + data.len()), 0u8, Some(spill));
                    bigger[..*used].copy_from_slice(&region[..*used]);
                    *region = bigger;
                }
                region[*used..*used + data.len()].copy_from_slice(data);
                *used += data.len();
            }
        }
    }

    pub fn flush_async(&self) {
        if let Arena::Mapped { region, .. } = self {
            region.flush_async();
        }
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self, Arena::Mapped { .. })
    }
}

impl std::ops::Deref for Arena {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            Arena::Heap(v) => v,
            Arena::Mapped { region, used, .. } => &region[..*used],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::table::{IntTable, StrTable};
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("maltrail-region-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_region_is_file_backed_and_leaves_nothing_behind() {
        let dir = scratch("backed");
        let spill = Spill::new(dir.clone());
        let mut region = Region::filled(1 << 20, u64::MAX, Some(&spill));
        assert!(region.is_mapped(), "positive control: this must not have fallen back to the heap");
        assert!(region.iter().all(|&v| v == u64::MAX));
        region[12345] = 7;
        assert_eq!(region[12345], 7);
        // unlinked at creation, so the directory is empty while the mapping is alive
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        drop(region);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unusable_directory_falls_back_to_the_heap() {
        let spill = Spill::new(PathBuf::from("/nonexistent/maltrail/region"));
        let region = Region::filled(1000, 3u64, Some(&spill));
        assert!(!region.is_mapped());
        assert!(region.iter().all(|&v| v == 3));
    }

    /// Mapped and heap tables must answer every lookup identically - including after the slot
    /// array grew (a tiny capacity forces several rehashes into fresh mappings) and after the arena
    /// outgrew its mapped bound (a tiny hint forces the copy path).
    #[test]
    fn file_backed_tables_answer_exactly_like_heap_ones() {
        let dir = scratch("tables");
        let spill = Spill::new(dir.clone());
        let mut mapped = StrTable::with_capacity_in(4, 16, Some(&spill));
        let mut heap = StrTable::with_capacity(4, 16);
        let mut mapped4: IntTable<u32> = IntTable::with_capacity_in(4, Some(&spill));
        let mut heap4: IntTable<u32> = IntTable::with_capacity(4);
        for i in 0..50_000u32 {
            let key = format!("host{i}.example.com");
            assert_eq!(mapped.insert(&key, i), heap.insert(&key, i));
            mapped4.insert(i.wrapping_mul(2_654_435_761), i);
            heap4.insert(i.wrapping_mul(2_654_435_761), i);
        }
        // positive control: the grown table must still be file-backed (only Linux maps at all)
        assert_eq!(mapped.is_mapped(), cfg!(target_os = "linux"));
        assert_eq!(mapped.len(), heap.len());
        for i in 0..60_000u32 {
            let key = format!("host{i}.example.com");
            assert_eq!(mapped.get(&key), heap.get(&key), "{key}");
            let k = i.wrapping_mul(2_654_435_761);
            assert_eq!(mapped4.get(k), heap4.get(k));
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

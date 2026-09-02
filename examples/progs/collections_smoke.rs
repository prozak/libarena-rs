#![no_std]
#![no_main]

//! Real Rust `alloc` collections running in BPF, backed by a BPF arena via
//! libarena's buddy allocator (see the libarena-rs README).
//!
//! Each SEC("syscall") program is a self-checking test run by the runner
//! with bpf_prog_test_run(); return 0 = pass, a small nonzero code = the
//! failing step. Userspace must run libarena's `arena_buddy_reset` program
//! first to initialize the allocator.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use libarena_rs::ArenaAlloc;

#[global_allocator]
static ALLOC: ArenaAlloc = ArenaAlloc;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rs_box(_ctx: *const c_void) -> i32 {
    let b = Box::new(0xdead_beefu64);
    if *b != 0xdead_beef {
        return 1;
    }
    // .get() instead of indexing: an out-of-bounds panic path would drag
    // core::fmt integer formatting into the object, which the BPF backend
    // cannot lower (6-arg calls / stack arguments)
    let b2 = Box::new([7u32; 16]);
    if b2.get(15).copied() != Some(7) {
        return 2;
    }
    drop(b);
    drop(b2);
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rs_vec(_ctx: *const c_void) -> i32 {
    let mut v: Vec<u64> = Vec::new();
    for i in 0..100u64 {
        v.push(i * i);
    }
    if v.len() != 100 {
        return 1;
    }
    let sum: u64 = v.iter().sum();
    if sum != (0..100u64).map(|i| i * i).sum::<u64>() {
        return 2;
    }
    // exercise realloc/shrink paths
    v.truncate(10);
    v.shrink_to_fit();
    if v.len() != 10 || v.get(9).copied() != Some(81) {
        return 3;
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rs_string(_ctx: *const c_void) -> i32 {
    let mut s = String::new();
    for _ in 0..10 {
        s.push_str("arena");
    }
    if s.len() != 50 {
        return 1;
    }
    if !s.starts_with("arenaarena") || !s.ends_with("arena") {
        return 2;
    }
    let mut upper = s.clone();
    upper.make_ascii_uppercase();
    if !upper.starts_with("ARENA") || upper.len() != s.len() {
        return 3;
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rs_vecdeque(_ctx: *const c_void) -> i32 {
    let mut q: VecDeque<u32> = VecDeque::new();
    for i in 0..64u32 {
        if i % 2 == 0 {
            q.push_back(i);
        } else {
            q.push_front(i);
        }
    }
    if q.len() != 64 {
        return 1;
    }
    // fronts are odd descending: 63, 61, ...
    if q.pop_front() != Some(63) || q.pop_back() != Some(62) {
        return 2;
    }
    let sum: u32 = q.iter().sum();
    if sum != (0..64u32).sum::<u32>() - 63 - 62 {
        return 3;
    }
    0
}

// NOTE: pointer-chasing collections (BTreeMap, Vec<Vec<..>>) are out of
// scope for v1: node/child pointers stored INSIDE arena memory come back
// as verifier scalars on reload, and only clang's __arena address space
// (a cast at every deref) can re-establish PTR_TO_ARENA typing — rustc
// has no equivalent. Flat collections (contiguous buffers whose only
// pointer lives in a stack-resident header) verify fine. See the README.

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rs_sort(_ctx: *const c_void) -> i32 {
    // in-place algorithms over an arena-backed Vec (flat, no stored ptrs)
    let mut v: Vec<u32> = Vec::with_capacity(24);
    let mut x: u32 = 1;
    for _ in 0..24 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        v.push(x % 1000);
    }
    // insertion sort via swaps
    for i in 1..24usize {
        let mut j = i;
        while j > 0 {
            let a = v.get(j - 1).copied();
            let b = v.get(j).copied();
            match (a, b) {
                (Some(a), Some(b)) if a > b => v.swap(j - 1, j),
                _ => break,
            }
            j -= 1;
        }
    }
    let mut prev = 0u32;
    for k in v.iter() {
        if *k < prev {
            return 1;
        }
        prev = *k;
    }
    if v.is_empty() || v.len() > 24 {
        return 2;
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_rs_grow_shrink(_ctx: *const c_void) -> i32 {
    // exercise the allocator through many realloc cycles
    let mut v: Vec<u64> = Vec::new();
    for round in 0..8u64 {
        for i in 0..64u64 {
            v.push(round * 1000 + i);
        }
        v.truncate(16);
        v.shrink_to_fit();
    }
    if v.len() != 16 {
        return 1;
    }
    // truncate(16) keeps the first 16 elements, which are the round-0
    // survivors 0..16 on every round
    let s: u64 = v.iter().sum();
    if s != (0..16u64).sum::<u64>() {
        return 2;
    }
    0
}

//! Spin-loop test fixture for the dvm-plugin-host bounds evidence (WP-M2b).
//!
//! Implements the Omega Plugin ABI v0 surface (`allocate`, `_start`, `memory`)
//! but `_start` spins in a tight CPU loop instead of returning. The host's
//! fuel budget / epoch deadline MUST terminate it (`timeout`); without host
//! enforcement this function never returns.
//!
//! This fixture is NOT a marketplace plugin — it exists only to prove the
//! enforcement point terminates CPU-bound guests.

#![no_std]
#![no_main]

use core::arch::wasm32;
use core::panic::PanicInfo;

static mut BUMP: usize = 0;

extern "C" {
    static __heap_base: u8;
}

/// Allocate `size` zero-initialized bytes (bump allocator, mirrors the seed).
#[no_mangle]
pub extern "C" fn allocate(size: u32) -> u32 {
    unsafe {
        let heap_base = &__heap_base as *const u8 as usize;
        if BUMP == 0 {
            BUMP = heap_base;
        }
        const ALIGN: usize = 8;
        let cur = BUMP;
        let aligned = (cur + ALIGN - 1) & !(ALIGN - 1);
        let end = aligned + size as usize;
        const MAX_BYTES: usize = 64 * 1024 * 1024;
        if end > MAX_BYTES {
            return 0;
        }
        let pages_needed = (end + 65535) / 65536;
        let current_pages = wasm32::memory_size::<0>() as usize;
        if pages_needed > current_pages {
            let grown = wasm32::memory_grow::<0>(pages_needed - current_pages);
            if grown == usize::MAX {
                return 0;
            }
        }
        BUMP = end;
        core::ptr::write_bytes(aligned as *mut u8, 0, size as usize);
        aligned as u32
    }
}

/// Entry point that NEVER returns: a tight CPU-bound loop.
///
/// # Safety
/// ABI signature surface only; the host must enforce time/fuel bounds.
#[no_mangle]
pub extern "C" fn _start(_ptr: u32, _len: u32) -> u32 {
    // Volatile counter so the loop cannot be optimized away.
    let mut counter: u32 = 0;
    loop {
        unsafe {
            core::ptr::read_volatile(&counter);
        }
        counter = counter.wrapping_add(1);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    wasm32::unreachable()
}
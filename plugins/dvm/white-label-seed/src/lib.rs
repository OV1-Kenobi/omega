//! White-label seed plugin for the Omega DVM marketplace.
//!
//! Implements the Omega Plugin ABI v0 (`allocate` + `_start`) as a PureCompute
//! plugin: no filesystem, no network, no ambient imports. Stateless — a fresh
//! instance per call.
//!
//! ABI contract (see WP-M1 01-manifest-schema.md):
//! - `allocate(size: i32) -> i32` — bump allocator, returns a pointer to
//!   `size` zero-initialized bytes, or 0 on out-of-memory.
//! - `_start(ptr: i32, len: i32) -> i32` — reads the JSON input at
//!   `[ptr, ptr+len)`, computes, writes the JSON output, and returns a pointer
//!   to an 8-byte result header `[out_ptr: i32, out_len: i32]` in linear
//!   memory. A header with `out_len == 0` signals an execution error.
//!
//! Service identity (F-04): the DVM identity the plugin reports comes from
//! `service_identity.rs` — the template's SINGLE machine-substitutable
//! substitution point, owned by `dvm-plugin-cli publish`. The manifest's
//! `omega.service` block and this compiled-in constant are produced from the
//! same publish-time input, and the publish pipeline's identity-consistency
//! assertion proves they match in the pinned artifact. Hand-editing
//! `service_identity.rs` is unsupported.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::alloc::Layout;
use alloc::format;
use alloc::string::{String, ToString};
use core::arch::wasm32;
use core::panic::PanicInfo;

// ---------------------------------------------------------------------------
// Global allocator: bump allocator over the wasm linear memory.
// A plugin instance lives for exactly one call, so free is a no-op.
// ---------------------------------------------------------------------------

struct BumpAllocator;

unsafe impl alloc::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocate(layout.size() as u32) as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: nothing to do. Instance is discarded after the call.
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = allocate(new_size as u32) as *mut u8;
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }
        core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
        new_ptr
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

// ---------------------------------------------------------------------------
// ABI exports
// ---------------------------------------------------------------------------

// Address of the start of the heap, defined by the linker.
extern "C" {
    static __heap_base: u8;
}

static mut BUMP: usize = 0;

/// Bump allocator exported to the host per Omega Plugin ABI v0.
///
/// # Safety
/// `size` is a host-supplied allocation request. Returns a pointer to
/// `size` zero-initialized bytes or 0 on failure.
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

        // Hard cap at 64 MiB (matches memory_max_mib in the manifest).
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

/// Entry point exported to the host per Omega Plugin ABI v0.
///
/// # Safety
/// `ptr`/`len` must reference a valid UTF-8 JSON string in the instance's
/// linear memory, as written by the host.
#[no_mangle]
pub extern "C" fn _start(ptr: u32, len: u32) -> u32 {
    let result = run(ptr, len);
    match result {
        Ok(output_json) => {
            let out_len = output_json.len() as u32;
            let out_ptr = allocate(out_len);
            if out_ptr == 0 {
                return write_error_header(ErrorCode::OutOfMemory, "out of memory");
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    output_json.as_ptr(),
                    out_ptr as *mut u8,
                    out_len as usize,
                );
            }
            write_header(out_ptr, out_len)
        }
        Err((code, message)) => write_error_header(code, &message),
    }
}

// ---------------------------------------------------------------------------
// Plugin logic
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct Input {
    text: String,
}

#[derive(serde::Serialize)]
struct Output {
    words: usize,
    lines: usize,
    chars: usize,
    service: ServiceIdentity,
}

#[derive(serde::Serialize)]
struct ServiceIdentity {
    npub: &'static str,
    relays: &'static [&'static str],
    kind: u32,
}

// ---------------------------------------------------------------------------
// Single service-identity substitution point (F-04)
// ---------------------------------------------------------------------------

// The DVM service identity lives in exactly one machine-substitutable place:
// the generated file below. The publish pipeline (`dvm-plugin-cli publish`)
// rewrites this file from the manifest's `omega.service` block, then rebuilds
// and pins the artifact, so the compiled-in identity and the manifest identity
// are the same publish-time input. The mandatory identity-consistency
// assertion (`dvm-plugin-cli verify-identity`) proves it in the artifact.
include!("service_identity.rs");

const SERVICE: ServiceIdentity = ServiceIdentity {
    npub: SERVICE_NPUB,
    relays: SERVICE_RELAYS,
    kind: SERVICE_KIND,
};

fn run(ptr: u32, len: u32) -> Result<String, (ErrorCode, String)> {
    let input_slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let input_text = core::str::from_utf8(input_slice).map_err(|_| {
        (
            ErrorCode::InputInvalid,
            "input is not valid UTF-8".to_string(),
        )
    })?;

    let input: Input = serde_json::from_str(input_text)
        .map_err(|e| (ErrorCode::InputInvalid, format!("input invalid: {e}")))?;

    let words = input.text.split_whitespace().count();
    let lines = if input.text.is_empty() {
        0
    } else {
        input.text.lines().count()
    };
    let chars = input.text.chars().count();

    let output = Output {
        words,
        lines,
        chars,
        service: SERVICE,
    };
    serde_json::to_string(&output)
        .map_err(|e| (ErrorCode::Internal, format!("serialize failed: {e}")))
}

// ---------------------------------------------------------------------------
// Result header helpers
// ---------------------------------------------------------------------------

#[repr(C)]
struct ResultHeader {
    out_ptr: u32,
    out_len: u32,
}

#[derive(Clone, Copy)]
enum ErrorCode {
    InputInvalid = 1,
    OutOfMemory = 2,
    Internal = 3,
}

fn write_header(out_ptr: u32, out_len: u32) -> u32 {
    let header_ptr = allocate(core::mem::size_of::<ResultHeader>() as u32);
    if header_ptr == 0 {
        return 0;
    }
    unsafe {
        let header = &mut *(header_ptr as *mut ResultHeader);
        header.out_ptr = out_ptr;
        header.out_len = out_len;
    }
    header_ptr
}

fn write_error_header(code: ErrorCode, message: &str) -> u32 {
    // Best-effort: serialize a small error object so the host can surface it.
    #[derive(serde::Serialize)]
    struct ErrorBody<'a> {
        error: ErrorDetail<'a>,
    }
    #[derive(serde::Serialize)]
    struct ErrorDetail<'a> {
        code: u32,
        message: &'a str,
    }
    if let Ok(json) = serde_json::to_string(&ErrorBody {
        error: ErrorDetail {
            code: code as u32,
            message,
        },
    }) {
        let out_len = json.len() as u32;
        let out_ptr = allocate(out_len);
        if out_ptr != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(json.as_ptr(), out_ptr as *mut u8, out_len as usize);
            }
            return write_header(out_ptr, out_len);
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Panic / OOM handlers
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    wasm32::unreachable()
}
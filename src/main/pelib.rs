use core::ffi::c_void;

use crate::main::windows::{
    GetProcAddress, LoadLibraryW, IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE,
    IMAGE_SECTION_HEADER,
};

use alloc::vec::{self, Vec};
use rust_syscalls::syscall;

pub fn get_headers_size(buffer: &[u8]) -> usize {
    // Check if the first two bytes of the buffer are "MZ"
    if buffer.len() >= 2 && buffer[0] == b'M' && buffer[1] == b'Z' {
        // Get the offset to the NT header
        if buffer.len() >= 64 {
            let offset =
                u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize;
            // Check the bit version and return the size of the headers
            if buffer.len() >= offset + 4 + 20 + 2 {
                match u16::from_le_bytes([buffer[offset + 4 + 20], buffer[offset + 4 + 20 + 1]]) {
                    523 | 267 => {
                        let headerssize = u32::from_le_bytes([
                            buffer[offset + 24 + 60],
                            buffer[offset + 24 + 60 + 1],
                            buffer[offset + 24 + 60 + 2],
                            buffer[offset + 24 + 60 + 3],
                        ]);
                        return headerssize as usize;
                    }
                    _ => panic!("nvld bit vrsn"),
                }
            } else {
                panic!("fl sz s lss thn rqrd ffst");
            }
        } else {
            panic!("fl sz s lss thn 64");
        }
    } else {
        panic!("it's nt a vld fl");
    }
}

pub fn get_image_size(buffer: &[u8]) -> usize {
    // Get the magic string from the buffer
    let magic = &buffer[0..2];
    // Convert the magic string to a string
    let magicstring = match core::str::from_utf8(magic) {
        Ok(s) => s,
        Err(_) => panic!("nvld mgc strng"),
    };
    // Check if the magic string is "MZ"
    assert_eq!(magicstring, "MZ", "it's not a PE fl");
    // Get the offset to the NT header
    let offset = {
        let ntoffset = &buffer[60..64];
        let mut offset = [0u8; 4];
        offset.copy_from_slice(ntoffset);
        i32::from_le_bytes(offset) as usize
    };
    // Get the bit version from the buffer
    let bit = {
        let bitversion = &buffer[offset + 4 + 20..offset + 4 + 20 + 2];
        let mut bit = [0u8; 2];
        bit.copy_from_slice(bitversion);
        u16::from_le_bytes(bit)
    };
    // Check the bit version and return the size of the image
    match bit {
        523 | 267 => {
            let index = offset + 24 + 60 - 4;
            let size = {
                let headerssize = &buffer[index..index + 4];
                let mut size = [0u8; 4];
                size.copy_from_slice(headerssize);
                i32::from_le_bytes(size)
            };
            size as usize
        }
        _ => panic!("nvld bit vrsn"),
    }
}

pub fn get_dos_header(lp_image: *const c_void) -> *const IMAGE_DOS_HEADER {
    lp_image as *const IMAGE_DOS_HEADER
}

pub fn get_nt_header(
    lp_image: *const c_void,
    lp_dos_header: *const IMAGE_DOS_HEADER,
) -> *const c_void {
    // Calculate the address of the NT header
    #[cfg(target_arch = "x86_64")]
    let lp_nt_header = unsafe {
        (lp_image as usize + (*lp_dos_header).e_lfanew as usize)
            as *const crate::main::windows::IMAGE_NT_HEADERS64
    };
    #[cfg(target_arch = "x86")]
    let lp_nt_header = unsafe {
        (lp_image as usize + (*lp_dos_header).e_lfanew as usize)
            as *const crate::main::windows::IMAGE_NT_HEADERS32
    };
    // Check if the NT header signature is valid
    if unsafe { (*lp_nt_header).Signature } != IMAGE_NT_SIGNATURE {
        return core::ptr::null_mut();
    }
    lp_nt_header as *const c_void
}

fn get_nt_header_size() -> usize {
    #[cfg(target_arch = "x86")]
    {
        core::mem::size_of::<crate::main::windows::IMAGE_NT_HEADERS32>()
    }
    #[cfg(target_arch = "x86_64")]
    {
        core::mem::size_of::<crate::main::windows::IMAGE_NT_HEADERS64>()
    }
}

fn get_number_of_sections(ntheader: *const c_void) -> u16 {
    #[cfg(target_arch = "x86_64")]
    return unsafe {
        (*(ntheader as *const crate::main::windows::IMAGE_NT_HEADERS64))
            .FileHeader
            .NumberOfSections
    };
    #[cfg(target_arch = "x86")]
    return unsafe {
        (*(ntheader as *const crate::main::windows::IMAGE_NT_HEADERS32))
            .FileHeader
            .NumberOfSections
    };
}

pub fn write_sections(
    baseptr: *const c_void,
    buffer: Vec<u8>,
    ntheader: *const c_void,
    dosheader: *const IMAGE_DOS_HEADER,
) -> Vec<(*const c_void, usize, u32)> {
    let number_of_sections = get_number_of_sections(ntheader);
    let nt_header_size = get_nt_header_size();

    let e_lfanew = (unsafe { *dosheader }).e_lfanew as usize;
    let mut st_section_header =
        (baseptr as usize + e_lfanew + nt_header_size) as *const IMAGE_SECTION_HEADER;

    let mut sections_info = alloc::vec![];
    for _i in 0..number_of_sections {
        let section_data = buffer
            .get(
                unsafe { (*st_section_header).PointerToRawData } as usize..(unsafe {
                    (*st_section_header).PointerToRawData
                } + (unsafe {
                    *st_section_header
                })
                .SizeOfRawData)
                    as usize,
            )
            .unwrap_or_default();

        let section_addr = (baseptr as usize
            + (unsafe { *st_section_header }).VirtualAddress as usize)
            as *const c_void;
        unsafe {
            core::ptr::copy_nonoverlapping(
                section_data.as_ptr() as *const c_void,
                section_addr as *mut c_void,
                (*st_section_header).SizeOfRawData as usize,
            )
        };

        sections_info.push((
            section_addr,
            (unsafe { *st_section_header }).SizeOfRawData as usize,
            (unsafe { *st_section_header }).Characteristics,
        ));
        st_section_header = unsafe { st_section_header.add(1) };
    }
    sections_info
}

pub unsafe fn apply_section_protections(sections_info: Vec<(*const c_void, usize, u32)>) {
    for (section_start, section_size, characteristics) in sections_info {
        let protection = translate_characteristics_to_protection(characteristics);
        let mut old_protect: u32 = 0;
        let result_allocation = syscall!(
            "NtProtectVirtualMemory",
            -1isize as *mut c_void,
            &mut (section_start as *mut c_void),
            &mut (section_size as usize),
            protection,
            &mut old_protect
        );
    }
}

pub const PAGE_READONLY: u32 = 0x2;
pub const PAGE_READWRITE: u32 = 0x4;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE: u32 = 0x10;

pub const SECTION_MEM_READ: u32 = 0x40000000;
pub const SECTION_MEM_WRITE: u32 = 0x80000000;
pub const SECTION_MEM_EXECUTE: u32 = 0x20000000;

pub fn translate_characteristics_to_protection(characteristics: u32) -> u32 {
    let is_read = (characteristics & SECTION_MEM_READ) != 0;
    let is_write = (characteristics & SECTION_MEM_WRITE) != 0;
    let is_execute = (characteristics & SECTION_MEM_EXECUTE) != 0;

    if is_read && !is_write && !is_execute {
        PAGE_READONLY
    } else if is_read && is_write && !is_execute {
        PAGE_READWRITE
    } else if is_read && is_write && is_execute {
        PAGE_EXECUTE_READWRITE
    } else if is_read && !is_write && is_execute {
        PAGE_EXECUTE_READ
    } else if !is_read && !is_write && is_execute {
        PAGE_EXECUTE
    } else {
        panic!("[x] Unknown section permission.");
    }
}

// This method is reponsible of cleaning IOCs that may reveal the pressence of a
// manually mapped PE in a private memory region. It will remove PE magic bytes,
// DOS header and DOS stub.
pub fn clean_dos_header(image_ptr: *mut c_void) {
    unsafe {
        let mut base_addr = image_ptr as *mut u8;
        let pe_header = image_ptr as isize + 0x3C;
        while (base_addr as isize) < pe_header {
            *base_addr = 0;
            base_addr = base_addr.add(1);
        }
        base_addr = base_addr.add(4);

        let e_lfanew = *((image_ptr as usize + 0x3C) as *const u32);
        let pe = image_ptr as isize + e_lfanew as isize;

        while (base_addr as isize) < pe {
            *base_addr = 0;
            base_addr = base_addr.add(1);
        }

        let pe = pe as *mut u16;
        *pe = 0;
    }
}

pub fn fix_base_relocations(
    // Pointer to the base address of the allocated memory in the target process
    baseptr: *const c_void,
    // Pointer to the NT header of the PE file
    ntheader: *const c_void,
) {
    // Get the NT header
    #[cfg(target_arch = "x86_64")]
    let nt_header =
        unsafe { &(*(ntheader as *const crate::main::windows::IMAGE_NT_HEADERS64)).OptionalHeader };
    #[cfg(target_arch = "x86")]
    let nt_header =
        unsafe { &(*(ntheader as *const crate::main::windows::IMAGE_NT_HEADERS32)).OptionalHeader };

    // Get the base relocation directory
    let basereloc = &nt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if basereloc.Size == 0 {
        return;
    }

    // Calculate the difference between the image base and the allocated memory base
    let image_base = nt_header.ImageBase;
    let diffaddress = baseptr as usize - image_base as usize;

    // Get the pointer to the base relocation block
    let mut relocptr =
        (baseptr as usize + basereloc.VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION;

    // Iterate through each block in the base relocation directory
    while unsafe { (*relocptr).SizeOfBlock } != 0 {
        // Get the number of entries in the current block
        let entries = (unsafe { (*relocptr).SizeOfBlock }
            - core::mem::size_of::<IMAGE_BASE_RELOCATION>() as u32)
            / 2;

        // Iterate through each entry in the current block
        for i in 0..entries {
            // Get the pointer to the current relocation offset
            let relocoffset_ptr = (relocptr as usize
                + core::mem::size_of::<IMAGE_BASE_RELOCATION>()
                + i as usize * 2) as *const u16;

            // Get the value of the current relocation offset
            let temp = unsafe { *relocoffset_ptr };

            // Check if the relocation type is not absolute
            if temp as u32 >> 12 as u32 != crate::main::windows::IMAGE_REL_BASED_ABSOLUTE {
                // Calculate the final address of the relocation
                let finaladdress = baseptr as usize
                    + unsafe { (*relocptr).VirtualAddress } as usize
                    + (temp & 0x0fff) as usize;

                // Read the original value at the final address
                let ogaddress = unsafe { core::ptr::read(finaladdress as *const usize) };

                // Calculate the fixed address of the relocation
                let fixedaddress = (ogaddress + diffaddress as usize) as usize;

                // Write the fixed address to the final address
                unsafe {
                    core::ptr::write(finaladdress as *mut usize, fixedaddress);
                }
            }
        }

        // Move to the next block in the base relocation directory
        relocptr = unsafe {
            (relocptr as *const u8).add((*relocptr).SizeOfBlock as usize)
                as *const IMAGE_BASE_RELOCATION
        };
    }
}

fn get_import_directory(ntheader: *const c_void) -> crate::main::windows::IMAGE_DATA_DIRECTORY {
    #[cfg(target_arch = "x86_64")]
    return unsafe {
        (*(ntheader as *const crate::main::windows::IMAGE_NT_HEADERS64))
            .OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
    };

    #[cfg(target_arch = "x86")]
    return unsafe {
        (*(ntheader as *const crate::main::windows::IMAGE_NT_HEADERS32))
            .OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
    };
}

pub fn write_import_table(baseptr: *const c_void, ntheader: *const c_void) {
    let import_dir = get_import_directory(ntheader);

    if import_dir.Size == 0 {
        return;
    }

    let mut ogfirstthunkptr = baseptr as usize + import_dir.VirtualAddress as usize;

    while unsafe { (*(ogfirstthunkptr as *const IMAGE_IMPORT_DESCRIPTOR)).Name } != 0
        && unsafe { (*(ogfirstthunkptr as *const IMAGE_IMPORT_DESCRIPTOR)).FirstThunk } != 0
    {
        let mut import = unsafe { core::mem::zeroed::<IMAGE_IMPORT_DESCRIPTOR>() };

        unsafe {
            core::ptr::copy_nonoverlapping(
                ogfirstthunkptr as *const u8,
                &mut import as *mut IMAGE_IMPORT_DESCRIPTOR as *mut u8,
                core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
            );
        }

        let dllname = crate::misc::utils::read_string_from_memory(
            (baseptr as usize + import.Name as usize) as *const u8,
        );

        let dllname_bytes = dllname.as_bytes();
        let mut dllname_wide: Vec<u16> = Vec::with_capacity(dllname_bytes.len() + 1);

        for &byte in dllname_bytes {
            dllname_wide.push(byte as u16);
        }
        dllname_wide.push(0);

        let dllhandle = unsafe { LoadLibraryW(dllname_wide.as_ptr()) };

        let mut thunkptr = unsafe {
            baseptr as usize
                + (import.Anonymous.OriginalFirstThunk as usize
                    | import.Anonymous.Characteristics as usize)
        };

        let mut i = 0;

        while unsafe { *(thunkptr as *const usize) } != 0 {
            let mut thunkdata: [u8; core::mem::size_of::<usize>()] =
                unsafe { core::mem::zeroed::<[u8; core::mem::size_of::<usize>()]>() };

            unsafe {
                if thunkptr as *const u8 == core::ptr::null() {
                    break;
                }

                core::ptr::copy_nonoverlapping(
                    thunkptr as *const u8,
                    &mut thunkdata as *mut u8,
                    core::mem::size_of::<usize>(),
                );
            }

            let offset = usize::from_ne_bytes(thunkdata);

            if (offset & 0x80000000) != 0 {
                let ordinal = offset & 0xffff;

                let funcaddress = unsafe { GetProcAddress(dllhandle, ordinal as *const u8) };

                if funcaddress.is_null() {
                    break;
                }

                let funcaddress_ptr = (baseptr as usize
                    + import.FirstThunk as usize
                    + i * core::mem::size_of::<usize>())
                    as *mut usize;

                if funcaddress_ptr == core::ptr::null_mut() {
                    break;
                }

                unsafe { core::ptr::write(funcaddress_ptr, funcaddress as usize) };
            } else {
                let funcname = crate::misc::utils::read_string_from_memory(
                    (baseptr as usize + offset as usize + 2) as *const u8,
                );

                if !funcname.is_empty() {
                    let funcaddress = unsafe {
                        GetProcAddress(dllhandle, funcname.as_bytes().as_ptr() as *const u8)
                    };

                    if funcaddress.is_null() {
                        break;
                    }

                    let funcaddress_ptr = (baseptr as usize
                        + import.FirstThunk as usize
                        + i * core::mem::size_of::<usize>())
                        as *mut usize;

                    if funcaddress_ptr == core::ptr::null_mut() {
                        break;
                    }

                    unsafe { core::ptr::write(funcaddress_ptr, funcaddress as usize) };
                }
            }

            i += 1;
            thunkptr += core::mem::size_of::<usize>();
        }

        ogfirstthunkptr += core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }
}

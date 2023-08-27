#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::c_void;
// use std::ffi::OsStr;

pub type VIRTUAL_ALLOCATION_TYPE = u32;
// pub type PAGE_PROTECTION_FLAGS = u32;
pub const MEM_RESERVE: VIRTUAL_ALLOCATION_TYPE = 0x2000;
pub const MEM_COMMIT: VIRTUAL_ALLOCATION_TYPE = 0x1000;
pub const PAGE_EXECUTE_READWRITE: VIRTUAL_ALLOCATION_TYPE = 0x40;
pub const PAGE_READWRITE: VIRTUAL_ALLOCATION_TYPE = 0x04;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_REL_BASED_ABSOLUTE: u32 = 0;
pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;

pub type LPFIBER_START_ROUTINE = Option<unsafe extern "system" fn(lpfiberparameter: *mut c_void)>;

#[link(name = "kernel32")]
extern "system" {

    pub fn GetProcAddress(hmodule: *mut c_void, lpprocname: *const u8) -> *mut c_void;

    pub fn LoadLibraryW(lplibfilename: *const u16) -> *mut c_void;

}
pub fn get_dll_handle(dll_name: &str) -> *mut c_void {
    const MAX_DLL_NAME_LENGTH: usize = 256;
    let mut dll_name_wide: [u16; MAX_DLL_NAME_LENGTH] = [0; MAX_DLL_NAME_LENGTH];

    let dll_name_bytes = dll_name.as_bytes();
    for i in 0..dll_name_bytes.len().min(MAX_DLL_NAME_LENGTH - 1) {
        dll_name_wide[i] = dll_name_bytes[i] as u16;
    }

    let ntdll_handle = unsafe { LoadLibraryW(dll_name_wide.as_ptr()) };
    return ntdll_handle;
}

// pub fn CreateFiber(
//     dwStackSize: usize,
//     lpStartAddress: LPFIBER_START_ROUTINE,
//     lpParameter: *const c_void,
// ) -> *mut c_void {
//     let kernel32dll_handle = get_dll_handle("KERNEL32.dll");
//     if !kernel32dll_handle.is_null() {
//         // Get the address of the NtAllocateVirtualMemory function
//         let CreateFiber: extern "system" fn(
//             usize,
//             LPFIBER_START_ROUTINE,
//             *const c_void,
//         ) -> *mut c_void = unsafe {
//             let proc_name = "CreateFiber\0";
//             let CreateFiber_ptr = GetProcAddress(kernel32dll_handle, proc_name.as_ptr());

//             core::mem::transmute(CreateFiber_ptr)
//         };

//         return CreateFiber(dwStackSize, lpStartAddress, lpParameter);
//     } else {
//         panic!("create fiber didn't find");
//     }
// }

// pub fn SwitchToFiber(lpFiber: *const c_void) {
//     // Prepare the DLL name
//     let kernel32dll_handle = get_dll_handle("KERNEL32.dll");
//     if !kernel32dll_handle.is_null() {
//         // Get the address of the NtAllocateVirtualMemory function
//         let CreateFiber: extern "system" fn(*const c_void) = unsafe {
//             let proc_name = "SwitchToFiber\0";
//             let SwitchToFiber_ptr = GetProcAddress(kernel32dll_handle, proc_name.as_ptr());

//             core::mem::transmute(SwitchToFiber_ptr)
//         };

//         return SwitchToFiber(lpFiber);
//     } else {
//         panic!("SwitchToFiber failer to resolve");
//     }
// }

// pub fn ConvertThreadToFiber(lpparameter: *const c_void) -> *mut c_void {
//     let kernel32dll_handle = get_dll_handle("KERNEL32.dll");
//     if !kernel32dll_handle.is_null() {
//         // Get the address of the NtAllocateVirtualMemory function
//         let ConvertThreadToFiber: extern "system" fn(*const c_void) -> *mut c_void = unsafe {
//             let proc_name = "ConvertThreadToFiber\0";
//             let ConvertThreadToFiber_ptr = GetProcAddress(kernel32dll_handle, proc_name.as_ptr());

//             core::mem::transmute(ConvertThreadToFiber_ptr)
//         };

//         return ConvertThreadToFiber(lpparameter);
//     } else {
//         panic!("create convert fiber");
//     }
// }

// pub fn NtAllocateVirtualMemory(
//     ProcHandle: *mut c_void,
//     BaseAddress: *mut *mut c_void,
//     ZeroBits: usize,
//     RegionSize: *mut usize,
//     AllocationType: u32,
//     Protect: u32,
// ) -> i32 {
//     // Prepare the DLL name
//     let dll_name = deobfuscate_string(&obfuscate_string!("ntdll.dll"));
//     let dll_name_bytes = dll_name.as_bytes();
//     let mut dll_name_wide: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(dll_name_bytes.len() + 1);

//     for &byte in dll_name_bytes {
//         dll_name_wide.push(byte as u16);
//     }
//     dll_name_wide.push(0); // Null-terminate the wide character string

//     // Load the ntdll.dll library
//     let ntdll_handle = unsafe { LoadLibraryW(dll_name_wide.as_ptr()) };
//     if !ntdll_handle.is_null() {
//         // Get the address of the NtAllocateVirtualMemory function
//         let NtAllocateVirtualMemory: extern "system" fn(
//             *mut c_void,
//             *mut *mut c_void,
//             usize,
//             *mut usize,
//             VIRTUAL_ALLOCATION_TYPE,
//             PAGE_PROTECTION_FLAGS,
//         ) -> i32 = unsafe {
//             let proc_name = deobfuscate_string(&obfuscate_string!("NtAllocateVirtualMemory"));
//             let NtAllocateVirtualMemory_ptr = GetProcAddress(ntdll_handle, proc_name.as_ptr());

//             core::mem::transmute(NtAllocateVirtualMemory_ptr)
//         };

//             return NtAllocateVirtualMemory(
//                 ProcHandle,
//                 BaseAddress,
//                 ZeroBits,
//                 RegionSize,
//                 AllocationType,
//                 Protect,
//             );
//     } else {
//         return -1;
//     }
// }

// pub fn NtProtectVirtualMemory(
//     ProcessHandle: *mut c_void,
//     BaseAddress: *mut *mut c_void,
//     RegionSize: *mut usize,
//     NewAccessProtection: u32,
//     OldAccessProtection: *mut u32,
// ) -> i32 {
//     // Prepare the DLL name
//     let dll_name = deobfuscate_string(&obfuscate_string!("ntdll.dll"));
//     let dll_name_bytes = dll_name.as_bytes();
//     let mut dll_name_wide: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(dll_name_bytes.len() + 1);

//     for &byte in dll_name_bytes {
//         dll_name_wide.push(byte as u16);
//     }
//     dll_name_wide.push(0); // Null-terminate the wide character string

//     // Load the ntdll.dll library
//     let ntdll_handle = unsafe { LoadLibraryW(dll_name_wide.as_ptr()) };
//     if !ntdll_handle.is_null() {
//         // Get the address of the NtAllocateVirtualMemory function
//         let NtProtectVirtualMemory: extern "system" fn(
//             *mut c_void,
//             *mut *mut c_void,
//             *mut usize,
//             u32,
//             *mut u32,
//         ) -> i32 = unsafe {
//             let proc_name = deobfuscate_string(&obfuscate_string!("NtProtectVirtualMemory"));
//             let NtProtectVirtualMemory_ptr = GetProcAddress(ntdll_handle, proc_name.as_ptr());
//             // Extract the syscall number from the function's prologue
//             let syscall_num = unsafe { *(NtProtectVirtualMemory_ptr.add(1) as *const u8) as u32 };
//             println!("{:?}", syscall_num);
//             core::mem::transmute(NtProtectVirtualMemory_ptr)
//         };

//         return NtProtectVirtualMemory(
//             ProcessHandle,
//             BaseAddress,
//             RegionSize,
//             NewAccessProtection,
//             OldAccessProtection,
//         );
//     } else {
//         return -1;
//     }
// }

// pub fn virtual_alloc(
//     lpaddress: *const c_void,
//     dwsize: usize,
//     flallocationtype: u32,
//     flprotect: u32,
// ) -> *mut c_void {
//     // Prepare the DLL name
//     let dll_name = alloc::string::String::from("kernel32.dll");
//     let dll_name_bytes = dll_name.as_bytes();
//     let mut dll_name_wide: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(dll_name_bytes.len() + 1);

//     for &byte in dll_name_bytes {
//         dll_name_wide.push(byte as u16);
//     }
//     dll_name_wide.push(0); // Null-terminate the wide character string

//     // Load the kernel32.dll library
//     let kernel32 = unsafe { LoadLibraryW(dll_name_wide.as_ptr()) };
//     if !kernel32.is_null() {
//         // Get the address of the VirtualAlloc function
//         let virtual_alloc = unsafe {
//             let proc_name = b"VirtualAlloc\0";
//             let virtual_alloc_ptr = GetProcAddress(kernel32, proc_name.as_ptr());
//             core::mem::transmute::<
//                 *mut c_void,
//                 extern "system" fn(*const c_void, usize, u32, u32) -> *mut c_void,
//             >(virtual_alloc_ptr)
//         };

//         // Call the VirtualAlloc function
//         unsafe { virtual_alloc(lpaddress, dwsize, flallocationtype, flprotect) }
//     } else {
//         core::ptr::null_mut()
//     }
// }

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[derive(Default)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[derive(Default)]
#[repr(C)]
#[cfg(target_arch = "x86_64")]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Default)]
#[repr(C, packed(4))]
#[cfg(target_arch = "x86_64")]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub Anonymous: IMAGE_IMPORT_DESCRIPTOR_0,
    pub TimeDateStamp: u32,
    pub ForwarderChain: u32,
    pub Name: u32,
    pub FirstThunk: u32,
}

#[repr(C)]
pub union IMAGE_IMPORT_DESCRIPTOR_0 {
    pub Characteristics: u32,
    pub OriginalFirstThunk: u32,
}

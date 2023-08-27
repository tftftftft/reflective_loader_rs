use crate::{
    main::windows::{get_dll_handle, GetProcAddress},
    misc::utils::*,
};

pub fn make_sleep(total_seconds: u32) -> Result<(), &'static str> {
    let kernel32_handle = get_dll_handle("KERNEL32.dll");
    if kernel32_handle.is_null() {
        return Err("Failed to get kernel handle");
    }

    let beep: extern "system" fn(u32, u32) -> i32 = unsafe {
        let proc_name = "Beep\0";
        let beep_ptr = GetProcAddress(kernel32_handle, proc_name.as_ptr());
        if beep_ptr.is_null() {
            return Err("Failed to get beep ptr");
        }
        core::mem::transmute(beep_ptr)
    };

    let total_milliseconds = total_seconds * 1000;
    const INTERVAL: u32 = 50;
    let num_intervals = total_milliseconds / INTERVAL;
    let remainder = total_milliseconds % INTERVAL;

    for _ in 0..num_intervals {
        beep(1, INTERVAL);
    }

    if remainder > 0 {
        beep(1, remainder);
    }

    Ok(())
}

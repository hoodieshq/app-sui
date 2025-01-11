#![cfg_attr(target_family = "bolos", no_std)]
#![cfg_attr(target_family = "bolos", no_main)]

#[cfg(not(target_family = "bolos"))]
fn main() {}

#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use sui::main_nanos::*;

#[cfg(any(target_os = "stax", target_os = "flex"))]
use sui::main_stax::*;

use sui::{
    ctx::RunModeCtx,
    swap::{lib_main, panic_handler::get_swap_panic_handler},
};

//ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);

pub fn custom_panic(_info: &PanicInfo) -> ! {
    use ledger_device_sdk::io;

    if let Some(swap_panic_handler) = get_swap_panic_handler() {
        // This handler is no-return
        swap_panic_handler(_info);
    }

    ledger_log::error!("Panic happened! {:#?}", _info);

    let mut comm = io::Comm::new();
    comm.reply(io::StatusWords::Panic);

    ledger_secure_sdk_sys::exit_app(0);
}

ledger_device_sdk::set_panic!(custom_panic);

#[no_mangle]
extern "C" fn sample_main(arg0: u32) {
    if arg0 == 0 {
        app_main(&RunModeCtx::app());
    } else {
        lib_main(arg0);
    }
}

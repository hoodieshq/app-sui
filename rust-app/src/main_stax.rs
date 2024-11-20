use crate::handle_apdu::handle_apdu;
use crate::implementation::*;
use crate::interface::*;
use crate::settings::*;
use crate::ui::APP_ICON;

use ledger_device_sdk::io;
use ledger_device_sdk::nbgl::{init_comm, NbglHomeAndSettings};
use ledger_log::{info, trace};

#[allow(dead_code)]
pub fn app_main() {
    let mut comm = io::Comm::new();
    let mut states = ParsersState::NoState;
    let mut settings = Settings;

    // Initialize reference to Comm instance for NBGL
    // API calls.
    init_comm(&mut comm);

    info!("Alamgu Example {}", env!("CARGO_PKG_VERSION"));
    info!(
        "State sizes\ncomm: {}\nstates: {}",
        core::mem::size_of::<io::Comm>(),
        core::mem::size_of::<ParsersState>()
    );

    let settings_strings = [[
        "Blind Signing",
        "Sign transactions for which details cannot be verified",
    ]];

    let mut main_menu = NbglHomeAndSettings::new()
        .glyph(&APP_ICON)
        .settings(settings.get_mut(), &settings_strings)
        .infos(
            "Alamgu Example App",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        );

    let mut menu = |states: &ParsersState| {
        if let ParsersState::NoState = states {
            main_menu.show_and_return()
        }
    };

    loop {
        // This must be here, before handle_apdu
        // somehow doesn't work if its after handle_apdu
        menu(&states);
        let ins: Ins = comm.next_command();

        match handle_apdu(&mut comm, ins, &mut states) {
            Ok(()) => {
                trace!("APDU accepted; sending response");
                comm.reply_ok();
                trace!("Replied");
            }
            Err(sw) => {
                comm.reply(sw);
            }
        };
    }
}

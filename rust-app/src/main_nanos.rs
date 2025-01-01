use crate::handle_apdu::*;
use crate::interface::*;
use crate::menu::*;
use crate::settings::*;
use crate::ui::UserInterface;
use crate::swap;
use crate::swap::get_params::my_get_check_address_params;
use crate::swap::get_params::my_get_printable_amount_params;
use crate::swap::get_params::my_sign_tx_params;
use crate::swap::get_params::swap_return;
use crate::swap::get_params::CreateTxParams;
use crate::swap::get_params::SwapResult;

use alamgu_async_block::*;

use ledger_device_sdk::io;
use ledger_device_sdk::libcall;
use ledger_device_sdk::libcall::LibCallCommand;
use ledger_device_sdk::uxapp::{UxEvent, BOLOS_UX_OK};
use ledger_log::{info, trace};
use ledger_prompts_ui::{handle_menu_button_event, show_menu};

use core::cell::RefCell;
use core::pin::Pin;
use pin_cell::*;

#[repr(u8)]
pub enum RunMode {
    App = 0x00,
    LibSwapSign {
        in_progress: bool,
        is_success: bool,
        tx_params: CreateTxParams,
    },
}

impl RunMode {
    pub fn is_swap_signing(&self) -> bool {
        matches!(self, RunMode::LibSwapSign { .. })
    }

    pub fn start_swap_signing(&mut self, tx_params: CreateTxParams) {
        debug_assert!(matches!(self, RunMode::App));

        *self = RunMode::LibSwapSign {
            in_progress: true,
            is_success: false,
            tx_params,
        };
    }

    pub fn set_signing_result(&mut self, success: bool) {
        let Self::LibSwapSign {
            in_progress,
            is_success,
            ..
        } = self
        else {
            // Don't care about signing result if we are in `App`` mode
            return;
        };

        assert!(*in_progress, "Signing result set when not in progress");

        *in_progress = false;
        *is_success = success;
    }

    pub fn is_swap_signing_done(&self) -> bool {
        matches!(
            self,
            RunMode::LibSwapSign {
                in_progress: false,
                ..
            }
        )
    }

    pub fn swap_sing_result(&self) -> (bool, *mut u8) {
        let Self::LibSwapSign {
            in_progress: false,
            is_success,
            tx_params,
        } = self
        else {
            panic!("Not in signing mode or still in progress");
        };

        (*is_success, tx_params.exit_code_ptr)
    }

    pub fn tx_params(&self) -> &CreateTxParams {
        let Self::LibSwapSign { tx_params, .. } = self else {
            panic!("Not in signing mode");
        };

        tx_params
    }
}

pub struct RunModeInstance;

impl RunModeInstance {
    pub fn get(&mut self) -> &mut RunMode {
        static mut RUN_MODE: RunMode = RunMode::App;

        // NOTE: returned lifetime is bound to self and not the 'static
        unsafe { &mut RUN_MODE }
    }
}

#[allow(dead_code)]
pub fn app_main() {
    let comm: SingleThreaded<RefCell<io::Comm>> = SingleThreaded(RefCell::new(io::Comm::new()));

    let hostio_state: SingleThreaded<RefCell<HostIOState>> =
        SingleThreaded(RefCell::new(HostIOState::new(unsafe {
            core::mem::transmute::<
                &core::cell::RefCell<ledger_device_sdk::io::Comm>,
                &core::cell::RefCell<ledger_device_sdk::io::Comm>,
            >(&comm.0)
        })));
    let hostio: SingleThreaded<HostIO> = SingleThreaded(HostIO(unsafe {
        core::mem::transmute::<
            &core::cell::RefCell<alamgu_async_block::HostIOState>,
            &core::cell::RefCell<alamgu_async_block::HostIOState>,
        >(&hostio_state.0)
    }));
    let states_backing: SingleThreaded<PinCell<Option<APDUsFuture>>> =
        SingleThreaded(PinCell::new(None));
    let states: SingleThreaded<Pin<&PinCell<Option<APDUsFuture>>>> =
        SingleThreaded(Pin::static_ref(unsafe {
            core::mem::transmute::<
                &pin_cell::PinCell<core::option::Option<APDUsFuture>>,
                &pin_cell::PinCell<core::option::Option<APDUsFuture>>,
            >(&states_backing.0)
        }));

    let mut idle_menu = IdleMenuWithSettings {
        idle_menu: IdleMenu::AppMain,
        settings: Settings,
    };
    let mut busy_menu = BusyMenu::Working;

    info!("Sui {}", env!("CARGO_PKG_VERSION"));
    info!(
        "State sizes\ncomm: {}\nstates: {}",
        core::mem::size_of::<io::Comm>(),
        core::mem::size_of::<Option<APDUsFuture>>()
    );

    let menu = |states: core::cell::Ref<'_, Option<APDUsFuture>>,
                idle: &IdleMenuWithSettings,
                busy: &BusyMenu| {
        if RunModeInstance.get().is_swap_signing() {
            return;
        }

        match states.is_none() {
            true => show_menu(idle),
            _ => show_menu(busy),
        }
    };

    // Draw some 'welcome' screen
    menu(states.borrow(), &idle_menu, &busy_menu);
    loop {
        if RunModeInstance.get().is_swap_signing_done() {
            comm.borrow_mut().swap_reply_ok();
            return;
        }

        // Wait for either a specific button push to exit the app
        // or an APDU command
        let evt = comm.borrow_mut().next_event::<Ins>();
        match evt {
            io::Event::Command(ins) => {
                trace!("Command received");
                let poll_rv = poll_apdu_handlers(
                    PinMut::as_mut(&mut states.0.borrow_mut()),
                    ins,
                    *hostio,
                    |io, ins| handle_apdu_async(io, ins, idle_menu.settings, UserInterface {}),
                );
                match poll_rv {
                    Ok(()) => {
                        trace!("APDU accepted; sending response");
                        comm.borrow_mut().reply_ok();
                        trace!("Replied");
                    }
                    Err(sw) => {
                        PinMut::as_mut(&mut states.0.borrow_mut()).set(None);
                        comm.borrow_mut().reply(sw);
                    }
                };
                // Reset BusyMenu if we are done handling APDU
                if states.borrow().is_none() {
                    busy_menu = BusyMenu::Working;
                }
                menu(states.borrow(), &idle_menu, &busy_menu);
                trace!("Command done");
            }
            io::Event::Button(btn) => {
                trace!("Button received");
                match states.borrow().is_none() {
                    true => {
                        if let Some(DoExitApp) = handle_menu_button_event(&mut idle_menu, btn) {
                            info!("Exiting app at user direction via root menu");
                            ledger_device_sdk::exit_app(0)
                        }
                    }
                    _ => {
                        if let Some(DoCancel) = handle_menu_button_event(&mut busy_menu, btn) {
                            info!("Resetting at user direction via busy menu");
                            PinMut::as_mut(&mut states.borrow_mut()).set(None);
                        }
                    }
                };
                menu(states.borrow(), &idle_menu, &busy_menu);
                trace!("Button done");
            }
            io::Event::Ticker => {
                if UxEvent::Event.request() != BOLOS_UX_OK {
                    UxEvent::block();
                    // Redisplay application menu here
                    menu(states.borrow(), &idle_menu, &busy_menu);
                }
                //trace!("Ignoring ticker event");
            }
        }
    }
}

// We are single-threaded in fact, albeit with nontrivial code flow. We don't need to worry about
// full atomicity of the below globals.
struct SingleThreaded<T>(T);
unsafe impl<T> Send for SingleThreaded<T> {}
unsafe impl<T> Sync for SingleThreaded<T> {}
impl<T> core::ops::Deref for SingleThreaded<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> core::ops::DerefMut for SingleThreaded<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

pub fn lib_main(arg0: u32) {
    let cmd = libcall::get_command(arg0);

    match &cmd {
        LibCallCommand::SwapSignTransaction => {
            trace!("lib_main: SwapSignTransaction");
        }
        LibCallCommand::SwapGetPrintableAmount => {
            trace!("lib_main: SwapGetPrintableAmount");
        }
        LibCallCommand::SwapCheckAddress => {
            trace!("lib_main: SwapCheckAddress");
        }
    }

    match cmd {
        LibCallCommand::SwapCheckAddress => {
            let mut params = my_get_check_address_params(arg0);
            trace!("{:X?}", params);
            let is_matched = swap::check_address(&mut params).unwrap();

            swap_return(SwapResult::CheckAddressResult(
                &mut params,
                is_matched as i32,
            ));
        }
        LibCallCommand::SwapGetPrintableAmount => {
            let mut params = my_get_printable_amount_params(arg0);
            trace!("{:X?}", params);
            let amount_str = swap::get_printable_amount(&mut params).unwrap();

            swap_return(SwapResult::PrintableAmountResult(
                &mut params,
                amount_str.as_str(),
            ));
        }
        LibCallCommand::SwapSignTransaction => {
            let mut params = my_sign_tx_params(arg0);
            trace!("{:X?}", params);
            trace!("amount {}", params.amount);

            RunModeInstance.get().start_swap_signing(params);
            app_main();
            let (is_ok, _) = RunModeInstance.get().swap_sing_result();

            swap_return(SwapResult::CreateTxResult(&mut params, is_ok as u8));
        }
    }
}

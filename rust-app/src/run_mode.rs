use crate::swap::get_params::CreateTxParams;

static mut RUN_MODE: RunModeState = RunModeState::App;

#[repr(u8)]
enum RunModeState {
    App = 0x00,
    LibSwapSign {
        in_progress: bool,
        is_success: bool,
        tx_params: CreateTxParams,
    },
}

pub struct RunMode;

impl RunMode {
    fn get_mut(&mut self) -> &mut RunModeState {
        unsafe { &mut RUN_MODE }
    }

    fn get(&self) -> &RunModeState {
        unsafe { &RUN_MODE }
    }

    pub fn is_swap_signing(&self) -> bool {
        matches!(self.get(), RunModeState::LibSwapSign { .. })
    }

    pub fn start_swap_signing(&mut self, tx_params: CreateTxParams) {
        debug_assert!(matches!(self.get(), RunModeState::App));

        *self.get_mut() = RunModeState::LibSwapSign {
            in_progress: true,
            is_success: false,
            tx_params,
        };
    }

    pub fn set_signing_result(&mut self, success: bool) {
        let RunModeState::LibSwapSign {
            in_progress,
            is_success,
            ..
        } = self.get_mut()
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
            self.get(),
            RunModeState::LibSwapSign {
                in_progress: false,
                ..
            }
        )
    }

    pub fn swap_sing_result(&self) -> (bool, *mut u8) {
        let RunModeState::LibSwapSign {
            in_progress: false,
            is_success,
            tx_params,
        } = self.get()
        else {
            panic!("Not in signing mode or still in progress");
        };

        (*is_success, tx_params.exit_code_ptr)
    }

    pub fn tx_params(&self) -> &CreateTxParams {
        let RunModeState::LibSwapSign { tx_params, .. } = self.get() else {
            panic!("Not in signing mode");
        };

        tx_params
    }
}

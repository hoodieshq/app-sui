use core::cell::Cell;

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum State {
    App = 0x00,
    LibSwapIdle,
    LibSwapSignSuccess,
    LibSwapSignFailure,
}

pub struct RunModeCtx {
    state: Cell<State>,
}

impl RunModeCtx {
    pub fn app() -> Self {
        RunModeCtx {
            state: Cell::new(State::App),
        }
    }

    pub fn lib_swap() -> Self {
        RunModeCtx {
            state: Cell::new(State::LibSwapIdle),
        }
    }

    pub fn is_swap_mode(&self) -> bool {
        !matches!(self.state.get(), State::App)
    }

    pub fn is_finished(&self) -> bool {
        matches!(
            self.state.get(),
            State::LibSwapSignSuccess | State::LibSwapSignFailure,
        )
    }

    pub fn is_success(&self) -> bool {
        matches!(self.state.get(), State::LibSwapSignSuccess)
    }

    pub fn success(&self) {
        self.state.set(State::LibSwapSignSuccess);
    }

    pub fn failure(&self) {
        self.state.set(State::LibSwapSignFailure);
    }
}

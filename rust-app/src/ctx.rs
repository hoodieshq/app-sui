use core::cell::Cell;

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum State {
    App = 0x00,
    LibSwapIdle,
    LibSwapSignSuccess,
    LibSwapSignFailure,
}

pub struct RunCtx {
    state: Cell<State>,
}

impl RunCtx {
    pub fn app() -> Self {
        RunCtx {
            state: Cell::new(State::App),
        }
    }

    pub fn lib_swap() -> Self {
        RunCtx {
            state: Cell::new(State::LibSwapIdle),
        }
    }

    pub fn is_swap(&self) -> bool {
        !matches!(self.state.get(), State::App)
    }

    pub fn is_swap_finished(&self) -> bool {
        matches!(
            self.state.get(),
            State::LibSwapSignSuccess | State::LibSwapSignFailure,
        )
    }

    pub fn is_swap_succeeded(&self) -> bool {
        matches!(self.state.get(), State::LibSwapSignSuccess)
    }

    pub fn set_success(&self) {
        self.state.set(State::LibSwapSignSuccess);
    }

    pub fn set_failure(&self) {
        self.state.set(State::LibSwapSignFailure);
    }
}

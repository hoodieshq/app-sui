// #[cfg(any(target_os = "stax", target_os = "flex"))]
// pub mod nbgl;
// pub use nbgl;

#[cfg(not(any(target_os = "stax", target_os = "flex")))]
pub mod nano;
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
pub use nano::*;

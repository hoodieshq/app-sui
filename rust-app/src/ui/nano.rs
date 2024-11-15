use core::fmt::Write;
use ledger_prompts_ui::*;
use ledger_crypto_helpers::eddsa::{
    Ed25519RawPubKeyAddress,
};
use ledger_crypto_helpers::hasher::{Base64Hash};

pub fn confirm_address(pkh: &Ed25519RawPubKeyAddress) -> Option<()> {
    scroller("Provide Public Key", |_w| Ok(()))?;
    scroller_paginated("Address", |w| Ok(write!(w, "{pkh}")?))?;
    final_accept_prompt(&[])
}

pub fn confirm_sign_tx(pkh: &Ed25519RawPubKeyAddress, hash: &Base64Hash<32>) -> Option<()> {
    scroller("Transaction hash", |w| {
        Ok(write!(w, "{}", hash)?)
    })?;
    scroller("Sign for Address", |w| Ok(write!(w, "{pkh}")?))?;
    final_accept_prompt(&["Sign Transaction?"])
}

#[cfg(not(target_os = "nanos"))]
#[inline(never)]
pub fn scroller<F: for<'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError>>(
    title: &str,
    prompt_function: F,
) -> Option<()> {
    ledger_prompts_ui::write_scroller_three_rows(false, title, prompt_function)
}

#[cfg(target_os = "nanos")]
#[inline(never)]
pub fn scroller<F: for<'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError>>(
    title: &str,
    prompt_function: F,
) -> Option<()> {
    ledger_prompts_ui::write_scroller(false, title, prompt_function)
}

#[cfg(not(target_os = "nanos"))]
#[inline(never)]
pub fn scroller_paginated<F: for<'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError>>(
    title: &str,
    prompt_function: F,
) -> Option<()> {
    ledger_prompts_ui::write_scroller_three_rows(true, title, prompt_function)
}

#[cfg(target_os = "nanos")]
#[inline(never)]
pub fn scroller_paginated<F: for<'b> Fn(&mut PromptWrite<'b, 16>) -> Result<(), ScrollerError>>(
    title: &str,
    prompt_function: F,
) -> Option<()> {
    ledger_prompts_ui::write_scroller(true, title, prompt_function)
}

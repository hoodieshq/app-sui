use core::{convert::TryInto, fmt::Write};

use arrayvec::ArrayString;
#[allow(unused_imports)]
use ledger_crypto_helpers::common::HexSlice;
use ledger_crypto_helpers::{
    common::{Address, CryptographyError},
    eddsa::with_public_keys,
};
use ledger_device_sdk::libcall::{
    self,
    swap::{
        get_check_address_params, get_printable_amount_params, sign_tx_params, swap_return,
        SwapResult,
    },
    LibCallCommand,
};
use ledger_log::{error, trace};
use panic_handler::{set_swap_panic_handler, swap_panic_handler};
use params::{CheckAddressParams, PrintableAmountParams, TxParams};

use crate::interface::SuiPubKeyAddress;
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use crate::main_nanos::app_main;
#[cfg(any(target_os = "stax", target_os = "flex"))]
use crate::main_stax::app_main;
use crate::{ctx::RunCtx, utils::get_amount_in_decimals};

pub mod panic_handler;
pub mod params;

#[derive(Debug)]
pub enum Error {
    DecodeDPathError,
    CryptographyError(CryptographyError),
    WrongAmountLength,
    WrongFeeLength,
    BadAddressASCII,
    BadAddressLength,
    BadAddressHex,
}

impl From<CryptographyError> for Error {
    fn from(e: CryptographyError) -> Self {
        Error::CryptographyError(e)
    }
}

pub fn check_address(params: &CheckAddressParams) -> Result<bool, Error> {
    let ref_addr = &params.ref_address;
    trace!("check_address: dpath: {:X?}", params.dpath);
    trace!("check_address: ref: 0x{}", HexSlice(ref_addr));

    Ok(with_public_keys(
        &params.dpath,
        true,
        |_, address: &SuiPubKeyAddress| -> Result<_, CryptographyError> {
            trace!("check_address: der: {}", address);
            let der_addr = address.get_binary_address();

            Ok(ref_addr == der_addr)
        },
    )?)
}

// Outputs a string with the amount of SUI.
//
// Max sui amount 10_000_000_000 SUI.
// So max string length is 11 (quotient) + 1 (dot) + 12 (reminder) + 4 (text) = 28
pub fn get_printable_amount(params: &PrintableAmountParams) -> Result<ArrayString<28>, Error> {
    let (quotient, remainder_str) = get_amount_in_decimals(params.amount);

    let mut printable_amount = ArrayString::<28>::default();
    write!(&mut printable_amount, "SUI {}.{}", quotient, remainder_str)
        .expect("string always fits");

    trace!(
        "get_printable_amount: amount: {}",
        printable_amount.as_str()
    );

    Ok(printable_amount)
}

pub fn check_tx_params(expected: &TxParams, received: &TxParams) -> bool {
    expected.amount == received.amount
        && expected.fee == received.fee
        && expected.destination_address == received.destination_address
}

pub fn lib_main(arg0: u32) {
    let cmd = libcall::get_command(arg0);

    match cmd {
        LibCallCommand::SwapCheckAddress => {
            let mut raw_params = get_check_address_params(arg0);

            if let Err::<_, Error>(error) = try {
                let params: CheckAddressParams = (&raw_params).try_into()?;
                trace!("{:X?}", &params);

                let is_matched = check_address(&params)?;

                swap_return(SwapResult::CheckAddressResult(
                    &mut raw_params,
                    is_matched as i32,
                ));
            } {
                error!("Error happened during CHECK_ADDRESS libcall:  {:?}", error);
            }
        }
        LibCallCommand::SwapGetPrintableAmount => {
            let mut raw_params = get_printable_amount_params(arg0);

            if let Err::<_, Error>(error) = try {
                let params: PrintableAmountParams = (&raw_params).try_into()?;
                trace!("{:X?}", &params);

                let amount_str = get_printable_amount(&params)?;

                swap_return(SwapResult::PrintableAmountResult(
                    &mut raw_params,
                    amount_str.as_str(),
                ));
            } {
                error!(
                    "Error happened during GET_PRINTABLE_AMOUNT libcall:  {:?}",
                    error
                );
            }
        }
        LibCallCommand::SwapSignTransaction => {
            let mut raw_params = sign_tx_params(arg0);

            let params = match (&raw_params).try_into() {
                Ok(params) => params,
                Err(error) => {
                    error!(
                        "Error happened during SIGN_TRANSACTION libcall:  {:?}",
                        error
                    );
                    unsafe { ledger_secure_sdk_sys::os_lib_end() }
                }
            };
            trace!("{:X?}", &params);

            // SAFETY: at this point, the app is initialized,
            // so we can safely set the panic handler
            unsafe {
                set_swap_panic_handler(swap_panic_handler);
            }

            let ctx = RunCtx::lib_swap(params);
            app_main(&ctx);
            let is_ok = ctx.is_swap_sign_succeeded();

            swap_return(SwapResult::CreateTxResult(&mut raw_params, is_ok as u8));
        }
    }
}

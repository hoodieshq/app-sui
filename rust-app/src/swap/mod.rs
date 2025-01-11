use core::{fmt::Write, str};

use arrayvec::ArrayString;
use ledger_crypto_helpers::{common::CryptographyError, eddsa::with_public_keys};
use ledger_device_sdk::libcall::{self, LibCallCommand};
use ledger_log::trace;
use panic_handler::{set_swap_panic_handler, swap_panic_handler, swap_panic_handler_comm};

use crate::{
    ctx::RunModeCtx,
    implementation::{get_amount_in_decimals, SuiPubKeyAddress},
    main_nanos::app_main,
};

use get_params::{
    get_check_address_params, get_printable_amount_params, sign_tx_params, swap_return,
    CheckAddressParams, CreateTxParams, PrintableAmountParams, SwapResult,
};
pub mod get_params;
pub mod panic_handler;

// Max SUI address str length is 32*2 + 2 (prefix)
const ADDRESS_STR_LENGTH: usize = 66;

pub const SWAP_BAD_VALID: u16 = 0x6e05;

#[derive(Debug)]
pub enum Error {
    DecodeDPathError(&'static str),
    CryptographyError(CryptographyError),
    BadAddressASCII,
    BadAddressLength,
}

impl From<CryptographyError> for Error {
    fn from(e: CryptographyError) -> Self {
        Error::CryptographyError(e)
    }
}

pub fn check_address(params: &CheckAddressParams) -> Result<bool, Error> {
    let ref_addr = params.ref_address.as_str();
    trace!("check_address: dpath: {:X?}", params.dpath);
    trace!("check_address: ref: {}", ref_addr);

    let mut der_addr = ArrayString::<ADDRESS_STR_LENGTH>::default();

    Ok(with_public_keys(
        &params.dpath,
        true,
        |_, address: &SuiPubKeyAddress| -> Result<_, CryptographyError> {
            write!(&mut der_addr, "{address}").expect("string always fits");
            trace!("check_address: der: {}", der_addr.as_str());

            Ok(ref_addr == der_addr.as_str())
        },
    )?)
}

// Outputs a string with the amount of SUI.
//
// Max sui amount 10_000_000_000 SUI.
// So max string length is 11 (quotient) + 1 (dot) + 12 (reminder) + 4 (text) = 28
pub fn get_printable_amount(params: &mut PrintableAmountParams) -> Result<ArrayString<28>, Error> {
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

pub static mut TX_PARAMS: Option<CreateTxParams> = None;

pub fn lib_main(arg0: u32) {
    let cmd = libcall::get_command(arg0);
    set_swap_panic_handler(swap_panic_handler);

    match cmd {
        LibCallCommand::SwapCheckAddress => {
            let mut params = get_check_address_params(arg0).unwrap();
            trace!("{:X?}", params);
            let is_matched = check_address(&mut params).unwrap();

            swap_return(SwapResult::CheckAddressResult(
                &mut params,
                is_matched as i32,
            ));
        }
        LibCallCommand::SwapGetPrintableAmount => {
            let mut params = get_printable_amount_params(arg0);
            trace!("{:X?}", params);
            let amount_str = get_printable_amount(&mut params).unwrap();

            swap_return(SwapResult::PrintableAmountResult(
                &mut params,
                amount_str.as_str(),
            ));
        }
        LibCallCommand::SwapSignTransaction => {
            set_swap_panic_handler(swap_panic_handler_comm);

            let mut params = sign_tx_params(arg0);
            trace!("{:X?}", params);
            trace!("amount {}", params.amount);
            unsafe {
                TX_PARAMS = Some(params);
            }

            let ctx = RunModeCtx::lib_swap();
            app_main(&ctx);
            let is_ok = ctx.is_success();

            swap_return(SwapResult::CreateTxResult(&mut params, is_ok as u8));
        }
    }
}

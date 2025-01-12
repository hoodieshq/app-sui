use core::{convert::TryInto, fmt::Write};

use arrayvec::ArrayString;
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
use ledger_log::trace;
use panic_handler::{set_swap_panic_handler, swap_panic_handler, swap_panic_handler_comm};
use params::{CheckAddressParams, CreateTxParams, PrintableAmountParams, TxParamsAccessor};

use crate::{
    ctx::RunModeCtx,
    implementation::{get_amount_in_decimals, SuiPubKeyAddress},
    main_nanos::app_main,
};

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

pub fn lib_main(arg0: u32) {
    let cmd = libcall::get_command(arg0);
    set_swap_panic_handler(swap_panic_handler);

    match cmd {
        LibCallCommand::SwapCheckAddress => {
            let mut raw_params = get_check_address_params(arg0);
            let params: CheckAddressParams = (&raw_params).try_into().unwrap();

            trace!("{:X?}", &params);
            let is_matched = check_address(&params).unwrap();

            swap_return(SwapResult::CheckAddressResult(
                &mut raw_params,
                is_matched as i32,
            ));
        }
        LibCallCommand::SwapGetPrintableAmount => {
            let mut raw_params = get_printable_amount_params(arg0);
            let params: PrintableAmountParams = (&raw_params).try_into().unwrap();

            trace!("{:X?}", &params);
            let amount_str = get_printable_amount(&params).unwrap();

            swap_return(SwapResult::PrintableAmountResult(
                &mut raw_params,
                amount_str.as_str(),
            ));
        }
        LibCallCommand::SwapSignTransaction => {
            set_swap_panic_handler(swap_panic_handler_comm);

            let mut raw_params = sign_tx_params(arg0);
            let params: CreateTxParams = (&raw_params).try_into().unwrap();

            trace!("{:X?}", &params);
            TxParamsAccessor.set(params);

            let ctx = RunModeCtx::lib_swap();
            app_main(&ctx);
            let is_ok = ctx.is_success();

            swap_return(SwapResult::CreateTxResult(&mut raw_params, is_ok as u8));
        }
    }
}

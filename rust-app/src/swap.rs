use core::fmt::Write;
use core::str;

use arrayvec::ArrayString;
use ledger_crypto_helpers::{common::CryptographyError, eddsa::with_public_keys};
use ledger_log::trace;

use crate::implementation::get_amount_in_decimals;
use crate::implementation::SuiPubKeyAddress;

use get_params::CheckAddressParams;
use get_params::PrintableAmountParams;

pub mod get_params;

// Max SUI address length is 32*2 + 2 (prefix)
const ADDRESS_STR_LENGTH: usize = 66;

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

// Outputs a string with the amount in SUI.
//
// Max sui amount 10_000_000_000 SUI.
// So max string length is 11 (quotient) + 1 (dot) + 12 (reminder) + 4 (text) = 28
pub fn get_printable_amount(params: &mut PrintableAmountParams) -> Result<ArrayString<28>, Error> {
    let (quotient, remainder_str) = get_amount_in_decimals(params.amount);

    let mut printable_amount = ArrayString::<28>::default();
    write!(&mut printable_amount, "SUI {}.{}", quotient, remainder_str,)
        .expect("string always fits");

    trace!(
        "get_printable_amount: amount: {}",
        printable_amount.as_str()
    );

    Ok(printable_amount)
}

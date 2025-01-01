use core::fmt::Write;
use core::mem;
use core::str;

use arrayvec::ArrayString;
use get_params::CheckAddressParams;
use get_params::PrintableAmountParams;
use ledger_crypto_helpers::{common::CryptographyError, eddsa::with_public_keys};
use ledger_device_sdk::libcall::string::uint256_to_float;
use ledger_device_sdk::libcall::string::CustomString;

use ledger_log::trace;

use crate::implementation::SuiPubKeyAddress;

pub mod get_params;

const MAX_BIP32_PATH_LENGTH: usize = 5;
const BIP32_PATH_SEGMENT_LEN: usize = mem::size_of::<u32>();

#[derive(Debug)]
pub enum Error {
    DecodeDPathError(&'static str),
    CryptographyError(CryptographyError),
    BadAddressASCII,
}

impl From<CryptographyError> for Error {
    fn from(e: CryptographyError) -> Self {
        Error::CryptographyError(e)
    }
}

fn unpack_path(buf: &[u8], out_path: &mut [u32]) -> Result<(), Error> {
    if buf.len() % BIP32_PATH_SEGMENT_LEN != 0 {
        return Err(Error::DecodeDPathError("Invalid path length"));
    }

    for i in (0..buf.len()).step_by(BIP32_PATH_SEGMENT_LEN) {
        // For some reason SUI coin app expects path in little endian byte order
        let path_seg = u32::from_le_bytes([buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3]]);

        out_path[i / BIP32_PATH_SEGMENT_LEN] = path_seg;
    }

    Ok(())
}

fn address_to_str(address: &[u8]) -> Result<&str, Error> {
    str::from_utf8(address).map_err(|_| Error::BadAddressASCII)
}

pub fn check_address(params: &CheckAddressParams) -> Result<bool, Error> {
    let mut dpath_buf = [0u32; MAX_BIP32_PATH_LENGTH];
    let dpath_len = params.dpath_len;
    unpack_path(
        &params.dpath[..dpath_len * BIP32_PATH_SEGMENT_LEN],
        &mut dpath_buf,
    )?;
    let dpath = &dpath_buf[..dpath_len];
    trace!("check_address: dpath: {:X?}", dpath);

    let ref_addr = address_to_str(&params.ref_address[..params.ref_address_len])?;
    trace!("check_address: ref: {}", ref_addr);
    // Max SUI address length is 32*2 + 2 (prefix)
    let mut der_addr = ArrayString::<66>::default();

    Ok(with_public_keys(
        dpath,
        true,
        |_, address: &SuiPubKeyAddress| -> Result<_, CryptographyError> {
            write!(&mut der_addr, "{address}").expect("string always fits");

            trace!("check_address: der: {}", der_addr.as_str());

            Ok(ref_addr == der_addr.as_str())
        },
    )?)
}

fn trim_trailing_zeroes<const N: usize>(str: &mut CustomString<N>) {
    while str.as_str().ends_with('0') {
        str.len -= 1;
    }
}

pub fn get_printable_amount(params: &mut PrintableAmountParams) -> Result<CustomString<79>, Error> {
    let mut amount_256 = [0u8; 32];
    amount_256[params.amount.len()..].copy_from_slice(&params.amount);

    let mut printable_amount = uint256_to_float(&amount_256, 9);
    trim_trailing_zeroes(&mut printable_amount);

    trace!("get_printable_amount: {}", printable_amount.as_str());

    Ok(printable_amount)
}

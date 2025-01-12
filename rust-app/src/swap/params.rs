use arrayvec::ArrayVec;
use core::cell::RefCell;
use core::convert::{TryFrom, TryInto};
use core::ffi::CStr;
use core::mem;
use ledger_device_sdk::libcall;

use crate::implementation::SuiAddressRaw;
use crate::swap::Error;

// Max SUI address str length is 32*2
const SUI_ADDRESS_STR_LENGTH: usize = 64;
const MAX_BIP32_PATH_LENGTH: usize = 5;
const BIP32_PATH_SEGMENT_LEN: usize = mem::size_of::<u32>();

#[derive(Debug)]
pub struct CheckAddressParams {
    pub dpath: ArrayVec<u32, MAX_BIP32_PATH_LENGTH>,
    pub ref_address: SuiAddressRaw,
}

impl TryFrom<&libcall::swap::CheckAddressParams> for CheckAddressParams {
    type Error = Error;

    fn try_from(params: &libcall::swap::CheckAddressParams) -> Result<Self, Self::Error> {
        let mut dpath = ArrayVec::from([0u32; MAX_BIP32_PATH_LENGTH]);
        let dpath_len = unpack_path(
            &params.dpath[..params.dpath_len * BIP32_PATH_SEGMENT_LEN],
            &mut dpath,
        )?;
        dpath.truncate(dpath_len);

        let ref_address = address_from_hex_cstr(params.ref_address.as_ptr())?;

        Ok(CheckAddressParams { dpath, ref_address })
    }
}

#[derive(Debug)]
pub struct PrintableAmountParams {
    pub amount: u64,
}

impl TryFrom<&libcall::swap::PrintableAmountParams> for PrintableAmountParams {
    type Error = Error;

    fn try_from(params: &libcall::swap::PrintableAmountParams) -> Result<Self, Self::Error> {
        let amount = u64::from_be_bytes(
            params.amount[params.amount.len() - mem::size_of::<u64>()..]
                .try_into()
                .map_err(|_| Error::WrongAmountLength)?,
        );

        Ok(PrintableAmountParams { amount })
    }
}

#[derive(Debug, Default)]
pub struct CreateTxParams {
    pub amount: u64,
    pub fee: u64,
    pub destination_address: SuiAddressRaw,
}

impl TryFrom<&libcall::swap::CreateTxParams> for CreateTxParams {
    type Error = Error;

    fn try_from(params: &libcall::swap::CreateTxParams) -> Result<Self, Self::Error> {
        let amount = u64::from_be_bytes(
            params.amount[params.amount.len() - mem::size_of::<u64>()..]
                .try_into()
                .map_err(|_| Error::WrongAmountLength)?,
        );

        let fee = u64::from_be_bytes(
            params.fee_amount[params.fee_amount.len() - mem::size_of::<u64>()..]
                .try_into()
                .map_err(|_| Error::WrongFeeLength)?,
        );

        let destination_address = address_from_hex_cstr(params.dest_address.as_ptr())?;

        Ok(CreateTxParams {
            amount,
            fee,
            destination_address,
        })
    }
}

fn unpack_path(buf: &[u8], out_path: &mut [u32]) -> Result<usize, Error> {
    if buf.len() % BIP32_PATH_SEGMENT_LEN != 0 {
        return Err(Error::DecodeDPathError);
    }

    for i in (0..buf.len()).step_by(BIP32_PATH_SEGMENT_LEN) {
        // For some reason SUI coin app expects path in little endian byte order
        let path_seg = u32::from_le_bytes([buf[i + 0], buf[i + 1], buf[i + 2], buf[i + 3]]);

        out_path[i / BIP32_PATH_SEGMENT_LEN] = path_seg;
    }

    Ok(buf.len() / BIP32_PATH_SEGMENT_LEN)
}

fn address_from_hex_cstr(c_str: *const u8) -> Result<SuiAddressRaw, Error> {
    let str = unsafe {
        CStr::from_ptr(c_str as *const i8)
            .to_str()
            .map_err(|_| Error::BadAddressASCII)?
    };

    if str.len() < SUI_ADDRESS_STR_LENGTH {
        return Err(Error::BadAddressLength);
    }

    // Trim zero terminator
    let str = &str[..SUI_ADDRESS_STR_LENGTH];

    let mut address = SuiAddressRaw::default();
    hex::decode_to_slice(str, &mut address).map_err(|_| Error::BadAddressHex)?;

    Ok(address)
}

static mut TX_PARAMS: RefCell<Option<CreateTxParams>> = RefCell::new(None);

pub struct TxParamsAccessor;

impl TxParamsAccessor {
    pub fn set(&self, params: CreateTxParams) {
        // SAFETY: app environment is inherently single-threaded
        unsafe {
            *TX_PARAMS.borrow_mut() = Some(params);
        }
    }

    pub fn access<R>(&self, f: impl FnOnce(&CreateTxParams) -> R) -> R {
        // SAFETY: app environment is inherently single-threaded
        f(unsafe { &TX_PARAMS.borrow().as_ref().expect("TX_PARAMS not set") })
    }
}

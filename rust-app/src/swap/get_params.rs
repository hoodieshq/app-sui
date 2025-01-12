use core::{ffi::CStr, mem};

use arrayvec::{ArrayString, ArrayVec};
#[cfg(any(target_os = "stax", target_os = "flex"))]
use ledger_device_sdk::nbgl::NbglSpinner;
use ledger_log::trace;
use ledger_secure_sdk_sys::{
    check_address_parameters_t, create_transaction_parameters_t, get_printable_amount_parameters_t,
    libargs_s__bindgen_ty_1, libargs_t,
};

use crate::implementation::SuiAddressRaw;
use crate::swap::Error;

use crate::swap::ADDRESS_STR_LENGTH;

const MAX_BIP32_PATH_LENGTH: usize = 5;
const BIP32_PATH_SEGMENT_LEN: usize = mem::size_of::<u32>();

#[derive(Debug)]
pub struct CheckAddressParams {
    pub dpath: ArrayVec<u32, MAX_BIP32_PATH_LENGTH>,
    pub ref_address: ArrayString<ADDRESS_STR_LENGTH>,
    pub result: *mut i32,
}

impl Default for CheckAddressParams {
    fn default() -> Self {
        CheckAddressParams {
            dpath: ArrayVec::from([0u32; MAX_BIP32_PATH_LENGTH]),
            ref_address: ArrayString::default(),
            result: core::ptr::null_mut(),
        }
    }
}

#[derive(Debug)]
pub struct PrintableAmountParams {
    pub amount: u64,
    pub amount_str: *mut i8,
}

impl Default for PrintableAmountParams {
    fn default() -> Self {
        PrintableAmountParams {
            amount: 0,
            amount_str: core::ptr::null_mut(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CreateTxParams {
    pub amount: u64,
    pub fee: u64,
    pub destination_address: SuiAddressRaw,
    pub exit_code_ptr: *mut u8,
}

impl Default for CreateTxParams {
    fn default() -> Self {
        CreateTxParams {
            amount: 0,
            fee: 0,
            destination_address: SuiAddressRaw::default(),
            exit_code_ptr: core::ptr::null_mut(),
        }
    }
}

pub fn get_check_address_params(arg0: u32) -> Result<CheckAddressParams, Error> {
    unsafe {
        trace!("=> get_check_address_params\n");

        let mut libarg: libargs_t = libargs_t::default();

        let arg = arg0 as *const u32;

        libarg.id = *arg;
        libarg.command = *arg.add(1);
        libarg.unused = *arg.add(2);

        libarg.__bindgen_anon_1 = *(arg.add(3) as *const libargs_s__bindgen_ty_1);

        let params: check_address_parameters_t =
            *(libarg.__bindgen_anon_1.check_address as *const check_address_parameters_t);

        let mut check_address_params: CheckAddressParams = Default::default();

        trace!("==> GET_DPATH_LENGTH\n");
        let dpath_len = *(params.address_parameters as *const u8) as usize;

        trace!("==> GET_DPATH \n");
        let mut dpath_buf = [0u8; MAX_BIP32_PATH_LENGTH * BIP32_PATH_SEGMENT_LEN];
        for i in 1..1 + dpath_len * BIP32_PATH_SEGMENT_LEN {
            let w = dpath_buf
                .get_mut(i - 1)
                .ok_or(Error::DecodeDPathError("Invalid path length"))?;
            *w = *(params.address_parameters.add(i));
        }
        unpack_path(&dpath_buf, &mut check_address_params.dpath)?;
        check_address_params.dpath.truncate(dpath_len);

        trace!("==> GET_REF_ADDRESS\n");
        let address = CStr::from_ptr(params.address_to_check)
            .to_str()
            .map_err(|_| Error::BadAddressASCII)?;
        check_address_params.ref_address =
            ArrayString::from(address).map_err(|_| Error::BadAddressLength)?;

        check_address_params.result = &(*(libarg.__bindgen_anon_1.check_address
            as *mut check_address_parameters_t))
            .result as *const i32 as *mut i32;

        Ok(check_address_params)
    }
}

pub fn get_printable_amount_params(arg0: u32) -> PrintableAmountParams {
    unsafe {
        trace!("=> get_printable_amount_params\n");

        let mut libarg: libargs_t = libargs_t::default();

        let arg = arg0 as *const u32;

        libarg.id = *arg;
        libarg.command = *arg.add(1);
        libarg.unused = *arg.add(2);

        libarg.__bindgen_anon_1 = *(arg.add(3) as *const libargs_s__bindgen_ty_1);

        let params: get_printable_amount_parameters_t =
            *(libarg.__bindgen_anon_1.get_printable_amount
                as *const get_printable_amount_parameters_t);

        let mut printable_amount_params: PrintableAmountParams = Default::default();

        let mut amount_buf = [0u8; 8];
        let amount_len = params.amount_length as usize;
        for i in 0..amount_len {
            amount_buf[mem::size_of_val(&amount_buf) - amount_len + i] = *(params.amount.add(i));
        }
        printable_amount_params.amount = u64::from_be_bytes(amount_buf);

        trace!("==> GET_AMOUNT_STR\n");
        printable_amount_params.amount_str = &(*(libarg.__bindgen_anon_1.get_printable_amount
            as *mut get_printable_amount_parameters_t))
            .printable_amount as *const i8 as *mut i8;

        printable_amount_params
    }
}

extern "C" {
    fn c_reset_bss();
    fn c_boot_std();
}

pub fn sign_tx_params(arg0: u32) -> CreateTxParams {
    unsafe {
        trace!("=> sign_tx_params\n");

        let mut libarg: libargs_t = libargs_t::default();

        let arg = arg0 as *const u32;

        libarg.id = *arg;
        libarg.command = *arg.add(1);
        libarg.unused = *arg.add(2);

        libarg.__bindgen_anon_1 = *(arg.add(3) as *const libargs_s__bindgen_ty_1);

        let params: create_transaction_parameters_t =
            *(libarg.__bindgen_anon_1.create_transaction as *const create_transaction_parameters_t);

        let mut create_tx_params: CreateTxParams = Default::default();

        trace!("==> GET_AMOUNT\n");
        let mut buf = [0u8; 8];
        let amount_len = params.amount_length as usize;
        for i in 0..amount_len {
            buf[mem::size_of_val(&buf) - amount_len + i] = *(params.amount.add(i));
        }
        create_tx_params.amount = u64::from_be_bytes(buf);

        trace!("==> GET_FEE\n");
        buf = [0u8; 8];
        let fee_len = params.fee_amount_length as usize;
        for i in 0..fee_len {
            buf[mem::size_of_val(&buf) - fee_len + i] = *(params.fee_amount.add(i));
        }
        create_tx_params.fee = u64::from_be_bytes(buf);

        trace!("==> GET_DESTINATION_ADDRESS\n");
        create_tx_params.destination_address = address_from_hex_cstr(params.destination_address);

        create_tx_params.exit_code_ptr = &(*(libarg.__bindgen_anon_1.create_transaction
            as *mut create_transaction_parameters_t))
            .result as *const u8 as *mut u8;

        /* Reset BSS and complete application boot */
        c_reset_bss();
        c_boot_std();

        #[cfg(any(target_os = "stax", target_os = "flex"))]
        NbglSpinner::new().text("Signing").show();

        create_tx_params
    }
}

pub enum SwapResult<'a> {
    CheckAddressResult(&'a mut CheckAddressParams, i32),
    PrintableAmountResult(&'a mut PrintableAmountParams, &'a str),
    CreateTxResult(&'a mut CreateTxParams, u8),
}

pub fn swap_return(res: SwapResult) {
    unsafe {
        match res {
            SwapResult::CheckAddressResult(&mut ref p, r) => {
                *(p.result) = r;
            }
            SwapResult::PrintableAmountResult(&mut ref p, s) => {
                for (i, c) in s.chars().enumerate() {
                    *(p.amount_str.add(i)) = c as i8;
                }
                *(p.amount_str.add(s.len())) = '\0' as i8;
            }
            SwapResult::CreateTxResult(&mut ref p, r) => {
                *(p.exit_code_ptr) = r;
            }
        }
        ledger_secure_sdk_sys::os_lib_end();
    }
}

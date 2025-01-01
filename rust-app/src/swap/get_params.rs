use core::{ffi::CStr, mem};

#[cfg(any(target_os = "stax", target_os = "flex"))]
use ledger_device_sdk::nbgl::NbglSpinner;
use ledger_device_sdk::testing::debug_print;
use ledger_secure_sdk_sys::{
    check_address_parameters_t, create_transaction_parameters_t, get_printable_amount_parameters_t,
    libargs_s__bindgen_ty_1, libargs_t,
};

use crate::implementation::SuiAddressRaw;

const ADDRESS_STR_LENGTH: usize = 66;

#[derive(Debug)]
pub struct CheckAddressParams {
    pub dpath: [u8; 64],
    pub dpath_len: usize,
    pub ref_address: [u8; ADDRESS_STR_LENGTH],
    pub ref_address_len: usize,
    pub result: *mut i32,
}

impl Default for CheckAddressParams {
    fn default() -> Self {
        CheckAddressParams {
            dpath: [0; 64],
            dpath_len: 0,
            ref_address: [0; ADDRESS_STR_LENGTH],
            ref_address_len: 0,
            result: core::ptr::null_mut(),
        }
    }
}

#[derive(Debug)]
pub struct PrintableAmountParams {
    pub amount: [u8; 16],
    pub amount_len: usize,
    pub amount_str: *mut i8,
}

impl Default for PrintableAmountParams {
    fn default() -> Self {
        PrintableAmountParams {
            amount: [0; 16],
            amount_len: 0,
            amount_str: core::ptr::null_mut(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CreateTxParams {
    pub amount: u64,
    pub destination_address: SuiAddressRaw,
    pub exit_code_ptr: *mut u8,
}

impl Default for CreateTxParams {
    fn default() -> Self {
        CreateTxParams {
            amount: 0,
            destination_address: SuiAddressRaw::default(),
            exit_code_ptr: core::ptr::null_mut(),
        }
    }
}

pub fn my_get_check_address_params(arg0: u32) -> CheckAddressParams {
    unsafe {
        debug_print("=> get_check_address_params\n");

        let mut libarg: libargs_t = libargs_t::default();

        let arg = arg0 as *const u32;

        libarg.id = *arg;
        libarg.command = *arg.add(1);
        libarg.unused = *arg.add(2);

        libarg.__bindgen_anon_1 = *(arg.add(3) as *const libargs_s__bindgen_ty_1);

        let params: check_address_parameters_t =
            *(libarg.__bindgen_anon_1.check_address as *const check_address_parameters_t);

        let mut check_address_params: CheckAddressParams = Default::default();

        debug_print("==> GET_DPATH_LENGTH\n");
        check_address_params.dpath_len = *(params.address_parameters as *const u8) as usize;

        debug_print("==> GET_DPATH \n");
        for i in 1..1 + check_address_params.dpath_len * 4 {
            check_address_params.dpath[i - 1] = *(params.address_parameters.add(i));
        }

        debug_print("==> GET_REF_ADDRESS\n");
        let mut address_length = 0usize;
        while *(params.address_to_check.wrapping_add(address_length)) != '\0' as i8 {
            check_address_params.ref_address[address_length] =
                *(params.address_to_check.wrapping_add(address_length)) as u8;
            address_length += 1;
        }
        check_address_params.ref_address_len = address_length;

        check_address_params.result = &(*(libarg.__bindgen_anon_1.check_address
            as *mut check_address_parameters_t))
            .result as *const i32 as *mut i32;

        check_address_params
    }
}

pub fn my_get_printable_amount_params(arg0: u32) -> PrintableAmountParams {
    unsafe {
        debug_print("=> get_printable_amount_params\n");

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

        debug_print("==> GET_AMOUNT_LENGTH\n");
        printable_amount_params.amount_len = params.amount_length as usize;

        debug_print("==> GET_AMOUNT\n");
        for i in 0..printable_amount_params.amount_len {
            printable_amount_params.amount[16 - printable_amount_params.amount_len + i] =
                *(params.amount.add(i));
        }

        debug_print("==> GET_AMOUNT_STR\n");
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

fn address_from_hex_cstr(c_str: *const i8) -> SuiAddressRaw {
    let mut str = unsafe { CStr::from_ptr(c_str).to_str().expect("valid utf8") };

    if str.starts_with("0x") {
        str = &str[2..];
    }

    let mut address = SuiAddressRaw::default();
    hex::decode_to_slice(str, &mut address).expect("valid hex");

    address
}

pub fn my_sign_tx_params(arg0: u32) -> CreateTxParams {
    unsafe {
        debug_print("=> sign_tx_params\n");

        let mut libarg: libargs_t = libargs_t::default();

        let arg = arg0 as *const u32;

        libarg.id = *arg;
        libarg.command = *arg.add(1);
        libarg.unused = *arg.add(2);

        libarg.__bindgen_anon_1 = *(arg.add(3) as *const libargs_s__bindgen_ty_1);

        let params: create_transaction_parameters_t =
            *(libarg.__bindgen_anon_1.create_transaction as *const create_transaction_parameters_t);

        let mut create_tx_params: CreateTxParams = Default::default();

        debug_print("==> GET_AMOUNT\n");
        let mut amount_buf = [0u8; 8];
        let amount_len = params.amount_length as usize;
        for i in 0..amount_len {
            amount_buf[mem::size_of_val(&amount_buf) - amount_len + i] = *(params.amount.add(i));
        }
        create_tx_params.amount = u64::from_be_bytes(amount_buf);

        //debug_print("==> GET_FEE\n");
        //create_tx_params.fee_amount_len = params.fee_amount_length as usize;
        //for i in 0..create_tx_params.fee_amount_len {
        //    create_tx_params.fee_amount[16 - create_tx_params.fee_amount_len + i] =
        //        *(params.fee_amount.add(i));
        //}

        debug_print("==> GET_DESTINATION_ADDRESS\n");
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

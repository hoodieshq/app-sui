use crate::interface::*;
use crate::utils::*;

extern crate alloc;
use alloc::format;

use include_gif::include_gif;
use ledger_crypto_helpers::common::HexSlice;
use ledger_crypto_helpers::hasher::HexHash;
use ledger_device_sdk::nbgl::*;

pub const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("sui_64x64.gif", NBGL));

pub fn confirm_address(address: &SuiPubKeyAddress) -> Option<()> {
    let success = NbglAddressReview::new()
        .glyph(&APP_ICON)
        .verify_str("Provide Public Key")
        .show(&format!("{address}"));
    NbglReviewStatus::new()
        .status_type(StatusType::Address)
        .show(success);
    if success {
        Some(())
    } else {
        None
    }
}

pub fn confirm_sign_tx(
    address: &SuiPubKeyAddress,
    recipient: [u8; 32],
    total_amount: u64,
    gas_budget: u64,
) -> Option<()> {
    let tx_fields = [
        Field {
            name: "From",
            value: &format!("{address}"),
        },
        Field {
            name: "To",
            value: &format!("0x{}", HexSlice(&recipient)),
        },
        Field {
            name: "Amount",
            value: {
                let (quotient, remainder_str) = get_amount_in_decimals(total_amount);
                &format!("SUI {}.{}", quotient, remainder_str.as_str())
            },
        },
        Field {
            name: "Max Gas",
            value: {
                let (quotient, remainder_str) = get_amount_in_decimals(gas_budget);
                &format!("SUI {}.{}", quotient, remainder_str.as_str())
            },
        },
    ];

    let success = NbglReview::new()
        .glyph(&APP_ICON)
        .titles("Transfer SUI", "", "")
        .show(&tx_fields);
    if success {
        Some(())
    } else {
        None
    }
}

pub fn confirm_blind_sign_tx(hash: &HexHash<32>) -> Option<()> {
    let tx_fields = [Field {
        name: "Transaction hash",
        value: &format!("0x{hash}"),
    }];

    let success = NbglReview::new()
        .glyph(&APP_ICON)
        .blind()
        .titles("Blind Sign Transaction", "", "")
        .show(&tx_fields);
    if success {
        Some(())
    } else {
        None
    }
}

pub fn warn_tx_not_recognized() {}

extern crate alloc;
use alloc::format;

use include_gif::include_gif;
use ledger_crypto_helpers::eddsa::Ed25519RawPubKeyAddress;
use ledger_crypto_helpers::hasher::Base64Hash;
use ledger_device_sdk::nbgl::*;

pub const APP_ICON: NbglGlyph = NbglGlyph::from_include(include_gif!("crab_64x64.gif", NBGL));

pub fn confirm_address(pkh: &Ed25519RawPubKeyAddress) -> Option<()> {
    let success = NbglAddressReview::new()
        .glyph(&APP_ICON)
        .verify_str("Provide Public Key")
        .show(&format!("{pkh}"));
    NbglReviewStatus::new()
        .status_type(StatusType::Address)
        .show(success);
    if success {
        Some(())
    } else {
        None
    }
}

pub fn confirm_sign_tx(pkh: &Ed25519RawPubKeyAddress, hash: &Base64Hash<32>) -> Option<()> {
    let tx_fields = [
        Field {
            name: "Transaction hash",
            value: &format!("{hash}"),
        },
        Field {
            name: "Sign for Address",
            value: &format!("{pkh}"),
        },
    ];

    let success = NbglReview::new()
        .glyph(&APP_ICON)
        .blind()
        .titles("Sign Transaction", "", "")
        .show(&tx_fields);
    NbglReviewStatus::new()
        .status_type(StatusType::Transaction)
        .show(success);
    if success {
        Some(())
    } else {
        None
    }
}

pub fn warn_tx_not_recognized() {}

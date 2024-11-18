use ledger_crypto_helpers::eddsa::Ed25519RawPubKeyAddress;
use ledger_crypto_helpers::hasher::Base64Hash;

pub fn confirm_address(pkh: &Ed25519RawPubKeyAddress) -> Option<()> {
    Some(())
}

pub fn confirm_sign_tx(pkh: &Ed25519RawPubKeyAddress, hash: &Base64Hash<32>) -> Option<()> {
    Some(())
}

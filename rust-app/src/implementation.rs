use crate::coin_config::check_coin_configuration_signature;
use crate::ctx::RunCtx;
use crate::interface::*;
use crate::settings::*;
use crate::swap;
use crate::swap::params::TxParams;
use crate::ui::*;
use crate::utils::*;
use alamgu_async_block::*;
use arrayvec::ArrayString;
use arrayvec::ArrayVec;
use ledger_crypto_helpers::common::{try_option, Address};
use ledger_crypto_helpers::eddsa::{ed25519_public_key_bytes, eddsa_sign, with_public_keys};
use ledger_crypto_helpers::hasher::{Blake2b, Hasher, HexHash};
use ledger_device_sdk::io::{StatusWords, SyscallError};
use ledger_log::trace;
use ledger_parser_combinators::async_parser::*;
use ledger_parser_combinators::bcs::async_parser::*;
use ledger_parser_combinators::interp::*;

use core::convert::TryFrom;
use core::future::Future;
use core::str;

pub type BipParserImplT = impl AsyncParser<Bip32Key, ByteStream, Output = ArrayVec<u32, 10>>;
pub const BIP_PATH_PARSER: BipParserImplT = SubInterp(DefaultInterp);

// Need a path of length 5, as make_bip32_path panics with smaller paths
pub const BIP32_PREFIX: [u32; 5] =
    ledger_device_sdk::ecc::make_bip32_path(b"m/44'/784'/123'/0'/0'");

pub async fn get_address_apdu(io: HostIO, ui: UserInterface, prompt: bool) {
    let input = match io.get_params::<1>() {
        Some(v) => v,
        None => reject(SyscallError::InvalidParameter as u16).await,
    };

    let path = BIP_PATH_PARSER.parse(&mut input[0].clone()).await;

    if !path.starts_with(&BIP32_PREFIX[0..2]) {
        reject::<()>(SyscallError::InvalidParameter as u16).await;
    }

    let mut rv = ArrayVec::<u8, 220>::new();

    if with_public_keys(&path, true, |key, address: &SuiPubKeyAddress| {
        try_option(|| -> Option<()> {
            if prompt {
                ui.confirm_address(address)?;
            }

            let key_bytes = ed25519_public_key_bytes(key);

            rv.try_push(u8::try_from(key_bytes.len()).ok()?).ok()?;
            rv.try_extend_from_slice(key_bytes).ok()?;

            // And we'll send the address along;
            let binary_address = address.get_binary_address();
            rv.try_push(u8::try_from(binary_address.len()).ok()?).ok()?;
            rv.try_extend_from_slice(binary_address).ok()?;
            Some(())
        }())
    })
    .is_err()
    {
        reject::<()>(StatusWords::UserCancelled as u16).await;
    }

    io.result_final(&rv).await;
}

#[derive(PartialEq)]
#[cfg_attr(feature = "speculos", derive(Debug))]
pub struct ObjectRefOutput {
    pub address: SuiAddressRaw,
    pub version: u64,
    pub digest: [u8; 32],
}

pub enum CallArg {
    RecipientAddress(SuiAddressRaw),
    Amount(u64),
    OtherPure,
    ImmOrOwnedObject(ObjectRefOutput),
    SharedObject,
}

impl HasOutput<CallArgSchema> for DefaultInterp {
    type Output = CallArg;
}

impl<BS: Clone + Readable> AsyncParser<CallArgSchema, BS> for DefaultInterp {
    type State<'c>
        = impl Future<Output = Self::Output> + 'c
    where
        BS: 'c;
    fn parse<'a: 'c, 'b: 'c, 'c>(&'b self, input: &'a mut BS) -> Self::State<'c> {
        async move {
            let enum_variant =
                <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;
            match enum_variant {
                0 => {
                    let length =
                        <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input)
                            .await;
                    trace!("CallArgSchema: Pure: length: {}", length);
                    match length {
                        8 => CallArg::Amount(
                            <DefaultInterp as AsyncParser<Amount, BS>>::parse(
                                &DefaultInterp,
                                input,
                            )
                            .await,
                        ),
                        32 => CallArg::RecipientAddress(
                            <DefaultInterp as AsyncParser<Recipient, BS>>::parse(
                                &DefaultInterp,
                                input,
                            )
                            .await,
                        ),
                        _ => {
                            for _ in 0..length {
                                let _: [u8; 1] = input.read().await;
                            }
                            CallArg::OtherPure
                        }
                    }
                }
                1 => {
                    let enum_variant =
                        <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input)
                            .await;
                    match enum_variant {
                        0 => {
                            trace!("CallArgSchema: ObjectArg: ImmOrOwnedObject");
                            let obj_ref = object_ref_parser_with_output().parse(input).await;
                            CallArg::ImmOrOwnedObject(obj_ref)
                        }
                        1 => {
                            trace!("CallArgSchema: ObjectArg: SharedObject");
                            <(DefaultInterp, DefaultInterp, DefaultInterp) as AsyncParser<
                                SharedObject,
                                BS,
                            >>::parse(
                                &(DefaultInterp, DefaultInterp, DefaultInterp), input
                            )
                            .await;
                            CallArg::SharedObject
                        }
                        _ => {
                            reject_on(
                                core::file!(),
                                core::line!(),
                                SyscallError::NotSupported as u16,
                            )
                            .await
                        }
                    }
                }
                _ => {
                    trace!("CallArgSchema: Unknown enum: {}", enum_variant);
                    reject_on(
                        core::file!(),
                        core::line!(),
                        SyscallError::NotSupported as u16,
                    )
                    .await
                }
            }
        }
    }
}

pub const TRANSFER_OBJECT_ARRAY_LENGTH: usize = 1;
pub const SPLIT_COIN_ARRAY_LENGTH: usize = 8;
pub const OBJECT_ARRAY_LENGTH: usize = 4;

pub enum Command {
    TransferObject(ArrayVec<Argument, TRANSFER_OBJECT_ARRAY_LENGTH>, Argument),
    SplitCoins(Argument, ArrayVec<Argument, SPLIT_COIN_ARRAY_LENGTH>),
    MergeCoins,
}

impl HasOutput<CommandSchema> for DefaultInterp {
    type Output = Command;
}

impl<BS: Clone + Readable> AsyncParser<CommandSchema, BS> for DefaultInterp {
    type State<'c>
        = impl Future<Output = Self::Output> + 'c
    where
        BS: 'c;
    fn parse<'a: 'c, 'b: 'c, 'c>(&'b self, input: &'a mut BS) -> Self::State<'c> {
        async move {
            let enum_variant =
                <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;
            match enum_variant {
                1 => {
                    trace!("CommandSchema: TransferObject");
                    let v1 = <SubInterp<DefaultInterp> as AsyncParser<
                        Vec<ArgumentSchema, TRANSFER_OBJECT_ARRAY_LENGTH>,
                        BS,
                    >>::parse(&SubInterp(DefaultInterp), input)
                    .await;
                    let v2 = <DefaultInterp as AsyncParser<ArgumentSchema, BS>>::parse(
                        &DefaultInterp,
                        input,
                    )
                    .await;
                    Command::TransferObject(v1, v2)
                }
                2 => {
                    trace!("CommandSchema: SplitCoins");
                    let v1 = <DefaultInterp as AsyncParser<ArgumentSchema, BS>>::parse(
                        &DefaultInterp,
                        input,
                    )
                    .await;
                    let v2 = <SubInterp<DefaultInterp> as AsyncParser<
                        Vec<ArgumentSchema, SPLIT_COIN_ARRAY_LENGTH>,
                        BS,
                    >>::parse(&SubInterp(DefaultInterp), input)
                    .await;
                    Command::SplitCoins(v1, v2)
                }
                3 => {
                    trace!("CommandSchema: MergeCoins");
                    // Don't care about the arguments, just consuming input
                    let _v1 = <DefaultInterp as AsyncParser<ArgumentSchema, BS>>::parse(
                        &DefaultInterp,
                        input,
                    )
                    .await;
                    let _v2 = <SubInterp<DefaultInterp> as AsyncParser<
                        Vec<ArgumentSchema, SPLIT_COIN_ARRAY_LENGTH>,
                        BS,
                    >>::parse(&SubInterp(DefaultInterp), input)
                    .await;
                    Command::MergeCoins
                }
                _ => {
                    trace!("CommandSchema: Unknown enum: {}", enum_variant);
                    reject_on(
                        core::file!(),
                        core::line!(),
                        SyscallError::NotSupported as u16,
                    )
                    .await
                }
            }
        }
    }
}

#[cfg_attr(feature = "speculos", derive(Debug))]
pub enum Argument {
    GasCoin,
    Input(u16),
    Result(u16),
    NestedResult(u16, u16),
}

impl HasOutput<ArgumentSchema> for DefaultInterp {
    type Output = Argument;
}

impl<BS: Clone + Readable> AsyncParser<ArgumentSchema, BS> for DefaultInterp {
    type State<'c>
        = impl Future<Output = Self::Output> + 'c
    where
        BS: 'c;
    fn parse<'a: 'c, 'b: 'c, 'c>(&'b self, input: &'a mut BS) -> Self::State<'c> {
        async move {
            let enum_variant =
                <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;
            match enum_variant {
                0 => {
                    trace!("ArgumentSchema: GasCoin");
                    Argument::GasCoin
                }
                1 => {
                    trace!("ArgumentSchema: Input");
                    Argument::Input(
                        <DefaultInterp as AsyncParser<U16LE, BS>>::parse(&DefaultInterp, input)
                            .await,
                    )
                }
                2 => {
                    trace!("ArgumentSchema: Result");
                    Argument::Result(
                        <DefaultInterp as AsyncParser<U16LE, BS>>::parse(&DefaultInterp, input)
                            .await,
                    )
                }
                3 => {
                    trace!("ArgumentSchema: NestedResult");
                    Argument::NestedResult(
                        <DefaultInterp as AsyncParser<U16LE, BS>>::parse(&DefaultInterp, input)
                            .await,
                        <DefaultInterp as AsyncParser<U16LE, BS>>::parse(&DefaultInterp, input)
                            .await,
                    )
                }
                _ => {
                    reject_on(
                        core::file!(),
                        core::line!(),
                        SyscallError::NotSupported as u16,
                    )
                    .await
                }
            }
        }
    }
}

impl HasOutput<ProgrammableTransaction> for ProgrammableTransaction {
    type Output = (
        <DefaultInterp as HasOutput<Recipient>>::Output,
        <DefaultInterp as HasOutput<Amount>>::Output,
        ArrayVec<SuiAddressRaw, OBJECT_ARRAY_LENGTH>,
    );
}

impl<BS: Clone + Readable> AsyncParser<ProgrammableTransaction, BS> for ProgrammableTransaction {
    type State<'c>
        = impl Future<Output = Self::Output> + 'c
    where
        BS: 'c;
    fn parse<'a: 'c, 'b: 'c, 'c>(&'b self, input: &'a mut BS) -> Self::State<'c> {
        async move {
            let mut recipient_addr = None;
            let mut recipient_index = None;
            let mut amounts: ArrayVec<(u64, u16), SPLIT_COIN_ARRAY_LENGTH> = ArrayVec::new();
            let mut objects = ArrayVec::<(SuiAddressRaw, u16), OBJECT_ARRAY_LENGTH>::new();

            // Handle inputs
            {
                let length =
                    <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;

                trace!("ProgrammableTransaction: Inputs: {}", length);
                for i in 0..length as u16 {
                    let arg = <DefaultInterp as AsyncParser<CallArgSchema, BS>>::parse(
                        &DefaultInterp,
                        input,
                    )
                    .await;
                    match arg {
                        CallArg::ImmOrOwnedObject(obj) => {
                            if let Err(_) = objects.try_push((obj.address, i)) {
                                // Reject on MAX coin objects
                                reject_on(
                                    core::file!(),
                                    core::line!(),
                                    SyscallError::NotSupported as u16,
                                )
                                .await
                            }
                        }
                        CallArg::RecipientAddress(addr) => match recipient_addr {
                            None => {
                                recipient_addr = Some(addr);
                                recipient_index = Some(i);
                            }
                            // Reject on multiple RecipientAddress(s)
                            _ => {
                                reject_on(
                                    core::file!(),
                                    core::line!(),
                                    SyscallError::NotSupported as u16,
                                )
                                .await
                            }
                        },
                        CallArg::Amount(amt) =>
                        {
                            #[allow(clippy::single_match)]
                            match amounts.try_push((amt, i)) {
                                Err(_) => {
                                    reject_on(
                                        core::file!(),
                                        core::line!(),
                                        SyscallError::NotSupported as u16,
                                    )
                                    .await
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
            }

            if recipient_index.is_none() || amounts.is_empty() {
                reject_on::<()>(
                    core::file!(),
                    core::line!(),
                    SyscallError::NotSupported as u16,
                )
                .await;
            }

            let recipient = match recipient_addr {
                Some(addr) => addr,
                _ => {
                    reject_on(
                        core::file!(),
                        core::line!(),
                        SyscallError::NotSupported as u16,
                    )
                    .await
                }
            };

            let mut verified_recipient = false;
            let mut total_amount: u64 = 0;
            // Handle commands
            {
                let length =
                    <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;
                trace!("ProgrammableTransaction: Commands: {}", length);
                for _ in 0..length {
                    let c = <DefaultInterp as AsyncParser<CommandSchema, BS>>::parse(
                        &DefaultInterp,
                        input,
                    )
                    .await;
                    match c {
                        Command::TransferObject(_nested_results, recipient_input) => {
                            if verified_recipient {
                                // Reject more than one TransferObject(s)
                                reject_on::<()>(
                                    core::file!(),
                                    core::line!(),
                                    SyscallError::NotSupported as u16,
                                )
                                .await;
                            }
                            match recipient_input {
                                Argument::Input(inp_index) => {
                                    if Some(inp_index) != recipient_index {
                                        trace!("TransferObject recipient mismatch");
                                        reject_on::<()>(
                                            core::file!(),
                                            core::line!(),
                                            SyscallError::NotSupported as u16,
                                        )
                                        .await;
                                    }
                                    verified_recipient = true;
                                }
                                _ => {
                                    reject_on(
                                        core::file!(),
                                        core::line!(),
                                        SyscallError::NotSupported as u16,
                                    )
                                    .await
                                }
                            }
                        }
                        Command::SplitCoins(coin, input_indices) => {
                            match coin {
                                Argument::GasCoin => {}
                                Argument::Input(input)
                                    if objects.iter().find(|(_, idx)| *idx == input).is_some() =>
                                {
                                    trace!("SplitCoins: Object");
                                }
                                _ => {
                                    reject_on(
                                        core::file!(),
                                        core::line!(),
                                        SyscallError::NotSupported as u16,
                                    )
                                    .await
                                }
                            }
                            for arg in &input_indices {
                                match arg {
                                    Argument::Input(inp_index) => {
                                        for (amt, ix) in &amounts {
                                            if *ix == (*inp_index) {
                                                match total_amount.checked_add(*amt) {
                                                    Some(t) => total_amount = t,
                                                    None => {
                                                        reject_on(
                                                            core::file!(),
                                                            core::line!(),
                                                            SyscallError::InvalidParameter as u16,
                                                        )
                                                        .await
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        reject_on(
                                            core::file!(),
                                            core::line!(),
                                            SyscallError::NotSupported as u16,
                                        )
                                        .await
                                    }
                                }
                            }
                        }
                        Command::MergeCoins => (),
                    }
                }
            }

            if !verified_recipient {
                reject_on::<()>(
                    core::file!(),
                    core::line!(),
                    SyscallError::NotSupported as u16,
                )
                .await;
            }

            let objects: ArrayVec<_, OBJECT_ARRAY_LENGTH> =
                objects.into_iter().map(|(addr, _)| addr).collect();

            (recipient, total_amount, objects)
        }
    }
}

impl HasOutput<TransactionKind> for TransactionKind {
    type Output = <ProgrammableTransaction as HasOutput<ProgrammableTransaction>>::Output;
}

impl<BS: Clone + Readable> AsyncParser<TransactionKind, BS> for TransactionKind {
    type State<'c>
        = impl Future<Output = Self::Output> + 'c
    where
        BS: 'c;
    fn parse<'a: 'c, 'b: 'c, 'c>(&'b self, input: &'a mut BS) -> Self::State<'c> {
        async move {
            let enum_variant =
                <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;
            match enum_variant {
                0 => {
                    trace!("TransactionKind: ProgrammableTransaction");
                    <ProgrammableTransaction as AsyncParser<ProgrammableTransaction, BS>>::parse(
                        &ProgrammableTransaction,
                        input,
                    )
                    .await
                }
                _ => {
                    trace!("TransactionKind: {}", enum_variant);
                    reject_on(
                        core::file!(),
                        core::line!(),
                        SyscallError::NotSupported as u16,
                    )
                    .await
                }
            }
        }
    }
}

impl HasOutput<TransactionExpiration> for DefaultInterp {
    type Output = ();
}

impl<BS: Clone + Readable> AsyncParser<TransactionExpiration, BS> for DefaultInterp {
    type State<'c>
        = impl Future<Output = Self::Output> + 'c
    where
        BS: 'c;
    fn parse<'a: 'c, 'b: 'c, 'c>(&'b self, input: &'a mut BS) -> Self::State<'c> {
        async move {
            let enum_variant =
                <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;
            match enum_variant {
                0 => {
                    trace!("TransactionExpiration: None");
                }
                1 => {
                    trace!("TransactionExpiration: Epoch");
                    <DefaultInterp as AsyncParser<EpochId, BS>>::parse(&DefaultInterp, input).await;
                }
                _ => {
                    reject_on(
                        core::file!(),
                        core::line!(),
                        SyscallError::NotSupported as u16,
                    )
                    .await
                }
            }
        }
    }
}

const fn gas_data_parser<BS: Clone + Readable>() -> impl AsyncParser<GasData, BS, Output = u64> {
    Action(
        (
            SubInterp(object_ref_parser()),
            DefaultInterp,
            DefaultInterp,
            DefaultInterp,
        ),
        |(_, _sender, _gas_price, gas_budget): (_, _, u64, u64)| {
            // Gas price is per gas amount. Gas budget is total, reflecting the amount of gas *
            // gas price. We only care about the total, not the price or amount in isolation , so we
            // just ignore that field.
            //
            // C.F. https://github.com/MystenLabs/sui/pull/8676
            Some(gas_budget)
        },
    )
}

const fn object_ref_parser<BS: Readable>() -> impl AsyncParser<ObjectRef, BS, Output = ()> {
    Action((DefaultInterp, DefaultInterp, DefaultInterp), |_| Some(()))
}

const fn object_ref_parser_with_output<BS: Readable>(
) -> impl AsyncParser<ObjectRef, BS, Output = ObjectRefOutput> {
    Action(
        (DefaultInterp, DefaultInterp, DefaultInterp),
        |(address, version, (_sz, digest))| {
            trace!(
                "ObjectRef{{ \naddr: {:X?}, \nversion: {} \ndigest {:X?} }}",
                &address,
                version,
                &digest
            );
            Some(ObjectRefOutput {
                address,
                version,
                digest,
            })
        },
    )
}

const fn intent_parser<BS: Readable>() -> impl AsyncParser<Intent, BS, Output = ()> {
    Action((DefaultInterp, DefaultInterp, DefaultInterp), |_| {
        trace!("Intent Ok");
        Some(())
    })
}

type TransactionDataV1Output = (<TransactionKind as HasOutput<TransactionKind>>::Output, u64);

const fn transaction_data_v1_parser<BS: Clone + Readable>(
) -> impl AsyncParser<TransactionDataV1, BS, Output = TransactionDataV1Output> {
    Action(
        (
            TransactionKind,
            DefaultInterp,
            gas_data_parser(),
            DefaultInterp,
        ),
        |(v, _, gas_budget, _)| Some((v, gas_budget)),
    )
}

impl HasOutput<TransactionData> for TransactionData {
    type Output = TransactionDataV1Output;
}

impl<BS: Clone + Readable> AsyncParser<TransactionData, BS> for TransactionData {
    type State<'c>
        = impl Future<Output = Self::Output> + 'c
    where
        BS: 'c;
    fn parse<'a: 'c, 'b: 'c, 'c>(&'b self, input: &'a mut BS) -> Self::State<'c> {
        async move {
            let enum_variant =
                <DefaultInterp as AsyncParser<ULEB128, BS>>::parse(&DefaultInterp, input).await;
            match enum_variant {
                0 => {
                    trace!("TransactionData: V1");
                    transaction_data_v1_parser().parse(input).await
                }
                _ => {
                    reject_on(
                        core::file!(),
                        core::line!(),
                        SyscallError::NotSupported as u16,
                    )
                    .await
                }
            }
        }
    }
}

const fn tx_parser<BS: Clone + Readable>(
) -> impl AsyncParser<IntentMessage, BS, Output = <TransactionData as HasOutput<TransactionData>>::Output>
{
    Action((intent_parser(), TransactionData), |(_, d)| Some(d))
}

async fn prompt_tx_params(
    ui: &UserInterface,
    path: &[u32],
    TxParams {
        amount,
        fee,
        destination_address,
    }: TxParams,
    ticker: &str,
    decimals: u8,
) {
    if with_public_keys(path, true, |_, address: &SuiPubKeyAddress| {
        try_option(ui.confirm_sign_tx(address, destination_address, amount, fee, ticker, decimals))
    })
    .ok()
    .is_none()
    {
        reject::<()>(StatusWords::UserCancelled as u16).await;
    };
}
async fn check_tx_params(expected: &TxParams, received: &TxParams) {
    if !swap::check_tx_params(expected, received) {
        reject::<()>(SW_SWAP_TX_PARAM_MISMATCH).await;
    }
}

async fn match_coin_objects(
    ctx: &RunCtx,
    coin_object_list: ArrayVec<SuiAddressRaw, OBJECT_ARRAY_LENGTH>,
) -> (ArrayString<8>, u8) {
    let res = ctx.access_coin_info(|stored_coin_info| -> Result<_, u16> {
        let Some(stored_coin_info) = stored_coin_info else {
            return Err(SW_TX_COIN_INFO_NOT_SET);
        };

        for coin_object in coin_object_list.iter() {
            if stored_coin_info
                .coin_objects
                .iter()
                .find(|&x| x == coin_object)
                .is_none()
            {
                return Err(SW_TX_COIN_INFO_MISMATCH);
            }
        }

        Ok((stored_coin_info.ticker.clone(), stored_coin_info.decimals))
    });

    match res {
        Ok(v) => v,
        Err(sw) => reject(sw).await,
    }
}

pub async fn sign_apdu(io: HostIO, ctx: &RunCtx, settings: Settings, ui: UserInterface) {
    let _on_failure = defer::defer(|| {
        // In case of a swap, we need to communicate that signing failed
        if ctx.is_swap() && !ctx.is_swap_sign_succeeded() {
            ctx.set_swap_sign_failure();
        }
    });

    let mut input = match io.get_params::<2>() {
        Some(v) => v,
        None => reject(SyscallError::InvalidParameter as u16).await,
    };

    // Read length, and move input[0] by one byte
    let length = usize::from_le_bytes(input[0].read().await);

    let known_txn = {
        let mut txn = input[0].clone();
        NoinlineFut(async move {
            trace!("Beginning check parse");
            TryFuture(tx_parser().parse(&mut txn)).await.is_some()
        })
        .await
    };

    if known_txn {
        let mut txn = input[0].clone();
        let ((recipient, total_amount, coin_objects), gas_budget) =
            tx_parser().parse(&mut txn).await;

        let mut bs = input[1].clone();
        let path = BIP_PATH_PARSER.parse(&mut bs).await;
        if !path.starts_with(&BIP32_PREFIX[0..2]) {
            reject::<()>(SyscallError::InvalidParameter as u16).await;
        }

        let tx_params = TxParams {
            amount: total_amount,
            fee: gas_budget,
            destination_address: recipient,
        };

        if ctx.is_swap() {
            let expected = ctx.get_swap_tx_params();
            check_tx_params(expected, &tx_params).await;
        } else {
            // No coin objects means it's a native SUI transaction
            let (ticker, decimals) = if coin_objects.is_empty() {
                (ArrayString::from("SUI").unwrap(), SUI_DECIMALS)
            } else {
                match_coin_objects(ctx, coin_objects).await
            };
            // Show prompts after all inputs have been parsed
            prompt_tx_params(&ui, path.as_slice(), tx_params, ticker.as_str(), decimals).await;
        }
    } else if !settings.get_blind_sign() || ctx.is_swap() {
        ui.warn_tx_not_recognized();
        reject::<()>(SyscallError::NotSupported as u16).await;
    }

    NoinlineFut(async move {
        let mut hasher: Blake2b = Hasher::new();
        {
            let mut txn: ByteStream = input[0].clone();
            const CHUNK_SIZE: usize = 128;
            let (chunks, rem) = (length / CHUNK_SIZE, length % CHUNK_SIZE);
            for _ in 0..chunks {
                let b: [u8; CHUNK_SIZE] = txn.read().await;
                hasher.update(&b);
            }
            for _ in 0..rem {
                let b: [u8; 1] = txn.read().await;
                hasher.update(&b);
            }
        }
        let hash: HexHash<32> = hasher.finalize();
        if !known_txn {
            // Show prompts after all inputs have been parsed
            if ui.confirm_blind_sign_tx(&hash).is_none() {
                reject::<()>(StatusWords::UserCancelled as u16).await;
            };
        }
        let path = BIP_PATH_PARSER.parse(&mut input[1].clone()).await;
        if !path.starts_with(&BIP32_PREFIX[0..2]) {
            reject::<()>(SyscallError::InvalidParameter as u16).await;
        }
        if let Some(sig) = { eddsa_sign(&path, true, &hash.0).ok() } {
            io.result_final(&sig.0[0..]).await;
        } else {
            reject::<()>(SyscallError::Unspecified as u16).await;
        }
    })
    .await;

    // Does nothing if not a swap mode
    ctx.set_swap_sign_success();
}

const TICKER_MAX_SIZE: usize = 8;

#[cfg_attr(feature = "speculos", derive(Debug))]
pub struct CoinInfo {
    pub ticker: ArrayString<TICKER_MAX_SIZE>,
    pub decimals: u8,
    pub coin_objects: ArrayVec<SuiAddressRaw, OBJECT_ARRAY_LENGTH>,
}

pub async fn set_coin_info_apdu(io: HostIO, ctx: &RunCtx) {
    const MAX_CONFIG_SIZE: usize = 96;
    const MAX_DER_SIGNATURE_SIZE: usize = 73;

    let input = match io.get_params::<1>() {
        Some(v) => v,
        None => reject(SyscallError::InvalidParameter as u16).await,
    };

    // Check coin config signature
    {
        let mut stream = input[0].clone();

        let config_size = u8::from_le_bytes(stream.read().await);
        let mut config_buf = ArrayVec::<u8, MAX_CONFIG_SIZE>::new();
        for _ in 0..config_size {
            let b = u8::from_le_bytes(stream.read().await);
            if let Err(_) = config_buf.try_push(b) {
                reject::<()>(SyscallError::InvalidParameter as u16).await;
            }
        }

        let der_sig_size = u8::from_le_bytes(stream.read().await);
        let mut der_signature_buf = ArrayVec::<u8, MAX_DER_SIGNATURE_SIZE>::new();
        for _ in 0..der_sig_size {
            let b = u8::from_le_bytes(stream.read().await);
            if let Err(_) = der_signature_buf.try_push(b) {
                reject::<()>(SyscallError::InvalidParameter as u16).await;
            }
        }

        if !check_coin_configuration_signature(&config_buf, &der_signature_buf) {
            reject::<()>(SW_SET_COIN_INFO_BAD_SIGN).await;
        }
    }

    let mut stream = input[0].clone();
    let _config_size = u8::from_le_bytes(stream.read().await);

    // Parse coin info
    let coin_info = CoinInfo {
        ticker: {
            let res: Option<_> = try {
                let ticker_len = u8::from_le_bytes(stream.read().await) as usize;
                let mut ticker_bytes = [0u8; TICKER_MAX_SIZE];
                for i in 0..ticker_len {
                    ticker_bytes[i] = u8::from_le_bytes(stream.read().await);
                }

                let ticker_str = str::from_utf8(&ticker_bytes[..ticker_len]).ok()?;
                ArrayString::from(ticker_str).ok()?
            };

            let Some(ticker) = res else {
                reject(SyscallError::InvalidParameter as u16).await
            };
            ticker
        },
        decimals: u8::from_le_bytes(stream.read().await),
        coin_objects: {
            let cnt = u8::from_le_bytes(stream.read().await) as usize;
            let mut coin_objects: ArrayVec<SuiAddressRaw, OBJECT_ARRAY_LENGTH> = ArrayVec::new();
            for _ in 0..cnt {
                if let Err(_) = coin_objects.try_push(stream.read().await) {
                    reject::<()>(SyscallError::InvalidParameter as u16).await;
                }
            }
            coin_objects
        },
    };

    ctx.set_coin_info(coin_info);

    io.result_final(&[]).await;
}

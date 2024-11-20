use crate::implementation::*;
use crate::interface::*;
#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use crate::test_parsers::*;

use arrayvec::ArrayVec;
use ledger_device_sdk::io;
use ledger_device_sdk::io::Reply;
use ledger_log::{info, trace};
use ledger_parser_combinators::interp_parser::OOB;

use ledger_parser_combinators::interp_parser::{InterpParser, ParserCommon};
fn run_parser_apdu<P: InterpParser<A, Returning = ArrayVec<u8, 128>>, A>(
    states: &mut ParsersState,
    get_state: fn(&mut ParsersState) -> &mut <P as ParserCommon<A>>::State,
    parser: &P,
    comm: &mut io::Comm,
) -> Result<(), Reply> {
    let cursor = comm.get_data()?;

    trace!("Parsing APDU input: {:?}\n", cursor);
    let mut parse_destination = None;
    let parse_rv =
        <P as InterpParser<A>>::parse(parser, get_state(states), cursor, &mut parse_destination);
    trace!("Parser result: {:?}\n", parse_rv);
    match parse_rv {
        // Explicit rejection; reset the parser. Possibly send error message to host?
        Err((Some(OOB::Reject), _)) => {
            reset_parsers_state(states);
            Err(io::StatusWords::Unknown.into())
        }
        // Deliberately no catch-all on the Err((Some case; we'll get error messages if we
        // add to OOB's out-of-band actions and forget to implement them.
        //
        // Finished the chunk with no further actions pending, but not done.
        Err((None, [])) => {
            trace!("Parser needs more; continuing");
            Ok(())
        }
        // Didn't consume the whole chunk; reset and error message.
        Err((None, _)) => {
            reset_parsers_state(states);
            Err(io::StatusWords::Unknown.into())
        }
        // Consumed the whole chunk and parser finished; send response.
        Ok([]) => {
            trace!("Parser finished, resetting state\n");
            match parse_destination.as_ref() {
                Some(rv) => comm.append(&rv[..]),
                None => return Err(io::StatusWords::Unknown.into()),
            }
            // Parse finished; reset.
            reset_parsers_state(states);
            Ok(())
        }
        // Parse ended before the chunk did; reset.
        Ok(_) => {
            reset_parsers_state(states);
            Err(io::StatusWords::Unknown.into())
        }
    }
}

#[inline(never)]
pub fn handle_apdu(comm: &mut io::Comm, ins: Ins, parser: &mut ParsersState) -> Result<(), Reply> {
    info!("entering handle_apdu with command {:?}", ins);
    if comm.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetVersion => {
            comm.append(&[
                env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
                env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
            ]);
            comm.append(b"alamgu example");
        }
        Ins::VerifyAddress => run_parser_apdu::<_, Bip32Key>(
            parser,
            get_get_address_state::<true>,
            &get_address_impl::<true>(),
            comm,
        )?,
        Ins::GetPubkey => run_parser_apdu::<_, Bip32Key>(
            parser,
            get_get_address_state::<false>,
            &get_address_impl::<false>(),
            comm,
        )?,
        Ins::Sign => {
            run_parser_apdu::<_, SignParameters>(parser, get_sign_state, &SIGN_IMPL, comm)?
        }
        Ins::TestParsers => {
            #[cfg(not(any(target_os = "stax", target_os = "flex")))]
            run_parser_apdu::<_, TestParsersSchema>(
                parser,
                get_test_parsers_state,
                &test_parsers_parser(),
                comm,
            )?;
        }
        Ins::GetVersionStr => {
            comm.append(concat!("Alamgu Example ", env!("CARGO_PKG_VERSION")).as_ref());
        }
        Ins::Exit => ledger_device_sdk::exit_app(0),
    }
    Ok(())
}

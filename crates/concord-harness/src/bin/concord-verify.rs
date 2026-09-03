use std::{env, error::Error, fs, io::Write, process::ExitCode};

use concord_harness::{replay_epact_events, verify_epact_program_image};
use concord_protocol::{canonical_epact_json_bytes, EpactProgramImage, EpactRuntimeEvent};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("concord-verify: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or(USAGE)?;
    let image_path = args.next().ok_or(USAGE)?;
    let image: EpactProgramImage = serde_json::from_slice(&fs::read(image_path)?)?;
    match command.as_str() {
        "verify-image" if args.next().is_none() => {
            verify_epact_program_image(&image)?;
            println!("{}", image.image_sha256);
        }
        "replay" => {
            let event_path = args.next().ok_or(USAGE)?;
            if args.next().is_some() {
                return Err(USAGE.into());
            }
            let events: Vec<EpactRuntimeEvent> = serde_json::from_slice(&fs::read(event_path)?)?;
            let state = replay_epact_events(&image, &events)?;
            std::io::stdout().write_all(&canonical_epact_json_bytes(&state)?)?;
            println!();
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

const USAGE: &str =
    "usage: concord-verify verify-image <image-path> | replay <image-path> <events-path>";

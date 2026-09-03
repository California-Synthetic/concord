use std::{env, error::Error, fs, io::Write, process::ExitCode};

use concord_protocol::{canonical_epact_json_bytes, EpactProgram, EpactProgramImage};
use epact_compiler::{compile_program, verify_program_image};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("epactc: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or(USAGE)?;
    let path = args.next().ok_or(USAGE)?;
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    let bytes = fs::read(path)?;
    match command.as_str() {
        "compile" => {
            let program: EpactProgram = serde_json::from_slice(&bytes)?;
            let image = compile_program(program)?;
            std::io::stdout().write_all(&canonical_epact_json_bytes(&image)?)?;
            println!();
        }
        "verify-image" => {
            let image: EpactProgramImage = serde_json::from_slice(&bytes)?;
            verify_program_image(&image)?;
            println!("{}", image.image_sha256);
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

const USAGE: &str = "usage: epactc <compile|verify-image> <json-path>";

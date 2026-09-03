use std::{env, error::Error, fs, io::Write, process::ExitCode};

use concord_kernel::{CreateBudgetRequest, CreateCampaignRequest, ReferenceKernel};
use concord_protocol::{
    AuthorizeCampaignDispatchRequest, DispatchOperation, DispatchPermitStatus,
    EpactDispatchBinding, ResolveInterruptedDispatchRequest,
};
use epact_compiler::compile_program;
use epact_protocol::{
    canonical_epact_json_bytes, EffectClass, EpactProgram, EpactProgramImage,
    EpactResourceEnvelope, EpactRuntimeEvent, EpactRuntimeEventKind, KernelOperation,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("concord: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("demo") => {
            let database = next(&mut arguments)?;
            end(&mut arguments)?;
            write_json(&run_demo(&database)?)?;
        }
        Some("compile") => {
            let program_path = next(&mut arguments)?;
            end(&mut arguments)?;
            let program: EpactProgram = read_json(&program_path)?;
            write_json(&compile_program(program)?)?;
        }
        Some("init") => {
            let database = next(&mut arguments)?;
            end(&mut arguments)?;
            let kernel = ReferenceKernel::open(&database)?;
            println!("{}", kernel.path().display());
        }
        Some("campaign-create") => {
            let database = next(&mut arguments)?;
            let id = next(&mut arguments)?;
            let name = next(&mut arguments)?;
            let objective = next(&mut arguments)?;
            let image_path = next(&mut arguments)?;
            end(&mut arguments)?;
            let kernel = ReferenceKernel::open(database)?;
            let image: EpactProgramImage = read_json(&image_path)?;
            write_json(&kernel.create_campaign(&CreateCampaignRequest {
                id,
                name,
                objective,
                image,
            })?)?;
        }
        Some("budget-create") => {
            let database = next(&mut arguments)?;
            let campaign_id = next(&mut arguments)?;
            let budget_id = next(&mut arguments)?;
            let total_usd: f64 = next(&mut arguments)?.parse()?;
            end(&mut arguments)?;
            let kernel = ReferenceKernel::open(database)?;
            write_json(&kernel.create_budget(
                &campaign_id,
                &CreateBudgetRequest {
                    id: budget_id,
                    total_usd,
                },
            )?)?;
        }
        Some("event-accept") => {
            let database = next(&mut arguments)?;
            let campaign_id = next(&mut arguments)?;
            let event_path = next(&mut arguments)?;
            end(&mut arguments)?;
            let kernel = ReferenceKernel::open(database)?;
            let event: EpactRuntimeEvent = read_json(&event_path)?;
            write_json(&kernel.accept_epact_event(&campaign_id, &event)?)?;
        }
        Some("dispatch-authorize") => {
            let database = next(&mut arguments)?;
            let campaign_id = next(&mut arguments)?;
            let request_path = next(&mut arguments)?;
            end(&mut arguments)?;
            let kernel = ReferenceKernel::open(database)?;
            let request: AuthorizeCampaignDispatchRequest = read_json(&request_path)?;
            write_json(&kernel.authorize_campaign_dispatch(&campaign_id, &request)?)?;
        }
        Some("dispatch-consume") => {
            let kernel = ReferenceKernel::open(next(&mut arguments)?)?;
            let token = next(&mut arguments)?;
            end(&mut arguments)?;
            write_json(&kernel.consume_campaign_dispatch(&token)?)?;
        }
        Some("dispatch-settle") => {
            let kernel = ReferenceKernel::open(next(&mut arguments)?)?;
            let token = next(&mut arguments)?;
            let actual_cost_usd: f64 = next(&mut arguments)?.parse()?;
            let basis = next(&mut arguments)?;
            end(&mut arguments)?;
            write_json(&kernel.settle_campaign_dispatch(&token, actual_cost_usd, &basis)?)?;
        }
        Some("dispatch-interrupt") => {
            let kernel = ReferenceKernel::open(next(&mut arguments)?)?;
            let token = next(&mut arguments)?;
            let reason = next(&mut arguments)?;
            end(&mut arguments)?;
            write_json(&kernel.interrupt_campaign_dispatch(&token, &reason)?)?;
        }
        Some("dispatch-release") => {
            let kernel = ReferenceKernel::open(next(&mut arguments)?)?;
            let token = next(&mut arguments)?;
            end(&mut arguments)?;
            write_json(&kernel.release_campaign_dispatch(&token)?)?;
        }
        Some("dispatch-resolve") => {
            let kernel = ReferenceKernel::open(next(&mut arguments)?)?;
            let campaign_id = next(&mut arguments)?;
            let token = next(&mut arguments)?;
            let request_path = next(&mut arguments)?;
            end(&mut arguments)?;
            let request: ResolveInterruptedDispatchRequest = read_json(&request_path)?;
            write_json(&kernel.resolve_interrupted_dispatch(&campaign_id, &token, &request)?)?;
        }
        Some("snapshot") => {
            let kernel = ReferenceKernel::open(next(&mut arguments)?)?;
            let campaign_id = next(&mut arguments)?;
            end(&mut arguments)?;
            write_json(&kernel.snapshot(&campaign_id)?)?;
        }
        Some("verify") => {
            let kernel = ReferenceKernel::open(next(&mut arguments)?)?;
            let campaign_id = next(&mut arguments)?;
            end(&mut arguments)?;
            write_json(&kernel.verify_campaign(&campaign_id)?)?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn next(arguments: &mut impl Iterator<Item = String>) -> Result<String, Box<dyn Error>> {
    arguments.next().ok_or_else(|| USAGE.into())
}

fn end(arguments: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    if arguments.next().is_some() {
        return Err(USAGE.into());
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json(value: &impl serde::Serialize) -> Result<(), Box<dyn Error>> {
    std::io::stdout().write_all(&canonical_epact_json_bytes(value)?)?;
    println!();
    Ok(())
}

fn run_demo(database: &str) -> Result<concord_kernel::VerificationReport, Box<dyn Error>> {
    let kernel = ReferenceKernel::open(database)?;
    let program: EpactProgram =
        serde_json::from_str(include_str!("../../../../examples/quickstart/program.json"))?;
    let image = compile_program(program)?;
    kernel.create_campaign(&CreateCampaignRequest {
        id: "campaign:quickstart".to_owned(),
        name: "Quickstart".to_owned(),
        objective: "Exercise the public Concord authority path.".to_owned(),
        image: image.clone(),
    })?;
    kernel.create_budget(
        "campaign:quickstart",
        &CreateBudgetRequest {
            id: "budget:local".to_owned(),
            total_usd: 1.0,
        },
    )?;
    let request = AuthorizeCampaignDispatchRequest {
        generation: 1,
        idempotency_key: "quickstart:dispatch".to_owned(),
        actor: "operator".to_owned(),
        operation: DispatchOperation::ExecutionRun,
        target_id: "local-analysis".to_owned(),
        budget_id: Some("budget:local".to_owned()),
        maximum_cost_usd: 0.1,
        reserve_budget: true,
        budget_pre_reserved: false,
        maximum_elapsed_seconds: 30,
        epact: Some(EpactDispatchBinding {
            program_image_sha256: image.image_sha256.clone(),
            obligation_id: "run-analysis".to_owned(),
            operation: KernelOperation::Dispatch,
            capability_id: Some("local-analysis".to_owned()),
            effects: vec![EffectClass::LocalWrite],
            resources: EpactResourceEnvelope {
                maximum_cost_usd: 0.1,
                maximum_elapsed_seconds: 30,
                maximum_tool_calls: 1,
                maximum_cpu_cores: 1.0,
                maximum_ram_gb: 1.0,
                maximum_storage_gb: 1.0,
                ..EpactResourceEnvelope::default()
            },
            placement: None,
        }),
    };
    let mut permit = kernel.authorize_campaign_dispatch("campaign:quickstart", &request)?;
    if permit.status == DispatchPermitStatus::Authorized {
        permit = kernel.consume_campaign_dispatch(&permit.token)?;
    }
    if permit.status == DispatchPermitStatus::Consumed {
        kernel.settle_campaign_dispatch(&permit.token, 0.0, "deterministic local fixture")?;
    }
    let event_time = "2026-09-03T12:00:00Z".to_owned();
    let object_event = EpactRuntimeEvent::build(
        "event:quickstart-result".to_owned(),
        image.image_sha256.clone(),
        0,
        "operator".to_owned(),
        "quickstart:result".to_owned(),
        EpactRuntimeEventKind::ObjectRecorded {
            object_id: "result".to_owned(),
        },
        Some("1".repeat(64)),
        None,
        event_time.clone(),
    )?;
    kernel.accept_epact_event("campaign:quickstart", &object_event)?;
    let completion_event = EpactRuntimeEvent::build(
        "event:quickstart-complete".to_owned(),
        image.image_sha256.clone(),
        1,
        "operator".to_owned(),
        "quickstart:complete".to_owned(),
        EpactRuntimeEventKind::ObligationSatisfied {
            obligation_id: "run-analysis".to_owned(),
            receipt_contract: "example.analysis-receipt/1".to_owned(),
        },
        Some("2".repeat(64)),
        Some(object_event.event_sha256),
        event_time,
    )?;
    kernel.accept_epact_event("campaign:quickstart", &completion_event)?;
    Ok(kernel.verify_campaign("campaign:quickstart")?)
}

const USAGE: &str = "usage:\n  concord demo <state.db>\n  concord compile <program.json>\n  concord init <state.db>\n  concord campaign-create <state.db> <campaign-id> <name> <objective> <image.json>\n  concord budget-create <state.db> <campaign-id> <budget-id> <total-usd>\n  concord event-accept <state.db> <campaign-id> <event.json>\n  concord dispatch-authorize <state.db> <campaign-id> <request.json>\n  concord dispatch-consume <state.db> <token>\n  concord dispatch-settle <state.db> <token> <actual-cost-usd> <basis>\n  concord dispatch-interrupt <state.db> <token> <reason>\n  concord dispatch-release <state.db> <token>\n  concord dispatch-resolve <state.db> <campaign-id> <token> <request.json>\n  concord snapshot <state.db> <campaign-id>\n  concord verify <state.db> <campaign-id>";

use std::fs;

use concord_protocol::{
    AuthorizeCampaignDispatchRequest, DispatchOperation, DispatchPermitStatus,
    EpactDispatchBinding, InterruptedDispatchResolution, ResolveInterruptedDispatchRequest,
};
use epact_compiler::compile_program;
use epact_protocol::{
    EffectClass, EpactAmendmentPolicy, EpactAuthorityGrant, EpactAuthorityScope,
    EpactCapabilityRequirement, EpactDischarge, EpactObjectDeclaration, EpactObligation,
    EpactPrincipal, EpactProgram, EpactResourceEnvelope, EpactRuntimeEvent, EpactRuntimeEventKind,
    EpactTerminalRule, KernelOperation, PrincipalKind, ProgramLifecycle, ReversibilityClass,
    ReversibilityPolicy, EPACT_PROGRAM_CONTRACT,
};
use rusqlite::Connection;
use tempfile::TempDir;

use super::*;

fn resources(cost: f64) -> EpactResourceEnvelope {
    EpactResourceEnvelope {
        maximum_cost_usd: cost,
        maximum_elapsed_seconds: 60,
        maximum_model_calls: 0,
        maximum_tool_calls: 1,
        maximum_external_jobs: 0,
        maximum_cpu_cores: 1.0,
        maximum_ram_gb: 1.0,
        maximum_gpu_count: 0,
        maximum_vram_gb: 0.0,
        maximum_storage_gb: 1.0,
        maximum_data_movement_gb: 0.0,
    }
}

fn image() -> EpactProgramImage {
    compile_program(EpactProgram {
        contract: EPACT_PROGRAM_CONTRACT.to_owned(),
        id: "program:quickstart".to_owned(),
        version: "1".to_owned(),
        title: "Quickstart analysis".to_owned(),
        lifecycle: ProgramLifecycle::Frozen,
        created_by: "operator".to_owned(),
        predecessor: None,
        imports: Vec::new(),
        principals: vec![EpactPrincipal {
            id: "operator".to_owned(),
            kind: PrincipalKind::Human,
            display_name: "Operator".to_owned(),
        }],
        objects: vec![EpactObjectDeclaration {
            id: "result".to_owned(),
            type_name: "example.analysis-result/1".to_owned(),
            schema_sha256: None,
            data_classes: Vec::new(),
        }],
        capabilities: vec![EpactCapabilityRequirement {
            id: "local-analysis".to_owned(),
            capability_type: "example.local-analysis/1".to_owned(),
            contract: "example.local-analysis/1".to_owned(),
            required_effects: vec![EffectClass::LocalWrite],
            required_data_classes: Vec::new(),
            placement: None,
        }],
        authorities: vec![EpactAuthorityGrant {
            id: "operator-dispatch".to_owned(),
            principal_id: "operator".to_owned(),
            operations: vec![
                KernelOperation::Freeze,
                KernelOperation::Authorize,
                KernelOperation::Propose,
                KernelOperation::Reserve,
                KernelOperation::Dispatch,
                KernelOperation::Amend,
            ],
            scope: EpactAuthorityScope {
                whole_program: true,
                obligation_ids: Vec::new(),
                capability_ids: Vec::new(),
            },
            maximum_cost_usd: 1.0,
            valid_after: None,
            valid_before: None,
        }],
        resources: resources(1.0),
        obligations: vec![EpactObligation {
            id: "run-analysis".to_owned(),
            label: "Run the analysis".to_owned(),
            description: "Produce one locally recorded result.".to_owned(),
            dependency_ids: Vec::new(),
            gate_ids: Vec::new(),
            discharge: EpactDischarge::Capability {
                capability_id: "local-analysis".to_owned(),
            },
            output_object_ids: vec!["result".to_owned()],
            effects: vec![EffectClass::LocalWrite],
            resources: resources(1.0),
            reversibility: ReversibilityPolicy {
                class: ReversibilityClass::CheckpointRestore,
                reversal_action: Some("Restore the campaign checkpoint.".to_owned()),
                limitations: Vec::new(),
            },
            retry_limit: 1,
            terminal_receipt_contract: "example.analysis-receipt/1".to_owned(),
        }],
        gates: Vec::new(),
        evidence_rules: Vec::new(),
        amendment_policy: EpactAmendmentPolicy {
            authorized_principal_ids: vec!["operator".to_owned()],
            rationale_required: true,
            effective_causal_head_required: true,
            preserve_prior_interpretation: true,
        },
        terminal: EpactTerminalRule {
            required_obligation_ids: vec!["run-analysis".to_owned()],
            required_object_ids: vec!["result".to_owned()],
            required_receipt_contracts: vec!["example.analysis-receipt/1".to_owned()],
        },
    })
    .expect("valid test program")
}

struct Fixture {
    _directory: TempDir,
    kernel: ReferenceKernel,
    image: EpactProgramImage,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let kernel = ReferenceKernel::open(directory.path().join("concord.db")).unwrap();
        let image = image();
        kernel
            .create_campaign(&CreateCampaignRequest {
                id: "campaign:test".to_owned(),
                name: "Test campaign".to_owned(),
                objective: "Exercise the public authority path.".to_owned(),
                image: image.clone(),
            })
            .unwrap();
        kernel
            .create_budget(
                "campaign:test",
                &CreateBudgetRequest {
                    id: "budget:local".to_owned(),
                    total_usd: 2.0,
                },
            )
            .unwrap();
        Self {
            _directory: directory,
            kernel,
            image,
        }
    }

    fn dispatch_request(&self, key: &str) -> AuthorizeCampaignDispatchRequest {
        AuthorizeCampaignDispatchRequest {
            generation: 1,
            idempotency_key: key.to_owned(),
            actor: "operator".to_owned(),
            operation: DispatchOperation::ExecutionRun,
            target_id: "local-analysis".to_owned(),
            budget_id: Some("budget:local".to_owned()),
            maximum_cost_usd: 0.25,
            reserve_budget: true,
            budget_pre_reserved: false,
            maximum_elapsed_seconds: 30,
            epact: Some(EpactDispatchBinding {
                program_image_sha256: self.image.image_sha256.clone(),
                obligation_id: "run-analysis".to_owned(),
                operation: KernelOperation::Dispatch,
                capability_id: Some("local-analysis".to_owned()),
                effects: vec![EffectClass::LocalWrite],
                resources: EpactResourceEnvelope {
                    maximum_cost_usd: 0.25,
                    maximum_elapsed_seconds: 30,
                    maximum_tool_calls: 1,
                    maximum_cpu_cores: 1.0,
                    maximum_ram_gb: 1.0,
                    maximum_storage_gb: 1.0,
                    ..EpactResourceEnvelope::default()
                },
                placement: None,
            }),
        }
    }
}

#[test]
fn durable_kernel_runs_and_replays_a_complete_local_campaign() {
    let fixture = Fixture::new();
    let request = fixture.dispatch_request("dispatch:one");
    let first = fixture
        .kernel
        .authorize_campaign_dispatch("campaign:test", &request)
        .unwrap();
    let retry = fixture
        .kernel
        .authorize_campaign_dispatch("campaign:test", &request)
        .unwrap();
    assert_eq!(first.token, retry.token);

    let consumed = fixture
        .kernel
        .consume_campaign_dispatch(&first.token)
        .unwrap();
    assert_eq!(consumed.status, DispatchPermitStatus::Consumed);
    let settled = fixture
        .kernel
        .settle_campaign_dispatch(&first.token, 0.2, "local worker receipt")
        .unwrap();
    assert_eq!(settled.status, DispatchPermitStatus::Settled);

    let created_at = "2026-09-03T12:00:00Z".to_owned();
    let object_event = EpactRuntimeEvent::build(
        "event:result".to_owned(),
        fixture.image.image_sha256.clone(),
        0,
        "operator".to_owned(),
        "record:result".to_owned(),
        EpactRuntimeEventKind::ObjectRecorded {
            object_id: "result".to_owned(),
        },
        Some("1".repeat(64)),
        None,
        created_at.clone(),
    )
    .unwrap();
    fixture
        .kernel
        .accept_epact_event("campaign:test", &object_event)
        .unwrap();
    let completion_event = EpactRuntimeEvent::build(
        "event:complete".to_owned(),
        fixture.image.image_sha256.clone(),
        1,
        "operator".to_owned(),
        "complete:result".to_owned(),
        EpactRuntimeEventKind::ObligationSatisfied {
            obligation_id: "run-analysis".to_owned(),
            receipt_contract: "example.analysis-receipt/1".to_owned(),
        },
        Some("2".repeat(64)),
        Some(object_event.event_sha256),
        created_at,
    )
    .unwrap();
    fixture
        .kernel
        .accept_epact_event("campaign:test", &completion_event)
        .unwrap();

    let reopened = ReferenceKernel::open(fixture.kernel.path()).unwrap();
    let report = reopened.verify_campaign("campaign:test").unwrap();
    assert!(report.terminal);
    assert_eq!(report.epact_event_count, 2);
    assert_eq!(report.dispatch_permit_count, 1);
    let snapshot = reopened.snapshot("campaign:test").unwrap();
    assert!((snapshot.budgets[0].spent_usd - 0.2).abs() < 1e-9);
    assert!((snapshot.budgets[0].exposure_usd).abs() < 1e-9);
}

#[test]
fn dispatch_fails_closed_without_epact_or_available_budget() {
    let fixture = Fixture::new();
    let mut request = fixture.dispatch_request("missing-binding");
    request.epact = None;
    assert!(matches!(
        fixture
            .kernel
            .authorize_campaign_dispatch("campaign:test", &request),
        Err(KernelError::AuthorityDenied(_))
    ));

    let mut request = fixture.dispatch_request("over-budget");
    request.maximum_cost_usd = 3.0;
    request.epact.as_mut().unwrap().resources.maximum_cost_usd = 3.0;
    assert!(matches!(
        fixture
            .kernel
            .authorize_campaign_dispatch("campaign:test", &request),
        Err(KernelError::AuthorityDenied(_))
    ));
}

#[test]
fn interrupted_dispatch_blocks_new_authority_until_reconciled() {
    let fixture = Fixture::new();
    let permit = fixture
        .kernel
        .authorize_campaign_dispatch("campaign:test", &fixture.dispatch_request("first"))
        .unwrap();
    fixture
        .kernel
        .consume_campaign_dispatch(&permit.token)
        .unwrap();
    fixture
        .kernel
        .interrupt_campaign_dispatch(&permit.token, "worker connection lost after start")
        .unwrap();
    assert!(matches!(
        fixture
            .kernel
            .authorize_campaign_dispatch("campaign:test", &fixture.dispatch_request("blocked")),
        Err(KernelError::AuthorityDenied(_))
    ));

    let resolved = fixture
        .kernel
        .resolve_interrupted_dispatch(
            "campaign:test",
            &permit.token,
            &ResolveInterruptedDispatchRequest {
                actor: "operator".to_owned(),
                resolution: InterruptedDispatchResolution::NoProviderStart,
                evidence_sha256: "a".repeat(64),
                actual_cost_usd: None,
                settlement_basis: None,
            },
        )
        .unwrap();
    assert_eq!(resolved.status, DispatchPermitStatus::Released);
    assert_eq!(
        fixture.kernel.campaign("campaign:test").unwrap().status,
        CampaignStatus::Open
    );
}

#[test]
fn verification_detects_a_tampered_kernel_chain() {
    let fixture = Fixture::new();
    let connection = Connection::open(fixture.kernel.path()).unwrap();
    let raw: String = connection
        .query_row(
            "SELECT event_json FROM kernel_events WHERE campaign_id='campaign:test' AND sequence=0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mutated = raw.replace("campaign_created", "budget_created");
    connection
        .execute(
            "UPDATE kernel_events SET event_json=?1 WHERE campaign_id='campaign:test' AND sequence=0",
            [mutated],
        )
        .unwrap();
    assert!(matches!(
        fixture.kernel.verify_campaign("campaign:test"),
        Err(KernelError::Integrity(_))
    ));
}

#[test]
fn database_is_not_created_in_the_source_tree() {
    let fixture = Fixture::new();
    assert!(fixture.kernel.path().exists());
    assert!(!fs::metadata("concord.db").is_ok());
}

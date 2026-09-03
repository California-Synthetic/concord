use concord_harness::{
    compile_epact_program, epact_program_is_terminal, evaluate_epact_operation,
    initial_epact_state, replay_epact_events, EpactRuntimeError,
};
use concord_protocol::{
    EffectClass, EpactAmendmentPolicy, EpactAuthorityGrant, EpactAuthorityScope,
    EpactCapabilityRequirement, EpactDischarge, EpactObjectDeclaration, EpactObligation,
    EpactPrincipal, EpactProgram, EpactResourceEnvelope, EpactRuntimeEvent, EpactRuntimeEventKind,
    EpactTerminalRule, KernelOperation, PrincipalKind, ProgramLifecycle, ReversibilityClass,
    ReversibilityPolicy, EPACT_PROGRAM_CONTRACT,
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn eligibility_is_fail_closed_across_authority_effect_and_resource_boundaries() {
    let image = compile_epact_program(program()).unwrap();
    let state = initial_epact_state(&image).unwrap();
    let allowed = evaluate_epact_operation(
        &image,
        &state,
        &request(
            "principal:agent",
            KernelOperation::Dispatch,
            "analyze",
            Some("capability:analyze"),
            vec![EffectClass::ReadOnly],
            EpactResourceEnvelope {
                maximum_cpu_cores: 1.0,
                maximum_ram_gb: 2.0,
                maximum_tool_calls: 1,
                ..EpactResourceEnvelope::default()
            },
        ),
    )
    .unwrap();
    assert!(allowed.allowed);

    let denied = evaluate_epact_operation(
        &image,
        &state,
        &request(
            "principal:agent",
            KernelOperation::Dispatch,
            "analyze",
            Some("capability:analyze"),
            vec![EffectClass::ExternalWrite],
            EpactResourceEnvelope {
                maximum_cost_usd: 2.0,
                maximum_cpu_cores: 8.0,
                ..EpactResourceEnvelope::default()
            },
        ),
    )
    .unwrap();
    let codes = denied
        .blockers
        .iter()
        .map(|blocker| blocker.code.as_str())
        .collect::<Vec<_>>();
    assert!(!denied.allowed);
    assert!(codes.contains(&"authority_denied"));
    assert!(codes.contains(&"effect_mismatch"));
    assert!(codes.contains(&"obligation_resource_ceiling"));
    assert!(codes.contains(&"program_resource_ceiling"));
}

#[test]
fn replay_reconstructs_the_same_terminal_projection_after_restart() {
    let image = compile_epact_program(program()).unwrap();
    let mut events = Vec::new();
    push_event(
        &image.image_sha256,
        &mut events,
        EpactRuntimeEventKind::ObjectRecorded {
            object_id: "object:result".to_owned(),
        },
        Some(DIGEST),
    );
    push_event(
        &image.image_sha256,
        &mut events,
        EpactRuntimeEventKind::ObligationSatisfied {
            obligation_id: "analyze".to_owned(),
            receipt_contract: "example.analysis-receipt/1".to_owned(),
        },
        Some(DIGEST),
    );
    push_event(
        &image.image_sha256,
        &mut events,
        EpactRuntimeEventKind::ObjectRecorded {
            object_id: "object:publication".to_owned(),
        },
        Some(DIGEST),
    );
    push_event(
        &image.image_sha256,
        &mut events,
        EpactRuntimeEventKind::ObligationSatisfied {
            obligation_id: "publish".to_owned(),
            receipt_contract: "example.publication-receipt/1".to_owned(),
        },
        Some(DIGEST),
    );

    let first = replay_epact_events(&image, &events).unwrap();
    let restarted = replay_epact_events(&image, &events).unwrap();
    assert_eq!(first, restarted);
    assert!(epact_program_is_terminal(&image, &restarted, &events).unwrap());
}

#[test]
fn replay_rejects_out_of_order_discharge_and_tampered_chain() {
    let image = compile_epact_program(program()).unwrap();
    let mut premature = Vec::new();
    push_event(
        &image.image_sha256,
        &mut premature,
        EpactRuntimeEventKind::ObjectRecorded {
            object_id: "object:publication".to_owned(),
        },
        Some(DIGEST),
    );
    push_event(
        &image.image_sha256,
        &mut premature,
        EpactRuntimeEventKind::ObligationSatisfied {
            obligation_id: "publish".to_owned(),
            receipt_contract: "example.publication-receipt/1".to_owned(),
        },
        Some(DIGEST),
    );
    assert!(matches!(
        replay_epact_events(&image, &premature),
        Err(EpactRuntimeError::UnsatisfiedDependency { .. })
    ));

    let mut broken = vec![EpactRuntimeEvent::build(
        "event:0".to_owned(),
        image.image_sha256.clone(),
        1,
        "principal:operator".to_owned(),
        "idempotency:0".to_owned(),
        EpactRuntimeEventKind::ObjectRecorded {
            object_id: "object:result".to_owned(),
        },
        Some(DIGEST.to_owned()),
        None,
        "2026-09-03T00:00:00Z".to_owned(),
    )
    .unwrap()];
    assert!(matches!(
        replay_epact_events(&image, &broken),
        Err(EpactRuntimeError::UnexpectedSequence {
            expected: 0,
            actual: 1
        })
    ));
    broken[0].sequence = 0;
    assert!(matches!(
        replay_epact_events(&image, &broken),
        Err(EpactRuntimeError::InvalidEvent(_))
    ));
}

#[test]
fn downstream_operation_is_ineligible_until_dependency_is_satisfied() {
    let image = compile_epact_program(program()).unwrap();
    let state = initial_epact_state(&image).unwrap();
    let eligibility = evaluate_epact_operation(
        &image,
        &state,
        &request(
            "principal:operator",
            KernelOperation::Publish,
            "publish",
            None,
            vec![EffectClass::ExternalWrite],
            EpactResourceEnvelope {
                maximum_cost_usd: 1.0,
                maximum_external_jobs: 1,
                ..EpactResourceEnvelope::default()
            },
        ),
    )
    .unwrap();
    assert!(!eligibility.allowed);
    assert!(eligibility
        .blockers
        .iter()
        .any(|blocker| blocker.code == "dependency_unsatisfied"));
}

#[test]
fn authority_is_ineligible_outside_its_compiled_time_window() {
    let mut source = program();
    let agent = source
        .authorities
        .iter_mut()
        .find(|grant| grant.principal_id == "principal:agent")
        .unwrap();
    agent.valid_after = Some("2026-09-04T00:00:00Z".to_owned());
    agent.valid_before = Some("2026-09-05T00:00:00Z".to_owned());
    let image = compile_epact_program(source).unwrap();
    let state = initial_epact_state(&image).unwrap();
    let eligibility = evaluate_epact_operation(
        &image,
        &state,
        &request(
            "principal:agent",
            KernelOperation::Dispatch,
            "analyze",
            Some("capability:analyze"),
            vec![EffectClass::ReadOnly],
            EpactResourceEnvelope {
                maximum_cpu_cores: 1.0,
                maximum_ram_gb: 2.0,
                maximum_tool_calls: 1,
                ..EpactResourceEnvelope::default()
            },
        ),
    )
    .unwrap();
    assert!(!eligibility.allowed);
    assert!(eligibility
        .blockers
        .iter()
        .any(|blocker| blocker.code == "authority_denied"));
}

fn push_event(
    image_sha256: &str,
    events: &mut Vec<EpactRuntimeEvent>,
    kind: EpactRuntimeEventKind,
    receipt_sha256: Option<&str>,
) {
    let sequence = events.len() as u64;
    let previous = events.last().map(|event| event.event_sha256.clone());
    events.push(
        EpactRuntimeEvent::build(
            format!("event:{sequence}"),
            image_sha256.to_owned(),
            sequence,
            "principal:operator".to_owned(),
            format!("idempotency:{sequence}"),
            kind,
            receipt_sha256.map(str::to_owned),
            previous,
            format!("2026-09-03T00:00:0{sequence}Z"),
        )
        .unwrap(),
    );
}

fn request(
    principal_id: &str,
    operation: KernelOperation,
    obligation_id: &str,
    capability_id: Option<&str>,
    effects: Vec<EffectClass>,
    resources: EpactResourceEnvelope,
) -> concord_protocol::EpactOperationRequest {
    concord_protocol::EpactOperationRequest {
        principal_id: principal_id.to_owned(),
        operation,
        requested_at: "2026-09-03T00:00:00Z".to_owned(),
        obligation_id: Some(obligation_id.to_owned()),
        capability_id: capability_id.map(str::to_owned),
        effects,
        resources,
    }
}

fn program() -> EpactProgram {
    EpactProgram {
        contract: EPACT_PROGRAM_CONTRACT.to_owned(),
        id: "program:runtime-fixture".to_owned(),
        version: "1".to_owned(),
        title: "Runtime conformance fixture".to_owned(),
        lifecycle: ProgramLifecycle::Frozen,
        created_by: "principal:operator".to_owned(),
        predecessor: None,
        imports: vec![],
        principals: vec![
            EpactPrincipal {
                id: "principal:operator".to_owned(),
                kind: PrincipalKind::Human,
                display_name: "Operator".to_owned(),
            },
            EpactPrincipal {
                id: "principal:agent".to_owned(),
                kind: PrincipalKind::Agent,
                display_name: "Workbench agent".to_owned(),
            },
        ],
        objects: vec![
            object("object:result", "example.result/1"),
            object("object:publication", "example.publication/1"),
        ],
        capabilities: vec![EpactCapabilityRequirement {
            id: "capability:analyze".to_owned(),
            capability_type: "deterministic_analysis".to_owned(),
            contract: "example.analysis/1".to_owned(),
            required_effects: vec![EffectClass::ReadOnly],
            required_data_classes: vec![],
        }],
        authorities: vec![
            authority(
                "principal:agent",
                vec![
                    KernelOperation::Propose,
                    KernelOperation::Reserve,
                    KernelOperation::Dispatch,
                ],
                &["analyze"],
                0.0,
                false,
            ),
            authority(
                "principal:operator",
                vec![KernelOperation::Authorize],
                &["analyze"],
                0.0,
                false,
            ),
            authority(
                "principal:operator",
                vec![
                    KernelOperation::Propose,
                    KernelOperation::Authorize,
                    KernelOperation::Reserve,
                    KernelOperation::Publish,
                ],
                &["publish"],
                2.0,
                false,
            ),
            authority(
                "principal:operator",
                vec![KernelOperation::Amend],
                &[],
                0.0,
                true,
            ),
        ],
        resources: EpactResourceEnvelope {
            maximum_cost_usd: 2.0,
            maximum_elapsed_seconds: 300,
            maximum_tool_calls: 2,
            maximum_external_jobs: 1,
            maximum_cpu_cores: 4.0,
            maximum_ram_gb: 8.0,
            ..EpactResourceEnvelope::default()
        },
        obligations: vec![
            EpactObligation {
                id: "analyze".to_owned(),
                label: "Analyze".to_owned(),
                description: "Produce the bounded analysis result.".to_owned(),
                dependency_ids: vec![],
                gate_ids: vec![],
                discharge: EpactDischarge::Capability {
                    capability_id: "capability:analyze".to_owned(),
                },
                output_object_ids: vec!["object:result".to_owned()],
                effects: vec![EffectClass::ReadOnly],
                resources: EpactResourceEnvelope {
                    maximum_elapsed_seconds: 120,
                    maximum_tool_calls: 1,
                    maximum_cpu_cores: 2.0,
                    maximum_ram_gb: 4.0,
                    ..EpactResourceEnvelope::default()
                },
                reversibility: ReversibilityPolicy {
                    class: ReversibilityClass::ReadOnly,
                    reversal_action: None,
                    limitations: vec![],
                },
                retry_limit: 1,
                terminal_receipt_contract: "example.analysis-receipt/1".to_owned(),
            },
            EpactObligation {
                id: "publish".to_owned(),
                label: "Publish".to_owned(),
                description: "Publish the reviewed analysis.".to_owned(),
                dependency_ids: vec!["analyze".to_owned()],
                gate_ids: vec![],
                discharge: EpactDischarge::Publication {
                    artifact_object_ids: vec!["object:publication".to_owned()],
                },
                output_object_ids: vec!["object:publication".to_owned()],
                effects: vec![EffectClass::ExternalWrite],
                resources: EpactResourceEnvelope {
                    maximum_cost_usd: 1.0,
                    maximum_external_jobs: 1,
                    ..EpactResourceEnvelope::default()
                },
                reversibility: ReversibilityPolicy {
                    class: ReversibilityClass::CompensatingAction,
                    reversal_action: Some("Publish a signed retraction.".to_owned()),
                    limitations: vec!["Copies may persist outside Concord.".to_owned()],
                },
                retry_limit: 0,
                terminal_receipt_contract: "example.publication-receipt/1".to_owned(),
            },
        ],
        gates: vec![],
        evidence_rules: vec![],
        amendment_policy: EpactAmendmentPolicy {
            authorized_principal_ids: vec!["principal:operator".to_owned()],
            rationale_required: true,
            effective_causal_head_required: true,
            preserve_prior_interpretation: true,
        },
        terminal: EpactTerminalRule {
            required_obligation_ids: vec!["analyze".to_owned(), "publish".to_owned()],
            required_object_ids: vec!["object:publication".to_owned()],
            required_receipt_contracts: vec![
                "example.analysis-receipt/1".to_owned(),
                "example.publication-receipt/1".to_owned(),
            ],
        },
    }
}

fn object(id: &str, type_name: &str) -> EpactObjectDeclaration {
    EpactObjectDeclaration {
        id: id.to_owned(),
        type_name: type_name.to_owned(),
        schema_sha256: None,
        data_classes: vec![],
    }
}

fn authority(
    principal_id: &str,
    operations: Vec<KernelOperation>,
    obligation_ids: &[&str],
    maximum_cost_usd: f64,
    whole_program: bool,
) -> EpactAuthorityGrant {
    EpactAuthorityGrant {
        id: format!("authority:{principal_id}:{}", obligation_ids.join("-")),
        principal_id: principal_id.to_owned(),
        operations,
        scope: EpactAuthorityScope {
            whole_program,
            obligation_ids: obligation_ids.iter().map(|id| (*id).to_owned()).collect(),
            capability_ids: vec![],
        },
        maximum_cost_usd,
        valid_after: None,
        valid_before: None,
    }
}

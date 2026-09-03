use concord_protocol::{
    EffectClass, EpactAmendmentPolicy, EpactAuthorityGrant, EpactAuthorityScope,
    EpactCapabilityRequirement, EpactDischarge, EpactEvidenceRule, EpactGate,
    EpactObjectDeclaration, EpactObligation, EpactPredicate, EpactPrincipal, EpactProgram,
    EpactProgramRef, EpactResourceEnvelope, EpactTerminalRule, KernelOperation, PrincipalKind,
    ProgramLifecycle, ReversibilityClass, ReversibilityPolicy, EPACT_PROGRAM_CONTRACT,
};
use epact_compiler::{
    compile_program, require_activatable, verify_amendment_record, verify_program_image,
    verify_program_successor, EpactCompileError,
};

#[test]
fn frozen_program_compiles_to_an_activatable_replayable_image() {
    let image = compile_program(program()).unwrap();
    assert!(image.activatable);
    assert!(image.activation_findings.is_empty());
    assert_eq!(image.obligation_order, ["analyze", "decide", "publish"]);
    assert_eq!(
        image.maximum_effects,
        [EffectClass::ReadOnly, EffectClass::ExternalWrite]
    );
    verify_program_image(&image).unwrap();
    require_activatable(&image).unwrap();
}

#[test]
fn irrelevant_order_and_duplicate_set_members_do_not_change_identity() {
    let expected = compile_program(program()).unwrap();
    let mut reordered = program();
    reordered.principals.reverse();
    reordered.objects.reverse();
    reordered.capabilities.reverse();
    reordered.authorities.reverse();
    reordered.obligations.reverse();
    reordered.gates.reverse();
    let duplicate_operation = reordered.authorities[0].operations[0];
    reordered.authorities[0]
        .operations
        .push(duplicate_operation);
    let duplicate_dependencies = reordered.obligations[0].dependency_ids.clone();
    reordered.obligations[0]
        .dependency_ids
        .extend(duplicate_dependencies);
    let actual = compile_program(reordered).unwrap();
    assert_eq!(actual.program_sha256, expected.program_sha256);
    assert_eq!(actual.image_sha256, expected.image_sha256);
    assert_eq!(actual, expected);
}

#[test]
fn structural_reference_cycle_and_resource_failures_are_compile_errors() {
    let mut missing = program();
    missing.obligations[0].output_object_ids = vec!["object:missing".to_owned()];
    assert!(matches!(
        compile_program(missing),
        Err(EpactCompileError::MissingReference { .. })
    ));

    let mut cyclic = program();
    cyclic.obligations[0].dependency_ids = vec!["publish".to_owned()];
    assert!(matches!(
        compile_program(cyclic),
        Err(EpactCompileError::DependencyCycle(_))
    ));

    let mut oversized = program();
    oversized.obligations[0].resources.maximum_cpu_cores = 8.0;
    assert!(matches!(
        compile_program(oversized),
        Err(EpactCompileError::ResourceCeilingExceeded(_))
    ));
}

#[test]
fn missing_authority_is_visible_without_manufacturing_activation() {
    let mut incomplete = program();
    incomplete.authorities.retain(|grant| {
        !grant.operations.contains(&KernelOperation::Publish)
            && !grant.operations.contains(&KernelOperation::Amend)
    });
    let image = compile_program(incomplete).unwrap();
    assert!(!image.activatable);
    assert!(image
        .activation_findings
        .iter()
        .any(|finding| finding.code == "missing_operation_authority"));
    assert!(image
        .activation_findings
        .iter()
        .any(|finding| finding.code == "missing_amend_authority"));
    assert!(matches!(
        require_activatable(&image),
        Err(EpactCompileError::ProgramNotActivatable)
    ));
}

#[test]
fn draft_compiles_for_review_but_cannot_activate() {
    let mut draft = program();
    draft.lifecycle = ProgramLifecycle::Draft;
    let image = compile_program(draft).unwrap();
    assert!(!image.activatable);
    assert!(image
        .activation_findings
        .iter()
        .any(|finding| finding.code == "program_not_frozen"));
}

#[test]
fn effect_and_reversibility_must_agree_before_compilation() {
    let mut disguised = program();
    let publish = disguised
        .obligations
        .iter_mut()
        .find(|obligation| obligation.id == "publish")
        .unwrap();
    publish.reversibility = ReversibilityPolicy {
        class: ReversibilityClass::ReadOnly,
        reversal_action: None,
        limitations: vec![],
    };
    assert!(matches!(
        compile_program(disguised),
        Err(EpactCompileError::InvalidReversibility { .. })
    ));
}

#[test]
fn authority_windows_are_canonical_and_well_ordered() {
    let mut malformed = program();
    malformed.authorities[0].valid_after = Some("next Tuesday".to_owned());
    assert!(matches!(
        compile_program(malformed),
        Err(EpactCompileError::InvalidAuthorityTimestamp(_))
    ));

    let mut reversed = program();
    reversed.authorities[0].valid_after = Some("2026-09-04T00:00:00Z".to_owned());
    reversed.authorities[0].valid_before = Some("2026-09-03T00:00:00Z".to_owned());
    assert!(matches!(
        compile_program(reversed),
        Err(EpactCompileError::InvalidAuthorityWindow(_))
    ));
}

#[test]
fn any_image_mutation_breaks_independent_verification() {
    let mut image = compile_program(program()).unwrap();
    image.program.title.push_str(" changed");
    assert!(matches!(
        verify_program_image(&image),
        Err(EpactCompileError::ImageHashMismatch)
    ));
}

#[test]
fn successor_is_prospective_and_bound_to_the_exact_prior_causal_head() {
    let predecessor = compile_program(program()).unwrap();
    let mut successor_program = program();
    successor_program.version = "2".to_owned();
    successor_program.title = "Bounded analysis and corrected publication".to_owned();
    successor_program.predecessor = Some(EpactProgramRef {
        id: predecessor.program.id.clone(),
        version: predecessor.program.version.clone(),
        program_sha256: predecessor.program_sha256.clone(),
    });
    let successor = compile_program(successor_program).unwrap();
    let event_head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let amendment = verify_program_successor(
        &predecessor,
        &successor,
        "principal:operator",
        "Correct the publication boundary without reinterpreting prior events.",
        event_head,
    )
    .unwrap();
    verify_amendment_record(&predecessor, &successor, &amendment).unwrap();
    assert_eq!(amendment.effective_event_head_sha256, event_head);
    assert_ne!(predecessor.image_sha256, successor.image_sha256);

    let mut tampered = amendment;
    tampered.rationale.push_str(" changed");
    assert!(matches!(
        verify_amendment_record(&predecessor, &successor, &tampered),
        Err(EpactCompileError::AmendmentRecordMismatch)
    ));
}

#[test]
fn successor_rejects_wrong_lineage_and_unapproved_amender() {
    let predecessor = compile_program(program()).unwrap();
    let mut successor_program = program();
    successor_program.version = "2".to_owned();
    successor_program.predecessor = Some(EpactProgramRef {
        id: predecessor.program.id.clone(),
        version: predecessor.program.version.clone(),
        program_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
    });
    let successor = compile_program(successor_program).unwrap();
    assert!(matches!(
        verify_program_successor(
            &predecessor,
            &successor,
            "principal:operator",
            "Attempt an incorrectly bound amendment.",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        Err(EpactCompileError::PredecessorMismatch)
    ));

    let mut correct_program = program();
    correct_program.version = "2".to_owned();
    correct_program.predecessor = Some(EpactProgramRef {
        id: predecessor.program.id.clone(),
        version: predecessor.program.version.clone(),
        program_sha256: predecessor.program_sha256.clone(),
    });
    let correct = compile_program(correct_program).unwrap();
    assert!(matches!(
        verify_program_successor(
            &predecessor,
            &correct,
            "principal:agent",
            "An agent cannot amend the frozen center.",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        Err(EpactCompileError::AmendmentAuthorityDenied(_))
    ));
}

fn program() -> EpactProgram {
    let program_resources = EpactResourceEnvelope {
        maximum_cost_usd: 10.0,
        maximum_elapsed_seconds: 600,
        maximum_model_calls: 2,
        maximum_tool_calls: 4,
        maximum_external_jobs: 1,
        maximum_cpu_cores: 4.0,
        maximum_ram_gb: 16.0,
        maximum_gpu_count: 0,
        maximum_vram_gb: 0.0,
        maximum_storage_gb: 2.0,
        maximum_data_movement_gb: 1.0,
    };
    EpactProgram {
        contract: EPACT_PROGRAM_CONTRACT.to_owned(),
        id: "program:alpha-fixture".to_owned(),
        version: "1".to_owned(),
        title: "Bounded analysis and publication".to_owned(),
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
            object("object:input", "example.input/1"),
            object("object:result", "example.result/1"),
            object("object:claim", "concord.claim/1"),
            object("object:evidence", "concord.observation/1"),
            object("object:decision", "concord.decision/1"),
            object("object:publication", "concord.publication/1"),
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
                "authority:agent-analyze",
                "principal:agent",
                vec![
                    KernelOperation::Propose,
                    KernelOperation::Reserve,
                    KernelOperation::Dispatch,
                ],
                &["analyze"],
                false,
            ),
            authority(
                "authority:operator-analyze",
                "principal:operator",
                vec![KernelOperation::Authorize],
                &["analyze"],
                false,
            ),
            authority(
                "authority:operator-decide",
                "principal:operator",
                vec![KernelOperation::Propose, KernelOperation::Decide],
                &["decide"],
                false,
            ),
            authority(
                "authority:operator-publish",
                "principal:operator",
                vec![
                    KernelOperation::Propose,
                    KernelOperation::Authorize,
                    KernelOperation::Reserve,
                    KernelOperation::Publish,
                ],
                &["publish"],
                false,
            ),
            authority(
                "authority:operator-amend",
                "principal:operator",
                vec![
                    KernelOperation::Freeze,
                    KernelOperation::Authorize,
                    KernelOperation::Amend,
                ],
                &[],
                true,
            ),
        ],
        resources: program_resources,
        obligations: vec![
            EpactObligation {
                id: "analyze".to_owned(),
                label: "Analyze input".to_owned(),
                description: "Produce a deterministic result from the frozen input.".to_owned(),
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
                id: "decide".to_owned(),
                label: "Record decision".to_owned(),
                description: "Record an operator decision over the result.".to_owned(),
                dependency_ids: vec!["analyze".to_owned()],
                gate_ids: vec!["gate:analysis-complete".to_owned()],
                discharge: EpactDischarge::Decision {
                    decision_object_id: "object:decision".to_owned(),
                },
                output_object_ids: vec!["object:decision".to_owned()],
                effects: vec![],
                resources: EpactResourceEnvelope::default(),
                reversibility: ReversibilityPolicy::default(),
                retry_limit: 0,
                terminal_receipt_contract: "concord.decision/1".to_owned(),
            },
            EpactObligation {
                id: "publish".to_owned(),
                label: "Publish result".to_owned(),
                description: "Publish the reviewed immutable result.".to_owned(),
                dependency_ids: vec!["decide".to_owned()],
                gate_ids: vec![],
                discharge: EpactDischarge::Publication {
                    artifact_object_ids: vec!["object:result".to_owned()],
                },
                output_object_ids: vec!["object:publication".to_owned()],
                effects: vec![EffectClass::ExternalWrite],
                resources: EpactResourceEnvelope {
                    maximum_elapsed_seconds: 60,
                    maximum_tool_calls: 1,
                    ..EpactResourceEnvelope::default()
                },
                reversibility: ReversibilityPolicy {
                    class: ReversibilityClass::AppendOnly,
                    reversal_action: Some("publish a superseding retraction".to_owned()),
                    limitations: vec!["prior recipients may retain the release".to_owned()],
                },
                retry_limit: 0,
                terminal_receipt_contract: "concord.publication-receipt/1".to_owned(),
            },
        ],
        gates: vec![EpactGate {
            id: "gate:analysis-complete".to_owned(),
            label: "Analysis completed".to_owned(),
            predicate: EpactPredicate::ObligationSatisfied {
                obligation_id: "analyze".to_owned(),
            },
        }],
        evidence_rules: vec![EpactEvidenceRule {
            id: "evidence:claim".to_owned(),
            claim_object_id: "object:claim".to_owned(),
            evidence_object_ids: vec!["object:evidence".to_owned()],
            evaluator_capability_id: Some("capability:analyze".to_owned()),
            minimum_observations: 1,
            independent_review_required: false,
        }],
        amendment_policy: EpactAmendmentPolicy {
            authorized_principal_ids: vec!["principal:operator".to_owned()],
            rationale_required: true,
            effective_causal_head_required: true,
            preserve_prior_interpretation: true,
        },
        terminal: EpactTerminalRule {
            required_obligation_ids: vec!["publish".to_owned()],
            required_object_ids: vec!["object:publication".to_owned()],
            required_receipt_contracts: vec!["concord.publication-receipt/1".to_owned()],
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
    id: &str,
    principal_id: &str,
    operations: Vec<KernelOperation>,
    obligation_ids: &[&str],
    whole_program: bool,
) -> EpactAuthorityGrant {
    EpactAuthorityGrant {
        id: id.to_owned(),
        principal_id: principal_id.to_owned(),
        operations,
        scope: EpactAuthorityScope {
            whole_program,
            obligation_ids: obligation_ids.iter().map(|id| (*id).to_owned()).collect(),
            capability_ids: vec![],
        },
        maximum_cost_usd: 10.0,
        valid_after: None,
        valid_before: None,
    }
}

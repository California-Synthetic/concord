//! Deterministic compilation from canonical Epact programs to kernel-consumable program images.

use std::collections::{BTreeMap, BTreeSet};

use concord_protocol::{
    canonical_epact_json_bytes, validate_epact_timestamp, CompiledAuthority, EffectClass,
    EpactAmendment, EpactAuthorityGrant, EpactCompilerFinding, EpactDischarge, EpactPredicate,
    EpactProgram, EpactProgramImage, EpactResourceEnvelope, KernelOperation, ProgramLifecycle,
    EPACT_AMENDMENT_CONTRACT, EPACT_PROGRAM_CONTRACT, EPACT_PROGRAM_IMAGE_CONTRACT,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EPACT_COMPILER_VERSION: &str = "0.1.0-alpha.1";

pub fn compile_program(mut program: EpactProgram) -> Result<EpactProgramImage, EpactCompileError> {
    normalize_program(&mut program)?;
    validate_program(&program)?;
    let obligation_order = obligation_order(&program)?;
    let authorities = compile_authorities(&program.authorities)?;
    let maximum_effects = program
        .obligations
        .iter()
        .flat_map(|obligation| obligation.effects.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let activation_findings = activation_findings(&program);
    let activatable =
        program.lifecycle == ProgramLifecycle::Frozen && activation_findings.is_empty();
    let program_sha256 = hash_json(&program)?;
    let mut image = EpactProgramImage {
        contract: EPACT_PROGRAM_IMAGE_CONTRACT.to_owned(),
        compiler_version: EPACT_COMPILER_VERSION.to_owned(),
        program_sha256,
        image_sha256: String::new(),
        program,
        obligation_order,
        authorities,
        maximum_effects,
        activation_findings,
        activatable,
    };
    image.image_sha256 = image_hash(&image)?;
    Ok(image)
}

pub fn verify_program_image(image: &EpactProgramImage) -> Result<(), EpactCompileError> {
    if image.contract != EPACT_PROGRAM_IMAGE_CONTRACT
        || image.compiler_version != EPACT_COMPILER_VERSION
    {
        return Err(EpactCompileError::UnsupportedImageContract);
    }
    if image.image_sha256 != image_hash(image)? {
        return Err(EpactCompileError::ImageHashMismatch);
    }
    let expected = compile_program(image.program.clone())?;
    if expected != *image {
        return Err(EpactCompileError::ImageReplayMismatch);
    }
    Ok(())
}

pub fn require_activatable(image: &EpactProgramImage) -> Result<(), EpactCompileError> {
    verify_program_image(image)?;
    if !image.activatable || !image.activation_findings.is_empty() {
        return Err(EpactCompileError::ProgramNotActivatable);
    }
    Ok(())
}

/// Validate a prospective successor against the exact immutable image and event head it extends.
///
/// The returned record is content-addressed but not an operator signature. Product kernels remain
/// responsible for authenticating the principal and persisting the accepted amendment.
pub fn verify_program_successor(
    predecessor: &EpactProgramImage,
    successor: &EpactProgramImage,
    principal_id: &str,
    rationale: &str,
    effective_event_head_sha256: &str,
) -> Result<EpactAmendment, EpactCompileError> {
    require_activatable(predecessor)?;
    require_activatable(successor)?;
    let principal_id = principal_id.trim();
    let rationale = rationale.trim();
    require_text("amendment principal", principal_id, 240)?;
    require_text("amendment rationale", rationale, 4_000)?;
    require_sha256("effective event head", effective_event_head_sha256)?;

    let predecessor_ref = successor
        .program
        .predecessor
        .as_ref()
        .ok_or(EpactCompileError::MissingPredecessor)?;
    if successor.program.id != predecessor.program.id
        || successor.program.version == predecessor.program.version
        || predecessor_ref.id != predecessor.program.id
        || predecessor_ref.version != predecessor.program.version
        || predecessor_ref.program_sha256 != predecessor.program_sha256
    {
        return Err(EpactCompileError::PredecessorMismatch);
    }
    if !predecessor
        .program
        .amendment_policy
        .authorized_principal_ids
        .iter()
        .any(|candidate| candidate == principal_id)
        || !predecessor.authorities.iter().any(|authority| {
            authority.principal_id == principal_id
                && authority.operation == KernelOperation::Amend
                && authority.whole_program
        })
    {
        return Err(EpactCompileError::AmendmentAuthorityDenied(
            principal_id.to_owned(),
        ));
    }

    let mut amendment = EpactAmendment {
        contract: EPACT_AMENDMENT_CONTRACT.to_owned(),
        predecessor_image_sha256: predecessor.image_sha256.clone(),
        successor_image_sha256: successor.image_sha256.clone(),
        principal_id: principal_id.to_owned(),
        rationale: rationale.to_owned(),
        effective_event_head_sha256: effective_event_head_sha256.to_owned(),
        amendment_sha256: String::new(),
    };
    amendment.amendment_sha256 = amendment_hash(&amendment)?;
    Ok(amendment)
}

pub fn verify_amendment_record(
    predecessor: &EpactProgramImage,
    successor: &EpactProgramImage,
    amendment: &EpactAmendment,
) -> Result<(), EpactCompileError> {
    if amendment.contract != EPACT_AMENDMENT_CONTRACT
        || amendment.predecessor_image_sha256 != predecessor.image_sha256
        || amendment.successor_image_sha256 != successor.image_sha256
        || amendment.amendment_sha256 != amendment_hash(amendment)?
    {
        return Err(EpactCompileError::AmendmentRecordMismatch);
    }
    let expected = verify_program_successor(
        predecessor,
        successor,
        &amendment.principal_id,
        &amendment.rationale,
        &amendment.effective_event_head_sha256,
    )?;
    if expected != *amendment {
        return Err(EpactCompileError::AmendmentRecordMismatch);
    }
    Ok(())
}

fn normalize_program(program: &mut EpactProgram) -> Result<(), EpactCompileError> {
    program
        .imports
        .sort_by(|left, right| left.id.cmp(&right.id));
    program
        .principals
        .sort_by(|left, right| left.id.cmp(&right.id));
    program
        .objects
        .sort_by(|left, right| left.id.cmp(&right.id));
    program
        .capabilities
        .sort_by(|left, right| left.id.cmp(&right.id));
    program
        .authorities
        .sort_by(|left, right| left.id.cmp(&right.id));
    program
        .obligations
        .sort_by(|left, right| left.id.cmp(&right.id));
    program.gates.sort_by(|left, right| left.id.cmp(&right.id));
    program
        .evidence_rules
        .sort_by(|left, right| left.id.cmp(&right.id));

    for object in &mut program.objects {
        sort_dedup(&mut object.data_classes);
    }
    for capability in &mut program.capabilities {
        capability.required_effects.sort();
        capability.required_effects.dedup();
        sort_dedup(&mut capability.required_data_classes);
    }
    for authority in &mut program.authorities {
        authority.operations.sort();
        authority.operations.dedup();
        sort_dedup(&mut authority.scope.obligation_ids);
        sort_dedup(&mut authority.scope.capability_ids);
    }
    for obligation in &mut program.obligations {
        sort_dedup(&mut obligation.dependency_ids);
        sort_dedup(&mut obligation.gate_ids);
        sort_dedup(&mut obligation.output_object_ids);
        obligation.effects.sort();
        obligation.effects.dedup();
        match &mut obligation.discharge {
            EpactDischarge::Evidence { evidence_rule_ids } => sort_dedup(evidence_rule_ids),
            EpactDischarge::Publication {
                artifact_object_ids,
            } => sort_dedup(artifact_object_ids),
            _ => {}
        }
    }
    for gate in &mut program.gates {
        normalize_predicate(&mut gate.predicate)?;
    }
    for rule in &mut program.evidence_rules {
        sort_dedup(&mut rule.evidence_object_ids);
    }
    sort_dedup(&mut program.amendment_policy.authorized_principal_ids);
    sort_dedup(&mut program.terminal.required_obligation_ids);
    sort_dedup(&mut program.terminal.required_object_ids);
    sort_dedup(&mut program.terminal.required_receipt_contracts);
    Ok(())
}

fn normalize_predicate(predicate: &mut EpactPredicate) -> Result<(), EpactCompileError> {
    match predicate {
        EpactPredicate::All { predicates } | EpactPredicate::Any { predicates } => {
            for child in predicates.iter_mut() {
                normalize_predicate(child)?;
            }
            let mut keyed = predicates
                .drain(..)
                .map(|child| Ok((serde_json::to_string(&child)?, child)))
                .collect::<Result<Vec<_>, EpactCompileError>>()?;
            keyed.sort_by(|left, right| left.0.cmp(&right.0));
            keyed.dedup_by(|left, right| left.0 == right.0);
            *predicates = keyed.into_iter().map(|(_, child)| child).collect();
        }
        EpactPredicate::Not { predicate } => normalize_predicate(predicate)?,
        _ => {}
    }
    Ok(())
}

fn validate_program(program: &EpactProgram) -> Result<(), EpactCompileError> {
    if program.contract != EPACT_PROGRAM_CONTRACT {
        return Err(EpactCompileError::UnsupportedProgramContract(
            program.contract.clone(),
        ));
    }
    require_text("program id", &program.id, 240)?;
    require_text("program version", &program.version, 80)?;
    require_text("program title", &program.title, 500)?;
    require_text("program creator", &program.created_by, 240)?;
    validate_resources("program", &program.resources)?;
    ensure_unique_ids("import", program.imports.iter().map(|item| &item.id))?;
    ensure_unique_ids("principal", program.principals.iter().map(|item| &item.id))?;
    ensure_unique_ids("object", program.objects.iter().map(|item| &item.id))?;
    ensure_unique_ids(
        "capability",
        program.capabilities.iter().map(|item| &item.id),
    )?;
    ensure_unique_ids("authority", program.authorities.iter().map(|item| &item.id))?;
    ensure_unique_ids(
        "obligation",
        program.obligations.iter().map(|item| &item.id),
    )?;
    ensure_unique_ids("gate", program.gates.iter().map(|item| &item.id))?;
    ensure_unique_ids(
        "evidence rule",
        program.evidence_rules.iter().map(|item| &item.id),
    )?;

    let principals = ids(program.principals.iter().map(|item| &item.id));
    let objects = ids(program.objects.iter().map(|item| &item.id));
    let capabilities = ids(program.capabilities.iter().map(|item| &item.id));
    let obligations = ids(program.obligations.iter().map(|item| &item.id));
    let gates = ids(program.gates.iter().map(|item| &item.id));
    let evidence_rules = ids(program.evidence_rules.iter().map(|item| &item.id));

    require_ref(
        "program creator",
        &program.created_by,
        &principals,
        &program.id,
    )?;
    if program.principals.is_empty() || program.obligations.is_empty() {
        return Err(EpactCompileError::EmptyProgram);
    }
    if let Some(predecessor) = &program.predecessor {
        require_text("predecessor id", &predecessor.id, 240)?;
        require_text("predecessor version", &predecessor.version, 80)?;
        require_sha256("predecessor program hash", &predecessor.program_sha256)?;
        if predecessor.id != program.id || predecessor.version == program.version {
            return Err(EpactCompileError::InvalidPredecessor);
        }
    }
    for import in &program.imports {
        require_text("import id", &import.id, 240)?;
        require_text("import version", &import.version, 80)?;
        require_sha256("import content hash", &import.content_sha256)?;
    }
    for principal in &program.principals {
        require_text("principal id", &principal.id, 240)?;
        require_text("principal display name", &principal.display_name, 500)?;
    }
    for object in &program.objects {
        require_text("object id", &object.id, 240)?;
        require_text("object type", &object.type_name, 240)?;
        if let Some(digest) = &object.schema_sha256 {
            require_sha256("object schema hash", digest)?;
        }
        validate_set("object data class", &object.data_classes)?;
    }
    for capability in &program.capabilities {
        require_text("capability id", &capability.id, 240)?;
        require_text("capability type", &capability.capability_type, 240)?;
        require_text("capability contract", &capability.contract, 240)?;
        validate_set("capability data class", &capability.required_data_classes)?;
    }
    for authority in &program.authorities {
        require_text("authority id", &authority.id, 240)?;
        require_ref(
            "authority principal",
            &authority.principal_id,
            &principals,
            &authority.id,
        )?;
        if authority.operations.is_empty()
            || (!authority.scope.whole_program
                && authority.scope.obligation_ids.is_empty()
                && authority.scope.capability_ids.is_empty())
        {
            return Err(EpactCompileError::EmptyAuthority(authority.id.clone()));
        }
        require_refs(
            "authority obligation",
            &authority.scope.obligation_ids,
            &obligations,
            &authority.id,
        )?;
        require_refs(
            "authority capability",
            &authority.scope.capability_ids,
            &capabilities,
            &authority.id,
        )?;
        if !authority.maximum_cost_usd.is_finite()
            || authority.maximum_cost_usd < 0.0
            || authority.maximum_cost_usd > program.resources.maximum_cost_usd + 1e-9
        {
            return Err(EpactCompileError::InvalidAuthorityCost(
                authority.id.clone(),
            ));
        }
        validate_optional_text(
            "authority validAfter",
            authority.valid_after.as_deref(),
            160,
        )?;
        validate_optional_text(
            "authority validBefore",
            authority.valid_before.as_deref(),
            160,
        )?;
        for timestamp in [
            authority.valid_after.as_deref(),
            authority.valid_before.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !validate_epact_timestamp(timestamp) {
                return Err(EpactCompileError::InvalidAuthorityTimestamp(
                    authority.id.clone(),
                ));
            }
        }
        if authority
            .valid_after
            .as_ref()
            .zip(authority.valid_before.as_ref())
            .is_some_and(|(after, before)| after >= before)
        {
            return Err(EpactCompileError::InvalidAuthorityWindow(
                authority.id.clone(),
            ));
        }
    }
    let capability_map = program
        .capabilities
        .iter()
        .map(|capability| (capability.id.as_str(), capability))
        .collect::<BTreeMap<_, _>>();
    for obligation in &program.obligations {
        require_text("obligation id", &obligation.id, 240)?;
        require_text("obligation label", &obligation.label, 500)?;
        require_text("obligation description", &obligation.description, 4_000)?;
        require_text(
            "terminal receipt contract",
            &obligation.terminal_receipt_contract,
            240,
        )?;
        require_refs(
            "obligation dependency",
            &obligation.dependency_ids,
            &obligations,
            &obligation.id,
        )?;
        if obligation.dependency_ids.contains(&obligation.id) {
            return Err(EpactCompileError::DependencyCycle(obligation.id.clone()));
        }
        require_refs(
            "obligation gate",
            &obligation.gate_ids,
            &gates,
            &obligation.id,
        )?;
        require_refs(
            "obligation output",
            &obligation.output_object_ids,
            &objects,
            &obligation.id,
        )?;
        validate_resources(&obligation.id, &obligation.resources)?;
        if !obligation.resources.fits_within(&program.resources) {
            return Err(EpactCompileError::ResourceCeilingExceeded(
                obligation.id.clone(),
            ));
        }
        if obligation.effects.is_empty() {
            if !obligation.reversibility.is_unspecified() {
                return Err(EpactCompileError::UnexpectedReversibility(
                    obligation.id.clone(),
                ));
            }
        } else {
            for effect in &obligation.effects {
                obligation
                    .reversibility
                    .validate(*effect)
                    .map_err(|error| EpactCompileError::InvalidReversibility {
                        obligation_id: obligation.id.clone(),
                        message: error.to_string(),
                    })?;
            }
        }
        match &obligation.discharge {
            EpactDischarge::Capability { capability_id } => validate_capability_discharge(
                &obligation.id,
                capability_id,
                &obligation.effects,
                &capability_map,
            )?,
            EpactDischarge::Decision { decision_object_id } => require_ref(
                "decision object",
                decision_object_id,
                &objects,
                &obligation.id,
            )?,
            EpactDischarge::Evidence {
                evidence_rule_ids: rules,
            } => {
                if rules.is_empty() {
                    return Err(EpactCompileError::EmptyDischarge(obligation.id.clone()));
                }
                require_refs("evidence rule", rules, &evidence_rules, &obligation.id)?;
            }
            EpactDischarge::Review {
                capability_id,
                review_object_id,
                ..
            } => {
                validate_capability_discharge(
                    &obligation.id,
                    capability_id,
                    &obligation.effects,
                    &capability_map,
                )?;
                require_ref("review object", review_object_id, &objects, &obligation.id)?;
            }
            EpactDischarge::Publication {
                artifact_object_ids,
            } => {
                if artifact_object_ids.is_empty() {
                    return Err(EpactCompileError::EmptyDischarge(obligation.id.clone()));
                }
                require_refs(
                    "publication artifact",
                    artifact_object_ids,
                    &objects,
                    &obligation.id,
                )?;
            }
        }
    }
    for gate in &program.gates {
        require_text("gate id", &gate.id, 240)?;
        require_text("gate label", &gate.label, 500)?;
        validate_predicate(
            &gate.predicate,
            &obligations,
            &objects,
            &evidence_rules,
            0,
            &gate.id,
        )?;
    }
    for rule in &program.evidence_rules {
        require_text("evidence rule id", &rule.id, 240)?;
        require_ref("claim object", &rule.claim_object_id, &objects, &rule.id)?;
        if rule.evidence_object_ids.is_empty()
            || rule.minimum_observations == 0
            || rule.minimum_observations as usize > rule.evidence_object_ids.len()
        {
            return Err(EpactCompileError::InvalidEvidenceRule(rule.id.clone()));
        }
        require_refs(
            "evidence object",
            &rule.evidence_object_ids,
            &objects,
            &rule.id,
        )?;
        if let Some(capability_id) = &rule.evaluator_capability_id {
            require_ref(
                "evaluator capability",
                capability_id,
                &capabilities,
                &rule.id,
            )?;
        }
    }
    if !program.amendment_policy.rationale_required
        || !program.amendment_policy.effective_causal_head_required
        || !program.amendment_policy.preserve_prior_interpretation
        || program.amendment_policy.authorized_principal_ids.is_empty()
    {
        return Err(EpactCompileError::UnsafeAmendmentPolicy);
    }
    require_refs(
        "amendment principal",
        &program.amendment_policy.authorized_principal_ids,
        &principals,
        &program.id,
    )?;
    if program.terminal.required_obligation_ids.is_empty()
        || program.terminal.required_receipt_contracts.is_empty()
    {
        return Err(EpactCompileError::EmptyTerminalRule);
    }
    require_refs(
        "terminal obligation",
        &program.terminal.required_obligation_ids,
        &obligations,
        &program.id,
    )?;
    require_refs(
        "terminal object",
        &program.terminal.required_object_ids,
        &objects,
        &program.id,
    )?;
    validate_set(
        "terminal receipt contract",
        &program.terminal.required_receipt_contracts,
    )?;
    Ok(())
}

fn activation_findings(program: &EpactProgram) -> Vec<EpactCompilerFinding> {
    let mut findings = Vec::new();
    if program.lifecycle != ProgramLifecycle::Frozen {
        findings.push(finding(
            "program_not_frozen",
            &program.id,
            "program must be frozen before activation",
        ));
    }
    for obligation in &program.obligations {
        require_operation_finding(program, obligation, KernelOperation::Propose, &mut findings);
        let operation = match obligation.discharge {
            EpactDischarge::Capability { .. } => KernelOperation::Dispatch,
            EpactDischarge::Decision { .. } => KernelOperation::Decide,
            EpactDischarge::Evidence { .. } => KernelOperation::Evaluate,
            EpactDischarge::Review { .. } => KernelOperation::Evaluate,
            EpactDischarge::Publication { .. } => KernelOperation::Publish,
        };
        require_operation_finding(program, obligation, operation, &mut findings);
        if !obligation.effects.is_empty() {
            require_operation_finding(
                program,
                obligation,
                KernelOperation::Authorize,
                &mut findings,
            );
        }
        if consumes_resources(&obligation.resources) {
            require_operation_finding(program, obligation, KernelOperation::Reserve, &mut findings);
        }
    }
    for principal_id in &program.amendment_policy.authorized_principal_ids {
        if !program.authorities.iter().any(|grant| {
            grant.principal_id == *principal_id
                && grant.operations.contains(&KernelOperation::Amend)
                && grant.scope.whole_program
        }) {
            findings.push(finding(
                "missing_amend_authority",
                principal_id,
                "amendment principal lacks whole-program amend authority",
            ));
        }
    }
    findings.sort_by(|left, right| {
        (&left.code, &left.subject_id, &left.message).cmp(&(
            &right.code,
            &right.subject_id,
            &right.message,
        ))
    });
    findings.dedup();
    findings
}

fn require_operation_finding(
    program: &EpactProgram,
    obligation: &concord_protocol::EpactObligation,
    operation: KernelOperation,
    findings: &mut Vec<EpactCompilerFinding>,
) {
    let capability_id = obligation_capability_id(&obligation.discharge);
    if !program.authorities.iter().any(|grant| {
        grant.operations.contains(&operation)
            && authority_applies(grant, &obligation.id, capability_id)
    }) {
        findings.push(finding(
            "missing_operation_authority",
            &obligation.id,
            &format!(
                "no principal may {} this obligation",
                operation_name(operation)
            ),
        ));
    }
}

fn authority_applies(
    grant: &EpactAuthorityGrant,
    obligation_id: &str,
    capability_id: Option<&str>,
) -> bool {
    grant.scope.whole_program
        || grant
            .scope
            .obligation_ids
            .iter()
            .any(|candidate| candidate == obligation_id)
        || capability_id.is_some_and(|id| {
            grant
                .scope
                .capability_ids
                .iter()
                .any(|candidate| candidate == id)
        })
}

fn obligation_capability_id(discharge: &EpactDischarge) -> Option<&str> {
    match discharge {
        EpactDischarge::Capability { capability_id }
        | EpactDischarge::Review { capability_id, .. } => Some(capability_id),
        _ => None,
    }
}

fn consumes_resources(resources: &EpactResourceEnvelope) -> bool {
    resources.maximum_cost_usd > 0.0
        || resources.maximum_elapsed_seconds > 0
        || resources.maximum_model_calls > 0
        || resources.maximum_tool_calls > 0
        || resources.maximum_external_jobs > 0
        || resources.maximum_cpu_cores > 0.0
        || resources.maximum_ram_gb > 0.0
        || resources.maximum_gpu_count > 0
        || resources.maximum_vram_gb > 0.0
        || resources.maximum_storage_gb > 0.0
        || resources.maximum_data_movement_gb > 0.0
}

fn compile_authorities(
    grants: &[EpactAuthorityGrant],
) -> Result<Vec<CompiledAuthority>, EpactCompileError> {
    let mut authorities = Vec::new();
    for grant in grants {
        let maximum_cost_microusd = if grant.maximum_cost_usd == 0.0 {
            None
        } else {
            Some((grant.maximum_cost_usd * 1_000_000.0).round() as u64)
        };
        for operation in &grant.operations {
            authorities.push(CompiledAuthority {
                principal_id: grant.principal_id.clone(),
                operation: *operation,
                whole_program: grant.scope.whole_program,
                obligation_ids: grant.scope.obligation_ids.clone(),
                capability_ids: grant.scope.capability_ids.clone(),
                maximum_cost_microusd,
                valid_after: grant.valid_after.clone(),
                valid_before: grant.valid_before.clone(),
            });
        }
    }
    authorities.sort();
    authorities.dedup();
    Ok(authorities)
}

fn obligation_order(program: &EpactProgram) -> Result<Vec<String>, EpactCompileError> {
    let mut dependencies = program
        .obligations
        .iter()
        .map(|obligation| {
            (
                obligation.id.clone(),
                obligation
                    .dependency_ids
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let gates = program
        .gates
        .iter()
        .map(|gate| (gate.id.as_str(), &gate.predicate))
        .collect::<BTreeMap<_, _>>();
    for obligation in &program.obligations {
        for gate_id in &obligation.gate_ids {
            collect_predicate_obligations(
                gates[gate_id.as_str()],
                &mut dependencies.get_mut(&obligation.id).unwrap(),
            );
        }
        dependencies
            .get_mut(&obligation.id)
            .unwrap()
            .remove(&obligation.id);
    }
    let mut order = Vec::new();
    let mut ready = dependencies
        .iter()
        .filter_map(|(id, requires)| requires.is_empty().then_some(id.clone()))
        .collect::<BTreeSet<_>>();
    while let Some(id) = ready.pop_first() {
        order.push(id.clone());
        for (candidate, requires) in &mut dependencies {
            if requires.remove(&id) && requires.is_empty() && !order.contains(candidate) {
                ready.insert(candidate.clone());
            }
        }
    }
    if order.len() != dependencies.len() {
        let member = dependencies
            .keys()
            .find(|id| !order.contains(id))
            .cloned()
            .unwrap_or_else(|| program.id.clone());
        return Err(EpactCompileError::DependencyCycle(member));
    }
    Ok(order)
}

fn collect_predicate_obligations(predicate: &EpactPredicate, output: &mut BTreeSet<String>) {
    match predicate {
        EpactPredicate::All { predicates } | EpactPredicate::Any { predicates } => {
            for child in predicates {
                collect_predicate_obligations(child, output);
            }
        }
        EpactPredicate::Not { predicate } => collect_predicate_obligations(predicate, output),
        EpactPredicate::ObligationSatisfied { obligation_id } => {
            output.insert(obligation_id.clone());
        }
        _ => {}
    }
}

fn validate_capability_discharge(
    obligation_id: &str,
    capability_id: &str,
    obligation_effects: &[EffectClass],
    capabilities: &BTreeMap<&str, &concord_protocol::EpactCapabilityRequirement>,
) -> Result<(), EpactCompileError> {
    let capability =
        capabilities
            .get(capability_id)
            .ok_or_else(|| EpactCompileError::MissingReference {
                kind: "capability",
                id: capability_id.to_owned(),
                subject_id: obligation_id.to_owned(),
            })?;
    if !capability
        .required_effects
        .iter()
        .all(|effect| obligation_effects.contains(effect))
    {
        return Err(EpactCompileError::CapabilityEffectMismatch(
            obligation_id.to_owned(),
        ));
    }
    Ok(())
}

fn validate_predicate(
    predicate: &EpactPredicate,
    obligations: &BTreeSet<&str>,
    objects: &BTreeSet<&str>,
    evidence_rules: &BTreeSet<&str>,
    depth: usize,
    gate_id: &str,
) -> Result<(), EpactCompileError> {
    if depth > 64 {
        return Err(EpactCompileError::PredicateTooDeep(gate_id.to_owned()));
    }
    match predicate {
        EpactPredicate::All { predicates } | EpactPredicate::Any { predicates } => {
            if predicates.is_empty() {
                return Err(EpactCompileError::EmptyPredicate(gate_id.to_owned()));
            }
            for child in predicates {
                validate_predicate(
                    child,
                    obligations,
                    objects,
                    evidence_rules,
                    depth + 1,
                    gate_id,
                )?;
            }
        }
        EpactPredicate::Not { predicate } => validate_predicate(
            predicate,
            obligations,
            objects,
            evidence_rules,
            depth + 1,
            gate_id,
        )?,
        EpactPredicate::ObligationSatisfied { obligation_id } => {
            require_ref("predicate obligation", obligation_id, obligations, gate_id)?
        }
        EpactPredicate::EvidenceSatisfied { evidence_rule_id } => require_ref(
            "predicate evidence rule",
            evidence_rule_id,
            evidence_rules,
            gate_id,
        )?,
        EpactPredicate::ObjectPresent { object_id } => {
            require_ref("predicate object", object_id, objects, gate_id)?
        }
    }
    Ok(())
}

fn validate_resources(
    subject_id: &str,
    resources: &EpactResourceEnvelope,
) -> Result<(), EpactCompileError> {
    if !resources.is_finite_and_non_negative() {
        return Err(EpactCompileError::InvalidResources(subject_id.to_owned()));
    }
    Ok(())
}

fn validate_set(label: &'static str, values: &[String]) -> Result<(), EpactCompileError> {
    for value in values {
        require_text(label, value, 240)?;
    }
    Ok(())
}

fn require_text(
    label: &'static str,
    value: &str,
    maximum_characters: usize,
) -> Result<(), EpactCompileError> {
    if value.trim().is_empty() || value.chars().count() > maximum_characters {
        return Err(EpactCompileError::InvalidText {
            label,
            maximum_characters,
        });
    }
    Ok(())
}

fn validate_optional_text(
    label: &'static str,
    value: Option<&str>,
    maximum_characters: usize,
) -> Result<(), EpactCompileError> {
    if let Some(value) = value {
        require_text(label, value, maximum_characters)?;
    }
    Ok(())
}

fn require_sha256(label: &'static str, value: &str) -> Result<(), EpactCompileError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EpactCompileError::InvalidSha256(label));
    }
    Ok(())
}

fn ensure_unique_ids<'a>(
    kind: &'static str,
    values: impl Iterator<Item = &'a String>,
) -> Result<(), EpactCompileError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_text(kind, value, 240)?;
        if !seen.insert(value) {
            return Err(EpactCompileError::DuplicateId {
                kind,
                id: value.clone(),
            });
        }
    }
    Ok(())
}

fn ids<'a>(values: impl Iterator<Item = &'a String>) -> BTreeSet<&'a str> {
    values.map(String::as_str).collect()
}

fn require_refs(
    kind: &'static str,
    values: &[String],
    known: &BTreeSet<&str>,
    subject_id: &str,
) -> Result<(), EpactCompileError> {
    for value in values {
        require_ref(kind, value, known, subject_id)?;
    }
    Ok(())
}

fn require_ref(
    kind: &'static str,
    value: &str,
    known: &BTreeSet<&str>,
    subject_id: &str,
) -> Result<(), EpactCompileError> {
    if !known.contains(value) {
        return Err(EpactCompileError::MissingReference {
            kind,
            id: value.to_owned(),
            subject_id: subject_id.to_owned(),
        });
    }
    Ok(())
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn finding(code: &str, subject_id: &str, message: &str) -> EpactCompilerFinding {
    EpactCompilerFinding {
        code: code.to_owned(),
        subject_id: subject_id.to_owned(),
        message: message.to_owned(),
    }
}

fn operation_name(operation: KernelOperation) -> &'static str {
    match operation {
        KernelOperation::Declare => "declare",
        KernelOperation::Freeze => "freeze",
        KernelOperation::Authorize => "authorize",
        KernelOperation::Delegate => "delegate",
        KernelOperation::Propose => "propose",
        KernelOperation::Reserve => "reserve",
        KernelOperation::Dispatch => "dispatch",
        KernelOperation::Observe => "observe",
        KernelOperation::Attest => "attest",
        KernelOperation::Evaluate => "evaluate",
        KernelOperation::Decide => "decide",
        KernelOperation::Amend => "amend",
        KernelOperation::Publish => "publish",
        KernelOperation::Retract => "retract",
    }
}

fn image_hash(image: &EpactProgramImage) -> Result<String, EpactCompileError> {
    let mut value = serde_json::to_value(image)?;
    value
        .as_object_mut()
        .ok_or(EpactCompileError::ImageNotObject)?
        .remove("imageSha256");
    hash_json(&value)
}

fn amendment_hash(amendment: &EpactAmendment) -> Result<String, EpactCompileError> {
    let mut value = serde_json::to_value(amendment)?;
    value
        .as_object_mut()
        .ok_or(EpactCompileError::CanonicalValueNotObject)?
        .remove("amendmentSha256");
    hash_json(&value)
}

fn hash_json(value: &impl serde::Serialize) -> Result<String, EpactCompileError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical_epact_json_bytes(value)?)
    ))
}

#[derive(Debug, Error)]
pub enum EpactCompileError {
    #[error("unsupported Epact program contract {0}")]
    UnsupportedProgramContract(String),
    #[error("unsupported Epact program image contract or compiler version")]
    UnsupportedImageContract,
    #[error("{label} must contain 1-{maximum_characters} characters")]
    InvalidText {
        label: &'static str,
        maximum_characters: usize,
    },
    #[error("{0} must be a lowercase SHA-256 digest")]
    InvalidSha256(&'static str),
    #[error("Epact program requires at least one principal and one obligation")]
    EmptyProgram,
    #[error("duplicate {kind} id {id}")]
    DuplicateId { kind: &'static str, id: String },
    #[error("{kind} {id} referenced by {subject_id} does not exist")]
    MissingReference {
        kind: &'static str,
        id: String,
        subject_id: String,
    },
    #[error("invalid predecessor identity or version")]
    InvalidPredecessor,
    #[error("successor program does not extend the supplied predecessor image")]
    PredecessorMismatch,
    #[error("successor program must declare a predecessor")]
    MissingPredecessor,
    #[error("principal {0} lacks prospective amendment authority")]
    AmendmentAuthorityDenied(String),
    #[error("amendment record does not match the predecessor and successor images")]
    AmendmentRecordMismatch,
    #[error("authority {0} has no operations or scope")]
    EmptyAuthority(String),
    #[error("authority {0} has an invalid or out-of-program cost ceiling")]
    InvalidAuthorityCost(String),
    #[error("authority {0} time must use canonical Epact UTC-second form")]
    InvalidAuthorityTimestamp(String),
    #[error("authority {0} validAfter must precede validBefore")]
    InvalidAuthorityWindow(String),
    #[error("resources for {0} must be finite and non-negative")]
    InvalidResources(String),
    #[error("resource request for obligation {0} exceeds the program ceiling")]
    ResourceCeilingExceeded(String),
    #[error("obligation {0} has an empty discharge requirement")]
    EmptyDischarge(String),
    #[error("obligation {0} does not declare all effects required by its capability")]
    CapabilityEffectMismatch(String),
    #[error("obligation {obligation_id} has invalid reversibility: {message}")]
    InvalidReversibility {
        obligation_id: String,
        message: String,
    },
    #[error("obligation {0} declares reversibility without an effect")]
    UnexpectedReversibility(String),
    #[error("obligation dependency cycle includes {0}")]
    DependencyCycle(String),
    #[error("gate {0} contains an empty all/any predicate")]
    EmptyPredicate(String),
    #[error("gate {0} predicate exceeds 64 levels")]
    PredicateTooDeep(String),
    #[error("evidence rule {0} has an invalid observation threshold")]
    InvalidEvidenceRule(String),
    #[error("amendment policy must require rationale, a causal head, prior interpretation, and an authorized principal")]
    UnsafeAmendmentPolicy,
    #[error("terminal rule requires obligations and receipt contracts")]
    EmptyTerminalRule,
    #[error("program image is not activatable")]
    ProgramNotActivatable,
    #[error("program image hash mismatch")]
    ImageHashMismatch,
    #[error("program image replay differs from the recorded image")]
    ImageReplayMismatch,
    #[error("program image did not serialize as an object")]
    ImageNotObject,
    #[error("canonical Epact record did not serialize as an object")]
    CanonicalValueNotObject,
    #[error("Epact serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

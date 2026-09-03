use std::collections::BTreeSet;

use concord_protocol::{
    validate_epact_timestamp, CompiledAuthority, EpactDischarge, EpactEligibility,
    EpactEligibilityBlocker, EpactObligation, EpactObligationProjection, EpactObligationState,
    EpactOperationRequest, EpactPredicate, EpactProgramImage, EpactResourceEnvelope,
    EpactRuntimeEvent, EpactRuntimeEventKind, EpactRuntimeState, KernelOperation,
};
use epact_compiler::{require_activatable, verify_program_image};
use thiserror::Error;

/// Construct the projection produced by replaying an empty history under one compiled image.
pub fn initial_epact_state(
    image: &EpactProgramImage,
) -> Result<EpactRuntimeState, EpactRuntimeError> {
    verify_program_image(image)
        .map_err(|error| EpactRuntimeError::InvalidImage(error.to_string()))?;
    Ok(EpactRuntimeState {
        program_image_sha256: image.image_sha256.clone(),
        next_sequence: 0,
        event_head_sha256: None,
        obligations: image
            .obligation_order
            .iter()
            .map(|obligation_id| EpactObligationProjection {
                obligation_id: obligation_id.clone(),
                state: EpactObligationState::Pending,
                terminal_event_sha256: None,
            })
            .collect(),
        present_object_ids: Vec::new(),
        satisfied_evidence_rule_ids: Vec::new(),
    })
}

/// Rebuild all authoritative Epact projections from the compiled image and its accepted facts.
///
/// Event hashes prove integrity and order. Receipt contents remain kernel-owned evidence; replay
/// never upgrades a digest into scientific truth.
pub fn replay_epact_events(
    image: &EpactProgramImage,
    events: &[EpactRuntimeEvent],
) -> Result<EpactRuntimeState, EpactRuntimeError> {
    let mut state = initial_epact_state(image)?;
    let mut event_ids = BTreeSet::new();
    let mut idempotency_keys = BTreeSet::new();

    for event in events {
        event
            .validate()
            .map_err(|error| EpactRuntimeError::InvalidEvent(error.to_string()))?;
        if event.program_image_sha256 != image.image_sha256 {
            return Err(EpactRuntimeError::ImageBindingMismatch);
        }
        if event.sequence != state.next_sequence {
            return Err(EpactRuntimeError::UnexpectedSequence {
                expected: state.next_sequence,
                actual: event.sequence,
            });
        }
        if event.previous_event_sha256 != state.event_head_sha256 {
            return Err(EpactRuntimeError::BrokenEventChain(event.id.clone()));
        }
        if !event_ids.insert(event.id.clone()) {
            return Err(EpactRuntimeError::DuplicateEventId(event.id.clone()));
        }
        if !idempotency_keys.insert(event.idempotency_key.clone()) {
            return Err(EpactRuntimeError::DuplicateIdempotencyKey(
                event.idempotency_key.clone(),
            ));
        }
        if !image
            .program
            .principals
            .iter()
            .any(|principal| principal.id == event.actor)
        {
            return Err(EpactRuntimeError::UnknownPrincipal(event.actor.clone()));
        }

        apply_event(image, &mut state, event)?;
        state.next_sequence += 1;
        state.event_head_sha256 = Some(event.event_sha256.clone());
    }
    Ok(state)
}

/// Decide whether a requested transition fits the frozen program and current projection.
///
/// This function is pure and provider-neutral. The kernel remains responsible for identity,
/// persistence, clocks, reservations, and effect execution.
pub fn evaluate_epact_operation(
    image: &EpactProgramImage,
    state: &EpactRuntimeState,
    request: &EpactOperationRequest,
) -> Result<EpactEligibility, EpactRuntimeError> {
    require_activatable(image)
        .map_err(|error| EpactRuntimeError::InvalidImage(error.to_string()))?;
    validate_state_shape(image, state)?;

    let mut blockers = Vec::new();
    let request_time_valid = validate_epact_timestamp(&request.requested_at);
    if !request_time_valid {
        blocker(
            &mut blockers,
            "invalid_request_time",
            &image.program.id,
            "request time must use canonical Epact UTC-second form",
        );
    }
    let principal_known = image
        .program
        .principals
        .iter()
        .any(|principal| principal.id == request.principal_id);
    if !principal_known {
        blocker(
            &mut blockers,
            "unknown_principal",
            &request.principal_id,
            "the requested principal is not declared by this program",
        );
    }

    let obligation = request.obligation_id.as_deref().and_then(|id| {
        image
            .program
            .obligations
            .iter()
            .find(|obligation| obligation.id == id)
    });
    if let Some(id) = &request.obligation_id {
        if obligation.is_none() {
            blocker(
                &mut blockers,
                "unknown_obligation",
                id,
                "the requested obligation is not declared by this program",
            );
        }
    } else if operation_requires_obligation(request.operation) {
        blocker(
            &mut blockers,
            "obligation_required",
            &image.program.id,
            "this operation must be bound to an obligation",
        );
    }

    let capability_known = request.capability_id.as_deref().is_none_or(|id| {
        image
            .program
            .capabilities
            .iter()
            .any(|capability| capability.id == id)
    });
    if !capability_known {
        blocker(
            &mut blockers,
            "unknown_capability",
            request.capability_id.as_deref().unwrap_or_default(),
            "the requested capability is not declared by this program",
        );
    }

    if !request.resources.is_finite_and_non_negative() {
        blocker(
            &mut blockers,
            "invalid_resources",
            &image.program.id,
            "requested resource values must be finite and non-negative",
        );
    } else if !request.resources.fits_within(&image.program.resources) {
        blocker(
            &mut blockers,
            "program_resource_ceiling",
            &image.program.id,
            "requested resources exceed the frozen program ceiling",
        );
    }

    if let Some(obligation) = obligation {
        evaluate_obligation_request(image, state, request, obligation, &mut blockers);
    }

    if request_time_valid
        && principal_known
        && capability_known
        && !authority_allows(image, request, &request.resources)
    {
        blocker(
            &mut blockers,
            "authority_denied",
            &request.principal_id,
            "no compiled authority covers this operation, scope, and cost",
        );
    }

    blockers.sort_by(|left, right| {
        (&left.code, &left.subject_id, &left.message).cmp(&(
            &right.code,
            &right.subject_id,
            &right.message,
        ))
    });
    blockers.dedup();
    Ok(EpactEligibility {
        allowed: blockers.is_empty(),
        blockers,
    })
}

/// True only when all declared terminal obligations, objects, and receipt contracts are present.
pub fn epact_program_is_terminal(
    image: &EpactProgramImage,
    state: &EpactRuntimeState,
    events: &[EpactRuntimeEvent],
) -> Result<bool, EpactRuntimeError> {
    validate_state_shape(image, state)?;
    let satisfied = state
        .obligations
        .iter()
        .filter(|projection| projection.state == EpactObligationState::Satisfied)
        .map(|projection| projection.obligation_id.as_str())
        .collect::<BTreeSet<_>>();
    let objects = state
        .present_object_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let receipts = events
        .iter()
        .filter_map(|event| match &event.kind {
            EpactRuntimeEventKind::ObligationSatisfied {
                receipt_contract, ..
            } => Some(receipt_contract.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    Ok(image
        .program
        .terminal
        .required_obligation_ids
        .iter()
        .all(|id| satisfied.contains(id.as_str()))
        && image
            .program
            .terminal
            .required_object_ids
            .iter()
            .all(|id| objects.contains(id.as_str()))
        && image
            .program
            .terminal
            .required_receipt_contracts
            .iter()
            .all(|contract| receipts.contains(contract.as_str())))
}

fn apply_event(
    image: &EpactProgramImage,
    state: &mut EpactRuntimeState,
    event: &EpactRuntimeEvent,
) -> Result<(), EpactRuntimeError> {
    match &event.kind {
        EpactRuntimeEventKind::ObjectRecorded { object_id } => {
            if !image
                .program
                .objects
                .iter()
                .any(|object| object.id == *object_id)
            {
                return Err(EpactRuntimeError::UnknownObject(object_id.clone()));
            }
            insert_sorted_unique(&mut state.present_object_ids, object_id.clone());
        }
        EpactRuntimeEventKind::EvidenceAccepted {
            evidence_rule_id,
            independent_review_receipt_sha256,
        } => {
            let rule = image
                .program
                .evidence_rules
                .iter()
                .find(|rule| rule.id == *evidence_rule_id)
                .ok_or_else(|| EpactRuntimeError::UnknownEvidenceRule(evidence_rule_id.clone()))?;
            let observation_count = rule
                .evidence_object_ids
                .iter()
                .filter(|id| state.present_object_ids.binary_search(id).is_ok())
                .count();
            if observation_count < rule.minimum_observations as usize {
                return Err(EpactRuntimeError::InsufficientEvidence(
                    evidence_rule_id.clone(),
                ));
            }
            if rule.independent_review_required && independent_review_receipt_sha256.is_none() {
                return Err(EpactRuntimeError::IndependentReviewRequired(
                    evidence_rule_id.clone(),
                ));
            }
            insert_sorted_unique(
                &mut state.satisfied_evidence_rule_ids,
                evidence_rule_id.clone(),
            );
        }
        EpactRuntimeEventKind::ObligationSatisfied {
            obligation_id,
            receipt_contract,
        } => {
            let obligation = find_obligation(image, obligation_id)?;
            require_obligation_pending(state, obligation_id)?;
            require_dependencies(state, obligation)?;
            require_gates(image, state, obligation)?;
            require_discharge_objects(state, obligation)?;
            require_discharge_evidence(state, obligation)?;
            if receipt_contract != &obligation.terminal_receipt_contract {
                return Err(EpactRuntimeError::ReceiptContractMismatch {
                    obligation_id: obligation_id.clone(),
                    expected: obligation.terminal_receipt_contract.clone(),
                    actual: receipt_contract.clone(),
                });
            }
            set_terminal_state(
                state,
                obligation_id,
                EpactObligationState::Satisfied,
                &event.event_sha256,
            )?;
        }
        EpactRuntimeEventKind::ObligationFailed { obligation_id, .. } => {
            find_obligation(image, obligation_id)?;
            require_obligation_pending(state, obligation_id)?;
            set_terminal_state(
                state,
                obligation_id,
                EpactObligationState::Failed,
                &event.event_sha256,
            )?;
        }
        EpactRuntimeEventKind::ObligationCancelled { obligation_id, .. } => {
            find_obligation(image, obligation_id)?;
            require_obligation_pending(state, obligation_id)?;
            set_terminal_state(
                state,
                obligation_id,
                EpactObligationState::Cancelled,
                &event.event_sha256,
            )?;
        }
    }
    Ok(())
}

fn evaluate_obligation_request(
    image: &EpactProgramImage,
    state: &EpactRuntimeState,
    request: &EpactOperationRequest,
    obligation: &EpactObligation,
    blockers: &mut Vec<EpactEligibilityBlocker>,
) {
    let projection = state
        .obligations
        .iter()
        .find(|projection| projection.obligation_id == obligation.id);
    if !projection.is_some_and(|projection| projection.state == EpactObligationState::Pending) {
        blocker(
            blockers,
            "obligation_not_pending",
            &obligation.id,
            "the obligation has already reached a terminal state",
        );
    }
    if !request.resources.fits_within(&obligation.resources) {
        blocker(
            blockers,
            "obligation_resource_ceiling",
            &obligation.id,
            "requested resources exceed the obligation ceiling",
        );
    }

    let mut requested_effects = request.effects.clone();
    requested_effects.sort();
    requested_effects.dedup();
    if requested_effects != obligation.effects {
        blocker(
            blockers,
            "effect_mismatch",
            &obligation.id,
            "requested effects must exactly match the frozen obligation declaration",
        );
    }

    if let Some(expected_capability) = obligation_capability_id(&obligation.discharge) {
        if request.capability_id.as_deref() != Some(expected_capability) {
            blocker(
                blockers,
                "capability_mismatch",
                &obligation.id,
                "requested capability does not discharge this obligation",
            );
        }
    } else if request.capability_id.is_some() {
        blocker(
            blockers,
            "unexpected_capability",
            &obligation.id,
            "this obligation is not discharged by a capability",
        );
    }

    if operation_requires_ready_obligation(request.operation) {
        for dependency in &obligation.dependency_ids {
            if obligation_state(state, dependency) != Some(EpactObligationState::Satisfied) {
                blocker(
                    blockers,
                    "dependency_unsatisfied",
                    dependency,
                    "a required predecessor obligation is not satisfied",
                );
            }
        }
        for gate_id in &obligation.gate_ids {
            if !gate_satisfied(image, state, gate_id) {
                blocker(
                    blockers,
                    "gate_unsatisfied",
                    gate_id,
                    "a required gate predicate is false",
                );
            }
        }
    }
}

fn authority_allows(
    image: &EpactProgramImage,
    request: &EpactOperationRequest,
    resources: &EpactResourceEnvelope,
) -> bool {
    image.authorities.iter().any(|authority| {
        authority.principal_id == request.principal_id
            && authority.operation == request.operation
            && authority_scope_matches(authority, request)
            && authority_cost_allows(authority, resources.maximum_cost_usd)
            && authority_time_allows(authority, &request.requested_at)
    })
}

fn authority_time_allows(authority: &CompiledAuthority, requested_at: &str) -> bool {
    authority
        .valid_after
        .as_ref()
        .is_none_or(|after| requested_at >= after)
        && authority
            .valid_before
            .as_ref()
            .is_none_or(|before| requested_at < before)
}

fn authority_scope_matches(authority: &CompiledAuthority, request: &EpactOperationRequest) -> bool {
    authority.whole_program
        || request.obligation_id.as_ref().is_some_and(|id| {
            authority
                .obligation_ids
                .iter()
                .any(|candidate| candidate == id)
        })
        || request.capability_id.as_ref().is_some_and(|id| {
            authority
                .capability_ids
                .iter()
                .any(|candidate| candidate == id)
        })
}

fn authority_cost_allows(authority: &CompiledAuthority, requested_cost_usd: f64) -> bool {
    if requested_cost_usd <= 0.0 {
        return true;
    }
    authority
        .maximum_cost_microusd
        .is_some_and(|ceiling| (requested_cost_usd * 1_000_000.0).round() as u64 <= ceiling)
}

fn operation_requires_obligation(operation: KernelOperation) -> bool {
    matches!(
        operation,
        KernelOperation::Propose
            | KernelOperation::Authorize
            | KernelOperation::Reserve
            | KernelOperation::Dispatch
            | KernelOperation::Attest
            | KernelOperation::Evaluate
            | KernelOperation::Decide
            | KernelOperation::Publish
            | KernelOperation::Retract
    )
}

fn operation_requires_ready_obligation(operation: KernelOperation) -> bool {
    matches!(
        operation,
        KernelOperation::Reserve
            | KernelOperation::Dispatch
            | KernelOperation::Evaluate
            | KernelOperation::Decide
            | KernelOperation::Publish
            | KernelOperation::Retract
    )
}

fn obligation_capability_id(discharge: &EpactDischarge) -> Option<&str> {
    match discharge {
        EpactDischarge::Capability { capability_id }
        | EpactDischarge::Review { capability_id, .. } => Some(capability_id),
        _ => None,
    }
}

fn validate_state_shape(
    image: &EpactProgramImage,
    state: &EpactRuntimeState,
) -> Result<(), EpactRuntimeError> {
    if state.program_image_sha256 != image.image_sha256 {
        return Err(EpactRuntimeError::ImageBindingMismatch);
    }
    let expected = image
        .obligation_order
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actual = state
        .obligations
        .iter()
        .map(|projection| projection.obligation_id.as_str())
        .collect::<BTreeSet<_>>();
    if expected != actual || actual.len() != state.obligations.len() {
        return Err(EpactRuntimeError::InvalidState(
            "obligation projection does not match compiled image",
        ));
    }
    if !is_sorted_unique(&state.present_object_ids)
        || !is_sorted_unique(&state.satisfied_evidence_rule_ids)
    {
        return Err(EpactRuntimeError::InvalidState(
            "set projections must be sorted and unique",
        ));
    }
    Ok(())
}

fn require_obligation_pending(
    state: &EpactRuntimeState,
    obligation_id: &str,
) -> Result<(), EpactRuntimeError> {
    if obligation_state(state, obligation_id) != Some(EpactObligationState::Pending) {
        return Err(EpactRuntimeError::ObligationAlreadyTerminal(
            obligation_id.to_owned(),
        ));
    }
    Ok(())
}

fn require_dependencies(
    state: &EpactRuntimeState,
    obligation: &EpactObligation,
) -> Result<(), EpactRuntimeError> {
    for dependency in &obligation.dependency_ids {
        if obligation_state(state, dependency) != Some(EpactObligationState::Satisfied) {
            return Err(EpactRuntimeError::UnsatisfiedDependency {
                obligation_id: obligation.id.clone(),
                dependency_id: dependency.clone(),
            });
        }
    }
    Ok(())
}

fn require_gates(
    image: &EpactProgramImage,
    state: &EpactRuntimeState,
    obligation: &EpactObligation,
) -> Result<(), EpactRuntimeError> {
    for gate_id in &obligation.gate_ids {
        if !gate_satisfied(image, state, gate_id) {
            return Err(EpactRuntimeError::UnsatisfiedGate {
                obligation_id: obligation.id.clone(),
                gate_id: gate_id.clone(),
            });
        }
    }
    Ok(())
}

fn require_discharge_objects(
    state: &EpactRuntimeState,
    obligation: &EpactObligation,
) -> Result<(), EpactRuntimeError> {
    let mut required = obligation.output_object_ids.clone();
    match &obligation.discharge {
        EpactDischarge::Decision { decision_object_id } => {
            required.push(decision_object_id.clone())
        }
        EpactDischarge::Review {
            review_object_id, ..
        } => required.push(review_object_id.clone()),
        EpactDischarge::Publication {
            artifact_object_ids,
        } => required.extend(artifact_object_ids.iter().cloned()),
        _ => {}
    }
    required.sort();
    required.dedup();
    for object_id in required {
        if state.present_object_ids.binary_search(&object_id).is_err() {
            return Err(EpactRuntimeError::MissingDischargeObject {
                obligation_id: obligation.id.clone(),
                object_id,
            });
        }
    }
    Ok(())
}

fn require_discharge_evidence(
    state: &EpactRuntimeState,
    obligation: &EpactObligation,
) -> Result<(), EpactRuntimeError> {
    if let EpactDischarge::Evidence { evidence_rule_ids } = &obligation.discharge {
        for rule_id in evidence_rule_ids {
            if state
                .satisfied_evidence_rule_ids
                .binary_search(rule_id)
                .is_err()
            {
                return Err(EpactRuntimeError::UnsatisfiedEvidence {
                    obligation_id: obligation.id.clone(),
                    evidence_rule_id: rule_id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn gate_satisfied(image: &EpactProgramImage, state: &EpactRuntimeState, gate_id: &str) -> bool {
    image
        .program
        .gates
        .iter()
        .find(|gate| gate.id == gate_id)
        .is_some_and(|gate| predicate_satisfied(&gate.predicate, state))
}

fn predicate_satisfied(predicate: &EpactPredicate, state: &EpactRuntimeState) -> bool {
    match predicate {
        EpactPredicate::All { predicates } => predicates
            .iter()
            .all(|predicate| predicate_satisfied(predicate, state)),
        EpactPredicate::Any { predicates } => predicates
            .iter()
            .any(|predicate| predicate_satisfied(predicate, state)),
        EpactPredicate::Not { predicate } => !predicate_satisfied(predicate, state),
        EpactPredicate::ObligationSatisfied { obligation_id } => {
            obligation_state(state, obligation_id) == Some(EpactObligationState::Satisfied)
        }
        EpactPredicate::EvidenceSatisfied { evidence_rule_id } => state
            .satisfied_evidence_rule_ids
            .binary_search(evidence_rule_id)
            .is_ok(),
        EpactPredicate::ObjectPresent { object_id } => {
            state.present_object_ids.binary_search(object_id).is_ok()
        }
    }
}

fn find_obligation<'a>(
    image: &'a EpactProgramImage,
    obligation_id: &str,
) -> Result<&'a EpactObligation, EpactRuntimeError> {
    image
        .program
        .obligations
        .iter()
        .find(|obligation| obligation.id == obligation_id)
        .ok_or_else(|| EpactRuntimeError::UnknownObligation(obligation_id.to_owned()))
}

fn obligation_state(
    state: &EpactRuntimeState,
    obligation_id: &str,
) -> Option<EpactObligationState> {
    state
        .obligations
        .iter()
        .find(|projection| projection.obligation_id == obligation_id)
        .map(|projection| projection.state)
}

fn set_terminal_state(
    state: &mut EpactRuntimeState,
    obligation_id: &str,
    terminal: EpactObligationState,
    event_sha256: &str,
) -> Result<(), EpactRuntimeError> {
    let projection = state
        .obligations
        .iter_mut()
        .find(|projection| projection.obligation_id == obligation_id)
        .ok_or_else(|| EpactRuntimeError::UnknownObligation(obligation_id.to_owned()))?;
    projection.state = terminal;
    projection.terminal_event_sha256 = Some(event_sha256.to_owned());
    Ok(())
}

fn insert_sorted_unique(values: &mut Vec<String>, value: String) {
    match values.binary_search(&value) {
        Ok(_) => {}
        Err(index) => values.insert(index, value),
    }
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn blocker(
    blockers: &mut Vec<EpactEligibilityBlocker>,
    code: &str,
    subject_id: &str,
    message: &str,
) {
    blockers.push(EpactEligibilityBlocker {
        code: code.to_owned(),
        subject_id: subject_id.to_owned(),
        message: message.to_owned(),
    });
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EpactRuntimeError {
    #[error("invalid Epact program image: {0}")]
    InvalidImage(String),
    #[error("invalid Epact runtime event: {0}")]
    InvalidEvent(String),
    #[error("runtime state or event is bound to another program image")]
    ImageBindingMismatch,
    #[error("expected event sequence {expected}, found {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
    #[error("event {0} does not extend the current event hash")]
    BrokenEventChain(String),
    #[error("duplicate event id {0}")]
    DuplicateEventId(String),
    #[error("duplicate idempotency key {0}")]
    DuplicateIdempotencyKey(String),
    #[error("unknown principal {0}")]
    UnknownPrincipal(String),
    #[error("unknown object {0}")]
    UnknownObject(String),
    #[error("unknown evidence rule {0}")]
    UnknownEvidenceRule(String),
    #[error("unknown obligation {0}")]
    UnknownObligation(String),
    #[error("evidence rule {0} has too few recorded observations")]
    InsufficientEvidence(String),
    #[error("evidence rule {0} requires an independent-review receipt")]
    IndependentReviewRequired(String),
    #[error("obligation {0} already reached a terminal state")]
    ObligationAlreadyTerminal(String),
    #[error("obligation {obligation_id} requires unsatisfied dependency {dependency_id}")]
    UnsatisfiedDependency {
        obligation_id: String,
        dependency_id: String,
    },
    #[error("obligation {obligation_id} requires unsatisfied gate {gate_id}")]
    UnsatisfiedGate {
        obligation_id: String,
        gate_id: String,
    },
    #[error("obligation {obligation_id} requires missing object {object_id}")]
    MissingDischargeObject {
        obligation_id: String,
        object_id: String,
    },
    #[error("obligation {obligation_id} requires unsatisfied evidence rule {evidence_rule_id}")]
    UnsatisfiedEvidence {
        obligation_id: String,
        evidence_rule_id: String,
    },
    #[error("obligation {obligation_id} requires receipt contract {expected}, found {actual}")]
    ReceiptContractMismatch {
        obligation_id: String,
        expected: String,
        actual: String,
    },
    #[error("invalid Epact runtime state: {0}")]
    InvalidState(&'static str),
}

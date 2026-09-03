use concord_protocol::{
    AuthorizeCampaignDispatchRequest, CampaignDispatchPermit, DispatchContractError,
    DispatchOperation, DispatchPermitStatus, InterruptedDispatchResolution,
    ResolveInterruptedDispatchRequest, CAMPAIGN_DISPATCH_PERMIT_CONTRACT,
};

fn request() -> AuthorizeCampaignDispatchRequest {
    AuthorizeCampaignDispatchRequest {
        generation: 3,
        idempotency_key: "dispatch:campaign-a:job-7".to_owned(),
        actor: "operator:alice".to_owned(),
        operation: DispatchOperation::ExternalJob,
        target_id: "job:7".to_owned(),
        budget_id: Some("budget:campaign-a".to_owned()),
        maximum_cost_usd: 12.5,
        reserve_budget: true,
        budget_pre_reserved: false,
        maximum_elapsed_seconds: 900,
    }
}

fn permit(status: DispatchPermitStatus) -> CampaignDispatchPermit {
    CampaignDispatchPermit {
        contract: CAMPAIGN_DISPATCH_PERMIT_CONTRACT.to_owned(),
        token: "permit:7".to_owned(),
        campaign_id: "campaign:a".to_owned(),
        generation: 3,
        idempotency_key: "dispatch:campaign-a:job-7".to_owned(),
        actor: "operator:alice".to_owned(),
        operation: DispatchOperation::ExternalJob,
        target_id: "job:7".to_owned(),
        budget_id: Some("budget:campaign-a".to_owned()),
        maximum_cost_usd: 12.5,
        reserve_budget: true,
        budget_pre_reserved: false,
        reconciliation_sha256: "a".repeat(64),
        status,
        issued_at: "2026-09-03T08:00:00Z".to_owned(),
        deadline_at: "2026-09-03T08:15:00Z".to_owned(),
        consumed_at: (status != DispatchPermitStatus::Authorized)
            .then(|| "2026-09-03T08:01:00Z".to_owned()),
        settled_at: (status == DispatchPermitStatus::Settled)
            .then(|| "2026-09-03T08:02:00Z".to_owned()),
        actual_cost_usd: (status == DispatchPermitStatus::Settled).then_some(4.25),
        settlement_basis: (status == DispatchPermitStatus::Settled)
            .then(|| "provider usage receipt".to_owned()),
        interruption: (status == DispatchPermitStatus::Interrupted)
            .then(|| "provider response missing usage".to_owned()),
        released_at: (status == DispatchPermitStatus::Released)
            .then(|| "2026-09-03T08:02:00Z".to_owned()),
        resolution_evidence_sha256: None,
        resolved_by: None,
    }
}

#[test]
fn dispatch_request_rejects_ambiguous_or_unbounded_accounting() {
    assert!(request().validate().is_ok());

    let mut missing_budget = request();
    missing_budget.budget_id = None;
    assert_eq!(
        missing_budget.validate(),
        Err(DispatchContractError::PaidDispatchMissingBudget)
    );

    let mut double_reserved = request();
    double_reserved.budget_pre_reserved = true;
    assert_eq!(
        double_reserved.validate(),
        Err(DispatchContractError::ConflictingReservationModes)
    );
}

#[test]
fn permit_validation_binds_lifecycle_to_terminal_fields() {
    for status in [
        DispatchPermitStatus::Authorized,
        DispatchPermitStatus::Consumed,
        DispatchPermitStatus::Settled,
        DispatchPermitStatus::Interrupted,
        DispatchPermitStatus::Released,
    ] {
        assert!(permit(status).validate().is_ok(), "{status:?}");
    }

    let mut impossible = permit(DispatchPermitStatus::Settled);
    impossible.actual_cost_usd = None;
    assert_eq!(
        impossible.validate(),
        Err(DispatchContractError::InconsistentPermitState)
    );
}

#[test]
fn wire_names_and_contract_identity_are_stable() {
    let encoded = serde_json::to_value(permit(DispatchPermitStatus::Authorized)).unwrap();
    assert_eq!(encoded["contract"], CAMPAIGN_DISPATCH_PERMIT_CONTRACT);
    assert_eq!(encoded["operation"], "external_job");
    assert_eq!(encoded["status"], "authorized");
    assert_eq!(encoded["maximumCostUsd"], 12.5);
    assert_eq!(encoded["reserveBudget"], true);
}

#[test]
fn interruption_resolution_requires_external_evidence() {
    let no_start = ResolveInterruptedDispatchRequest {
        actor: "operator:alice".to_owned(),
        resolution: InterruptedDispatchResolution::NoProviderStart,
        evidence_sha256: "b".repeat(64),
        actual_cost_usd: None,
        settlement_basis: None,
    };
    assert!(no_start.validate().is_ok());

    let mut unsupported = no_start;
    unsupported.actual_cost_usd = Some(0.0);
    assert_eq!(
        unsupported.validate(),
        Err(DispatchContractError::UnexpectedActualCost)
    );
}

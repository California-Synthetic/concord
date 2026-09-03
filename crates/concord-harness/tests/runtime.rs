use std::{cell::RefCell, error::Error, fmt};

use concord_harness::{DispatchAllocator, DispatchKernel, DispatchRuntimeError};
use concord_protocol::{
    AuthorizeCampaignDispatchRequest, CampaignDispatchPermit, DispatchOperation,
    DispatchPermitStatus, CAMPAIGN_DISPATCH_PERMIT_CONTRACT,
};

#[derive(Debug)]
struct FakeKernelError(&'static str);

impl fmt::Display for FakeKernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for FakeKernelError {}

struct FakeKernel {
    permit: RefCell<CampaignDispatchPermit>,
    calls: RefCell<Vec<&'static str>>,
    drift_on_authorize: bool,
}

impl FakeKernel {
    fn new(drift_on_authorize: bool) -> Self {
        Self {
            permit: RefCell::new(authorized_permit()),
            calls: RefCell::new(Vec::new()),
            drift_on_authorize,
        }
    }
}

impl DispatchKernel for FakeKernel {
    type Error = FakeKernelError;

    fn authorize_dispatch(
        &self,
        _campaign_id: &str,
        _request: &AuthorizeCampaignDispatchRequest,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.calls.borrow_mut().push("authorize");
        let mut permit = self.permit.borrow().clone();
        if self.drift_on_authorize {
            permit.target_id = "job:other".to_owned();
        }
        Ok(permit)
    }

    fn consume_dispatch(&self, _token: &str) -> Result<CampaignDispatchPermit, Self::Error> {
        self.calls.borrow_mut().push("consume");
        let mut permit = self.permit.borrow_mut();
        permit.status = DispatchPermitStatus::Consumed;
        permit.consumed_at = Some("2026-09-03T08:01:00Z".to_owned());
        Ok(permit.clone())
    }

    fn settle_dispatch(
        &self,
        _token: &str,
        actual_cost_usd: f64,
        settlement_basis: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.calls.borrow_mut().push("settle");
        let mut permit = self.permit.borrow_mut();
        permit.status = DispatchPermitStatus::Settled;
        permit.actual_cost_usd = Some(actual_cost_usd);
        permit.settlement_basis = Some(settlement_basis.to_owned());
        permit.settled_at = Some("2026-09-03T08:02:00Z".to_owned());
        permit.interruption = None;
        Ok(permit.clone())
    }

    fn interrupt_dispatch(
        &self,
        _token: &str,
        reason: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.calls.borrow_mut().push("interrupt");
        let mut permit = self.permit.borrow_mut();
        permit.status = DispatchPermitStatus::Interrupted;
        permit.interruption = Some(reason.to_owned());
        Ok(permit.clone())
    }

    fn release_dispatch(&self, _token: &str) -> Result<CampaignDispatchPermit, Self::Error> {
        self.calls.borrow_mut().push("release");
        let mut permit = self.permit.borrow_mut();
        permit.status = DispatchPermitStatus::Released;
        permit.released_at = Some("2026-09-03T08:02:00Z".to_owned());
        Ok(permit.clone())
    }
}

#[test]
fn allocator_composes_reserve_consume_and_settle() {
    let kernel = FakeKernel::new(false);
    let allocator = DispatchAllocator::new(&kernel);
    let mut allocation = allocator.reserve("campaign:a", &request()).unwrap();

    assert_eq!(allocation.permit().status, DispatchPermitStatus::Authorized);
    allocation.consume().unwrap();
    assert_eq!(allocation.permit().status, DispatchPermitStatus::Consumed);
    allocation.settle(4.25, "provider usage receipt").unwrap();
    assert_eq!(allocation.permit().status, DispatchPermitStatus::Settled);
    assert_eq!(
        kernel.calls.borrow().as_slice(),
        ["authorize", "consume", "settle"]
    );
}

#[test]
fn unconsumed_allocation_can_be_explicitly_released() {
    let kernel = FakeKernel::new(false);
    let allocator = DispatchAllocator::new(&kernel);
    let mut allocation = allocator.reserve("campaign:a", &request()).unwrap();
    allocation.release().unwrap();
    assert_eq!(allocation.permit().status, DispatchPermitStatus::Released);
    assert_eq!(kernel.calls.borrow().as_slice(), ["authorize", "release"]);
}

#[test]
fn dropping_a_handle_does_not_manufacture_a_release_receipt() {
    let kernel = FakeKernel::new(false);
    {
        let allocator = DispatchAllocator::new(&kernel);
        let _allocation = allocator.reserve("campaign:a", &request()).unwrap();
    }
    assert_eq!(kernel.calls.borrow().as_slice(), ["authorize"]);
}

#[test]
fn allocator_rejects_illegal_order_before_calling_the_kernel() {
    let kernel = FakeKernel::new(false);
    let allocator = DispatchAllocator::new(&kernel);
    let mut allocation = allocator.reserve("campaign:a", &request()).unwrap();
    let error = allocation
        .settle(4.25, "provider usage receipt")
        .unwrap_err();
    assert!(matches!(
        error,
        DispatchRuntimeError::IllegalLifecycle { .. }
    ));
    assert_eq!(kernel.calls.borrow().as_slice(), ["authorize"]);
}

#[test]
fn allocator_rejects_kernel_binding_drift() {
    let kernel = FakeKernel::new(true);
    let allocator = DispatchAllocator::new(&kernel);
    let error = match allocator.reserve("campaign:a", &request()) {
        Ok(_) => panic!("drifted permit must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, DispatchRuntimeError::KernelInvariant(_)));
}

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

fn authorized_permit() -> CampaignDispatchPermit {
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
        status: DispatchPermitStatus::Authorized,
        issued_at: "2026-09-03T08:00:00Z".to_owned(),
        deadline_at: "2026-09-03T08:15:00Z".to_owned(),
        consumed_at: None,
        settled_at: None,
        actual_cost_usd: None,
        settlement_basis: None,
        interruption: None,
        released_at: None,
        resolution_evidence_sha256: None,
        resolved_by: None,
    }
}

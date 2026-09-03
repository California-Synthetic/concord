use std::{error::Error, fmt};

use concord_protocol::{
    AuthorizeCampaignDispatchRequest, CampaignDispatchPermit, DispatchContractError,
    DispatchPermitStatus,
};

/// Product or reference-kernel boundary used by the portable runtime library.
///
/// Implementations own storage, authentication, clocks, credentials, provider calls, and durable
/// authority. The harness only composes the legal permit lifecycle and validates returned records.
pub trait DispatchKernel {
    type Error;

    fn authorize_dispatch(
        &self,
        campaign_id: &str,
        request: &AuthorizeCampaignDispatchRequest,
    ) -> Result<CampaignDispatchPermit, Self::Error>;

    fn consume_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit, Self::Error>;

    fn settle_dispatch(
        &self,
        token: &str,
        actual_cost_usd: f64,
        settlement_basis: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error>;

    fn interrupt_dispatch(
        &self,
        token: &str,
        reason: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error>;

    fn release_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit, Self::Error>;
}

/// Safe, provider-neutral allocation facade over the dispatch syscall family.
pub struct DispatchAllocator<'kernel, Kernel> {
    kernel: &'kernel Kernel,
}

impl<'kernel, Kernel> DispatchAllocator<'kernel, Kernel>
where
    Kernel: DispatchKernel,
{
    pub fn new(kernel: &'kernel Kernel) -> Self {
        Self { kernel }
    }

    /// Atomically obtains bounded authority and, when requested, reserves its maximum spend.
    pub fn reserve(
        &self,
        campaign_id: &str,
        request: &AuthorizeCampaignDispatchRequest,
    ) -> Result<DispatchAllocation<'kernel, Kernel>, DispatchRuntimeError<Kernel::Error>> {
        request.validate().map_err(DispatchRuntimeError::Contract)?;
        let permit = self
            .kernel
            .authorize_dispatch(campaign_id, request)
            .map_err(DispatchRuntimeError::Kernel)?;
        validate_initial_permit(campaign_id, request, &permit)?;
        Ok(DispatchAllocation {
            kernel: self.kernel,
            permit,
        })
    }
}

/// A checked handle to one durable dispatch allocation.
///
/// Dropping the handle does not claim that authority was released. The kernel remains responsible
/// for expiring an unconsumed permit and reconciling an ambiguous consumed permit.
pub struct DispatchAllocation<'kernel, Kernel>
where
    Kernel: DispatchKernel,
{
    kernel: &'kernel Kernel,
    permit: CampaignDispatchPermit,
}

impl<Kernel> DispatchAllocation<'_, Kernel>
where
    Kernel: DispatchKernel,
{
    pub fn permit(&self) -> &CampaignDispatchPermit {
        &self.permit
    }

    /// Cross the external-start boundary exactly once.
    pub fn consume(
        &mut self,
    ) -> Result<&CampaignDispatchPermit, DispatchRuntimeError<Kernel::Error>> {
        self.require_status(DispatchPermitStatus::Authorized)?;
        let next = self
            .kernel
            .consume_dispatch(&self.permit.token)
            .map_err(DispatchRuntimeError::Kernel)?;
        self.accept_successor(next, DispatchPermitStatus::Consumed)?;
        Ok(&self.permit)
    }

    /// Record provider-reported cost and close a consumed allocation.
    pub fn settle(
        &mut self,
        actual_cost_usd: f64,
        settlement_basis: &str,
    ) -> Result<&CampaignDispatchPermit, DispatchRuntimeError<Kernel::Error>> {
        if !matches!(
            self.permit.status,
            DispatchPermitStatus::Consumed | DispatchPermitStatus::Interrupted
        ) {
            return Err(DispatchRuntimeError::IllegalLifecycle {
                expected: "consumed or interrupted",
                actual: self.permit.status,
            });
        }
        let settlement_basis = settlement_basis.trim();
        if !actual_cost_usd.is_finite() || actual_cost_usd < 0.0 || settlement_basis.is_empty() {
            return Err(DispatchRuntimeError::InvalidSettlement);
        }
        let next = self
            .kernel
            .settle_dispatch(&self.permit.token, actual_cost_usd, settlement_basis)
            .map_err(DispatchRuntimeError::Kernel)?;
        self.accept_successor(next, DispatchPermitStatus::Settled)?;
        if self.permit.actual_cost_usd != Some(actual_cost_usd)
            || self.permit.settlement_basis.as_deref() != Some(settlement_basis)
        {
            return Err(DispatchRuntimeError::KernelInvariant(
                "settlement receipt differs from the submitted accounting",
            ));
        }
        Ok(&self.permit)
    }

    /// Preserve an ambiguous external start for operator reconciliation.
    pub fn interrupt(
        &mut self,
        reason: &str,
    ) -> Result<&CampaignDispatchPermit, DispatchRuntimeError<Kernel::Error>> {
        self.require_status(DispatchPermitStatus::Consumed)?;
        if reason.trim().is_empty() {
            return Err(DispatchRuntimeError::InvalidInterruption);
        }
        let next = self
            .kernel
            .interrupt_dispatch(&self.permit.token, reason)
            .map_err(DispatchRuntimeError::Kernel)?;
        self.accept_successor(next, DispatchPermitStatus::Interrupted)?;
        Ok(&self.permit)
    }

    /// Return authority that never crossed the external-start boundary.
    pub fn release(
        &mut self,
    ) -> Result<&CampaignDispatchPermit, DispatchRuntimeError<Kernel::Error>> {
        self.require_status(DispatchPermitStatus::Authorized)?;
        let next = self
            .kernel
            .release_dispatch(&self.permit.token)
            .map_err(DispatchRuntimeError::Kernel)?;
        self.accept_successor(next, DispatchPermitStatus::Released)?;
        Ok(&self.permit)
    }

    fn require_status(
        &self,
        expected: DispatchPermitStatus,
    ) -> Result<(), DispatchRuntimeError<Kernel::Error>> {
        if self.permit.status != expected {
            return Err(DispatchRuntimeError::IllegalLifecycle {
                expected: expected.as_str(),
                actual: self.permit.status,
            });
        }
        Ok(())
    }

    fn accept_successor(
        &mut self,
        next: CampaignDispatchPermit,
        expected: DispatchPermitStatus,
    ) -> Result<(), DispatchRuntimeError<Kernel::Error>> {
        next.validate().map_err(DispatchRuntimeError::Contract)?;
        if !same_binding(&self.permit, &next) {
            return Err(DispatchRuntimeError::KernelInvariant(
                "dispatch successor changed immutable permit bindings",
            ));
        }
        if next.status != expected {
            return Err(DispatchRuntimeError::IllegalLifecycle {
                expected: expected.as_str(),
                actual: next.status,
            });
        }
        self.permit = next;
        Ok(())
    }
}

#[derive(Debug)]
pub enum DispatchRuntimeError<KernelError> {
    Contract(DispatchContractError),
    Kernel(KernelError),
    IllegalLifecycle {
        expected: &'static str,
        actual: DispatchPermitStatus,
    },
    InvalidSettlement,
    InvalidInterruption,
    KernelInvariant(&'static str),
}

impl<KernelError> fmt::Display for DispatchRuntimeError<KernelError>
where
    KernelError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid dispatch contract: {error}"),
            Self::Kernel(error) => write!(formatter, "kernel dispatch failed: {error}"),
            Self::IllegalLifecycle { expected, actual } => write!(
                formatter,
                "dispatch lifecycle requires {expected}, found {}",
                actual.as_str()
            ),
            Self::InvalidSettlement => formatter
                .write_str("settlement requires finite non-negative cost and a non-empty basis"),
            Self::InvalidInterruption => {
                formatter.write_str("dispatch interruption requires a non-empty reason")
            }
            Self::KernelInvariant(message) => {
                write!(formatter, "kernel invariant failed: {message}")
            }
        }
    }
}

impl<KernelError> Error for DispatchRuntimeError<KernelError> where
    KernelError: fmt::Debug + fmt::Display + 'static
{
}

fn validate_initial_permit<KernelError>(
    campaign_id: &str,
    request: &AuthorizeCampaignDispatchRequest,
    permit: &CampaignDispatchPermit,
) -> Result<(), DispatchRuntimeError<KernelError>> {
    permit.validate().map_err(DispatchRuntimeError::Contract)?;
    if permit.status != DispatchPermitStatus::Authorized {
        return Err(DispatchRuntimeError::IllegalLifecycle {
            expected: DispatchPermitStatus::Authorized.as_str(),
            actual: permit.status,
        });
    }
    if permit.campaign_id != campaign_id
        || permit.generation != request.generation
        || permit.idempotency_key != request.idempotency_key
        || permit.actor != request.actor
        || permit.operation != request.operation
        || permit.target_id != request.target_id
        || permit.budget_id != request.budget_id
        || permit.maximum_cost_usd != request.maximum_cost_usd
        || permit.reserve_budget != request.reserve_budget
        || permit.budget_pre_reserved != request.budget_pre_reserved
        || permit.epact != request.epact
    {
        return Err(DispatchRuntimeError::KernelInvariant(
            "authorized permit differs from the requested authority",
        ));
    }
    Ok(())
}

fn same_binding(left: &CampaignDispatchPermit, right: &CampaignDispatchPermit) -> bool {
    left.contract == right.contract
        && left.token == right.token
        && left.campaign_id == right.campaign_id
        && left.generation == right.generation
        && left.idempotency_key == right.idempotency_key
        && left.actor == right.actor
        && left.operation == right.operation
        && left.target_id == right.target_id
        && left.budget_id == right.budget_id
        && left.maximum_cost_usd == right.maximum_cost_usd
        && left.reserve_budget == right.reserve_budget
        && left.budget_pre_reserved == right.budget_pre_reserved
        && left.epact == right.epact
        && left.reconciliation_sha256 == right.reconciliation_sha256
        && left.issued_at == right.issued_at
        && left.deadline_at == right.deadline_at
}

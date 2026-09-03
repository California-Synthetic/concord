use anyhow::Error;
use concord_harness::DispatchKernel;
use concord_protocol::{AuthorizeCampaignDispatchRequest, CampaignDispatchPermit};

use crate::Database;

impl DispatchKernel for Database {
    type Error = Error;

    fn authorize_dispatch(
        &self,
        campaign_id: &str,
        request: &AuthorizeCampaignDispatchRequest,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.authorize_campaign_dispatch(campaign_id, request)
    }

    fn consume_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit, Self::Error> {
        self.consume_campaign_dispatch(token)
    }

    fn settle_dispatch(
        &self,
        token: &str,
        actual_cost_usd: f64,
        settlement_basis: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.settle_campaign_dispatch(token, actual_cost_usd, settlement_basis)
    }

    fn interrupt_dispatch(
        &self,
        token: &str,
        reason: &str,
    ) -> Result<CampaignDispatchPermit, Self::Error> {
        self.interrupt_campaign_dispatch(token, reason)
    }

    fn release_dispatch(&self, token: &str) -> Result<CampaignDispatchPermit, Self::Error> {
        self.release_campaign_dispatch(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_implements_the_public_dispatch_kernel() {
        fn assert_kernel<Kernel: DispatchKernel<Error = Error>>() {}
        assert_kernel::<Database>();
    }
}

//! The pre-claim confirmation summary (RFP-017 U4): claimable amount, estimated fee, and whether
//! the fee payer can cover it.

/// Where the claim's tokens go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationKind {
    Public,
    Private,
}

/// Everything the mini-app and the CLI show before a claim is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreClaimSummary {
    pub schedule_account: lee_core::account::AccountId,
    pub asset: String,
    pub claimable_now: u128,
    pub requested_amount: u128,
    /// Execution gas: public cycles (+ `PRIVATE_VERIFY_GAS` on the private path).
    pub estimated_exec_gas: u64,
    /// Storage gas: transaction bytes (public) or the flat `PRIVATE_GAS_STOR` (private).
    pub estimated_stor_gas: u64,
    /// The fee at today's base fees.
    pub estimated_fee_native: u128,
    /// What the payer must hold: the public reserve (`gas_limit`-priced) or the private in-proof
    /// reserve (the fee at the headroom ceilings).
    pub required_balance_native: u128,
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
    /// A label for the fee payer: a public address, or "private account <wallet label>" (the
    /// private payer's id is never printed by default).
    pub fee_payer: String,
    pub fee_payer_balance: u128,
    pub sufficient_gas: bool,
    pub destination_kind: DestinationKind,
}

impl PreClaimSummary {
    #[must_use]
    pub fn render(&self) -> String {
        let kind = match self.destination_kind {
            DestinationKind::Public => "public account",
            DestinationKind::Private => "private account (through a one-time alias)",
        };
        let gas = if self.sufficient_gas { "yes" } else { "NO" };
        format!(
            "Claim summary\n\
             - schedule:            {}\n\
             - asset:               {}\n\
             - claimable now:       {}\n\
             - this claim:          {}\n\
             - destination:         {kind}\n\
             - estimated fee:       {} native units ({} execution gas x {} + {} storage gas x {})\n\
             - fee payer:           {} (holds {}; needs {})\n\
             - enough for the fee:  {gas}\n",
            self.schedule_account,
            self.asset,
            self.claimable_now,
            self.requested_amount,
            self.estimated_fee_native,
            self.estimated_exec_gas,
            self.base_fee_exec,
            self.estimated_stor_gas,
            self.base_fee_stor,
            self.fee_payer,
            self.fee_payer_balance,
            self.required_balance_native,
        )
    }
}

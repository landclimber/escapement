# Events (F6)

Escapement emits one LEZ `ProgramEvent` per state transition through `Response::event` (LEZ v0.4's
native event mechanism, the successor of LP-0012). Each event is `{ selector, data }`:

- `selector`: 8 bytes, `sha256("escapement::<EventName>")[..8]`, precomputed as a constant in
  `crates/escapement-core/src/event.rs` and checked against SHA-256 by the unit test
  `event::tests::compile_time_selectors_match_sha256`;
- `data`: the Borsh encoding of the event struct below, fields in the order listed.

The same schema is in the SPEL IDL (`idl/escapement.idl.json`, `events`), generated from the source
and drift-checked by `crates/escapement-idl/tests/idl.rs`.

| Transition (RFP F6) | Event | Selector (hex) |
|---|---|---|
| schedule creation (single and each batch entry) | `ScheduleCreated` | `19b9a1a1b4aa6bf0` |
| claim (public and private) | `Claimed` | `b60e4b76d5a97ea4` |
| cancellation | `Cancelled` | `07845bd4d6cc2519` |
| milestone signal | `MilestoneSignaled` | `df390f1f9e9c7ad1` |
| beneficiary transfer | `BeneficiaryTransferred` | `e036c24529f4bfe1` |
| conversion to non-cancelable | `MadeNonCancelable` | `3ea301a9e70190c2` |
| fee configuration | `FeeConfigUpdated` | `276e3d2350da1865` |
| fee withdrawal | `FeeWithdrawn` | `8eee04e4d493ecc4` |

## Fields

Types: `AccountId` = 32 bytes; `Asset` = Borsh enum, tag `0` `Native`, tag `1` `Token { definition: AccountId }`;
`Option<T>` = `0` or `1` then `T`; integers little-endian.

**`ScheduleCreated`**: `schedule_id: AccountId`, `batch_id: Option<[u8; 32]>` (set for batch entries),
`creator: AccountId`, `beneficiary: AccountId`, `asset: Asset`, `escrow_account: AccountId`,
`refund_holding: AccountId`, `total_amount: u128`, `kind_tag: u8` (`0` cliff+linear, `1` linear,
`2` milestone), `cancelable: bool`, `transferable: bool`, `cancel_authority: Option<AccountId>`,
`milestone_authority: Option<AccountId>`.

**`Claimed`**: `schedule_id: AccountId`, `beneficiary: AccountId`, `amount: u128`,
`total_claimed: u128`, `timestamp_ms: u64` (the clock for a public claim; the claim's
`effective_ts` for a private claim).

**`Cancelled`**: `schedule_id: AccountId`, `cancelled_by: AccountId`, `cancelled_at_ms: u64`,
`vested_at_cancel: u128` (never below what was already claimed), `refunded_amount: u128`,
`refund_holding: AccountId`.

**`MilestoneSignaled`**: `schedule_id: AccountId`, `milestone_index: u8`, `amount_unlocked: u128`,
`signaled_by: AccountId`, `unlocked_at_ms: u64`.

**`BeneficiaryTransferred`**: `schedule_id: AccountId`, `old_beneficiary: AccountId`,
`new_beneficiary: AccountId`.

**`MadeNonCancelable`**: `schedule_id: AccountId`, `by: AccountId`.

**`FeeConfigUpdated`**: `token_program_id: AccountId`, `fee_bps: u16`, `fee_treasury: Option<AccountId>`.

**`FeeWithdrawn`**: `asset: Asset`, `amount: u128`, `withdrawn_by: AccountId`.

## Privacy

No event carries a claim's destination. On a private claim, `Claimed` is emitted by the schedule
actor, which runs in the transaction's public part; the destination is a one-time blinded alias that
appears only in the `ClaimExact` message, and the private account behind it appears nowhere in the
transaction's public bytes (checked by `adversarial_20_claim_privacy_linkability_suite` and, on the
sequencer, by `e2e/run_e2e.sh`'s `claim-private-applied` step). `FeeWithdrawn` omits its destination too.

## Reading events

On LEZ `v0.4.0-rc3`, `getEvents` is an RPC of the **indexer** service (`lez/indexer/service/rpc`),
not of the sequencer: a standalone sequencer answers it with `Method not found` (recorded by
`e2e/run_e2e.sh`, step `getEvents-observation`), and the sequencer stores a block's events with the
blocks it finalizes through Bedrock (`lez/sequencer/core/src/lib.rs`, `apply_finalized`). So events
cannot be read back from the standalone sequencer the suite runs on. Every event's fields are
asserted in the in-process tests on LEZ's own state machine (`crates/escapement-tests`, including the
`Claimed` event of private claims); reading them back through an indexer on LEZ testnet 0.4 is part of
the testnet milestone.

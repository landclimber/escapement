//! Real-ELF integration, security-regression, privacy, invariant, and cycle-benchmark suite
//! for Escapement on LEZ v0.4.0-rc3.
//!
//! Runs the real compiled RISC Zero guest ELFs (`ESCAPEMENT_ELF`, `TOKEN_ELF`, `CLOCK_ELF`)
//! through LEZ v0.4.0-rc3's `V03State`, `ValidatedStateDiff`, `simulate_public_transaction`,
//! `simulate_privacy_preserving_transaction`, and `execute_and_prove`.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use borsh::BorshSerialize;
use clock_core::{clock_account_id, clock_actor, ClockAccountData, CLOCK_PROGRAM_ACCOUNT_ID};
use escapement_core::{
    batch_coord_pda, batch_escrow_pda, batch_schedule_pda, config_pda,
    event::{
        BeneficiaryTransferred, Cancelled, Claimed, FeeConfigUpdated, FeeWithdrawn,
        MadeNonCancelable, MilestoneSignaled, ScheduleCreated, VestingEvent,
    },
    fee_vault_pda, schedule_pda, single_escrow_pda, Asset, BatchCreateParams, BatchRecipient,
    BrokerFee, Config, CreateScheduleParams, Message as VestingMessage, MilestoneTranche, PdaCall,
    ScheduleAccount, ScheduleKind, VestingActorState, MAX_BROKER_FEE_BPS, ZERO_ACCOUNT_ID,
};
use escapement_methods::{ESCAPEMENT_ELF, ESCAPEMENT_ID};
use escapement_test_methods::{RelayMessage, RELAY_ELF};
use lee::{
    error::LeeError,
    privacy_preserving_transaction::{
        circuit::{
            execute_and_prove, simulate_privacy_preserving_transaction,
            simulate_public_transaction, ProgramCatalog, Proof, Simulation,
        },
        Message as PrivateTxMessage, WitnessSet as PrivateWitnessSet,
    },
    program::Program,
    public_transaction::{Message as PublicTxMessage, WitnessSet as PublicWitnessSet},
    test_utils::{init_witness, no_seal, update_witness, TestPrivateKeys},
    PrivacyPreservingTransaction, PrivateKey, PublicKey, PublicTransaction, V03State,
    ValidatedStateDiff,
};
use lee_core::{
    account::{Account, AccountId, Actor},
    execution_state::{BoundaryStep, PublicExecutionContext, TransactionEntry},
    program::PdaSeed,
    program::TransactionEvent,
    AuthorizationSecretKey, Commitment, EncryptionScheme, PrivacyPreservingCircuitOutput,
    ProvingInput, RegularKey, RootCall, SenderPresentation, SharedSecretKey, WitnessKind,
};
use lez_admin_authority::{admin_op, AdminOp};
use lez_authority::Wire;
use risc0_zkvm::InnerReceipt;
use token_core::{Message as TokenMessage, TokenHolding, TokenState};
use token_methods::TOKEN_ELF;

const MAX_GAS_EXEC: u64 = 10_000_000;
/// Two program ids running the test relay guest (a third-party program, a multisig, a launchpad).
const RELAY_A: AccountId = AccountId::new([0x7a; 32]);
const RELAY_B: AccountId = AccountId::new([0x7b; 32]);
/// LEZ v0.4's native balance program (`NATIVE_TOKEN_PROGRAM_ID`).
const NATIVE: AccountId = escapement_core::NATIVE_PROGRAM_ID;

fn key(byte: u8) -> PrivateKey {
    PrivateKey::try_new([byte; 32]).expect("valid test key")
}

fn account(k: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(k))
}

fn assert_refused<T: std::fmt::Debug>(res: &Result<T, LeeError>, needle: &str) {
    assert!(
        matches!(res, Err(LeeError::ProgramExecutionFailed(msg)) if msg.contains(needle)),
        "expected ProgramExecutionFailed containing {needle:?}, got {res:?}"
    );
}

/// Verifies a cycle-metered non-zero guest exit (`env::exit(code)`), proving the caller
/// pays only actual cycles executed rather than the full `gas_limit`.
/// LEZ v0.4 refuses a message to a never-initialized account that carries no admission
/// evidence; the whole transaction is rejected before the token program runs.
fn assert_unadmitted<T: std::fmt::Debug>(res: &Result<T, LeeError>, account_id: AccountId) {
    let msg = format!("{res:?}");
    assert!(
        msg.contains("UnadmittedPublicActor") && msg.contains(&format!("{account_id:?}")),
        "expected UnadmittedPublicActor for {account_id:?}, got {msg}"
    );
}

fn assert_exit_code<T: std::fmt::Debug>(res: &Result<T, LeeError>, expected_code: u32) -> u64 {
    match res {
        Err(LeeError::ProgramExitedWithCode { code, cycles }) if *code == expected_code => {
            assert!(
                *cycles > 0 && *cycles < MAX_GAS_EXEC,
                "expected metered cycles in (0, {MAX_GAS_EXEC}), got {cycles}"
            );
            *cycles
        }
        other => {
            panic!("expected ProgramExitedWithCode {{ code: {expected_code} }}, got {other:?}")
        }
    }
}

fn events_of<E: VestingEvent + borsh::BorshDeserialize>(events: &[TransactionEvent]) -> Vec<E> {
    events
        .iter()
        .filter(|e| e.event.selector == E::SELECTOR)
        .map(|e| borsh::from_slice(&e.event.data).expect("event payload decodes"))
        .collect()
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

struct PrivateWallet {
    keys: TestPrivateKeys,
    account: Option<Account>,
}

impl PrivateWallet {
    fn new(byte: u8) -> Self {
        Self {
            keys: TestPrivateKeys {
                ask: AuthorizationSecretKey([byte; 32]),
                d: [byte; 32],
                z: [byte; 32],
            },
            account: None,
        }
    }

    fn id(&self) -> AccountId {
        self.keys.account_id()
    }

    fn npk_bytes(&self) -> [u8; 32] {
        self.keys.npk().0
    }

    fn vpk_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self.keys.vpk()).expect("vpk encodes")
    }

    fn balance(&self, token_prog: AccountId) -> u128 {
        let acct = self.account.as_ref().expect("private account committed");
        match TokenState::decode(acct.data.actor_state(token_prog)) {
            Some(TokenState::Holding(TokenHolding { balance, .. })) => balance,
            other => panic!("expected private token holding, got {other:?}"),
        }
    }
}

struct PrivateClaimArgs<'a> {
    beneficiary_key: &'a PrivateKey,
    schedule_id: AccountId,
    blinding_factor: [u8; 32],
    random_seed: [u8; 32],
    amount: u128,
    effective_ts: u64,
    promote_credit: bool,
}

struct PrivateClaimResult {
    output: PrivacyPreservingCircuitOutput,
    proof: Proof,
    tx_msg: PrivateTxMessage,
    events: Vec<TransactionEvent>,
    pub_cycles: u64,
}

impl std::fmt::Debug for PrivateClaimResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateClaimResult")
            .field("events", &self.events.len())
            .field("pub_cycles", &self.pub_cycles)
            .finish_non_exhaustive()
    }
}

struct TestChain {
    state: V03State,
    vesting: AccountId,
    token: AccountId,
    /// Header block id of the block currently being built.
    block_id: u64,
    /// Block id last written into `clock_actor()` (lags `block_id` by one inside a block,
    /// because on LEZ v0.4.0-rc3 `Clock::Tick` is the last transaction of each block).
    clock_block_id: u64,
    timestamp_ms: u64,
}

impl TestChain {
    fn new_unconfigured(initial_ts_ms: u64) -> Self {
        Self::new_unconfigured_funded(initial_ts_ms, &[])
    }

    /// Like `new_unconfigured`, with genesis native balances for `funded` accounts.
    fn new_unconfigured_funded(initial_ts_ms: u64, funded: &[(AccountId, u128)]) -> Self {
        let deployer = key(100);
        let vesting = account(&deployer);
        let token = AccountId::new([0x70; 32]);
        let clock_data = ClockAccountData {
            block_id: 1,
            timestamp: initial_ts_ms,
        };
        let state = V03State::new()
            .with_named_programs([
                (
                    vesting,
                    Program::new(Cow::Borrowed(ESCAPEMENT_ELF)).expect("escapement elf loads"),
                ),
                (
                    token,
                    Program::new(Cow::Borrowed(TOKEN_ELF)).expect("token elf loads"),
                ),
                (clock_account_id(), programs::clock()),
                (
                    RELAY_A,
                    Program::new(Cow::Borrowed(RELAY_ELF)).expect("relay elf loads"),
                ),
                (
                    RELAY_B,
                    Program::new(Cow::Borrowed(RELAY_ELF)).expect("relay elf loads"),
                ),
            ])
            .with_public_accounts(
                [(
                    CLOCK_PROGRAM_ACCOUNT_ID,
                    Account::default()
                        .with_actor_state(clock_account_id(), clock_data.to_bytes().into()),
                )]
                .into_iter()
                .chain(funded.iter().map(|(id, amount)| {
                    (
                        *id,
                        Account::default().with_actor_state(
                            NATIVE,
                            lee_core::native_token::encode_balance(*amount),
                        ),
                    )
                })),
            );

        Self {
            state,
            vesting,
            token,
            block_id: 1,
            clock_block_id: 1,
            timestamp_ms: initial_ts_ms,
        }
    }

    fn new(initial_ts_ms: u64) -> Self {
        Self::new_funded(initial_ts_ms, &[])
    }

    /// Initialized and configured chain with genesis native balances for `funded` accounts.
    fn new_funded(initial_ts_ms: u64, funded: &[(AccountId, u128)]) -> Self {
        let mut chain = Self::new_unconfigured_funded(initial_ts_ms, funded);
        let vesting = chain.vesting;
        let token = chain.token;
        let cfg = config_pda(vesting);
        chain
            .submit_public(
                Actor::new(vesting, vesting),
                &[Actor::new(vesting, vesting), Actor::new(cfg, vesting)],
                &[&key(100)],
                &admin_op::<VestingMessage>(AdminOp::Init),
            )
            .expect("admin init succeeds");
        chain
            .submit_public(
                Actor::new(vesting, vesting),
                &[Actor::new(vesting, vesting), Actor::new(cfg, vesting)],
                &[&key(100)],
                &Wire::Program(VestingMessage::Configure {
                    token_program_id: Some(token),
                    fee_bps: 0,
                    fee_treasury: None,
                }),
            )
            .expect("initial configure succeeds");
        chain
    }

    fn catalog(&self) -> ProgramCatalog {
        [
            (self.vesting, ESCAPEMENT_ELF),
            (self.token, TOKEN_ELF),
            (RELAY_A, RELAY_ELF),
            (RELAY_B, RELAY_ELF),
        ]
        .into_iter()
        .map(|(id, elf)| (id, Program::new(Cow::Borrowed(elf)).expect("guest loads")))
        .chain([(clock_account_id(), programs::clock())])
        .collect()
    }

    fn simulation_for(&self, public: &[Actor]) -> Simulation {
        Simulation {
            public_actor_states: public
                .iter()
                .map(|actor| {
                    (
                        *actor,
                        self.state
                            .get_account_by_id(actor.account_id)
                            .data
                            .actor_state(actor.program_account_id)
                            .clone(),
                    )
                })
                .collect(),
            admitted_accounts: None,
        }
    }

    /// Writes the next block id and `next_ts_ms` into `clock_actor()`. After
    /// `advance_block_header_only`, this is the end-of-block tick of that same block.
    fn tick(&mut self, next_ts_ms: u64) {
        self.clock_block_id += 1;
        self.block_id = self.block_id.max(self.clock_block_id);
        self.timestamp_ms = next_ts_ms;
        self.submit_public(
            clock_actor(),
            &[clock_actor()],
            &[],
            &clock_core::Message::Tick {
                timestamp: next_ts_ms,
                block_id: self.clock_block_id,
            },
        )
        .expect("clock tick succeeds");
    }

    /// Advances the block header timestamp WITHOUT ticking `clock_actor()` yet,
    /// mirroring LEZ v0.4.0-rc3's real block execution order where `Clock::Tick` runs last.
    fn advance_block_header_only(&mut self, next_ts_ms: u64) {
        self.block_id += 1;
        self.timestamp_ms = next_ts_ms;
    }

    fn build_public_tx(
        &self,
        root: Actor,
        declared: &[Actor],
        signers: &[&PrivateKey],
        message: &impl BorshSerialize,
    ) -> PublicTransaction {
        let nonces = signers
            .iter()
            .map(|k| {
                let id = account(k);
                (id, self.state.get_account_by_id(id).nonce)
            })
            .collect();
        let tx = PublicTxMessage::try_new(root, declared.iter().copied(), nonces, message)
            .expect("public tx encodes");
        let ws = PublicWitnessSet::for_message(&tx, signers);
        PublicTransaction::new(tx, ws)
    }

    fn submit_public(
        &mut self,
        root: Actor,
        declared: &[Actor],
        signers: &[&PrivateKey],
        message: &impl BorshSerialize,
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let tx = self.build_public_tx(root, declared, signers, message);
        self.state
            .transition_from_public_transaction(&tx, self.block_id, self.timestamp_ms)
    }

    fn measure_public(
        &self,
        root: Actor,
        declared: &[Actor],
        signers: &[&PrivateKey],
        message: &impl BorshSerialize,
    ) -> (u64, Result<(), LeeError>) {
        let tx = self.build_public_tx(root, declared, signers, message);
        let sim = self.simulation_for(declared);
        simulate_public_transaction(&tx, &sim, &self.catalog(), MAX_GAS_EXEC)
    }

    fn create_token(&mut self, def_key: &PrivateKey, holder_key: &PrivateKey, supply: u128) {
        let def = account(def_key);
        let holder = account(holder_key);
        self.submit_public(
            Actor::new(def, self.token),
            &[Actor::new(def, self.token), Actor::new(holder, self.token)],
            &[def_key, holder_key],
            &TokenMessage::NewDefinition {
                name: "LOGOS-TEST".into(),
                total_supply: supply,
                mint_authority: None,
                holding: holder,
            },
        )
        .expect("token definition created");
    }

    fn init_public_holding(&mut self, holder_key: &PrivateKey, def: AccountId) {
        let holder = account(holder_key);
        self.submit_public(
            Actor::new(holder, self.token),
            &[Actor::new(holder, self.token), Actor::new(def, self.token)],
            &[holder_key],
            &TokenMessage::InitializeHolding { definition: def },
        )
        .expect("public holding initialized");
    }

    fn transfer_public(&mut self, from_key: &PrivateKey, to: AccountId, amount: u128) {
        let from = account(from_key);
        self.submit_public(
            Actor::new(from, self.token),
            &[Actor::new(from, self.token), Actor::new(to, self.token)],
            &[from_key],
            &TokenMessage::Transfer { to, amount },
        )
        .expect("public transfer succeeds");
    }

    fn token_balance(&self, holder: AccountId) -> u128 {
        match TokenState::decode(
            self.state
                .get_account_by_id(holder)
                .data
                .actor_state(self.token),
        ) {
            Some(TokenState::Holding(h)) => h.balance,
            other => panic!("expected holding at {holder:?}, got {other:?}"),
        }
    }

    fn native_balance(&self, id: AccountId) -> u128 {
        lee_core::native_token::decode_balance(
            self.state.get_account_by_id(id).data.actor_state(NATIVE),
        )
        .expect("canonical native balance")
    }

    /// Actors a native-asset `CreateSchedule` touches (fee vault actors when a fee is due).
    fn native_create_actors(
        &self,
        creator: AccountId,
        params: &CreateScheduleParams,
        with_fee_vault: bool,
    ) -> Vec<Actor> {
        let sched_id = schedule_pda(self.vesting, &creator, &params.salt);
        let escrow_id = single_escrow_pda(self.vesting, &sched_id);
        let mut actors = vec![
            Actor::new(creator, self.vesting),
            Actor::new(sched_id, self.vesting),
            Actor::new(config_pda(self.vesting), self.vesting),
            Actor::new(creator, NATIVE),
            Actor::new(escrow_id, NATIVE),
        ];
        if let Some(b) = &params.broker {
            actors.push(Actor::new(b.holding, NATIVE));
        }
        if with_fee_vault {
            let fv = fee_vault_pda(self.vesting, &Asset::Native.key());
            actors.push(Actor::new(fv, self.vesting));
            actors.push(Actor::new(fv, NATIVE));
        }
        actors
    }

    /// Actors a native-asset `BatchCreate` touches.
    fn native_batch_actors(
        &self,
        creator: AccountId,
        params: &BatchCreateParams,
        with_fee_vault: bool,
    ) -> Vec<Actor> {
        let coord = batch_coord_pda(self.vesting, &creator, &params.batch_id);
        let escrow = batch_escrow_pda(self.vesting, &creator, &params.batch_id);
        let mut actors = vec![
            Actor::new(creator, self.vesting),
            Actor::new(coord, self.vesting),
            Actor::new(config_pda(self.vesting), self.vesting),
            Actor::new(creator, NATIVE),
            Actor::new(escrow, NATIVE),
        ];
        for i in 0..params.items.len() {
            let sid = batch_schedule_pda(self.vesting, &creator, &params.batch_id, i as u32);
            actors.push(Actor::new(sid, self.vesting));
        }
        if with_fee_vault {
            let fv = fee_vault_pda(self.vesting, &Asset::Native.key());
            actors.push(Actor::new(fv, self.vesting));
            actors.push(Actor::new(fv, NATIVE));
        }
        actors
    }

    /// Submits `message` through relay program `relay` rooted at `(signer, relay)`: the relay
    /// forwards it to `to`, granting `seeds` (the relay's own PDA seeds).
    #[allow(clippy::too_many_arguments)]
    fn submit_via_relay(
        &mut self,
        relay: AccountId,
        signer_k: &PrivateKey,
        to: Actor,
        message: Vec<u8>,
        seeds: Vec<PdaSeed>,
        extra: &[Actor],
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let signer = account(signer_k);
        let root = Actor::new(signer, relay);
        let mut declared = vec![root, to];
        declared.extend_from_slice(extra);
        self.submit_public(
            root,
            &declared,
            &[signer_k],
            &RelayMessage::Forward { to, message, seeds },
        )
    }

    /// Like `submit_via_relay`, but the relay sends `message` to `to` as an asynchronous message
    /// (LEZ's mailbox path; to a declared public actor it runs in the same transaction).
    fn submit_via_relay_async(
        &mut self,
        relay: AccountId,
        signer_k: &PrivateKey,
        to: Actor,
        message: Vec<u8>,
        extra: &[Actor],
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let signer = account(signer_k);
        let root = Actor::new(signer, relay);
        let mut declared = vec![root, to];
        declared.extend(extra.iter().filter(|a| **a != to && **a != root));
        self.submit_public(
            root,
            &declared,
            &[signer_k],
            &RelayMessage::ForwardAsync { to, message },
        )
    }

    fn schedule(&self, sched_id: AccountId) -> ScheduleAccount {
        match VestingActorState::decode(
            self.state
                .get_account_by_id(sched_id)
                .data
                .actor_state(self.vesting),
        ) {
            Some(VestingActorState::Schedule(s)) => *s,
            other => panic!("expected schedule at {sched_id:?}, got {other:?}"),
        }
    }

    fn config(&self) -> Config {
        let cfg_id = config_pda(self.vesting);
        borsh::from_slice(
            self.state
                .get_account_by_id(cfg_id)
                .data
                .actor_state(self.vesting),
        )
        .expect("config decodes")
    }

    fn create_schedule_actors(
        &self,
        creator: AccountId,
        params: &CreateScheduleParams,
        extra_fee_targets: &[AccountId],
    ) -> Vec<Actor> {
        let sched_id = schedule_pda(self.vesting, &creator, &params.salt);
        let escrow_id = single_escrow_pda(self.vesting, &sched_id);
        let mut actors = vec![
            Actor::new(creator, self.vesting),
            Actor::new(sched_id, self.vesting),
            Actor::new(config_pda(self.vesting), self.vesting),
            Actor::new(params.refund_holding, self.token),
            Actor::new(escrow_id, self.token),
            Actor::new(params.asset.key(), self.token),
            Actor::new(params.creator_holding, self.token),
        ];
        if let Some(b) = &params.broker {
            actors.push(Actor::new(b.holding, self.token));
        }
        for t in extra_fee_targets {
            actors.push(Actor::new(*t, self.token));
        }
        actors
    }

    fn batch_create_actors(
        &self,
        creator: AccountId,
        params: &BatchCreateParams,
        extra_fee_targets: &[AccountId],
    ) -> Vec<Actor> {
        let coord = batch_coord_pda(self.vesting, &creator, &params.batch_id);
        let escrow = batch_escrow_pda(self.vesting, &creator, &params.batch_id);
        let mut actors = vec![
            Actor::new(creator, self.vesting),
            Actor::new(coord, self.vesting),
            Actor::new(config_pda(self.vesting), self.vesting),
            Actor::new(params.refund_holding, self.token),
            Actor::new(escrow, self.token),
            Actor::new(params.asset.key(), self.token),
            Actor::new(params.creator_holding, self.token),
        ];
        for i in 0..params.items.len() {
            let sid = batch_schedule_pda(self.vesting, &creator, &params.batch_id, i as u32);
            actors.push(Actor::new(sid, self.vesting));
        }
        if let Some(b) = &params.broker {
            actors.push(Actor::new(b.holding, self.token));
        }
        for t in extra_fee_targets {
            actors.push(Actor::new(*t, self.token));
        }
        actors
    }

    fn init_private_holding(&mut self, wallet: &mut PrivateWallet, def: AccountId) -> Proof {
        let root = Actor::new(wallet.id(), self.token);
        let public = [Actor::new(def, self.token)];
        let witness = match &wallet.account {
            None => init_witness(&wallet.keys),
            Some(acct) => update_witness(
                &wallet.keys,
                acct.clone(),
                self.state
                    .get_proof_for_commitment(&Commitment::new(&wallet.id(), acct))
                    .expect("committed"),
            ),
        };
        let (output, proof) = execute_and_prove(
            ProvingInput {
                root: TransactionEntry::Sync(RootCall {
                    to: root,
                    message: borsh::to_vec(&TokenMessage::InitializeHolding { definition: def })
                        .unwrap(),
                }),
                claims: Vec::new(),
                fee: None,
                public_context: PublicExecutionContext::new(public.to_vec(), std::iter::empty()),
                private_witnesses: vec![witness],
                dummy_inputs: Vec::new(),
                ciphertext_padding: None,
                recoveries: Vec::new(),
                private_promotions: BTreeSet::new(),
            },
            &self.simulation_for(&public),
            &self.catalog(),
            |_| SenderPresentation::Canonical,
            |_, _| false,
            no_seal,
        )
        .expect("private holding init proves");
        let tx_msg = PrivateTxMessage::from_circuit_output(BTreeMap::new(), output.clone());
        let proof_clone = Proof::from_inner(proof.clone().into_inner());
        let tx_ws = PrivateWitnessSet::for_message(&tx_msg, proof, &[]);
        let diff = ValidatedStateDiff::from_privacy_preserving_transaction(
            &PrivacyPreservingTransaction::new(tx_msg, tx_ws),
            &self.state,
            self.block_id,
            self.timestamp_ms,
        )
        .expect("private holding init validates");
        self.state.apply_state_diff(diff).expect("applies");
        decrypt_update(&output, wallet);
        proof_clone
    }

    /// Builds and proves a `ClaimExact` PPTX without applying it to chain state yet.
    fn prove_private_claim(
        &self,
        args: &PrivateClaimArgs<'_>,
        dest: &PrivateWallet,
    ) -> Result<
        (
            PrivacyPreservingTransaction,
            PrivacyPreservingCircuitOutput,
            Proof,
            u64,
        ),
        LeeError,
    > {
        let beneficiary_id = account(args.beneficiary_key);
        let sched = self.schedule(args.schedule_id);
        let alias = dest.id().blinded(&args.blinding_factor);

        let root = Actor::new(beneficiary_id, self.vesting);
        let public = [
            root,
            Actor::new(args.schedule_id, self.vesting),
            Actor::new(sched.escrow_account, sched.asset_program_id),
        ];

        let mut witness = match &dest.account {
            None => init_witness(&dest.keys),
            Some(acct) => update_witness(
                &dest.keys,
                acct.clone(),
                self.state
                    .get_proof_for_commitment(&Commitment::new(&dest.id(), acct))
                    .expect("dest account committed"),
            ),
        };
        witness.random_seed = args.random_seed;
        witness.kind = WitnessKind::Regular(RegularKey::Nullifying(dest.keys.nsk()));
        witness.address_openings.insert(args.blinding_factor);

        let wire = Wire::Program(VestingMessage::ClaimExact {
            schedule_id: args.schedule_id,
            destination: alias,
            amount: args.amount,
            effective_ts: args.effective_ts,
        });
        let proving_input = ProvingInput {
            root: TransactionEntry::Sync(RootCall {
                to: root,
                message: borsh::to_vec(&wire).expect("claim wire encodes"),
            }),
            claims: Vec::new(),
            fee: None,
            public_context: PublicExecutionContext::new(public.to_vec(), [beneficiary_id]),
            private_witnesses: vec![witness],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        };

        let sim = self.simulation_for(&public);
        let catalog = self.catalog();
        let token_prog = sched.asset_program_id;
        let promote = args.promote_credit;
        let pub_cycles = simulate_privacy_preserving_transaction(
            &proving_input,
            &sim,
            &catalog,
            |_| SenderPresentation::Canonical,
            |_, body| {
                promote && body.to.account_id == alias && body.to.program_account_id == token_prog
            },
        )?;

        let (output, proof) = execute_and_prove(
            proving_input,
            &sim,
            &catalog,
            |_| SenderPresentation::Canonical,
            |_, body| {
                promote && body.to.account_id == alias && body.to.program_account_id == token_prog
            },
            no_seal,
        )?;

        let nonces = BTreeMap::from([(
            beneficiary_id,
            self.state.get_account_by_id(beneficiary_id).nonce,
        )]);
        let tx_msg = PrivateTxMessage::from_circuit_output(nonces, output.clone());
        let proof_copy = Proof::from_inner(proof.clone().into_inner());
        let tx_ws = PrivateWitnessSet::for_message(&tx_msg, proof, &[args.beneficiary_key]);
        let tx = PrivacyPreservingTransaction::new(tx_msg, tx_ws);
        Ok((tx, output, proof_copy, pub_cycles))
    }

    /// Executes `ClaimExact` in a single PPTX with a fresh blinded alias `dest.id().blinded(&factor)`.
    fn claim_private_blinded(
        &mut self,
        args: &PrivateClaimArgs<'_>,
        dest: &mut PrivateWallet,
    ) -> Result<PrivateClaimResult, LeeError> {
        let (tx, output, proof, pub_cycles) = self.prove_private_claim(args, dest)?;
        let tx_msg = tx.message().clone();
        let diff = ValidatedStateDiff::from_privacy_preserving_transaction(
            &tx,
            &self.state,
            self.block_id,
            self.timestamp_ms,
        )?;
        let events = self.state.apply_state_diff(diff)?;
        decrypt_update(&output, dest);
        Ok(PrivateClaimResult {
            output,
            proof,
            tx_msg,
            events,
            pub_cycles,
        })
    }
}

fn decrypt_update(output: &PrivacyPreservingCircuitOutput, wallet: &mut PrivateWallet) {
    let commitments = output.execution.commitments();
    let updated = output
        .execution
        .private_actions
        .iter()
        .find_map(|action| {
            let secret = SharedSecretKey::decapsulate(
                &action.encrypted_post_state.epk,
                &wallet.keys.d,
                &wallet.keys.z,
            )?;
            let (_, state) = EncryptionScheme::decrypt(
                &action.encrypted_post_state.ciphertext,
                &secret,
                &action.nullifier,
            )?;
            commitments
                .contains(&Commitment::new(&wallet.id(), &state))
                .then_some(state)
        })
        .expect("wallet decrypts its committed private note");
    wallet.account = Some(updated);
}

fn assert_no_private_leak(
    chain: &TestChain,
    res: &PrivateClaimResult,
    sched_id: AccountId,
    escrow_id: AccountId,
    wallets: &[&PrivateWallet],
    alias: AccountId,
) {
    assert!(
        res.output.execution.async_messages.is_empty(),
        "zero mailbox publications"
    );
    assert!(
        res.output.execution.recovery_bindings.is_empty(),
        "zero recovery bindings"
    );
    assert_eq!(chain.state.publications_from(0).count(), 0);
    assert!(
        res.events.iter().all(|e| e.account_id == chain.vesting),
        "private token::increase_balance must emit zero Transferred events"
    );
    assert_eq!(events_of::<Claimed>(&res.events).len(), 1);

    let ev_bytes = borsh::to_vec(&res.events).unwrap();
    assert!(
        !contains_subslice(&ev_bytes, alias.value()),
        "blinded alias must NOT appear in Claimed event bytes"
    );

    let full_tx_bytes = res.tx_msg.to_bytes();
    let sched_state_bytes = chain
        .state
        .get_account_by_id(sched_id)
        .data
        .actor_state(chain.vesting)
        .as_ref()
        .to_vec();
    let escrow_state_bytes = chain
        .state
        .get_account_by_id(escrow_id)
        .data
        .actor_state(chain.token)
        .as_ref()
        .to_vec();
    let observer_bytes = [
        full_tx_bytes,
        ev_bytes,
        sched_state_bytes,
        escrow_state_bytes,
    ]
    .concat();

    for w in wallets {
        assert!(
            !contains_subslice(&observer_bytes, w.id().value()),
            "real private AccountId leaked in public bytes!"
        );
        assert!(
            !contains_subslice(&observer_bytes, &w.npk_bytes()),
            "private npk leaked in public bytes!"
        );
        assert!(
            !contains_subslice(&observer_bytes, &w.vpk_bytes()),
            "private vpk leaked in public bytes!"
        );
    }

    let mut p2p_count = 0usize;
    let mut priv2pub_count = 0usize;
    let mut seen_alias = None;
    for step in &res.output.execution.boundary {
        match step {
            BoundaryStep::PublicToPrivate(del) => {
                p2p_count += 1;
                seen_alias = Some(del.envelope.to.account_id);
            }
            BoundaryStep::PrivateToPublic(_) => {
                priv2pub_count += 1;
            }
            BoundaryStep::EndPrivateSubtree | BoundaryStep::EndPublicSubtree => {}
        }
    }
    assert_eq!(p2p_count, 1, "expected exactly 1 PublicToPrivate step");
    assert_eq!(priv2pub_count, 0, "expected 0 PrivateToPublic steps");
    assert_eq!(seen_alias, Some(alias));
}

// ============================================================================
// SPIKE S-1: 1-tx blinded-alias promoted private token claim + onchain rollbacks
// ============================================================================

#[test]
fn s1_private_claim_blinded_alias_single_tx_and_fresh_values_per_claim() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(1);
    let creator_k = key(2);
    let benef_k = key(3);
    let uninit_pub_k = key(4);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);

    chain.create_token(&def_k, &creator_k, 1_000_000);
    chain.init_public_holding(&benef_k, def);

    let params = CreateScheduleParams {
        salt: [0x11; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 100_000,
        kind: ScheduleKind::CliffLinear {
            start_ts: 1_000_000,
            cliff_ts: 2_000_000,
            end_ts: 5_000_000,
            cliff_amount: 25_000,
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let actors = chain.create_schedule_actors(creator, &params, &[]);
    let sched_id = schedule_pda(chain.vesting, &creator, &params.salt);
    let escrow_id = single_escrow_pda(chain.vesting, &sched_id);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
        )
        .expect("schedule created");
    assert_eq!(chain.token_balance(escrow_id), 100_000);

    // Move to cliff_ts (25,000 claimable).
    chain.tick(2_000_000);

    // 1) Genuine onchain V03State rollback: ClaimPublic to an uninitialized public holding
    //    stages the schedule update and escrow debit, then the runtime refuses delivery to the
    //    never-initialized holding (`UnadmittedPublicActor`); nothing is applied.
    let before = chain.state.clone();
    let uninit_pub = account(&uninit_pub_k);
    let err_pub = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(sched_id, chain.vesting),
            clock_actor(),
            Actor::new(escrow_id, chain.token),
            Actor::new(uninit_pub, chain.token),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::ClaimPublic {
            schedule_id: sched_id,
            destination: uninit_pub,
            amount: Some(10_000),
        }),
    );
    assert_unadmitted(&err_pub, uninit_pub);
    assert!(
        chain.state == before,
        "failed public claim must roll back schedule & escrow atomically"
    );
    assert_eq!(chain.schedule(sched_id).claimed_amount, 0);
    assert_eq!(chain.token_balance(escrow_id), 100_000);

    // 2) Uninitialized private holding rejected cleanly (R1).
    let mut uninit_priv = PrivateWallet::new(71);
    let before = chain.state.clone();
    let err = chain.claim_private_blinded(
        &PrivateClaimArgs {
            beneficiary_key: &benef_k,
            schedule_id: sched_id,
            blinding_factor: [0xA1; 32],
            random_seed: [0x11; 32],
            amount: 10_000,
            effective_ts: 2_000_000,
            promote_credit: true,
        },
        &mut uninit_priv,
    );
    assert_refused(&err, "recipient has no token holding; initialize it first");
    assert!(chain.state == before);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 0);

    // 3) Omitted promotion rejected with UnboundAsyncDestination (R1).
    let mut dest_priv = PrivateWallet::new(72);
    chain.init_private_holding(&mut dest_priv, def);
    let before = chain.state.clone();
    let err = chain.claim_private_blinded(
        &PrivateClaimArgs {
            beneficiary_key: &benef_k,
            schedule_id: sched_id,
            blinding_factor: [0xB1; 32],
            random_seed: [0x12; 32],
            amount: 10_000,
            effective_ts: 2_000_000,
            promote_credit: false,
        },
        &mut dest_priv,
    );
    assert!(
        matches!(err, Err(LeeError::UnboundAsyncDestination { .. })),
        "unpromoted blinded alias must fail atomically, got {err:?}"
    );
    assert!(chain.state == before);
    assert_eq!(dest_priv.balance(chain.token), 0);

    // 4) Genuine onchain V03State PPTX settlement rollback: prove a valid 25,000 ClaimExact PPTX,
    //    race it onchain with a 15,000 ClaimExact (leaving only 10,000), then submit the stale
    //    proven PPTX directly to ValidatedStateDiff::from_privacy_preserving_transaction!
    let (stale_tx, _, _, _) = chain
        .prove_private_claim(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: sched_id,
                blinding_factor: [0xBF; 32],
                random_seed: [0x13; 32],
                amount: 25_000,
                effective_ts: 2_000_000,
                promote_credit: true,
            },
            &dest_priv,
        )
        .expect("pre-race PPTX proves");

    // 5) Retry with promotion -> succeeds in ONE transaction!
    let f1 = [0xC1; 32];
    let res1 = chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: sched_id,
                blinding_factor: f1,
                random_seed: [0x14; 32],
                amount: 15_000,
                effective_ts: 2_000_000,
                promote_credit: true,
            },
            &mut dest_priv,
        )
        .expect("blinded-alias private claim succeeds in 1 tx");
    assert_eq!(dest_priv.balance(chain.token), 15_000);
    assert_eq!(chain.token_balance(escrow_id), 85_000);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 15_000);
    let c1 = &events_of::<Claimed>(&res1.events)[0];
    assert_eq!(c1.amount, 15_000);
    assert_eq!(c1.total_claimed, 15_000);
    assert_no_private_leak(
        &chain,
        &res1,
        sched_id,
        escrow_id,
        &[&dest_priv],
        dest_priv.id().blinded(&f1),
    );

    // Submit the raced proven PPTX directly to V03State validation -> rejected atomically!
    let before_race = chain.state.clone();
    let raced_res = ValidatedStateDiff::from_privacy_preserving_transaction(
        &stale_tx,
        &chain.state,
        chain.block_id,
        chain.timestamp_ms,
    );
    // The stale PPTX claimed 25,000 when only 10,000 remains. Both claims are signed by the
    // beneficiary, so LEZ's replay protection refuses the stale one first: its signer nonce
    // was spent by the competing claim. (The guest overclaim guard, exit 27, is covered
    // directly in `negative_guards_authority_zero_address_and_overclaim_suite`.)
    match raced_res {
        Err(LeeError::InvalidInput(ref msg)) if msg == "Nonce mismatch" => {}
        other => panic!(
            "raced proven PPTX must be refused by the nonce check, got {:?}",
            other.err()
        ),
    }
    assert!(
        chain.state == before_race,
        "raced PPTX must leave state intact"
    );

    // 6) Second private claim into SAME private account uses a fresh alias + distinct nullifier/commitment/epk!
    let f2 = [0xC2; 32];
    assert_ne!(dest_priv.id().blinded(&f1), dest_priv.id().blinded(&f2));
    let res2 = chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: sched_id,
                blinding_factor: f2,
                random_seed: [0x15; 32],
                amount: 10_000,
                effective_ts: 2_000_000,
                promote_credit: true,
            },
            &mut dest_priv,
        )
        .expect("second private claim to same private account succeeds");
    assert_eq!(dest_priv.balance(chain.token), 25_000);
    assert_eq!(chain.token_balance(escrow_id), 75_000);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 25_000);
    assert_no_private_leak(
        &chain,
        &res2,
        sched_id,
        escrow_id,
        &[&dest_priv],
        dest_priv.id().blinded(&f2),
    );
    assert_ne!(
        res1.output.execution.private_actions[0].nullifier,
        res2.output.execution.private_actions[0].nullifier
    );
    assert_ne!(
        res1.output.execution.private_actions[0].commitment,
        res2.output.execution.private_actions[0].commitment
    );
    assert_ne!(
        res1.output.execution.private_actions[0]
            .encrypted_post_state
            .epk,
        res2.output.execution.private_actions[0]
            .encrypted_post_state
            .epk
    );
    eprintln!(
        "[S-1] blinded-alias private claim public cycles = {}",
        res1.pub_cycles
    );
}

// ============================================================================
// SPIKE S-1 REAL PROOF (`RISC0_DEV_MODE=0`) — run explicitly with --ignored
// ============================================================================

#[test]
#[ignore]
fn s1_real_proof_dev_mode_0() {
    // Env-var guard (accepts 1/true/yes); the authoritative check is the
    // `InnerReceipt::Succinct` assertion on both proofs below.
    #[allow(deprecated)]
    let dev_mode = risc0_zkvm::is_dev_mode();
    assert!(
        !dev_mode,
        "s1_real_proof_dev_mode_0 must run with RISC0_DEV_MODE=0 (dev mode disabled)"
    );
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(11);
    let creator_k = key(12);
    let benef_k = key(13);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    chain.create_token(&def_k, &creator_k, 500_000);

    let params = CreateScheduleParams {
        salt: [0x99; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 100_000,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 2_000_000,
        },
        cancelable: true,
        transferable: true,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let actors = chain.create_schedule_actors(creator, &params, &[]);
    let sched_id = schedule_pda(chain.vesting, &creator, &params.salt);
    let escrow_id = single_escrow_pda(chain.vesting, &sched_id);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
        )
        .expect("schedule created");

    let mut dest_priv = PrivateWallet::new(91);
    let t_init = Instant::now();
    let init_proof = chain.init_private_holding(&mut dest_priv, def);
    let init_s = t_init.elapsed().as_secs_f64();
    let init_receipt: InnerReceipt =
        borsh::from_slice(&init_proof.into_inner()).expect("init InnerReceipt decodes");
    assert!(
        matches!(init_receipt, InnerReceipt::Succinct(_)),
        "expected real Succinct STARK receipt for init_private_holding, got {init_receipt:?}"
    );

    // Advance halfway (50,000 claimable).
    chain.tick(1_500_000);
    let factor = [0xEE; 32];
    let t_claim = Instant::now();
    let res = chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: sched_id,
                blinding_factor: factor,
                random_seed: [0x77; 32],
                amount: 50_000,
                effective_ts: 1_500_000,
                promote_credit: true,
            },
            &mut dest_priv,
        )
        .expect("real-proof private claim succeeds");
    let claim_s = t_claim.elapsed().as_secs_f64();

    let claim_receipt: InnerReceipt =
        borsh::from_slice(&res.proof.clone().into_inner()).expect("claim InnerReceipt decodes");
    assert!(
        matches!(claim_receipt, InnerReceipt::Succinct(_)),
        "expected real Succinct STARK receipt for ClaimExact, got {claim_receipt:?}"
    );

    assert_eq!(dest_priv.balance(chain.token), 50_000);
    assert_eq!(chain.token_balance(escrow_id), 50_000);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 50_000);
    let claimed = &events_of::<Claimed>(&res.events)[0];
    assert_eq!(claimed.schedule_id, sched_id);
    assert_eq!(claimed.beneficiary, benef);
    assert_eq!(claimed.amount, 50_000);
    assert_eq!(claimed.total_claimed, 50_000);
    assert_eq!(claimed.timestamp_ms, 1_500_000);
    assert_no_private_leak(
        &chain,
        &res,
        sched_id,
        escrow_id,
        &[&dest_priv],
        dest_priv.id().blinded(&factor),
    );

    let prog = Program::new(Cow::Borrowed(ESCAPEMENT_ELF)).unwrap();
    assert_eq!(prog.id(), ESCAPEMENT_ID);
    eprintln!(
        "[REAL_PROOF_DEV_MODE_0] escapement_image_id={:?} init_holding_s={init_s:.2} private_claim_s={claim_s:.2} public_cycles={}",
        prog.id(),
        res.pub_cycles
    );
}

// ============================================================================
// SPIKE S-2: Time asymmetry (timestamp_window vs live clock on Cancel)
// ============================================================================

#[test]
fn s2_time_asymmetry_validity_window_and_live_clock_cancel() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(21);
    let creator_k = key(22);
    let benef_k = key(23);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    chain.create_token(&def_k, &creator_k, 1_000_000);

    let params = CreateScheduleParams {
        salt: [0x22; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 100_000,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 3_000_000,
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let actors = chain.create_schedule_actors(creator, &params, &[]);
    let sched_id = schedule_pda(chain.vesting, &creator, &params.salt);
    let escrow_id = single_escrow_pda(chain.vesting, &sched_id);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
        )
        .expect("schedule created");

    let mut dest_priv = PrivateWallet::new(73);
    chain.init_private_holding(&mut dest_priv, def);

    // At t = 1_500_000 (25% = 25,000 vested), trying to claim with future effective_ts = 2_000_000
    // is rejected by LEZ's runtime validity window (`OutOfValidityWindow`).
    chain.tick(1_500_000);
    let fut = chain.claim_private_blinded(
        &PrivateClaimArgs {
            beneficiary_key: &benef_k,
            schedule_id: sched_id,
            blinding_factor: [0xD1; 32],
            random_seed: [0x21; 32],
            amount: 50_000,
            effective_ts: 2_000_000,
            promote_credit: true,
        },
        &mut dest_priv,
    );
    assert!(
        matches!(fut, Err(LeeError::OutOfValidityWindow)),
        "future effective_ts must fail OutOfValidityWindow, got {fut:?}"
    );

    // Delayed private claim: beneficiary proved at effective_ts = 1_500_000, tx lands 10 min later
    // at block_ts = 2_100_000 -> STILL SUCCEEDS with zero expiry!
    chain.tick(2_100_000);
    chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: sched_id,
                blinding_factor: [0xD2; 32],
                random_seed: [0x22; 32],
                amount: 25_000,
                effective_ts: 1_500_000,
                promote_credit: true,
            },
            &mut dest_priv,
        )
        .expect("delayed private claim never expires under timestamp_window");
    assert_eq!(dest_priv.balance(chain.token), 25_000);

    // Live clock Cancel at t = 2_200_000 (60% vested = 60,000; 40,000 unvested refunded to creator).
    chain.tick(2_200_000);
    let creator_before = chain.token_balance(creator);
    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sched_id, chain.vesting),
                clock_actor(),
                Actor::new(escrow_id, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::Cancel {
                schedule_id: sched_id,
            }),
        )
        .expect("cancel succeeds");
    let cancel_evs = events_of::<Cancelled>(&evs);
    assert_eq!(cancel_evs.len(), 1);
    assert_eq!(cancel_evs[0].vested_at_cancel, 60_000);
    assert_eq!(cancel_evs[0].refunded_amount, 40_000);
    assert_eq!(chain.token_balance(creator), creator_before + 40_000);
    assert_eq!(chain.token_balance(escrow_id), 35_000);

    // Beneficiary claims the remaining 35,000 vested post-cancel privately!
    chain.tick(5_000_000);
    chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: sched_id,
                blinding_factor: [0xD3; 32],
                random_seed: [0x23; 32],
                amount: 35_000,
                effective_ts: 5_000_000,
                promote_credit: true,
            },
            &mut dest_priv,
        )
        .expect("post-cancel private claim of vested remainder succeeds");
    assert_eq!(dest_priv.balance(chain.token), 60_000);
    assert_eq!(chain.token_balance(escrow_id), 0);

    // Any further claim (+1 unit) fails cleanly (NothingClaimable, exit code 26).
    let over = chain.claim_private_blinded(
        &PrivateClaimArgs {
            beneficiary_key: &benef_k,
            schedule_id: sched_id,
            blinding_factor: [0xD4; 32],
            random_seed: [0x24; 32],
            amount: 1,
            effective_ts: 5_000_000,
            promote_credit: true,
        },
        &mut dest_priv,
    );
    assert_exit_code(&over, 26);
}

// ============================================================================
// CRITICAL [C-1] REGRESSION: Same-block clock lag on ClaimExact + Cancel over shared batch escrow
// ============================================================================

#[test]
fn c1_same_block_clock_lag_cancel_protects_shared_batch_escrow() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(24);
    let creator_k = key(25);
    let alice_k = key(26);
    let bob_k = key(27);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let alice = account(&alice_k);
    let bob = account(&bob_k);
    chain.create_token(&def_k, &creator_k, 1_000_000);

    let batch_id = [0xC1; 32];
    let params = BatchCreateParams {
        batch_id,
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        broker: None,
        items: vec![
            BatchRecipient {
                beneficiary: alice,
                total_amount: 100_000,
                kind: ScheduleKind::CliffLinear {
                    start_ts: 1_000_000,
                    cliff_ts: 2_000_000,
                    end_ts: 5_000_000,
                    cliff_amount: 50_000,
                },
                cancelable: true,
                transferable: false,
                cancel_authority: None,
                milestone_authority: None,
            },
            BatchRecipient {
                beneficiary: bob,
                total_amount: 100_000,
                kind: ScheduleKind::CliffLinear {
                    start_ts: 1_000_000,
                    cliff_ts: 2_000_000,
                    end_ts: 5_000_000,
                    cliff_amount: 50_000,
                },
                cancelable: true,
                transferable: false,
                cancel_authority: None,
                milestone_authority: None,
            },
        ],
    };
    let actors = chain.batch_create_actors(creator, &params, &[]);
    let escrow = batch_escrow_pda(chain.vesting, &creator, &batch_id);
    let alice_sched = batch_schedule_pda(chain.vesting, &creator, &batch_id, 0);
    let bob_sched = batch_schedule_pda(chain.vesting, &creator, &batch_id, 1);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(params))),
        )
        .expect("batch created");
    assert_eq!(chain.token_balance(escrow), 200_000);

    let mut alice_priv = PrivateWallet::new(74);
    let mut bob_priv = PrivateWallet::new(75);
    chain.init_private_holding(&mut alice_priv, def);
    chain.init_private_holding(&mut bob_priv, def);

    // Block N-1 ticks clock to 1_990_000 (< cliff_ts). Block N header advances to 2_000_000
    // while clock_actor() STILL holds 1_990_000 (exact LEZ v0.4.0-rc3 end-of-block tick semantics!).
    chain.tick(1_990_000);
    chain.advance_block_header_only(2_000_000);

    // Alice claims her 50,000 cliff via ClaimExact(effective_ts = 2_000_000).
    chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &alice_k,
                schedule_id: alice_sched,
                blinding_factor: [0xE1; 32],
                random_seed: [0xE1; 32],
                amount: 50_000,
                effective_ts: 2_000_000,
                promote_credit: true,
            },
            &mut alice_priv,
        )
        .expect("alice cliff claim succeeds at block header ts");
    assert_eq!(chain.token_balance(escrow), 150_000);

    // Same block N (clock still 1_990_000): creator cancels Alice.
    // Clamping vested_at_cancel >= claimed_amount ensures ONLY 50,000 refunds, NEVER touching Bob!
    let creator_before = chain.token_balance(creator);
    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(alice_sched, chain.vesting),
                clock_actor(),
                Actor::new(escrow, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::Cancel {
                schedule_id: alice_sched,
            }),
        )
        .expect("clamped cancel succeeds safely");
    let cev = &events_of::<Cancelled>(&evs)[0];
    assert_eq!(cev.vested_at_cancel, 50_000);
    assert_eq!(cev.refunded_amount, 50_000);
    assert_eq!(chain.token_balance(creator), creator_before + 50_000);
    assert_eq!(chain.token_balance(escrow), 100_000);

    // Now test fully-claimed ClaimExact at end_ts = 5_000_000 with clock lagging at 4_990_000:
    // Bob claims 100% (100,000), then same-block Cancel(Bob) MUST reject with AlreadyFullyVested (20)!
    chain.tick(4_990_000);
    chain.advance_block_header_only(5_000_000);
    chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &bob_k,
                schedule_id: bob_sched,
                blinding_factor: [0xE2; 32],
                random_seed: [0xE2; 32],
                amount: 100_000,
                effective_ts: 5_000_000,
                promote_credit: true,
            },
            &mut bob_priv,
        )
        .expect("bob claims full 100,000");
    assert_eq!(bob_priv.balance(chain.token), 100_000);
    assert_eq!(chain.token_balance(escrow), 0);

    // R2: this cancel fails after its first step. `Cancel` has already set the schedule to wait
    // for the clock reply when the continuation refuses (fully claimed, code 20); the whole
    // transaction must be undone, leaving every account as it was.
    let before_cancel = chain.state.clone();
    let cancel_bob = chain.submit_public(
        Actor::new(creator, chain.vesting),
        &[
            Actor::new(creator, chain.vesting),
            Actor::new(bob_sched, chain.vesting),
            clock_actor(),
            Actor::new(escrow, chain.token),
            Actor::new(creator, chain.token),
        ],
        &[&creator_k],
        &Wire::Program(VestingMessage::Cancel {
            schedule_id: bob_sched,
        }),
    );
    assert_exit_code(&cancel_bob, 20);
    assert!(
        chain.state == before_cancel,
        "R2: a cancel refused after its clock read leaves every account as it was"
    );
    assert!(
        chain.schedule(bob_sched).cancelled.is_none(),
        "R2: the schedule is back in its prior, uncancelled state"
    );
}

// ============================================================================
// AUDIT REGRESSION: partial private cliff claim followed by a lagged cancellation
// ============================================================================

#[test]
fn audit_lagged_cancel_preserves_previously_vested_unclaimed_tokens() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(28);
    let creator_k = key(29);
    let benef_k = key(30);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    chain.create_token(&def_k, &creator_k, 1_000_000);

    let params = CreateScheduleParams {
        salt: [0xC2; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 100_000,
        kind: ScheduleKind::CliffLinear {
            start_ts: 1_000_000,
            cliff_ts: 2_000_000,
            end_ts: 5_000_000,
            cliff_amount: 50_000,
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let actors = chain.create_schedule_actors(creator, &params, &[]);
    let sched = schedule_pda(chain.vesting, &creator, &params.salt);
    let escrow = single_escrow_pda(chain.vesting, &sched);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
        )
        .expect("schedule created");

    let mut private_dest = PrivateWallet::new(76);
    chain.init_private_holding(&mut private_dest, def);
    chain.tick(1_990_000);
    chain.advance_block_header_only(2_000_000);

    // The cliff validates 50,000 as vested, but the beneficiary withdraws only one unit.
    chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: sched,
                blinding_factor: [0xE3; 32],
                random_seed: [0xE3; 32],
                amount: 1,
                effective_ts: 2_000_000,
                promote_credit: true,
            },
            &mut private_dest,
        )
        .expect("partial cliff claim succeeds");

    // In the same block the clock still reads 1,990,000. Cancellation must retain all
    // 50,000 that vested at the cliff, not just the single unit already claimed.
    let creator_before = chain.token_balance(creator);
    let events = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sched, chain.vesting),
                clock_actor(),
                Actor::new(escrow, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::Cancel { schedule_id: sched }),
        )
        .expect("cancel succeeds");
    let cancelled = &events_of::<Cancelled>(&events)[0];
    assert_eq!(cancelled.vested_at_cancel, 50_000);
    assert_eq!(cancelled.refunded_amount, 50_000);
    assert_eq!(chain.token_balance(creator), creator_before + 50_000);
    assert_eq!(chain.token_balance(escrow), 49_999);
}

// ============================================================================
// SPIKE S-3 & [H-1]: `lez-admin-authority` v0.2.0, multi-token fee vaults & WithdrawFees
// ============================================================================

#[test]
fn s3_lez_admin_authority_fee_switch_multi_token_vaults_and_immutability() {
    let mut chain = TestChain::new(1_000_000);
    let deployer_k = key(100);
    let new_admin_k = key(31);
    let outsider_k = key(32);
    let treasury_k = key(33);
    let treasury_dest_a_k = key(134);
    let treasury_dest_b_k = key(135);
    let treasury_dest_c_k = key(136);
    let broker_a_k = key(34);
    let broker_b_k = key(137);
    let def_a_k = key(35);
    let def_b_k = key(138);
    let def_c_k = key(139);
    let creator_a_k = key(36);
    let creator_b_k = key(140);
    let creator_c_k = key(141);
    let benef_k = key(37);

    let cfg = config_pda(chain.vesting);
    let def_a = account(&def_a_k);
    let def_b = account(&def_b_k);
    let def_c = account(&def_c_k);
    let creator_a = account(&creator_a_k);
    let creator_b = account(&creator_b_k);
    let creator_c = account(&creator_c_k);
    let treasury = account(&treasury_k);
    let broker_a = account(&broker_a_k);
    let broker_b = account(&broker_b_k);

    // Three distinct tokens on LEZ v0.4 (each holding can only hold ONE token definition).
    chain.create_token(&def_a_k, &creator_a_k, 1_000_000);
    chain.create_token(&def_b_k, &creator_b_k, 1_000_000);
    chain.create_token(&def_c_k, &creator_c_k, 1_000_000);
    chain.init_public_holding(&broker_a_k, def_a);
    chain.init_public_holding(&broker_b_k, def_b);
    chain.init_public_holding(&treasury_dest_a_k, def_a);
    chain.init_public_holding(&treasury_dest_b_k, def_b);
    chain.init_public_holding(&treasury_dest_c_k, def_c);

    // Non-admin refused on Configure (E103).
    let res = chain.submit_public(
        Actor::new(account(&outsider_k), chain.vesting),
        &[
            Actor::new(account(&outsider_k), chain.vesting),
            Actor::new(cfg, chain.vesting),
        ],
        &[&outsider_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 10,
            fee_treasury: Some(treasury),
        }),
    );
    assert_refused(&res, "E103");

    // Changing token_program_id refused (write-once immutable, exit code 9).
    let res = chain.submit_public(
        Actor::new(chain.vesting, chain.vesting),
        &[
            Actor::new(chain.vesting, chain.vesting),
            Actor::new(cfg, chain.vesting),
        ],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: Some(AccountId::new([0x99; 32])),
            fee_bps: 0,
            fee_treasury: None,
        }),
    );
    assert_exit_code(&res, 9);

    // Fee cap > 100 bps refused (exit code 7); fee_bps > 0 without treasury refused (exit code 8).
    let res = chain.submit_public(
        Actor::new(chain.vesting, chain.vesting),
        &[
            Actor::new(chain.vesting, chain.vesting),
            Actor::new(cfg, chain.vesting),
        ],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 101,
            fee_treasury: Some(treasury),
        }),
    );
    assert_exit_code(&res, 7);

    let res = chain.submit_public(
        Actor::new(chain.vesting, chain.vesting),
        &[
            Actor::new(chain.vesting, chain.vesting),
            Actor::new(cfg, chain.vesting),
        ],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 10,
            fee_treasury: None,
        }),
    );
    assert_exit_code(&res, 8);

    // Set 50 bps (0.50%) protocol fee with treasury controller -> emits FeeConfigUpdated.
    let evs = chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[
                Actor::new(chain.vesting, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&deployer_k],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: None,
                fee_bps: 50,
                fee_treasury: Some(treasury),
            }),
        )
        .expect("set 50 bps fee succeeds");
    assert_eq!(events_of::<FeeConfigUpdated>(&evs).len(), 1);
    assert_eq!(chain.config().fee_bps, 50);

    // 1. Token A schedule: 10,001 with 50 bps protocol fee (ceil=51 -> fee_vault_a) + 100 bps broker (ceil=101).
    let fv_a = fee_vault_pda(chain.vesting, &def_a);
    let params_a = CreateScheduleParams {
        salt: [0x33; 32],
        asset: Asset::Token { definition: def_a },
        creator_holding: creator_a,
        refund_holding: creator_a,
        beneficiary: account(&benef_k),
        total_amount: 10_001,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 2_000_000,
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: Some(BrokerFee {
            holding: broker_a,
            bps: 100,
        }),
    };
    let actors_a = chain.create_schedule_actors(creator_a, &params_a, &[fv_a]);
    let sched_a = schedule_pda(chain.vesting, &creator_a, &params_a.salt);
    let escrow_a = single_escrow_pda(chain.vesting, &sched_a);
    chain
        .submit_public(
            Actor::new(creator_a, chain.vesting),
            &actors_a,
            &[&creator_a_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params_a))),
        )
        .expect("token A fee-bearing schedule created");
    assert_eq!(chain.token_balance(escrow_a), 10_001);
    assert_eq!(chain.token_balance(fv_a), 51);
    assert_eq!(chain.token_balance(broker_a), 101);
    assert_eq!(
        chain.token_balance(creator_a),
        1_000_000 - 10_001 - 51 - 101
    );

    // 2. Token B BatchCreate with BOTH 50 bps protocol fee (ceil(30,001 * 50 / 10000) = 151)
    //    AND 200 bps broker fee (ceil(30,001 * 200 / 10000) = 601)!
    let fv_b = fee_vault_pda(chain.vesting, &def_b);
    let batch_b = BatchCreateParams {
        batch_id: [0x3B; 32],
        asset: Asset::Token { definition: def_b },
        creator_holding: creator_b,
        refund_holding: creator_b,
        broker: Some(BrokerFee {
            holding: broker_b,
            bps: 200,
        }),
        items: vec![
            BatchRecipient {
                beneficiary: account(&benef_k),
                total_amount: 10_000,
                kind: ScheduleKind::Linear {
                    start_ts: 1_000_000,
                    end_ts: 2_000_000,
                },
                cancelable: true,
                transferable: false,
                cancel_authority: None,
                milestone_authority: None,
            },
            BatchRecipient {
                beneficiary: account(&outsider_k),
                total_amount: 20_001,
                kind: ScheduleKind::Linear {
                    start_ts: 1_000_000,
                    end_ts: 2_000_000,
                },
                cancelable: false,
                transferable: true,
                cancel_authority: None,
                milestone_authority: None,
            },
        ],
    };
    let actors_b = chain.batch_create_actors(creator_b, &batch_b, &[fv_b]);
    let escrow_b = batch_escrow_pda(chain.vesting, &creator_b, &batch_b.batch_id);
    chain
        .submit_public(
            Actor::new(creator_b, chain.vesting),
            &actors_b,
            &[&creator_b_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(batch_b))),
        )
        .expect("token B fee-bearing batch created");
    assert_eq!(chain.token_balance(escrow_b), 30_001);
    assert_eq!(chain.token_balance(fv_b), 151);
    assert_eq!(chain.token_balance(broker_b), 601);
    assert_eq!(
        chain.token_balance(creator_b),
        1_000_000 - 30_001 - 151 - 601
    );

    // 3. WithdrawFees authorization & self-lock checks + successful multi-token sweeps.
    let unauth_wd = chain.submit_public(
        Actor::new(account(&outsider_k), chain.vesting),
        &[
            Actor::new(account(&outsider_k), chain.vesting),
            Actor::new(cfg, chain.vesting),
            Actor::new(fv_a, chain.token),
            Actor::new(account(&treasury_dest_a_k), chain.token),
        ],
        &[&outsider_k],
        &Wire::Program(VestingMessage::WithdrawFees {
            asset: Asset::Token { definition: def_a },
            destination: account(&treasury_dest_a_k),
            amount: 51,
        }),
    );
    assert_exit_code(&unauth_wd, 13);

    let self_lock_wd = chain.submit_public(
        Actor::new(treasury, chain.vesting),
        &[
            Actor::new(treasury, chain.vesting),
            Actor::new(cfg, chain.vesting),
            Actor::new(fv_a, chain.token),
        ],
        &[&treasury_k],
        &Wire::Program(VestingMessage::WithdrawFees {
            asset: Asset::Token { definition: def_a },
            destination: fv_a,
            amount: 51,
        }),
    );
    assert_exit_code(&self_lock_wd, 31);

    let ev_wd_a = chain
        .submit_public(
            Actor::new(treasury, chain.vesting),
            &[
                Actor::new(treasury, chain.vesting),
                Actor::new(cfg, chain.vesting),
                Actor::new(fv_a, chain.token),
                Actor::new(account(&treasury_dest_a_k), chain.token),
            ],
            &[&treasury_k],
            &Wire::Program(VestingMessage::WithdrawFees {
                asset: Asset::Token { definition: def_a },
                destination: account(&treasury_dest_a_k),
                amount: 51,
            }),
        )
        .expect("treasury withdraws token A fees");
    assert_eq!(events_of::<FeeWithdrawn>(&ev_wd_a)[0].amount, 51);
    assert_eq!(chain.token_balance(account(&treasury_dest_a_k)), 51);
    assert_eq!(chain.token_balance(fv_a), 0);

    chain
        .submit_public(
            Actor::new(treasury, chain.vesting),
            &[
                Actor::new(treasury, chain.vesting),
                Actor::new(cfg, chain.vesting),
                Actor::new(fv_b, chain.token),
                Actor::new(account(&treasury_dest_b_k), chain.token),
            ],
            &[&treasury_k],
            &Wire::Program(VestingMessage::WithdrawFees {
                asset: Asset::Token { definition: def_b },
                destination: account(&treasury_dest_b_k),
                amount: 151,
            }),
        )
        .expect("treasury withdraws token B fees");
    assert_eq!(chain.token_balance(account(&treasury_dest_b_k)), 151);
    assert_eq!(chain.token_balance(fv_b), 0);

    // 4. Two-step Nominate -> Accept -> Renounce (while fee_bps = 50 remains active!).
    let new_admin = account(&new_admin_k);
    chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[
                Actor::new(chain.vesting, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&deployer_k],
            &admin_op::<VestingMessage>(AdminOp::Nominate { next: new_admin }),
        )
        .expect("nominate succeeds");
    chain
        .submit_public(
            Actor::new(new_admin, chain.vesting),
            &[
                Actor::new(new_admin, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&new_admin_k],
            &admin_op::<VestingMessage>(AdminOp::Accept { pda_seed: None }),
        )
        .expect("accept succeeds");
    let old = chain.submit_public(
        Actor::new(chain.vesting, chain.vesting),
        &[
            Actor::new(chain.vesting, chain.vesting),
            Actor::new(cfg, chain.vesting),
        ],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 0,
            fee_treasury: None,
        }),
    );
    assert_refused(&old, "E103");

    chain
        .submit_public(
            Actor::new(new_admin, chain.vesting),
            &[
                Actor::new(new_admin, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&new_admin_k],
            &admin_op::<VestingMessage>(AdminOp::Renounce),
        )
        .expect("renounce succeeds");
    let after_renounce = chain.submit_public(
        Actor::new(new_admin, chain.vesting),
        &[
            Actor::new(new_admin, chain.vesting),
            Actor::new(cfg, chain.vesting),
        ],
        &[&new_admin_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 10,
            fee_treasury: Some(treasury),
        }),
    );
    assert_refused(&after_renounce, "E102");

    // 5. Even AFTER AdminOp::Renounce with fee_bps = 50, a brand-new Token C schedule still
    //    auto-initializes fee_vault_pda(token_C) permissionlessly and treasury withdraws it!
    let fv_c = fee_vault_pda(chain.vesting, &def_c);
    let params_c = CreateScheduleParams {
        salt: [0x3C; 32],
        asset: Asset::Token { definition: def_c },
        creator_holding: creator_c,
        refund_holding: creator_c,
        beneficiary: account(&benef_k),
        total_amount: 20_000,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 2_000_000,
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let actors_c = chain.create_schedule_actors(creator_c, &params_c, &[fv_c]);
    chain
        .submit_public(
            Actor::new(creator_c, chain.vesting),
            &actors_c,
            &[&creator_c_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params_c))),
        )
        .expect("token C schedule succeeds permissionlessly even post-renounce");
    assert_eq!(chain.token_balance(fv_c), 100);
    chain
        .submit_public(
            Actor::new(treasury, chain.vesting),
            &[
                Actor::new(treasury, chain.vesting),
                Actor::new(cfg, chain.vesting),
                Actor::new(fv_c, chain.token),
                Actor::new(account(&treasury_dest_c_k), chain.token),
            ],
            &[&treasury_k],
            &Wire::Program(VestingMessage::WithdrawFees {
                asset: Asset::Token { definition: def_c },
                destination: account(&treasury_dest_c_k),
                amount: 100,
            }),
        )
        .expect("treasury withdraws token C fees post-renounce");
    assert_eq!(chain.token_balance(account(&treasury_dest_c_k)), 100);
}

// ============================================================================
// Full lifecycle: Cliff, Linear, Milestone, Soft-1/2, F4 (incl. private claim), R4, Donation
// ============================================================================

#[test]
fn full_lifecycle_all_schedule_types_authorities_and_refusals() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(41);
    let creator_k = key(42);
    let benef_k = key(43);
    let benef2_k = key(44);
    let cancel_auth_k = key(45);
    let ms_auth_k = key(46);
    let donor_k = key(47);
    let refund_treasury_k = key(48);

    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    let benef2 = account(&benef2_k);
    let cancel_auth = account(&cancel_auth_k);
    let ms_auth = account(&ms_auth_k);
    let refund_treasury = account(&refund_treasury_k);

    chain.create_token(&def_k, &creator_k, 1_000_000);
    chain.init_public_holding(&benef_k, def);
    chain.init_public_holding(&benef2_k, def);
    chain.init_public_holding(&donor_k, def);
    chain.init_public_holding(&refund_treasury_k, def);
    chain.transfer_public(&creator_k, account(&donor_k), 5_000);

    // 1. Milestone schedule with exclusive Soft-1 & Soft-2 AND distinct refund_holding != creator_holding.
    let ms_params = CreateScheduleParams {
        salt: [0x44; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: refund_treasury,
        beneficiary: benef,
        total_amount: 60_000,
        kind: ScheduleKind::Milestone {
            tranches: vec![
                MilestoneTranche {
                    amount: 20_000,
                    unlocked: false,
                    unlocked_at_ms: None,
                },
                MilestoneTranche {
                    amount: 40_000,
                    unlocked: false,
                    unlocked_at_ms: None,
                },
            ],
        },
        cancelable: true,
        transferable: true,
        cancel_authority: Some(cancel_auth),
        milestone_authority: Some(ms_auth),
        broker: None,
    };
    let actors = chain.create_schedule_actors(creator, &ms_params, &[]);
    let ms_sched = schedule_pda(chain.vesting, &creator, &ms_params.salt);
    let ms_escrow = single_escrow_pda(chain.vesting, &ms_sched);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(ms_params))),
        )
        .expect("milestone schedule created");

    // Unsolicited direct donation to escrow does NOT inflate claimable or corrupt cancellation!
    chain.transfer_public(&donor_k, ms_escrow, 5_000);
    assert_eq!(chain.token_balance(ms_escrow), 65_000);

    // Creator refused on SignalMilestone when milestone_authority is delegated (Soft-2, exit code 13).
    let res = chain.submit_public(
        Actor::new(creator, chain.vesting),
        &[
            Actor::new(creator, chain.vesting),
            Actor::new(ms_sched, chain.vesting),
            clock_actor(),
        ],
        &[&creator_k],
        &Wire::Program(VestingMessage::SignalMilestone {
            schedule_id: ms_sched,
            milestone_index: 0,
        }),
    );
    assert_exit_code(&res, 13);

    // Delegated milestone_authority signals tranche 0 -> succeeds.
    chain.tick(1_100_000);
    let evs = chain
        .submit_public(
            Actor::new(ms_auth, chain.vesting),
            &[
                Actor::new(ms_auth, chain.vesting),
                Actor::new(ms_sched, chain.vesting),
                clock_actor(),
            ],
            &[&ms_auth_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: ms_sched,
                milestone_index: 0,
            }),
        )
        .expect("delegated milestone signal succeeds");
    assert_eq!(
        events_of::<MilestoneSignaled>(&evs)[0].amount_unlocked,
        20_000
    );

    // Double-signalling same tranche rejected (R4, exit code 25).
    let dup = chain.submit_public(
        Actor::new(ms_auth, chain.vesting),
        &[
            Actor::new(ms_auth, chain.vesting),
            Actor::new(ms_sched, chain.vesting),
            clock_actor(),
        ],
        &[&ms_auth_k],
        &Wire::Program(VestingMessage::SignalMilestone {
            schedule_id: ms_sched,
            milestone_index: 0,
        }),
    );
    assert_exit_code(&dup, 25);

    // Transfer beneficiary rights (F4): benef -> benef2.
    let evs = chain
        .submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(ms_sched, chain.vesting),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::TransferBeneficiary {
                schedule_id: ms_sched,
                new_beneficiary: benef2,
            }),
        )
        .expect("beneficiary transfer succeeds");
    assert_eq!(
        events_of::<BeneficiaryTransferred>(&evs)[0].new_beneficiary,
        benef2
    );

    // Old beneficiary refused on BOTH ClaimPublic AND ClaimExact (private)!
    let old_claim = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(ms_sched, chain.vesting),
            clock_actor(),
            Actor::new(ms_escrow, chain.token),
            Actor::new(benef, chain.token),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::ClaimPublic {
            schedule_id: ms_sched,
            destination: benef,
            amount: None,
        }),
    );
    assert_exit_code(&old_claim, 13);

    let mut benef2_priv = PrivateWallet::new(76);
    chain.init_private_holding(&mut benef2_priv, def);
    let old_priv = chain.claim_private_blinded(
        &PrivateClaimArgs {
            beneficiary_key: &benef_k,
            schedule_id: ms_sched,
            blinding_factor: [0x91; 32],
            random_seed: [0x91; 32],
            amount: 10_000,
            effective_ts: 1_100_000,
            promote_credit: true,
        },
        &mut benef2_priv,
    );
    assert_exit_code(&old_priv, 13);

    // Creator refused from cancelling when cancel_authority is delegated (Soft-1, exit code 13).
    let creator_cancel = chain.submit_public(
        Actor::new(creator, chain.vesting),
        &[
            Actor::new(creator, chain.vesting),
            Actor::new(ms_sched, chain.vesting),
            clock_actor(),
            Actor::new(ms_escrow, chain.token),
            Actor::new(refund_treasury, chain.token),
        ],
        &[&creator_k],
        &Wire::Program(VestingMessage::Cancel {
            schedule_id: ms_sched,
        }),
    );
    assert_exit_code(&creator_cancel, 13);

    // Delegated cancel_authority cancels -> 40,000 unvested returns strictly to pinned distinct refund_treasury.
    chain
        .submit_public(
            Actor::new(cancel_auth, chain.vesting),
            &[
                Actor::new(cancel_auth, chain.vesting),
                Actor::new(ms_sched, chain.vesting),
                clock_actor(),
                Actor::new(ms_escrow, chain.token),
                Actor::new(refund_treasury, chain.token),
            ],
            &[&cancel_auth_k],
            &Wire::Program(VestingMessage::Cancel {
                schedule_id: ms_sched,
            }),
        )
        .expect("delegated cancel succeeds");
    assert_eq!(chain.token_balance(refund_treasury), 40_000);

    // New beneficiary benef2 claims half privately (blinded alias!) and half publicly!
    chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef2_k,
                schedule_id: ms_sched,
                blinding_factor: [0x92; 32],
                random_seed: [0x92; 32],
                amount: 10_000,
                effective_ts: 1_100_000,
                promote_credit: true,
            },
            &mut benef2_priv,
        )
        .expect("new beneficiary claims milestone tranche privately");
    assert_eq!(benef2_priv.balance(chain.token), 10_000);

    chain
        .submit_public(
            Actor::new(benef2, chain.vesting),
            &[
                Actor::new(benef2, chain.vesting),
                Actor::new(ms_sched, chain.vesting),
                clock_actor(),
                Actor::new(ms_escrow, chain.token),
                Actor::new(benef2, chain.token),
            ],
            &[&benef2_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: ms_sched,
                destination: benef2,
                amount: None,
            }),
        )
        .expect("new beneficiary claims remaining unlocked milestone publicly");
    assert_eq!(chain.token_balance(benef2), 10_000);
    // Escrow holds only the 5,000 unsolicited donation, zero schedule funds left!
    assert_eq!(chain.token_balance(ms_escrow), 5_000);

    // 2. Cliff+Linear: pre-cliff metered exit code 26; MakeNonCancelable irreversible; non-transferable.
    let cl_params = CreateScheduleParams {
        salt: [0x45; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 100_000,
        kind: ScheduleKind::CliffLinear {
            start_ts: 2_000_000,
            cliff_ts: 3_000_000,
            end_ts: 5_000_000,
            cliff_amount: 40_000,
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let actors = chain.create_schedule_actors(creator, &cl_params, &[]);
    let cl_sched = schedule_pda(chain.vesting, &creator, &cl_params.salt);
    let cl_escrow = single_escrow_pda(chain.vesting, &cl_sched);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(cl_params))),
        )
        .expect("cliff schedule created");

    chain.tick(2_500_000);
    let pre = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(cl_sched, chain.vesting),
            clock_actor(),
            Actor::new(cl_escrow, chain.token),
            Actor::new(benef, chain.token),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::ClaimPublic {
            schedule_id: cl_sched,
            destination: benef,
            amount: None,
        }),
    );
    let pre_cycles = assert_exit_code(&pre, 26);
    assert_eq!(
        escapement_core::math::next_unlock_after(&chain.schedule(cl_sched), 2_500_000),
        Some(3_000_000)
    );
    eprintln!(
        "[METERED_REFUSAL] Pre-cliff ClaimPublic exit code 26 metered {pre_cycles} cycles (vs 10,000,000 panic cap)"
    );

    let nt = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(cl_sched, chain.vesting),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::TransferBeneficiary {
            schedule_id: cl_sched,
            new_beneficiary: benef2,
        }),
    );
    assert_exit_code(&nt, 21);

    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(cl_sched, chain.vesting),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::MakeNonCancelable {
                schedule_id: cl_sched,
            }),
        )
        .expect("make non-cancelable succeeds");
    assert_eq!(events_of::<MadeNonCancelable>(&evs).len(), 1);
    let cancel_after = chain.submit_public(
        Actor::new(creator, chain.vesting),
        &[
            Actor::new(creator, chain.vesting),
            Actor::new(cl_sched, chain.vesting),
            clock_actor(),
            Actor::new(cl_escrow, chain.token),
            Actor::new(creator, chain.token),
        ],
        &[&creator_k],
        &Wire::Program(VestingMessage::Cancel {
            schedule_id: cl_sched,
        }),
    );
    assert_exit_code(&cancel_after, 17);
}

// ============================================================================
// Comprehensive negative-test suite covering ALL remaining VestingError codes & [M-1]/[L-1..L-4]
// ============================================================================

#[test]
fn comprehensive_error_codes_and_security_hardening_suite() {
    // 1. Unconfigured chain checks: code 10 (TokenProgramNotConfigured) & code 34 (InvalidTokenProgram).
    let mut uncfg = TestChain::new_unconfigured(1_000_000);
    let deployer_k = key(100);
    let cfg = config_pda(uncfg.vesting);
    uncfg
        .submit_public(
            Actor::new(uncfg.vesting, uncfg.vesting),
            &[
                Actor::new(uncfg.vesting, uncfg.vesting),
                Actor::new(cfg, uncfg.vesting),
            ],
            &[&deployer_k],
            &admin_op::<VestingMessage>(AdminOp::Init),
        )
        .unwrap();

    // Configure without token_program_id -> code 10.
    let r = uncfg.submit_public(
        Actor::new(uncfg.vesting, uncfg.vesting),
        &[
            Actor::new(uncfg.vesting, uncfg.vesting),
            Actor::new(cfg, uncfg.vesting),
        ],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 0,
            fee_treasury: None,
        }),
    );
    assert_exit_code(&r, 10);

    // Configure with own_program or clock_account_id -> code 34 ([L-4]).
    for bad_tp in [uncfg.vesting, cfg, clock_account_id()] {
        let r = uncfg.submit_public(
            Actor::new(uncfg.vesting, uncfg.vesting),
            &[
                Actor::new(uncfg.vesting, uncfg.vesting),
                Actor::new(cfg, uncfg.vesting),
            ],
            &[&deployer_k],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: Some(bad_tp),
                fee_bps: 0,
                fee_treasury: None,
            }),
        );
        assert_exit_code(&r, 34);
    }

    // 2. Configured chain covering codes 1..=33 + [M-1] + [L-1] + [L-2] + [L-3].
    let mut chain = TestChain::new(1_000_000);
    let def1_k = key(201);
    let def2_k = key(202);
    let creator_k = key(203);
    let wrong_tok_k = key(204);
    let uninit_ref_k = key(205);
    let benef_k = key(206);
    let benef2_k = key(207);
    let def1 = account(&def1_k);
    let def2 = account(&def2_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    let benef2 = account(&benef2_k);
    chain.create_token(&def1_k, &creator_k, 10_000_000);
    chain.create_token(&def2_k, &wrong_tok_k, 10_000_000);
    chain.init_public_holding(&benef_k, def1);

    let base_params = |salt: u8| CreateScheduleParams {
        salt: [salt; 32],
        asset: Asset::Token { definition: def1 },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 10_000,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 2_000_000,
        },
        cancelable: true,
        transferable: true,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };

    // [M-1]: schedule_id = config_pda MUST exit cleanly with code 16 (NOT panic!).
    let cfg_id = config_pda(chain.vesting);
    let r = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(cfg_id, chain.vesting),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::Cancel {
            schedule_id: cfg_id,
        }),
    );
    assert_exit_code(&r, 16);

    // [L-3]: Root ReadState -> code 32; malformed raw wire bytes -> code 32.
    let r = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[Actor::new(benef, chain.vesting)],
        &[&benef_k],
        &Wire::Program(VestingMessage::ReadState),
    );
    assert_exit_code(&r, 32);
    let r = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[Actor::new(benef, chain.vesting)],
        &[&benef_k],
        &[0xFEu8, 0xFF, 0x01, 0x02],
    );
    assert_exit_code(&r, 32);

    // Code 1 (ZeroAmount), 2 (InvalidTimeRange), 3 (InvalidCliffAmount), 4 (InvalidMilestoneCount),
    // 5 (InvalidMilestoneTranche), 6 (MilestoneSumMismatch), 11 (ZeroAddress creator_holding),
    // 33 (InvalidAuthorityForSchedule).
    let mut p = base_params(1);
    p.total_amount = 0;
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        1,
    );

    let mut p = base_params(2);
    p.kind = ScheduleKind::Linear {
        start_ts: 2_000_000,
        end_ts: 2_000_000,
    };
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        2,
    );

    let mut p = base_params(3);
    p.kind = ScheduleKind::CliffLinear {
        start_ts: 1_000_000,
        cliff_ts: 1_500_000,
        end_ts: 2_000_000,
        cliff_amount: 10_001,
    };
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        3,
    );

    let mut p = base_params(4);
    p.kind = ScheduleKind::Milestone { tranches: vec![] };
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        4,
    );

    let mut p = base_params(5);
    p.kind = ScheduleKind::Milestone {
        tranches: vec![MilestoneTranche {
            amount: 10_000,
            unlocked: true,
            unlocked_at_ms: None,
        }],
    };
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        5,
    );

    let mut p = base_params(6);
    p.kind = ScheduleKind::Milestone {
        tranches: vec![MilestoneTranche {
            amount: 9_999,
            unlocked: false,
            unlocked_at_ms: None,
        }],
    };
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        6,
    );

    let mut p = base_params(11);
    p.creator_holding = ZERO_ACCOUNT_ID;
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        11,
    );

    // Code 33: cancel_authority when cancelable == false; milestone_authority on Linear.
    let mut p = base_params(33);
    p.cancelable = false;
    p.cancel_authority = Some(benef2);
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        33,
    );

    let mut p = base_params(34);
    p.milestone_authority = Some(benef2);
    let a = chain.create_schedule_actors(creator, &p, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        ),
        33,
    );

    // refund_holding never initialized: LEZ v0.4 refuses the `token::ReadState` delivery to a
    // never-initialized account (`UnadmittedPublicActor`) before the program sees it.
    {
        let bad_refund = account(&uninit_ref_k);
        let mut p = base_params(28);
        p.refund_holding = bad_refund;
        let a = chain.create_schedule_actors(creator, &p, &[]);
        let before = chain.state.clone();
        let res = chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
        );
        assert_unadmitted(&res, bad_refund);
        assert!(
            chain.state == before,
            "refused creation must leave state unchanged"
        );
    }
    // Code 28: InvalidRefundHolding (initialized holding of a different token_definition).
    {
        let mut p = base_params(28);
        p.refund_holding = account(&wrong_tok_k);
        let a = chain.create_schedule_actors(creator, &p, &[]);
        assert_exit_code(
            &chain.submit_public(
                Actor::new(creator, chain.vesting),
                &a,
                &[&creator_k],
                &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
            ),
            28,
        );
    }

    // Code 12 (EmptyBatch) & Code 30 (Batch u128 sum overflow). Broker fee-cap (code 7) and
    // broker zero-address (code 11) guards are covered by
    // `negative_guards_authority_zero_address_and_overclaim_suite`.
    let empty_b = BatchCreateParams {
        batch_id: [0x12; 32],
        asset: Asset::Token { definition: def1 },
        creator_holding: creator,
        refund_holding: creator,
        broker: None,
        items: vec![],
    };
    let a = chain.batch_create_actors(creator, &empty_b, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(empty_b))),
        ),
        12,
    );

    let over_b = BatchCreateParams {
        batch_id: [0x30; 32],
        asset: Asset::Token { definition: def1 },
        creator_holding: creator,
        refund_holding: creator,
        broker: None,
        items: vec![
            BatchRecipient {
                beneficiary: benef,
                total_amount: u128::MAX,
                kind: ScheduleKind::Linear {
                    start_ts: 1_000_000,
                    end_ts: 2_000_000,
                },
                cancelable: true,
                transferable: false,
                cancel_authority: None,
                milestone_authority: None,
            },
            BatchRecipient {
                beneficiary: benef2,
                total_amount: 1,
                kind: ScheduleKind::Linear {
                    start_ts: 1_000_000,
                    end_ts: 2_000_000,
                },
                cancelable: true,
                transferable: false,
                cancel_authority: None,
                milestone_authority: None,
            },
        ],
    };
    let a = chain.batch_create_actors(creator, &over_b, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(over_b))),
        ),
        30,
    );

    // Create a valid schedule & verify duplicate salt -> code 14, duplicate batch_id -> code 15.
    let p_ok = base_params(0x55);
    let a = chain.create_schedule_actors(creator, &p_ok, &[]);
    let sid = schedule_pda(chain.vesting, &creator, &p_ok.salt);
    let eid = single_escrow_pda(chain.vesting, &sid);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p_ok.clone()))),
        )
        .unwrap();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p_ok))),
        ),
        14,
    );

    let b_ok = BatchCreateParams {
        batch_id: [0x56; 32],
        asset: Asset::Token { definition: def1 },
        creator_holding: creator,
        refund_holding: creator,
        broker: None,
        items: vec![BatchRecipient {
            beneficiary: benef,
            total_amount: 5_000,
            kind: ScheduleKind::Milestone {
                tranches: vec![MilestoneTranche {
                    amount: 5_000,
                    unlocked: false,
                    unlocked_at_ms: None,
                }],
            },
            cancelable: true,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
        }],
    };
    let ba = chain.batch_create_actors(creator, &b_ok, &[]);
    let ms_sid = batch_schedule_pda(chain.vesting, &creator, &b_ok.batch_id, 0);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &ba,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(b_ok.clone()))),
        )
        .unwrap();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &ba,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(b_ok))),
        ),
        15,
    );

    // Code 22 (SameBeneficiary), Code 31 (TransferBeneficiary self-lock to schedule/escrow),
    // Code 23 (NotMilestoneSchedule), Code 24 (MilestoneIndexOutOfBounds).
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sid, chain.vesting),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::TransferBeneficiary {
                schedule_id: sid,
                new_beneficiary: benef,
            }),
        ),
        22,
    );
    for bad_b in [sid, eid] {
        assert_exit_code(
            &chain.submit_public(
                Actor::new(benef, chain.vesting),
                &[
                    Actor::new(benef, chain.vesting),
                    Actor::new(sid, chain.vesting),
                ],
                &[&benef_k],
                &Wire::Program(VestingMessage::TransferBeneficiary {
                    schedule_id: sid,
                    new_beneficiary: bad_b,
                }),
            ),
            31,
        );
    }
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sid, chain.vesting),
                clock_actor(),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: sid,
                milestone_index: 0,
            }),
        ),
        23,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(ms_sid, chain.vesting),
                clock_actor(),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: ms_sid,
                milestone_index: 5,
            }),
        ),
        24,
    );

    // Advance to midpoint (5,000 claimable on sid): test ClaimPublic amount=Some(0) (code 1),
    // ClaimPublic overclaim (code 27), ClaimPublic self-lock destination==escrow (code 31),
    // ClaimExact amount=0 (code 1) & self-lock (code 31).
    chain.tick(1_500_000);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sid, chain.vesting),
                clock_actor(),
                Actor::new(eid, chain.token),
                Actor::new(benef, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: sid,
                destination: benef,
                amount: Some(0),
            }),
        ),
        1,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sid, chain.vesting),
                clock_actor(),
                Actor::new(eid, chain.token),
                Actor::new(benef, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: sid,
                destination: benef,
                amount: Some(5_001),
            }),
        ),
        27,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sid, chain.vesting),
                clock_actor(),
                Actor::new(eid, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: sid,
                destination: eid,
                amount: Some(100),
            }),
        ),
        31,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sid, chain.vesting),
                Actor::new(eid, chain.token),
                Actor::new(benef, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimExact {
                schedule_id: sid,
                destination: benef,
                amount: 0,
                effective_ts: 1_500_000,
            }),
        ),
        1,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sid, chain.vesting),
                Actor::new(eid, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimExact {
                schedule_id: sid,
                destination: eid,
                amount: 100,
                effective_ts: 1_500_000,
            }),
        ),
        31,
    );

    // [L-1]: Unlock milestone on ms_sid, then attempt ClaimExact with future effective_ts = u64::MAX -> OutOfValidityWindow!
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(ms_sid, chain.vesting),
                clock_actor(),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: ms_sid,
                milestone_index: 0,
            }),
        )
        .unwrap();
    let ms_escrow = batch_escrow_pda(chain.vesting, &creator, &[0x56; 32]);
    let fut_ms = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(ms_sid, chain.vesting),
            Actor::new(ms_escrow, chain.token),
            Actor::new(benef, chain.token),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::ClaimExact {
            schedule_id: ms_sid,
            destination: benef,
            amount: 5_000,
            effective_ts: u64::MAX,
        }),
    );
    assert!(
        matches!(fut_ms, Err(LeeError::OutOfValidityWindow)),
        "milestone ClaimExact must still enforce timestamp_window against future spoofing, got {fut_ms:?}"
    );
    // Milestone ClaimExact with effective_ts = 0 succeeds!
    chain
        .submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(ms_sid, chain.vesting),
                Actor::new(ms_escrow, chain.token),
                Actor::new(benef, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimExact {
                schedule_id: ms_sid,
                destination: benef,
                amount: 5_000,
                effective_ts: 0,
            }),
        )
        .expect("milestone ClaimExact with effective_ts=0 succeeds");

    // Cancel sid -> Cancel twice (code 18), MakeNonCancelable after Cancel (code 18), SignalMilestone after Cancel (code 18).
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sid, chain.vesting),
                clock_actor(),
                Actor::new(eid, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::Cancel { schedule_id: sid }),
        )
        .unwrap();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sid, chain.vesting),
                clock_actor(),
                Actor::new(eid, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::Cancel { schedule_id: sid }),
        ),
        18,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sid, chain.vesting),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::MakeNonCancelable { schedule_id: sid }),
        ),
        18,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sid, chain.vesting),
                clock_actor(),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: sid,
                milestone_index: 0,
            }),
        ),
        18,
    );

    // Code 19: MakeNonCancelable twice.
    let p_mnc = base_params(0x57);
    let a = chain.create_schedule_actors(creator, &p_mnc, &[]);
    let sid_mnc = schedule_pda(chain.vesting, &creator, &p_mnc.salt);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p_mnc))),
        )
        .unwrap();
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sid_mnc, chain.vesting),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::MakeNonCancelable {
                schedule_id: sid_mnc,
            }),
        )
        .unwrap();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sid_mnc, chain.vesting),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::MakeNonCancelable {
                schedule_id: sid_mnc,
            }),
        ),
        19,
    );
    // Keep def2 used cleanly.
    assert_ne!(def1, def2);
}

// ============================================================================
// Mutation-hardening negative guards: guest-side authority checks (Cancel,
// MakeNonCancelable, TransferBeneficiary), zero-address destinations, broker
// fee caps, ClaimExact overclaim — each refusal asserted with its exact exit
// code AND byte-identical chain state afterwards.
// ============================================================================

#[test]
fn negative_guards_authority_zero_address_and_overclaim_suite() {
    // 1. Unconfigured chain: Configure with token_program_id = zero address -> code 11.
    let mut uncfg = TestChain::new_unconfigured(1_000_000);
    let deployer_k = key(100);
    let cfg0 = config_pda(uncfg.vesting);
    uncfg
        .submit_public(
            Actor::new(uncfg.vesting, uncfg.vesting),
            &[
                Actor::new(uncfg.vesting, uncfg.vesting),
                Actor::new(cfg0, uncfg.vesting),
            ],
            &[&deployer_k],
            &admin_op::<VestingMessage>(AdminOp::Init),
        )
        .unwrap();
    assert_exit_code(
        &uncfg.submit_public(
            Actor::new(uncfg.vesting, uncfg.vesting),
            &[
                Actor::new(uncfg.vesting, uncfg.vesting),
                Actor::new(cfg0, uncfg.vesting),
            ],
            &[&deployer_k],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: Some(ZERO_ACCOUNT_ID),
                fee_bps: 0,
                fee_treasury: None,
            }),
        ),
        11,
    );

    let mut chain = TestChain::new(1_000_000);
    let def_k = key(210);
    let creator_k = key(211);
    let benef_k = key(212);
    let broker_k = key(213);
    let donor_k = key(214);
    let cfg = config_pda(chain.vesting);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    let broker = account(&broker_k);
    chain.create_token(&def_k, &creator_k, 1_000_000);
    chain.init_public_holding(&benef_k, def);
    chain.init_public_holding(&broker_k, def);

    // 2. Configure with a zero-address fee_treasury while fee_bps > 0 -> code 11.
    assert_exit_code(
        &chain.submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[
                Actor::new(chain.vesting, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&key(100)],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: None,
                fee_bps: 10,
                fee_treasury: Some(ZERO_ACCOUNT_ID),
            }),
        ),
        11,
    );

    // 3. WithdrawFees input guards fire before any transfer:
    //    amount == 0 -> 1; zero token_definition or destination -> 11.
    let wroot = Actor::new(benef, chain.vesting);
    let wactors = [wroot, Actor::new(cfg, chain.vesting)];
    assert_exit_code(
        &chain.submit_public(
            wroot,
            &wactors,
            &[&benef_k],
            &Wire::Program(VestingMessage::WithdrawFees {
                asset: Asset::Token { definition: def },
                destination: benef,
                amount: 0,
            }),
        ),
        1,
    );
    assert_exit_code(
        &chain.submit_public(
            wroot,
            &wactors,
            &[&benef_k],
            &Wire::Program(VestingMessage::WithdrawFees {
                asset: Asset::Token {
                    definition: ZERO_ACCOUNT_ID,
                },
                destination: benef,
                amount: 10,
            }),
        ),
        11,
    );
    assert_exit_code(
        &chain.submit_public(
            wroot,
            &wactors,
            &[&benef_k],
            &Wire::Program(VestingMessage::WithdrawFees {
                asset: Asset::Token { definition: def },
                destination: ZERO_ACCOUNT_ID,
                amount: 10,
            }),
        ),
        11,
    );

    // 4. Create a transferable, cancelable schedule (beneficiary = benef), 5,000 claimable
    //    at the midpoint tick below.
    let base_params = |salt: u8| CreateScheduleParams {
        salt: [salt; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 10_000,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 2_000_000,
        },
        cancelable: true,
        transferable: true,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let params = base_params(0x71);
    let actors = chain.create_schedule_actors(creator, &params, &[]);
    let sched_id = schedule_pda(chain.vesting, &creator, &params.salt);
    let escrow_id = single_escrow_pda(chain.vesting, &sched_id);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
        )
        .expect("schedule created");

    // 5. CreateSchedule zero-address and broker-cap guards: beneficiary (11),
    //    token_definition (11), refund_holding (11), broker holding (11), broker 501 bps (7).
    type ParamMutator = Box<dyn Fn(&mut CreateScheduleParams)>;
    let mutators: Vec<(u8, ParamMutator)> = vec![
        (
            0x72u8,
            Box::new(|p: &mut CreateScheduleParams| p.beneficiary = ZERO_ACCOUNT_ID),
        ),
        (
            0x73u8,
            Box::new(|p: &mut CreateScheduleParams| {
                p.asset = Asset::Token {
                    definition: ZERO_ACCOUNT_ID,
                }
            }),
        ),
        (
            0x74u8,
            Box::new(|p: &mut CreateScheduleParams| p.refund_holding = ZERO_ACCOUNT_ID),
        ),
        (
            0x75u8,
            Box::new(|p: &mut CreateScheduleParams| {
                p.broker = Some(BrokerFee {
                    holding: ZERO_ACCOUNT_ID,
                    bps: 100,
                });
            }),
        ),
        (
            0x76u8,
            Box::new(move |p: &mut CreateScheduleParams| {
                p.broker = Some(BrokerFee {
                    holding: broker,
                    bps: MAX_BROKER_FEE_BPS + 1,
                });
            }),
        ),
    ];
    for (salt, mutate) in mutators {
        let mut p = base_params(salt);
        mutate(&mut p);
        let a = chain.create_schedule_actors(creator, &p, &[]);
        let expected = if salt == 0x76 { 7 } else { 11 };
        assert_exit_code(
            &chain.submit_public(
                Actor::new(creator, chain.vesting),
                &a,
                &[&creator_k],
                &Wire::Program(VestingMessage::CreateSchedule(Box::new(p))),
            ),
            expected,
        );
        assert!(
            VestingActorState::decode(
                chain
                    .state
                    .get_account_by_id(schedule_pda(chain.vesting, &creator, &[salt; 32]))
                    .data
                    .actor_state(chain.vesting)
                    .as_ref()
            )
            .is_none(),
            "refused CreateSchedule({salt:#04x}) must not persist any schedule state"
        );
    }

    // 6. BatchCreate broker guards: zero holding -> 11; 501 bps -> 7.
    let b_params = |broker_fee: Option<BrokerFee>, batch_id: [u8; 32]| BatchCreateParams {
        batch_id,
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        broker: broker_fee,
        items: vec![BatchRecipient {
            beneficiary: benef,
            total_amount: 1_000,
            kind: ScheduleKind::Linear {
                start_ts: 1_000_000,
                end_ts: 2_000_000,
            },
            cancelable: true,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
        }],
    };
    let b_zero_holding = b_params(
        Some(BrokerFee {
            holding: ZERO_ACCOUNT_ID,
            bps: 100,
        }),
        [0xB1; 32],
    );
    let ba = chain.batch_create_actors(creator, &b_zero_holding, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &ba,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(b_zero_holding))),
        ),
        11,
    );
    let b_over_bps = b_params(
        Some(BrokerFee {
            holding: broker,
            bps: MAX_BROKER_FEE_BPS + 1,
        }),
        [0xB2; 32],
    );
    let ba = chain.batch_create_actors(creator, &b_over_bps, &[]);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &ba,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(b_over_bps))),
        ),
        7,
    );

    chain.tick(1_500_000); // 5,000 of 10,000 vested and claimable.

    // 7. Guest-side authority checks: beneficiary cannot Cancel (13) or MakeNonCancelable (13),
    //    and the creator (non-beneficiary) cannot TransferBeneficiary (13). All leave
    //    schedule state, escrow balance, and claimed_amount untouched.
    let before = chain.state.clone();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sched_id, chain.vesting),
                clock_actor(),
                Actor::new(escrow_id, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::Cancel {
                schedule_id: sched_id,
            }),
        ),
        13,
    );
    assert!(
        chain.state == before,
        "unauthorized Cancel must not change state"
    );
    assert_eq!(chain.schedule(sched_id).claimed_amount, 0);
    assert_eq!(chain.token_balance(escrow_id), 10_000);

    let before = chain.state.clone();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sched_id, chain.vesting),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::MakeNonCancelable {
                schedule_id: sched_id,
            }),
        ),
        13,
    );
    assert!(
        chain.state == before,
        "unauthorized MakeNonCancelable must not change state"
    );
    assert!(chain.schedule(sched_id).cancelable);

    let before = chain.state.clone();
    let newb = account(&donor_k);
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sched_id, chain.vesting),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::TransferBeneficiary {
                schedule_id: sched_id,
                new_beneficiary: newb,
            }),
        ),
        13,
    );
    assert!(
        chain.state == before,
        "non-beneficiary TransferBeneficiary must not change state"
    );
    assert_eq!(chain.schedule(sched_id).beneficiary, benef);

    // 8. Zero-address claim and transfer destinations in the public handlers -> 11.
    let before = chain.state.clone();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[Actor::new(benef, chain.vesting)],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: sched_id,
                destination: ZERO_ACCOUNT_ID,
                amount: Some(100),
            }),
        ),
        11,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[Actor::new(benef, chain.vesting)],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimExact {
                schedule_id: sched_id,
                destination: ZERO_ACCOUNT_ID,
                amount: 100,
                effective_ts: 1_500_000,
            }),
        ),
        11,
    );
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sched_id, chain.vesting),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::TransferBeneficiary {
                schedule_id: sched_id,
                new_beneficiary: ZERO_ACCOUNT_ID,
            }),
        ),
        11,
    );
    assert!(
        chain.state == before,
        "zero-address destinations must not change state"
    );

    // 9. ClaimExact overclaim (guest-side, amount > claimable) -> exact 27 with nothing applied.
    let before = chain.state.clone();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(sched_id, chain.vesting),
                Actor::new(escrow_id, chain.token),
                Actor::new(benef, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimExact {
                schedule_id: sched_id,
                destination: benef,
                amount: 5_001,
                effective_ts: 1_500_000,
            }),
        ),
        27,
    );
    assert!(
        chain.state == before,
        "ClaimExact overclaim must not change state"
    );
    assert_eq!(chain.schedule(sched_id).claimed_amount, 0);
    assert_eq!(chain.token_balance(escrow_id), 10_000);

    // 10. ClaimExact with nothing vested yet -> 26, and host-side error carries the
    //     exact next unlock time (U7: "nothing claimable ... with the next unlock time displayed").
    let mut future_params = base_params(0x77);
    future_params.kind = ScheduleKind::Linear {
        start_ts: 2_000_000,
        end_ts: 3_000_000,
    };
    let fa = chain.create_schedule_actors(creator, &future_params, &[]);
    let future_id = schedule_pda(chain.vesting, &creator, &future_params.salt);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &fa,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(future_params))),
        )
        .expect("future schedule created");
    let before = chain.state.clone();
    let nothing = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(future_id, chain.vesting),
            Actor::new(benef, chain.token),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::ClaimExact {
            schedule_id: future_id,
            destination: benef,
            amount: 1,
            effective_ts: 1_500_000,
        }),
    );
    assert_exit_code(&nothing, 26);
    assert_eq!(
        escapement_core::math::next_unlock_after(&chain.schedule(future_id), 1_500_000),
        Some(2_000_100),
        "host-side E026 must name the exact first millisecond at which 1 of the \
         10,000 units vests (start 2_000_000 + 1_000_000/10_000)"
    );
    assert!(
        chain.state == before,
        "nothing-claimable must not change state"
    );

    // 11. R4 "must not double-unlock": re-signalling an already-unlocked milestone exits 25
    //     and the schedule state (claimable, tranche flags) stays byte-identical.
    let mut ms_params = base_params(0x78);
    ms_params.kind = ScheduleKind::Milestone {
        tranches: vec![
            MilestoneTranche {
                amount: 3_000,
                unlocked: false,
                unlocked_at_ms: None,
            },
            MilestoneTranche {
                amount: 7_000,
                unlocked: false,
                unlocked_at_ms: None,
            },
        ],
    };
    let ma = chain.create_schedule_actors(creator, &ms_params, &[]);
    let ms_id = schedule_pda(chain.vesting, &creator, &ms_params.salt);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &ma,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(ms_params))),
        )
        .expect("milestone schedule created");
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(ms_id, chain.vesting),
                clock_actor(),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: ms_id,
                milestone_index: 0,
            }),
        )
        .expect("first milestone signal succeeds");
    let before = chain.state.clone();
    assert_exit_code(
        &chain.submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(ms_id, chain.vesting),
                clock_actor(),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: ms_id,
                milestone_index: 0,
            }),
        ),
        25,
    );
    assert!(
        chain.state == before,
        "double milestone signal must not change state"
    );
    let ms = chain.schedule(ms_id);
    if let ScheduleKind::Milestone { tranches } = &ms.kind {
        assert_eq!(
            tranches.iter().filter(|t| t.unlocked).count(),
            1,
            "R4: a refused double-signal must not unlock twice"
        );
    } else {
        panic!("milestone schedule lost its kind");
    }

    // F1c: the creator's own signal unlocked exactly tranche 0; the beneficiary claims exactly it.
    let ms_escrow = single_escrow_pda(chain.vesting, &ms_id);
    let benef_before = chain.token_balance(benef);
    chain
        .submit_public(
            Actor::new(benef, chain.vesting),
            &[
                Actor::new(benef, chain.vesting),
                Actor::new(ms_id, chain.vesting),
                clock_actor(),
                Actor::new(ms_escrow, chain.token),
                Actor::new(benef, chain.token),
            ],
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: ms_id,
                destination: benef,
                amount: None,
            }),
        )
        .expect("F1c: the beneficiary claims the tranche the creator signalled");
    assert_eq!(chain.token_balance(benef) - benef_before, 3_000);
    assert_eq!(chain.token_balance(ms_escrow), 7_000);
    assert_eq!(chain.schedule(ms_id).claimed_amount, 3_000);
}

// ============================================================================
// Batch creation (F5), concurrent batch claims (R3), exact 3-config cycle & N_max bench (P2)
// ============================================================================

#[test]
fn batch_create_concurrent_claims_and_exact_ceiling_benchmark() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(51);
    let creator_k = key(52);
    let def = account(&def_k);
    let creator = account(&creator_k);
    chain.create_token(&def_k, &creator_k, 100_000_000);

    let prog = Program::new(Cow::Borrowed(ESCAPEMENT_ELF)).unwrap();
    assert_eq!(prog.id(), ESCAPEMENT_ID);

    // Measure single CreateSchedule cycles.
    let b0_k = key(60);
    chain.init_public_holding(&b0_k, def);
    let single_params = CreateScheduleParams {
        salt: [0x51; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: account(&b0_k),
        total_amount: 100_000,
        kind: ScheduleKind::CliffLinear {
            start_ts: 1_000_000,
            cliff_ts: 2_000_000,
            end_ts: 5_000_000,
            cliff_amount: 25_000,
        },
        cancelable: true,
        transferable: true,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let single_actors = chain.create_schedule_actors(creator, &single_params, &[]);
    let single_sched = schedule_pda(chain.vesting, &creator, &single_params.salt);
    let single_escrow = single_escrow_pda(chain.vesting, &single_sched);
    let single_wire = Wire::Program(VestingMessage::CreateSchedule(Box::new(single_params)));
    let (cyc_create, r) = chain.measure_public(
        Actor::new(creator, chain.vesting),
        &single_actors,
        &[&creator_k],
        &single_wire,
    );
    r.expect("create sim ok");
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &single_actors,
            &[&creator_k],
            &single_wire,
        )
        .unwrap();

    // Measure ClaimPublic, ClaimExact, TransferBeneficiary, Cancel, MakeNonCancelable, SignalMilestone.
    chain.tick(2_000_000);
    let claim_pub_actors = [
        Actor::new(account(&b0_k), chain.vesting),
        Actor::new(single_sched, chain.vesting),
        clock_actor(),
        Actor::new(single_escrow, chain.token),
        Actor::new(account(&b0_k), chain.token),
    ];
    let claim_pub_wire = Wire::Program(VestingMessage::ClaimPublic {
        schedule_id: single_sched,
        destination: account(&b0_k),
        amount: Some(10_000),
    });
    let (cyc_claim_pub, r) = chain.measure_public(
        Actor::new(account(&b0_k), chain.vesting),
        &claim_pub_actors,
        &[&b0_k],
        &claim_pub_wire,
    );
    r.expect("claim_pub sim ok");
    chain
        .submit_public(
            Actor::new(account(&b0_k), chain.vesting),
            &claim_pub_actors,
            &[&b0_k],
            &claim_pub_wire,
        )
        .unwrap();

    let mut p0 = PrivateWallet::new(81);
    chain.init_private_holding(&mut p0, def);
    let res_priv = chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &b0_k,
                schedule_id: single_sched,
                blinding_factor: [0xD1; 32],
                random_seed: [0xD1; 32],
                amount: 15_000,
                effective_ts: 2_000_000,
                promote_credit: true,
            },
            &mut p0,
        )
        .unwrap();
    let cyc_claim_priv = res_priv.pub_cycles;

    let b1_k = key(61);
    let xfer_wire = Wire::Program(VestingMessage::TransferBeneficiary {
        schedule_id: single_sched,
        new_beneficiary: account(&b1_k),
    });
    let xfer_actors = [
        Actor::new(account(&b0_k), chain.vesting),
        Actor::new(single_sched, chain.vesting),
    ];
    let (cyc_transfer, r) = chain.measure_public(
        Actor::new(account(&b0_k), chain.vesting),
        &xfer_actors,
        &[&b0_k],
        &xfer_wire,
    );
    r.expect("transfer sim ok");
    chain
        .submit_public(
            Actor::new(account(&b0_k), chain.vesting),
            &xfer_actors,
            &[&b0_k],
            &xfer_wire,
        )
        .unwrap();

    let cancel_actors = [
        Actor::new(creator, chain.vesting),
        Actor::new(single_sched, chain.vesting),
        clock_actor(),
        Actor::new(single_escrow, chain.token),
        Actor::new(creator, chain.token),
    ];
    let cancel_wire = Wire::Program(VestingMessage::Cancel {
        schedule_id: single_sched,
    });
    let (cyc_cancel, r) = chain.measure_public(
        Actor::new(creator, chain.vesting),
        &cancel_actors,
        &[&creator_k],
        &cancel_wire,
    );
    r.expect("cancel sim ok");
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &cancel_actors,
            &[&creator_k],
            &cancel_wire,
        )
        .unwrap();

    let ms_params = CreateScheduleParams {
        salt: [0x52; 32],
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: account(&b0_k),
        total_amount: 20_000,
        kind: ScheduleKind::Milestone {
            tranches: vec![MilestoneTranche {
                amount: 20_000,
                unlocked: false,
                unlocked_at_ms: None,
            }],
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let ms_actors = chain.create_schedule_actors(creator, &ms_params, &[]);
    let ms_sched = schedule_pda(chain.vesting, &creator, &ms_params.salt);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &ms_actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(ms_params))),
        )
        .unwrap();
    let mnc_actors = [
        Actor::new(creator, chain.vesting),
        Actor::new(ms_sched, chain.vesting),
    ];
    let mnc_wire = Wire::Program(VestingMessage::MakeNonCancelable {
        schedule_id: ms_sched,
    });
    let (cyc_mnc, r) = chain.measure_public(
        Actor::new(creator, chain.vesting),
        &mnc_actors,
        &[&creator_k],
        &mnc_wire,
    );
    r.expect("mnc sim ok");
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &mnc_actors,
            &[&creator_k],
            &mnc_wire,
        )
        .unwrap();

    let sig_actors = [
        Actor::new(creator, chain.vesting),
        Actor::new(ms_sched, chain.vesting),
        clock_actor(),
    ];
    let sig_wire = Wire::Program(VestingMessage::SignalMilestone {
        schedule_id: ms_sched,
        milestone_index: 0,
    });
    let (cyc_signal, r) = chain.measure_public(
        Actor::new(creator, chain.vesting),
        &sig_actors,
        &[&creator_k],
        &sig_wire,
    );
    r.expect("signal sim ok");
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &sig_actors,
            &[&creator_k],
            &sig_wire,
        )
        .unwrap();

    // Batch of 8 recipients: concurrent public + private claims & cancel over one shared escrow.
    let batch_keys: Vec<PrivateKey> = (110u8..118u8).map(key).collect();
    for k in &batch_keys {
        chain.init_public_holding(k, def);
    }
    let batch_id = [0xBB; 32];
    let batch8 = BatchCreateParams {
        batch_id,
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        broker: None,
        items: batch_keys
            .iter()
            .enumerate()
            .map(|(i, k)| BatchRecipient {
                beneficiary: account(k),
                total_amount: 10_000 * (i as u128 + 1),
                kind: ScheduleKind::Linear {
                    start_ts: 2_000_000,
                    end_ts: 4_000_000,
                },
                cancelable: true,
                transferable: false,
                cancel_authority: None,
                milestone_authority: None,
            })
            .collect(),
    };
    let b8_actors = chain.batch_create_actors(creator, &batch8, &[]);
    let b8_escrow = batch_escrow_pda(chain.vesting, &creator, &batch_id);
    let b8_wire = Wire::Program(VestingMessage::BatchCreate(Box::new(batch8)));
    let (cyc_batch8, r) = chain.measure_public(
        Actor::new(creator, chain.vesting),
        &b8_actors,
        &[&creator_k],
        &b8_wire,
    );
    r.expect("batch8 sim ok");
    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &b8_actors,
            &[&creator_k],
            &b8_wire,
        )
        .unwrap();
    assert_eq!(events_of::<ScheduleCreated>(&evs).len(), 8);
    assert_eq!(chain.token_balance(b8_escrow), 360_000);

    chain.tick(3_000_000);
    let s0 = batch_schedule_pda(chain.vesting, &creator, &batch_id, 0);
    let s1 = batch_schedule_pda(chain.vesting, &creator, &batch_id, 1);
    let s2 = batch_schedule_pda(chain.vesting, &creator, &batch_id, 2);

    chain
        .submit_public(
            Actor::new(account(&batch_keys[0]), chain.vesting),
            &[
                Actor::new(account(&batch_keys[0]), chain.vesting),
                Actor::new(s0, chain.vesting),
                clock_actor(),
                Actor::new(b8_escrow, chain.token),
                Actor::new(account(&batch_keys[0]), chain.token),
            ],
            &[&batch_keys[0]],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: s0,
                destination: account(&batch_keys[0]),
                amount: None,
            }),
        )
        .unwrap();
    assert_eq!(chain.token_balance(account(&batch_keys[0])), 5_000);

    let mut priv1 = PrivateWallet::new(82);
    chain.init_private_holding(&mut priv1, def);
    chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &batch_keys[1],
                schedule_id: s1,
                blinding_factor: [0xE1; 32],
                random_seed: [0xE1; 32],
                amount: 10_000,
                effective_ts: 3_000_000,
                promote_credit: true,
            },
            &mut priv1,
        )
        .unwrap();
    assert_eq!(priv1.balance(chain.token), 10_000);

    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(s2, chain.vesting),
                clock_actor(),
                Actor::new(b8_escrow, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::Cancel { schedule_id: s2 }),
        )
        .unwrap();
    assert_eq!(chain.token_balance(b8_escrow), 330_000);

    // Binary search exact N_max across ALL 3 canonical schedule configurations!
    #[derive(Clone, Copy)]
    enum BatchProfile {
        Linear,
        CliffLinearWithCancelAuth,
        Milestone4WithBothAuth,
    }
    let find_n_max = |profile: BatchProfile, tag_base: u8| -> (usize, u64, usize, u64, u64) {
        let make = |n: usize, tag: u8| -> (Vec<Actor>, Wire<VestingMessage>) {
            let bid = [tag; 32];
            let del_cancel = AccountId::new([0xC0; 32]);
            let del_ms = AccountId::new([0xD0; 32]);
            let items = (0..n)
                .map(|i| {
                    let mut b = [0u8; 32];
                    b[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                    b[31] = 0x77;
                    match profile {
                        BatchProfile::Linear => BatchRecipient {
                            beneficiary: AccountId::new(b),
                            total_amount: 1_000,
                            kind: ScheduleKind::Linear {
                                start_ts: 2_000_000,
                                end_ts: 4_000_000,
                            },
                            cancelable: true,
                            transferable: false,
                            cancel_authority: None,
                            milestone_authority: None,
                        },
                        BatchProfile::CliffLinearWithCancelAuth => BatchRecipient {
                            beneficiary: AccountId::new(b),
                            total_amount: 1_000,
                            kind: ScheduleKind::CliffLinear {
                                start_ts: 2_000_000,
                                cliff_ts: 3_000_000,
                                end_ts: 6_000_000,
                                cliff_amount: 250,
                            },
                            cancelable: true,
                            transferable: true,
                            cancel_authority: Some(del_cancel),
                            milestone_authority: None,
                        },
                        BatchProfile::Milestone4WithBothAuth => BatchRecipient {
                            beneficiary: AccountId::new(b),
                            total_amount: 1_000,
                            kind: ScheduleKind::Milestone {
                                tranches: vec![
                                    MilestoneTranche {
                                        amount: 250,
                                        unlocked: false,
                                        unlocked_at_ms: None,
                                    };
                                    4
                                ],
                            },
                            cancelable: true,
                            transferable: true,
                            cancel_authority: Some(del_cancel),
                            milestone_authority: Some(del_ms),
                        },
                    }
                })
                .collect();
            let params = BatchCreateParams {
                batch_id: bid,
                asset: Asset::Token { definition: def },
                creator_holding: creator,
                refund_holding: creator,
                broker: None,
                items,
            };
            let actors = chain.batch_create_actors(creator, &params, &[]);
            (
                actors,
                Wire::Program(VestingMessage::BatchCreate(Box::new(params))),
            )
        };
        let (a1, w1) = make(1, tag_base);
        let (cyc1, r1) =
            chain.measure_public(Actor::new(creator, chain.vesting), &a1, &[&creator_k], &w1);
        r1.expect("batch(1) fits");

        let mut lo = 1usize;
        let mut hi = 300usize;
        loop {
            let (a, w) = make(hi, tag_base + 1);
            let (_, res) =
                chain.measure_public(Actor::new(creator, chain.vesting), &a, &[&creator_k], &w);
            if res.is_err() {
                break;
            }
            lo = hi;
            hi *= 2;
        }
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            let (a, w) = make(mid, tag_base + 2);
            let (_, res) =
                chain.measure_public(Actor::new(creator, chain.vesting), &a, &[&creator_k], &w);
            if res.is_ok() {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let (a_max, w_max) = make(lo, tag_base + 3);
        let (cyc_max, r_max) = chain.measure_public(
            Actor::new(creator, chain.vesting),
            &a_max,
            &[&creator_k],
            &w_max,
        );
        r_max.expect("N_max passes");
        let tx_bytes = borsh::to_vec(&chain.build_public_tx(
            Actor::new(creator, chain.vesting),
            &a_max,
            &[&creator_k],
            &w_max,
        ))
        .unwrap()
        .len();
        let (a_over, w_over) = make(lo + 1, tag_base + 4);
        let (cyc_over, r_over) = chain.measure_public(
            Actor::new(creator, chain.vesting),
            &a_over,
            &[&creator_k],
            &w_over,
        );
        assert!(
            matches!(r_over, Err(LeeError::OutOfGas { .. })),
            "N_max + 1 must fail with OutOfGas, got {r_over:?}"
        );
        assert!(lo >= 100, "expected N_max >= 100, got {lo}");
        (lo, cyc_max, tx_bytes, cyc1, cyc_over)
    };

    let (n_lin, cyc_lin, bytes_lin, cyc_b1, cyc_lin_over) = find_n_max(BatchProfile::Linear, 0xA0);
    let (n_cl, cyc_cl, bytes_cl, _, _) = find_n_max(BatchProfile::CliffLinearWithCancelAuth, 0xB0);
    let (n_ms, cyc_ms, bytes_ms, _, _) = find_n_max(BatchProfile::Milestone4WithBothAuth, 0xC0);

    eprintln!("=== MEASURED LEZ v0.4.0-rc3 CYCLE REPORT (MAX_GAS_EXEC = 10,000,000) ===");
    eprintln!("ESCAPEMENT_ELF_BYTES={}", ESCAPEMENT_ELF.len());
    eprintln!("ESCAPEMENT_IMAGE_ID={:?}", prog.id());
    eprintln!(
        "CreateSchedule       = {cyc_create} cycles ({:.2}%)",
        cyc_create as f64 / 100_000.0
    );
    eprintln!(
        "ClaimPublic          = {cyc_claim_pub} cycles ({:.2}%)",
        cyc_claim_pub as f64 / 100_000.0
    );
    eprintln!(
        "ClaimExact (private) = {cyc_claim_priv} public cycles ({:.2}%)",
        cyc_claim_priv as f64 / 100_000.0
    );
    eprintln!(
        "Cancel               = {cyc_cancel} cycles ({:.2}%)",
        cyc_cancel as f64 / 100_000.0
    );
    eprintln!(
        "MakeNonCancelable    = {cyc_mnc} cycles ({:.2}%)",
        cyc_mnc as f64 / 100_000.0
    );
    eprintln!(
        "SignalMilestone      = {cyc_signal} cycles ({:.2}%)",
        cyc_signal as f64 / 100_000.0
    );
    eprintln!(
        "TransferBeneficiary  = {cyc_transfer} cycles ({:.2}%)",
        cyc_transfer as f64 / 100_000.0
    );
    eprintln!(
        "BatchCreate(1 Linear)= {cyc_b1} cycles ({:.2}%)",
        cyc_b1 as f64 / 100_000.0
    );
    eprintln!(
        "BatchCreate(8 Linear)= {cyc_batch8} cycles ({:.2}%)",
        cyc_batch8 as f64 / 100_000.0
    );
    eprintln!(
        "BatchCreate(Linear N_max={n_lin}) = {cyc_lin} cycles ({:.2}%), tx_bytes={bytes_lin}, N_max+1 charged={cyc_lin_over}",
        cyc_lin as f64 / 100_000.0
    );
    eprintln!(
        "BatchCreate(CliffLinear+Soft1 N_max={n_cl}) = {cyc_cl} cycles ({:.2}%), tx_bytes={bytes_cl}",
        cyc_cl as f64 / 100_000.0
    );
    eprintln!(
        "BatchCreate(Milestone4+Soft1/2 N_max={n_ms}) = {cyc_ms} cycles ({:.2}%), tx_bytes={bytes_ms}",
        cyc_ms as f64 / 100_000.0
    );
}

// ============================================================================
// Handler-driven stateful conservation invariant suite (global supply + all transitions + probes)
// ============================================================================

#[test]
fn stateful_handler_conservation_invariant_suite() {
    let mut chain = TestChain::new(1_000_000);
    let deployer_k = key(100);
    let treasury_k = key(69);
    let def_k = key(70);
    let creator_k = key(71);
    let donor_k = key(72);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let donor = account(&donor_k);
    // Never granted any role: the unauthorized-cancel probe always applies.
    let outsider_k = key(73);
    let outsider = account(&outsider_k);
    let cfg = config_pda(chain.vesting);
    let fv = fee_vault_pda(chain.vesting, &def);
    let total_supply: u128 = 100_000_000;

    chain.create_token(&def_k, &creator_k, total_supply);
    chain.init_public_holding(&donor_k, def);
    chain.transfer_public(&creator_k, donor, 1_000_000);

    // Enable a 25 bps protocol fee before any schedule exists, so every creation pays into the fee vault.
    chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[
                Actor::new(chain.vesting, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&deployer_k],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: None,
                fee_bps: 25,
                fee_treasury: Some(account(&treasury_k)),
            }),
        )
        .unwrap();

    struct Tracked {
        sched_id: AccountId,
        escrow_id: AccountId,
        benef_key: PrivateKey,
        /// Most recently retired beneficiary key; used by the claim-by-old-beneficiary probe.
        stale_benef_key: Option<PrivateKey>,
        priv_wallet: PrivateWallet,
        last_claimed: u128,
        was_non_cancelable: bool,
        /// F4: the transferability the schedule was created with; it must never change.
        transferable_at_creation: bool,
        was_cancelled: bool,
    }
    let mut tracked: Vec<Tracked> = Vec::new();
    let mut all_pub_holders: BTreeSet<AccountId> = BTreeSet::from([creator, donor]);
    let mut donations_per_escrow: BTreeMap<AccountId, u128> = BTreeMap::new();

    // Seed 4 single schedules + 1 batch of 4 schedules.
    let single_specs = [
        (
            [1u8; 32],
            key(121),
            123_457u128,
            ScheduleKind::CliffLinear {
                start_ts: 1_000_000,
                cliff_ts: 1_500_000,
                end_ts: 3_000_000,
                cliff_amount: 30_000,
            },
            true,
            true,
        ),
        (
            [2u8; 32],
            key(122),
            99_991u128,
            ScheduleKind::Linear {
                start_ts: 1_000_000,
                end_ts: 2_500_000,
            },
            true,
            false,
        ),
        (
            [3u8; 32],
            key(123),
            60_000u128,
            ScheduleKind::Milestone {
                tranches: vec![
                    MilestoneTranche {
                        amount: 15_000,
                        unlocked: false,
                        unlocked_at_ms: None,
                    },
                    MilestoneTranche {
                        amount: 20_000,
                        unlocked: false,
                        unlocked_at_ms: None,
                    },
                    MilestoneTranche {
                        amount: 25_000,
                        unlocked: false,
                        unlocked_at_ms: None,
                    },
                ],
            },
            true,
            true,
        ),
        (
            [4u8; 32],
            key(124),
            50_000u128,
            ScheduleKind::Linear {
                start_ts: 1_100_000,
                end_ts: 2_100_000,
            },
            false,
            false,
        ),
    ];

    for (idx, (salt, bk, amt, kind, cancelable, transferable)) in
        single_specs.into_iter().enumerate()
    {
        chain.init_public_holding(&bk, def);
        all_pub_holders.insert(account(&bk));
        let mut pw = PrivateWallet::new(150 + idx as u8);
        chain.init_private_holding(&mut pw, def);
        let params = CreateScheduleParams {
            salt,
            asset: Asset::Token { definition: def },
            creator_holding: creator,
            refund_holding: creator,
            beneficiary: account(&bk),
            total_amount: amt,
            kind,
            cancelable,
            transferable,
            cancel_authority: None,
            milestone_authority: None,
            broker: None,
        };
        let actors = chain.create_schedule_actors(creator, &params, &[fv]);
        let sid = schedule_pda(chain.vesting, &creator, &salt);
        let eid = single_escrow_pda(chain.vesting, &sid);
        chain
            .submit_public(
                Actor::new(creator, chain.vesting),
                &actors,
                &[&creator_k],
                &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
            )
            .unwrap();
        tracked.push(Tracked {
            sched_id: sid,
            escrow_id: eid,
            benef_key: bk,
            stale_benef_key: None,
            priv_wallet: pw,
            last_claimed: 0,
            was_non_cancelable: !cancelable,
            transferable_at_creation: transferable,
            was_cancelled: false,
        });
    }

    // Add a batch of 4 schedules sharing one batch escrow.
    let bid = [0xF0; 32];
    let batch_bks: Vec<PrivateKey> = (125u8..129u8).map(key).collect();
    for k in &batch_bks {
        chain.init_public_holding(k, def);
        all_pub_holders.insert(account(k));
    }
    let batch_params = BatchCreateParams {
        batch_id: bid,
        asset: Asset::Token { definition: def },
        creator_holding: creator,
        refund_holding: creator,
        broker: None,
        items: batch_bks
            .iter()
            .enumerate()
            .map(|(i, k)| BatchRecipient {
                beneficiary: account(k),
                total_amount: 40_000 + (i as u128) * 7_777,
                kind: ScheduleKind::CliffLinear {
                    start_ts: 1_000_000,
                    cliff_ts: 1_400_000,
                    end_ts: 2_800_000,
                    cliff_amount: 10_000,
                },
                cancelable: true,
                transferable: true,
                cancel_authority: None,
                milestone_authority: None,
            })
            .collect(),
    };
    let b_actors = chain.batch_create_actors(creator, &batch_params, &[fv]);
    let b_escrow = batch_escrow_pda(chain.vesting, &creator, &bid);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &b_actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(batch_params))),
        )
        .unwrap();
    for (i, bk) in batch_bks.into_iter().enumerate() {
        let mut pw = PrivateWallet::new(160 + i as u8);
        chain.init_private_holding(&mut pw, def);
        tracked.push(Tracked {
            sched_id: batch_schedule_pda(chain.vesting, &creator, &bid, i as u32),
            escrow_id: b_escrow,
            benef_key: bk,
            stale_benef_key: None,
            priv_wallet: pw,
            last_claimed: 0,
            was_non_cancelable: false,
            transferable_at_creation: true,
            was_cancelled: false,
        });
    }

    let mut rng: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut next_u64 = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut ops_attempted = 0u32;
    let mut ops_succeeded = 0u32;
    let mut transfers_done = 0u32;
    let mut mnc_done = 0u32;
    let mut neg_probes_rejected = 0u32;
    let mut next_transfer_key_byte = 175u8;

    for step in 0..80u64 {
        if step.is_multiple_of(3) {
            let delta = 100_000 + (next_u64() % 150_000);
            let next_t = chain.timestamp_ms + delta;
            chain.tick(next_t);
        }
        let idx = (next_u64() as usize) % tracked.len();
        let action = next_u64() % 8;
        let sched = chain.schedule(tracked[idx].sched_id);
        let now = chain.timestamp_ms;

        match action {
            0 | 1 => {
                // Public claim (partial or full) + interleaved overclaim negative probe.
                let avail = escapement_core::math::claimable_at(&sched, now);
                if avail > 0 {
                    let b_id = account(&tracked[idx].benef_key);
                    let actors = [
                        Actor::new(b_id, chain.vesting),
                        Actor::new(tracked[idx].sched_id, chain.vesting),
                        clock_actor(),
                        Actor::new(tracked[idx].escrow_id, chain.token),
                        Actor::new(b_id, chain.token),
                    ];
                    ops_attempted += 1;
                    let req = if action == 0 {
                        Some((avail / 2).max(1))
                    } else {
                        None
                    };
                    chain
                        .submit_public(
                            Actor::new(b_id, chain.vesting),
                            &actors,
                            &[&tracked[idx].benef_key],
                            &Wire::Program(VestingMessage::ClaimPublic {
                                schedule_id: tracked[idx].sched_id,
                                destination: b_id,
                                amount: req,
                            }),
                        )
                        .expect("bounded public claim succeeds");
                    ops_succeeded += 1;
                }
            }
            2 => {
                // Private blinded-alias claim.
                let avail = escapement_core::math::claimable_at(&sched, now);
                if avail > 0 {
                    ops_attempted += 1;
                    let amt = (avail / 3).max(1);
                    let mut factor = [0u8; 32];
                    factor[0..8].copy_from_slice(&step.to_le_bytes());
                    factor[8..16].copy_from_slice(&(idx as u64).to_le_bytes());
                    let mut rseed = [0u8; 32];
                    rseed[0..8].copy_from_slice(&(step + 1000).to_le_bytes());
                    let bk = tracked[idx].benef_key.clone();
                    let sid = tracked[idx].sched_id;
                    chain
                        .claim_private_blinded(
                            &PrivateClaimArgs {
                                beneficiary_key: &bk,
                                schedule_id: sid,
                                blinding_factor: factor,
                                random_seed: rseed,
                                amount: amt,
                                effective_ts: now,
                                promote_credit: true,
                            },
                            &mut tracked[idx].priv_wallet,
                        )
                        .expect("bounded private claim succeeds");
                    ops_succeeded += 1;
                }
            }
            3 => {
                // Signal next locked milestone.
                if sched.cancelled.is_none() {
                    if let ScheduleKind::Milestone { ref tranches } = sched.kind {
                        if let Some((mi, _)) =
                            tranches.iter().enumerate().find(|(_, t)| !t.unlocked)
                        {
                            ops_attempted += 1;
                            let actors = [
                                Actor::new(creator, chain.vesting),
                                Actor::new(tracked[idx].sched_id, chain.vesting),
                                clock_actor(),
                            ];
                            chain
                                .submit_public(
                                    Actor::new(creator, chain.vesting),
                                    &actors,
                                    &[&creator_k],
                                    &Wire::Program(VestingMessage::SignalMilestone {
                                        schedule_id: tracked[idx].sched_id,
                                        milestone_index: mi as u8,
                                    }),
                                )
                                .expect("milestone signal succeeds");
                            ops_succeeded += 1;
                        }
                    }
                }
            }
            4 => {
                // Cancel if cancelable, uncancelled, and unvested > 0.
                if sched.cancelable && sched.cancelled.is_none() {
                    let v = escapement_core::math::vested_at(&sched, now);
                    if v < sched.total_amount {
                        ops_attempted += 1;
                        let actors = [
                            Actor::new(creator, chain.vesting),
                            Actor::new(tracked[idx].sched_id, chain.vesting),
                            clock_actor(),
                            Actor::new(tracked[idx].escrow_id, chain.token),
                            Actor::new(creator, chain.token),
                        ];
                        chain
                            .submit_public(
                                Actor::new(creator, chain.vesting),
                                &actors,
                                &[&creator_k],
                                &Wire::Program(VestingMessage::Cancel {
                                    schedule_id: tracked[idx].sched_id,
                                }),
                            )
                            .expect("bounded cancel succeeds");
                        ops_succeeded += 1;
                    }
                }
            }
            5 => {
                // TransferBeneficiary when transferable == true.
                if sched.transferable && next_transfer_key_byte < 240 {
                    let new_k = key(next_transfer_key_byte);
                    next_transfer_key_byte += 1;
                    let new_id = account(&new_k);
                    chain.init_public_holding(&new_k, def);
                    all_pub_holders.insert(new_id);
                    let old_id = account(&tracked[idx].benef_key);
                    tracked[idx].stale_benef_key = Some(tracked[idx].benef_key.clone());
                    ops_attempted += 1;
                    chain
                        .submit_public(
                            Actor::new(old_id, chain.vesting),
                            &[
                                Actor::new(old_id, chain.vesting),
                                Actor::new(tracked[idx].sched_id, chain.vesting),
                            ],
                            &[&tracked[idx].benef_key],
                            &Wire::Program(VestingMessage::TransferBeneficiary {
                                schedule_id: tracked[idx].sched_id,
                                new_beneficiary: new_id,
                            }),
                        )
                        .expect("bounded transfer succeeds");
                    tracked[idx].benef_key = new_k;
                    transfers_done += 1;
                    ops_succeeded += 1;
                }
            }
            6 => {
                // MakeNonCancelable when cancelable && uncancelled.
                if sched.cancelable && sched.cancelled.is_none() {
                    ops_attempted += 1;
                    chain
                        .submit_public(
                            Actor::new(creator, chain.vesting),
                            &[
                                Actor::new(creator, chain.vesting),
                                Actor::new(tracked[idx].sched_id, chain.vesting),
                            ],
                            &[&creator_k],
                            &Wire::Program(VestingMessage::MakeNonCancelable {
                                schedule_id: tracked[idx].sched_id,
                            }),
                        )
                        .expect("make non-cancelable succeeds");
                    mnc_done += 1;
                    ops_succeeded += 1;
                }
            }
            _ => {
                // Unsolicited donation into escrow.
                ops_attempted += 1;
                let gift = 137u128;
                chain.transfer_public(&donor_k, tracked[idx].escrow_id, gift);
                *donations_per_escrow
                    .entry(tracked[idx].escrow_id)
                    .or_insert(0) += gift;
                ops_succeeded += 1;
            }
        }

        // Deterministic interleaved negative probe every 4th step, rotating 5 refusal
        // classes against a randomly-picked tracked schedule: unauthorized cancel,
        // double cancel, overclaim, escrow self-lock destination, and claim by the
        // retired beneficiary. Every probe must exit with its exact code AND leave
        // the whole V03State byte-identical, so deleting or inverting any of these
        // guest guards flips a code or mutates state and fails this suite.
        if step.is_multiple_of(4) {
            let probe_kind = (step / 4) % 5;
            let idx_p = (next_u64() as usize) % tracked.len();
            let sched_p = chain.schedule(tracked[idx_p].sched_id);
            let now_p = chain.timestamp_ms;
            let avail_p = escapement_core::math::claimable_at(&sched_p, now_p);
            let b_id_p = account(&tracked[idx_p].benef_key);
            let sid_p = tracked[idx_p].sched_id;
            let eid_p = tracked[idx_p].escrow_id;
            let before = chain.state.clone();
            let (res, expected): (Result<Vec<TransactionEvent>, LeeError>, u32) =
                if probe_kind == 1 && sched_p.cancelled.is_some() {
                    // Double cancel by the rightful authority: 18.
                    (
                        chain.submit_public(
                            Actor::new(creator, chain.vesting),
                            &[
                                Actor::new(creator, chain.vesting),
                                Actor::new(sid_p, chain.vesting),
                                clock_actor(),
                                Actor::new(eid_p, chain.token),
                                Actor::new(creator, chain.token),
                            ],
                            &[&creator_k],
                            &Wire::Program(VestingMessage::Cancel { schedule_id: sid_p }),
                        ),
                        18,
                    )
                } else if probe_kind == 2 && avail_p > 0 {
                    // Overclaim by exactly one unit above claimable: 27.
                    (
                        chain.submit_public(
                            Actor::new(b_id_p, chain.vesting),
                            &[
                                Actor::new(b_id_p, chain.vesting),
                                Actor::new(sid_p, chain.vesting),
                                clock_actor(),
                                Actor::new(eid_p, chain.token),
                                Actor::new(b_id_p, chain.token),
                            ],
                            &[&tracked[idx_p].benef_key],
                            &Wire::Program(VestingMessage::ClaimPublic {
                                schedule_id: sid_p,
                                destination: b_id_p,
                                amount: Some(avail_p + 1),
                            }),
                        ),
                        27,
                    )
                } else if probe_kind == 3 {
                    // Destination equal to the schedule's own escrow: 31.
                    (
                        chain.submit_public(
                            Actor::new(b_id_p, chain.vesting),
                            &[
                                Actor::new(b_id_p, chain.vesting),
                                Actor::new(sid_p, chain.vesting),
                                Actor::new(eid_p, chain.token),
                            ],
                            &[&tracked[idx_p].benef_key],
                            &Wire::Program(VestingMessage::ClaimPublic {
                                schedule_id: sid_p,
                                destination: eid_p,
                                amount: Some(100),
                            }),
                        ),
                        31,
                    )
                } else if probe_kind == 4 && tracked[idx_p].stale_benef_key.is_some() {
                    // Claim by the retired (pre-transfer) beneficiary: 13.
                    let stale_k = tracked[idx_p]
                        .stale_benef_key
                        .as_ref()
                        .expect("checked Some above");
                    let stale_id = account(stale_k);
                    (
                        chain.submit_public(
                            Actor::new(stale_id, chain.vesting),
                            &[
                                Actor::new(stale_id, chain.vesting),
                                Actor::new(sid_p, chain.vesting),
                                clock_actor(),
                                Actor::new(eid_p, chain.token),
                                Actor::new(stale_id, chain.token),
                            ],
                            &[stale_k],
                            &Wire::Program(VestingMessage::ClaimPublic {
                                schedule_id: sid_p,
                                destination: stale_id,
                                amount: None,
                            }),
                        ),
                        13,
                    )
                } else {
                    // Unauthorized cancel (probe class 0, and the fallback whenever a
                    // class-specific precondition does not hold): 13.
                    (
                        chain.submit_public(
                            Actor::new(outsider, chain.vesting),
                            &[
                                Actor::new(outsider, chain.vesting),
                                Actor::new(sid_p, chain.vesting),
                                clock_actor(),
                                Actor::new(eid_p, chain.token),
                                Actor::new(creator, chain.token),
                            ],
                            &[&outsider_k],
                            &Wire::Program(VestingMessage::Cancel { schedule_id: sid_p }),
                        ),
                        13,
                    )
                };
            assert_exit_code(&res, expected);
            assert!(
                chain.state == before,
                "negative probe class {probe_kind} at step {step} must leave state unchanged"
            );
            assert_eq!(
                chain.schedule(sid_p).claimed_amount,
                sched_p.claimed_amount,
                "negative probe class {probe_kind} at step {step} must not change claimed_amount"
            );
            neg_probes_rejected += 1;
        }

        // Assert ALL strict invariants + global supply conservation after EVERY step!
        let mut expected_by_escrow: BTreeMap<AccountId, u128> = BTreeMap::new();
        for t in &mut tracked {
            let s = chain.schedule(t.sched_id);
            let v = escapement_core::math::vested_at(&s, chain.timestamp_ms);
            assert!(s.claimed_amount >= t.last_claimed, "claimed decreased");
            assert!(s.claimed_amount <= v, "claimed exceeded vested");
            assert!(v <= s.total_amount, "vested exceeded total");
            t.last_claimed = s.claimed_amount;

            if t.was_non_cancelable {
                assert!(!s.cancelable, "non-cancelable reversed!");
            }
            assert_eq!(
                s.transferable, t.transferable_at_creation,
                "F4: transferability never changes after creation"
            );
            if !s.cancelable {
                t.was_non_cancelable = true;
            }
            if t.was_cancelled {
                assert!(s.cancelled.is_some(), "cancelled reversed!");
            }
            if let Some(rec) = s.cancelled {
                assert_eq!(rec.vested_at_cancel + rec.refunded_amount, s.total_amount);
                assert!(rec.vested_at_cancel >= s.claimed_amount);
                assert_eq!(v, rec.vested_at_cancel);
                t.was_cancelled = true;
            }

            let refunded = s.cancelled.map_or(0, |r| r.refunded_amount);
            let remaining = s.total_amount - s.claimed_amount - refunded;
            *expected_by_escrow.entry(t.escrow_id).or_insert(0) += remaining;
        }
        let mut escrow_sum = 0u128;
        for (escrow_id, expected_remaining) in &expected_by_escrow {
            let donated = donations_per_escrow.get(escrow_id).copied().unwrap_or(0);
            let actual = chain.token_balance(*escrow_id);
            assert_eq!(
                actual,
                *expected_remaining + donated,
                "strict escrow conservation violated at step {step}"
            );
            escrow_sum += actual;
        }
        // Global token supply conservation across ALL public holdings + escrows + fee vault + private wallets!
        let pub_sum: u128 = all_pub_holders
            .iter()
            .map(|h| chain.token_balance(*h))
            .sum();
        let priv_sum: u128 = tracked
            .iter()
            .map(|t| t.priv_wallet.balance(chain.token))
            .sum();
        let fv_bal = chain.token_balance(fv);
        assert_eq!(
            pub_sum + escrow_sum + fv_bal + priv_sum,
            total_supply,
            "global token supply conservation violated at step {step}"
        );
    }
    assert!(
        ops_attempted >= 30,
        "invariant handler must exercise deep state"
    );
    assert_eq!(
        ops_succeeded, ops_attempted,
        "handler revert rate must be 0%"
    );
    assert!(transfers_done >= 1, "must exercise TransferBeneficiary");
    assert!(mnc_done >= 1, "must exercise MakeNonCancelable");
    assert!(
        neg_probes_rejected >= 16,
        "must exercise frequent interleaved failure probes (unauthorized cancel, double cancel, overclaim, self-lock, stale beneficiary), got {neg_probes_rejected}"
    );
    eprintln!(
        "[INVARIANTS] {ops_succeeded}/{ops_attempted} stateful ops passed (transfers={transfers_done}, make_non_cancelable={mnc_done}, neg_probes={neg_probes_rejected} across 5 refusal classes, each state-unchanged), strict per-escrow + global supply conservation held on every step"
    );
}

// ============================================================================
// Adversarial 20-claim privacy linkability suite (full observer surface scan)
// ============================================================================

#[test]
fn adversarial_20_claim_no_leak_and_distinct_values_suite() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(81);
    let creator_k = key(82);
    let def = account(&def_k);
    let creator = account(&creator_k);
    chain.create_token(&def_k, &creator_k, 10_000_000);

    // 5 public beneficiaries -> 5 private wallets, 4 claims each = 20 private claims.
    let benef_keys: Vec<PrivateKey> = (130u8..135u8).map(key).collect();
    let mut priv_wallets: Vec<PrivateWallet> = (140u8..145u8).map(PrivateWallet::new).collect();
    let mut sched_ids = Vec::new();
    let mut escrow_ids = Vec::new();

    for (i, bk) in benef_keys.iter().enumerate() {
        chain.init_private_holding(&mut priv_wallets[i], def);
        let params = CreateScheduleParams {
            salt: [0x80 + i as u8; 32],
            asset: Asset::Token { definition: def },
            creator_holding: creator,
            refund_holding: creator,
            beneficiary: account(bk),
            total_amount: 40_000,
            kind: ScheduleKind::Linear {
                start_ts: 1_000_000,
                end_ts: 5_000_000,
            },
            cancelable: false,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
            broker: None,
        };
        let actors = chain.create_schedule_actors(creator, &params, &[]);
        let sid = schedule_pda(chain.vesting, &creator, &params.salt);
        let eid = single_escrow_pda(chain.vesting, &sid);
        chain
            .submit_public(
                Actor::new(creator, chain.vesting),
                &actors,
                &[&creator_k],
                &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
            )
            .unwrap();
        sched_ids.push(sid);
        escrow_ids.push(eid);
    }

    let real_priv_ids: BTreeSet<AccountId> = priv_wallets.iter().map(PrivateWallet::id).collect();
    let pub_benef_ids: BTreeSet<AccountId> = benef_keys.iter().map(account).collect();
    let mut observed_aliases: BTreeSet<AccountId> = BTreeSet::new();
    let mut observed_nullifiers: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut observed_commitments: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut observed_epks: BTreeSet<Vec<u8>> = BTreeSet::new();

    for round in 1u64..=4u64 {
        let ts = 1_000_000 + round * 1_000_000;
        chain.tick(ts);
        for i in 0..5usize {
            let mut factor = [0u8; 32];
            factor[0] = round as u8;
            factor[1] = i as u8;
            factor[31] = 0xAA;
            let mut rseed = [0u8; 32];
            rseed[0] = round as u8;
            rseed[1] = i as u8;
            rseed[30] = 0x55;
            let expected_alias = priv_wallets[i].id().blinded(&factor);
            let res = chain
                .claim_private_blinded(
                    &PrivateClaimArgs {
                        beneficiary_key: &benef_keys[i],
                        schedule_id: sched_ids[i],
                        blinding_factor: factor,
                        random_seed: rseed,
                        amount: 10_000,
                        effective_ts: ts,
                        promote_credit: true,
                    },
                    &mut priv_wallets[i],
                )
                .expect("private claim succeeds");

            let wallet_refs: Vec<&PrivateWallet> = priv_wallets.iter().collect();
            assert_no_private_leak(
                &chain,
                &res,
                sched_ids[i],
                escrow_ids[i],
                &wallet_refs,
                expected_alias,
            );
            assert!(
                !real_priv_ids.contains(&expected_alias)
                    && !pub_benef_ids.contains(&expected_alias),
                "alias must be disjoint from real private and public addresses"
            );
            assert!(
                observed_aliases.insert(expected_alias),
                "alias reused across claims — linkability leak!"
            );
            assert_eq!(res.output.execution.private_actions.len(), 1);
            let act = &res.output.execution.private_actions[0];
            assert!(
                observed_nullifiers.insert(borsh::to_vec(&act.nullifier).unwrap()),
                "nullifier reused!"
            );
            assert!(
                observed_commitments.insert(borsh::to_vec(&act.commitment).unwrap()),
                "commitment reused!"
            );
            assert!(
                observed_epks.insert(borsh::to_vec(&act.encrypted_post_state.epk).unwrap()),
                "epk reused!"
            );
            assert_eq!(
                res.output.execution.validity.timestamps.end(),
                None,
                "ClaimExact validity window must be unbounded above so proofs never expire"
            );
        }
    }

    assert_eq!(observed_aliases.len(), 20);
    assert_eq!(observed_nullifiers.len(), 20);
    assert_eq!(observed_commitments.len(), 20);
    assert_eq!(observed_epks.len(), 20);
    for w in &priv_wallets {
        assert_eq!(w.balance(chain.token), 40_000);
    }
    eprintln!("[PRIVACY_20] 20/20 private claims verified: 0 real private IDs/npks/vpks leaked across full tx+events+state, 0 blinded aliases in events, 20/20 pairwise-distinct aliases/nullifiers/commitments/epks, 5/5 wallets reconciled");
}

// ============================================================================
// T1 (24 Nov): signer-relay refusal, direct-PDA calls, native-asset schedules
// ============================================================================

fn wire(msg: VestingMessage) -> Vec<u8> {
    borsh::to_vec(&Wire::Program(msg)).expect("wire encodes")
}

fn linear_params(
    salt: u8,
    asset: Asset,
    creator: AccountId,
    beneficiary: AccountId,
    total: u128,
) -> CreateScheduleParams {
    CreateScheduleParams {
        salt: [salt; 32],
        asset,
        creator_holding: creator,
        refund_holding: creator,
        beneficiary,
        total_amount: total,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 2_000_000,
        },
        cancelable: true,
        transferable: true,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    }
}

/// LEZ v0.4 authorizes a signer's account on every message of the call tree. A program the user
/// signs a transaction for (here the relay) must not be able to act in the user's name: every
/// user transition arriving from another program without `AsPda` exits with code 35, metered,
/// and leaves state byte-identical.
#[test]
fn sec_relay_eoa_refused() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(201);
    let creator_k = key(202);
    let benef_k = key(203);
    let treasury_k = key(204);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    let treasury = account(&treasury_k);
    chain.create_token(&def_k, &creator_k, 1_000_000);
    chain.init_public_holding(&benef_k, def);
    chain.init_public_holding(&treasury_k, def);

    let mut params = linear_params(
        0x21,
        Asset::Token { definition: def },
        creator,
        benef,
        100_000,
    );
    params.kind = ScheduleKind::Milestone {
        tranches: vec![MilestoneTranche {
            amount: 100_000,
            unlocked: false,
            unlocked_at_ms: None,
        }],
    };
    let actors = chain.create_schedule_actors(creator, &params, &[]);
    let sched = schedule_pda(chain.vesting, &creator, &params.salt);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params.clone()))),
        )
        .expect("schedule created");

    let attacker = AccountId::new([0xEE; 32]);
    let cases: Vec<(&str, &PrivateKey, AccountId, VestingMessage)> = vec![
        (
            "ClaimPublic",
            &benef_k,
            benef,
            VestingMessage::ClaimPublic {
                schedule_id: sched,
                destination: attacker,
                amount: None,
            },
        ),
        (
            "ClaimExact",
            &benef_k,
            benef,
            VestingMessage::ClaimExact {
                schedule_id: sched,
                destination: attacker,
                amount: 1,
                effective_ts: 0,
            },
        ),
        (
            "TransferBeneficiary",
            &benef_k,
            benef,
            VestingMessage::TransferBeneficiary {
                schedule_id: sched,
                new_beneficiary: attacker,
            },
        ),
        (
            "Cancel",
            &creator_k,
            creator,
            VestingMessage::Cancel { schedule_id: sched },
        ),
        (
            "MakeNonCancelable",
            &creator_k,
            creator,
            VestingMessage::MakeNonCancelable { schedule_id: sched },
        ),
        (
            "SignalMilestone",
            &creator_k,
            creator,
            VestingMessage::SignalMilestone {
                schedule_id: sched,
                milestone_index: 0,
            },
        ),
        (
            "CreateSchedule",
            &creator_k,
            creator,
            VestingMessage::CreateSchedule(Box::new(CreateScheduleParams {
                salt: [0x22; 32],
                beneficiary: attacker,
                ..params.clone()
            })),
        ),
        (
            "BatchCreate",
            &creator_k,
            creator,
            VestingMessage::BatchCreate(Box::new(BatchCreateParams {
                batch_id: [0x23; 32],
                asset: Asset::Token { definition: def },
                creator_holding: creator,
                refund_holding: creator,
                broker: None,
                items: vec![BatchRecipient {
                    beneficiary: attacker,
                    total_amount: 1_000,
                    kind: ScheduleKind::Linear {
                        start_ts: 1_000_000,
                        end_ts: 2_000_000,
                    },
                    cancelable: true,
                    transferable: true,
                    cancel_authority: None,
                    milestone_authority: None,
                }],
            })),
        ),
        (
            "WithdrawFees",
            &treasury_k,
            treasury,
            VestingMessage::WithdrawFees {
                asset: Asset::Token { definition: def },
                destination: attacker,
                amount: 1,
            },
        ),
    ];
    for (name, signer_k, seat, msg) in cases {
        let before = chain.state.clone();
        let res = chain.submit_via_relay(
            RELAY_A,
            signer_k,
            Actor::new(seat, chain.vesting),
            wire(msg),
            vec![],
            &[Actor::new(sched, chain.vesting), clock_actor()],
        );
        let cycles = assert_exit_code(&res, 35);
        assert!(chain.state == before, "{name}: relayed call changed state");
        eprintln!("[SEC_RELAY] {name} relayed by another program -> exit 35 ({cycles} cycles)");
    }
    // The same calls signed directly still work (root rule does not block the owner).
    chain.tick(1_500_000);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[
                Actor::new(creator, chain.vesting),
                Actor::new(sched, chain.vesting),
                clock_actor(),
            ],
            &[&creator_k],
            &Wire::Program(VestingMessage::SignalMilestone {
                schedule_id: sched,
                milestone_index: 0,
            }),
        )
        .expect("direct signal by the creator still succeeds");
}

/// A multisig/launchpad program acting as one of its own PDAs (`AsPda`) can create, signal,
/// claim, make non-cancelable and cancel; another program holding only an inherited grant of
/// that PDA, or the right program with a wrong seed, is refused with code 35.
#[test]
fn sec_pda_cpi_succeeds_and_inherited_seed_relay_refused() {
    let user_k = key(210);
    let creator_k = key(211);
    let user = account(&user_k);
    let creator = account(&creator_k);
    let seed = PdaSeed::new([0x5e; 32]);
    let pda = AccountId::for_public_pda(&RELAY_A, &seed);
    let mut chain = TestChain::new_funded(
        1_000_000,
        &[(user, 1_000), (creator, 10_000_000), (pda, 5_000_000)],
    );
    let as_pda = |call: PdaCall| {
        wire(VestingMessage::AsPda {
            seed: *seed.as_bytes(),
            call: Box::new(call),
        })
    };

    // 1) The PDA creates a native schedule as creator (its own native balance funds it).
    let params = linear_params(0x31, Asset::Native, pda, creator, 1_000_000);
    let sched_by_pda = schedule_pda(chain.vesting, &pda, &params.salt);
    let mut extra = chain.native_create_actors(pda, &params, false);
    extra.retain(|a| *a != Actor::new(pda, chain.vesting));
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(PdaCall::CreateSchedule(Box::new(params.clone()))),
            vec![seed],
            &extra,
        )
        .expect("PDA-created native schedule");
    assert_eq!(chain.schedule(sched_by_pda).creator, pda);
    assert_eq!(chain.native_balance(pda), 4_000_000);

    // 2) An EOA creates a milestone schedule whose beneficiary and both authorities are the PDA.
    let ms = CreateScheduleParams {
        salt: [0x32; 32],
        asset: Asset::Native,
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: pda,
        total_amount: 300_000,
        kind: ScheduleKind::Milestone {
            tranches: vec![
                MilestoneTranche {
                    amount: 100_000,
                    unlocked: false,
                    unlocked_at_ms: None,
                },
                MilestoneTranche {
                    amount: 200_000,
                    unlocked: false,
                    unlocked_at_ms: None,
                },
            ],
        },
        cancelable: true,
        transferable: false,
        cancel_authority: Some(pda),
        milestone_authority: Some(pda),
        broker: None,
    };
    let ms_sched = schedule_pda(chain.vesting, &creator, &ms.salt);
    let ms_escrow = single_escrow_pda(chain.vesting, &ms_sched);
    let actors = chain.native_create_actors(creator, &ms, false);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(ms))),
        )
        .expect("EOA-created milestone schedule");

    // Inherited grant: RELAY_A grants the PDA seed to RELAY_B's actor at the PDA account, and
    // RELAY_B forwards `AsPda` to the vesting seat. RELAY_B does not own the PDA -> 35.
    let inner = RelayMessage::Forward {
        to: Actor::new(pda, chain.vesting),
        message: as_pda(PdaCall::SignalMilestone {
            schedule_id: ms_sched,
            milestone_index: 0,
        }),
        seeds: vec![],
    };
    let before = chain.state.clone();
    let res = chain.submit_via_relay(
        RELAY_A,
        &user_k,
        Actor::new(pda, RELAY_B),
        borsh::to_vec(&inner).unwrap(),
        vec![seed],
        &[
            Actor::new(pda, chain.vesting),
            Actor::new(ms_sched, chain.vesting),
            clock_actor(),
        ],
    );
    assert_exit_code(&res, 35);
    assert!(chain.state == before);
    // The same inherited grant used for a plain (root-style) call -> 35.
    let inner_plain = RelayMessage::Forward {
        to: Actor::new(pda, chain.vesting),
        message: wire(VestingMessage::SignalMilestone {
            schedule_id: ms_sched,
            milestone_index: 0,
        }),
        seeds: vec![],
    };
    let res = chain.submit_via_relay(
        RELAY_A,
        &user_k,
        Actor::new(pda, RELAY_B),
        borsh::to_vec(&inner_plain).unwrap(),
        vec![seed],
        &[
            Actor::new(pda, chain.vesting),
            Actor::new(ms_sched, chain.vesting),
            clock_actor(),
        ],
    );
    assert_exit_code(&res, 35);
    // The owning program with a seed that does not derive the PDA -> 35.
    let res = chain.submit_via_relay(
        RELAY_A,
        &user_k,
        Actor::new(pda, chain.vesting),
        wire(VestingMessage::AsPda {
            seed: [0x5f; 32],
            call: Box::new(PdaCall::SignalMilestone {
                schedule_id: ms_sched,
                milestone_index: 0,
            }),
        }),
        vec![PdaSeed::new([0x5f; 32])],
        &[Actor::new(ms_sched, chain.vesting), clock_actor()],
    );
    assert_exit_code(&res, 35);
    assert!(chain.state == before);

    // 3) The owning program signals tranche 0 as the PDA (milestone authority) -> succeeds.
    chain.tick(1_100_000);
    let evs = chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(PdaCall::SignalMilestone {
                schedule_id: ms_sched,
                milestone_index: 0,
            }),
            vec![seed],
            &[Actor::new(ms_sched, chain.vesting), clock_actor()],
        )
        .expect("PDA milestone signal");
    assert_eq!(events_of::<MilestoneSignaled>(&evs)[0].signaled_by, pda);

    // 4) The PDA (beneficiary) claims tranche 0 to the creator's account.
    let creator_before = chain.native_balance(creator);
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(PdaCall::ClaimPublic {
                schedule_id: ms_sched,
                destination: creator,
                amount: None,
            }),
            vec![seed],
            &[
                Actor::new(ms_sched, chain.vesting),
                clock_actor(),
                Actor::new(ms_escrow, NATIVE),
                Actor::new(creator, NATIVE),
            ],
        )
        .expect("PDA claim");
    assert_eq!(chain.native_balance(creator), creator_before + 100_000);
    assert_eq!(chain.native_balance(ms_escrow), 200_000);

    // 5) The PDA (cancel authority) cancels: the unvested 200,000 return to the refund account.
    let creator_before = chain.native_balance(creator);
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(PdaCall::Cancel {
                schedule_id: ms_sched,
            }),
            vec![seed],
            &[
                Actor::new(ms_sched, chain.vesting),
                clock_actor(),
                Actor::new(ms_escrow, NATIVE),
                Actor::new(creator, NATIVE),
            ],
        )
        .expect("PDA cancel");
    assert_eq!(chain.native_balance(creator), creator_before + 200_000);
    assert_eq!(chain.native_balance(ms_escrow), 0);

    // 6) The PDA, as creator of its own schedule, makes it non-cancelable.
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(PdaCall::MakeNonCancelable {
                schedule_id: sched_by_pda,
            }),
            vec![seed],
            &[Actor::new(sched_by_pda, chain.vesting)],
        )
        .expect("PDA make non-cancelable");
    assert!(!chain.schedule(sched_by_pda).cancelable);
    eprintln!("[SEC_PDA] AsPda create/signal/claim/cancel/make-non-cancelable succeed; inherited grant, plain relay and wrong seed refused with 35");
}

/// Native LEZ schedules end to end: create (single, batch), public claims (partial, full),
/// cancel with refund, milestone, protocol fee into the native fee vault and its withdrawal,
/// a one-transaction private claim, refusals, cycle costs and the batch ceiling per shape.
#[test]
fn native_asset_lifecycle_fees_batch_private_claim_and_ceilings() {
    let creator_k = key(221);
    let benef_k = key(222);
    let benef2_k = key(223);
    let treasury_k = key(224);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    let benef2 = account(&benef2_k);
    let treasury = account(&treasury_k);
    let mut chain = TestChain::new_funded(
        1_000_000,
        &[
            (creator, 1_000_000_000),
            (benef, 1),
            (benef2, 1),
            (treasury, 1),
        ],
    );

    // Refusals: funding from another account (13), refund to the schedule's own escrow (28).
    let mut bad = linear_params(0x40, Asset::Native, creator, benef, 1_000);
    bad.creator_holding = benef;
    let res = chain.submit_public(
        Actor::new(creator, chain.vesting),
        &chain.native_create_actors(creator, &bad, false),
        &[&creator_k],
        &Wire::Program(VestingMessage::CreateSchedule(Box::new(bad))),
    );
    assert_exit_code(&res, 13);
    let mut bad = linear_params(0x41, Asset::Native, creator, benef, 1_000);
    let bad_sched = schedule_pda(chain.vesting, &creator, &bad.salt);
    bad.refund_holding = single_escrow_pda(chain.vesting, &bad_sched);
    let res = chain.submit_public(
        Actor::new(creator, chain.vesting),
        &chain.native_create_actors(creator, &bad, false),
        &[&creator_k],
        &Wire::Program(VestingMessage::CreateSchedule(Box::new(bad))),
    );
    assert_exit_code(&res, 28);

    // 1) Linear native schedule: escrow holds exactly the total, creator debited.
    let params = linear_params(0x42, Asset::Native, creator, benef, 1_000_000);
    let sched = schedule_pda(chain.vesting, &creator, &params.salt);
    let escrow = single_escrow_pda(chain.vesting, &sched);
    let actors = chain.native_create_actors(creator, &params, false);
    let (cyc_create, r) = chain.measure_public(
        Actor::new(creator, chain.vesting),
        &actors,
        &[&creator_k],
        &Wire::Program(VestingMessage::CreateSchedule(Box::new(params.clone()))),
    );
    r.expect("native create simulates");
    let creator_before = chain.native_balance(creator);
    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
        )
        .expect("native schedule created");
    assert_eq!(chain.native_balance(escrow), 1_000_000);
    assert_eq!(chain.native_balance(creator), creator_before - 1_000_000);
    assert_eq!(events_of::<ScheduleCreated>(&evs)[0].asset, Asset::Native);
    assert_eq!(chain.schedule(sched).asset_program_id, NATIVE);

    // 2) Partial then full public claim.
    chain.tick(1_250_000);
    let claim_actors = [
        Actor::new(benef, chain.vesting),
        Actor::new(sched, chain.vesting),
        clock_actor(),
        Actor::new(escrow, NATIVE),
        Actor::new(benef, NATIVE),
    ];
    let partial = Wire::Program(VestingMessage::ClaimPublic {
        schedule_id: sched,
        destination: benef,
        amount: Some(100_000),
    });
    let (cyc_claim, r) = chain.measure_public(
        Actor::new(benef, chain.vesting),
        &claim_actors,
        &[&benef_k],
        &partial,
    );
    r.expect("native claim simulates");
    chain
        .submit_public(
            Actor::new(benef, chain.vesting),
            &claim_actors,
            &[&benef_k],
            &partial,
        )
        .expect("partial native claim");
    assert_eq!(chain.native_balance(benef), 1 + 100_000);
    // Overclaim (27) and nothing changed.
    let before = chain.state.clone();
    let res = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &claim_actors,
        &[&benef_k],
        &Wire::Program(VestingMessage::ClaimPublic {
            schedule_id: sched,
            destination: benef,
            amount: Some(200_000),
        }),
    );
    assert_exit_code(&res, 27);
    assert!(chain.state == before);
    chain.tick(2_000_000);
    chain
        .submit_public(
            Actor::new(benef, chain.vesting),
            &claim_actors,
            &[&benef_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: sched,
                destination: benef,
                amount: None,
            }),
        )
        .expect("full native claim");
    assert_eq!(chain.native_balance(benef), 1 + 1_000_000);
    assert_eq!(chain.native_balance(escrow), 0);

    // 3) Cancel mid-schedule: unvested back to the creator, vested stays claimable.
    let mut cp = linear_params(0x43, Asset::Native, creator, benef2, 400_000);
    cp.kind = ScheduleKind::Linear {
        start_ts: 2_000_000,
        end_ts: 3_000_000,
    };
    let c_sched = schedule_pda(chain.vesting, &creator, &cp.salt);
    let c_escrow = single_escrow_pda(chain.vesting, &c_sched);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &chain.native_create_actors(creator, &cp, false),
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(cp))),
        )
        .expect("cancelable native schedule");
    chain.tick(2_250_000);
    let cancel_actors = [
        Actor::new(creator, chain.vesting),
        Actor::new(c_sched, chain.vesting),
        clock_actor(),
        Actor::new(c_escrow, NATIVE),
        Actor::new(creator, NATIVE),
    ];
    let cancel = Wire::Program(VestingMessage::Cancel {
        schedule_id: c_sched,
    });
    let (cyc_cancel, r) = chain.measure_public(
        Actor::new(creator, chain.vesting),
        &cancel_actors,
        &[&creator_k],
        &cancel,
    );
    r.expect("native cancel simulates");
    let creator_before = chain.native_balance(creator);
    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &cancel_actors,
            &[&creator_k],
            &cancel,
        )
        .expect("native cancel");
    let c = &events_of::<Cancelled>(&evs)[0];
    assert_eq!(c.vested_at_cancel, 100_000);
    assert_eq!(c.refunded_amount, 300_000);
    assert_eq!(chain.native_balance(creator), creator_before + 300_000);
    assert_eq!(chain.native_balance(c_escrow), 100_000);
    chain
        .submit_public(
            Actor::new(benef2, chain.vesting),
            &[
                Actor::new(benef2, chain.vesting),
                Actor::new(c_sched, chain.vesting),
                clock_actor(),
                Actor::new(c_escrow, NATIVE),
                Actor::new(benef2, NATIVE),
            ],
            &[&benef2_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: c_sched,
                destination: benef2,
                amount: None,
            }),
        )
        .expect("vested share claimable after cancel");
    assert_eq!(chain.native_balance(benef2), 1 + 100_000);
    assert_eq!(chain.native_balance(c_escrow), 0);

    // 4) Protocol fee (50 bps) on a native creation lands in the native fee vault; the treasury
    //    withdraws it; a non-treasury caller is refused (13).
    let cfg = config_pda(chain.vesting);
    chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[
                Actor::new(chain.vesting, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&key(100)],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: Some(chain.token),
                fee_bps: 50,
                fee_treasury: Some(treasury),
            }),
        )
        .expect("fee switch on");
    let fp = linear_params(0x44, Asset::Native, creator, benef, 200_000);
    let fv = fee_vault_pda(chain.vesting, &Asset::Native.key());
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &chain.native_create_actors(creator, &fp, true),
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(fp))),
        )
        .expect("native create with protocol fee");
    assert_eq!(chain.native_balance(fv), 1_000);
    let withdraw_actors = [
        Actor::new(treasury, chain.vesting),
        Actor::new(cfg, chain.vesting),
        Actor::new(fv, NATIVE),
        Actor::new(treasury, NATIVE),
    ];
    let res = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[
            Actor::new(benef, chain.vesting),
            Actor::new(cfg, chain.vesting),
            Actor::new(fv, NATIVE),
            Actor::new(benef, NATIVE),
        ],
        &[&benef_k],
        &Wire::Program(VestingMessage::WithdrawFees {
            asset: Asset::Native,
            destination: benef,
            amount: 1_000,
        }),
    );
    assert_exit_code(&res, 13);
    let evs = chain
        .submit_public(
            Actor::new(treasury, chain.vesting),
            &withdraw_actors,
            &[&treasury_k],
            &Wire::Program(VestingMessage::WithdrawFees {
                asset: Asset::Native,
                destination: treasury,
                amount: 1_000,
            }),
        )
        .expect("treasury withdraws native fees");
    assert_eq!(events_of::<FeeWithdrawn>(&evs)[0].asset, Asset::Native);
    assert_eq!(chain.native_balance(treasury), 1 + 1_000);
    assert_eq!(chain.native_balance(fv), 0);
    chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[
                Actor::new(chain.vesting, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&key(100)],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: Some(chain.token),
                fee_bps: 0,
                fee_treasury: None,
            }),
        )
        .expect("fee switch off");

    // 5) Native batch of 8 with per-recipient amounts over one shared escrow; two claims.
    let items: Vec<BatchRecipient> = (0..8u8)
        .map(|i| BatchRecipient {
            beneficiary: if i % 2 == 0 { benef } else { benef2 },
            total_amount: 10_000 * (u128::from(i) + 1),
            kind: ScheduleKind::Linear {
                start_ts: 2_000_000,
                end_ts: 3_000_000,
            },
            cancelable: true,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
        })
        .collect();
    let bp = BatchCreateParams {
        batch_id: [0x45; 32],
        asset: Asset::Native,
        creator_holding: creator,
        refund_holding: creator,
        broker: None,
        items,
    };
    let b_escrow = batch_escrow_pda(chain.vesting, &creator, &bp.batch_id);
    let b_actors = chain.native_batch_actors(creator, &bp, false);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &b_actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::BatchCreate(Box::new(bp.clone()))),
        )
        .expect("native batch of 8");
    assert_eq!(chain.native_balance(b_escrow), 360_000);
    chain.tick(3_000_000);
    for (idx, who_k) in [(0u32, &benef_k), (7u32, &benef2_k)] {
        let who = account(who_k);
        let sid = batch_schedule_pda(chain.vesting, &creator, &bp.batch_id, idx);
        let before = chain.native_balance(who);
        chain
            .submit_public(
                Actor::new(who, chain.vesting),
                &[
                    Actor::new(who, chain.vesting),
                    Actor::new(sid, chain.vesting),
                    clock_actor(),
                    Actor::new(b_escrow, NATIVE),
                    Actor::new(who, NATIVE),
                ],
                &[who_k],
                &Wire::Program(VestingMessage::ClaimPublic {
                    schedule_id: sid,
                    destination: who,
                    amount: None,
                }),
            )
            .expect("batch claim");
        assert_eq!(
            chain.native_balance(who),
            before + 10_000 * (u128::from(idx) + 1)
        );
    }
    assert_eq!(chain.native_balance(b_escrow), 360_000 - 10_000 - 80_000);

    // 6) One-transaction private native claim into a fresh blinded alias (dev-mode receipt).
    let mut pp = linear_params(0x46, Asset::Native, creator, benef, 500_000);
    pp.kind = ScheduleKind::Linear {
        start_ts: 3_000_000,
        end_ts: 4_000_000,
    };
    let p_sched = schedule_pda(chain.vesting, &creator, &pp.salt);
    let p_escrow = single_escrow_pda(chain.vesting, &p_sched);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &chain.native_create_actors(creator, &pp, false),
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(pp))),
        )
        .expect("native schedule for private claim");
    chain.tick(3_500_000);
    let mut dest = PrivateWallet::new(0xA7);
    let res = chain
        .claim_private_blinded(
            &PrivateClaimArgs {
                beneficiary_key: &benef_k,
                schedule_id: p_sched,
                blinding_factor: [0xA8; 32],
                random_seed: [0xA9; 32],
                amount: 200_000,
                effective_ts: 3_400_000,
                promote_credit: true,
            },
            &mut dest,
        )
        .expect("one-tx private native claim");
    let cyc_claim_priv = res.pub_cycles;
    assert_eq!(chain.native_balance(p_escrow), 300_000);
    assert_eq!(chain.schedule(p_sched).claimed_amount, 200_000);
    let acct = dest.account.as_ref().expect("private account committed");
    assert_eq!(
        lee_core::native_token::decode_balance(acct.data.actor_state(NATIVE)),
        Ok(200_000)
    );
    assert_eq!(events_of::<Claimed>(&res.events)[0].amount, 200_000);
    let tx_bytes = borsh::to_vec(&res.tx_msg).unwrap();
    assert!(!contains_subslice(&tx_bytes, dest.id().value()));

    // 7) Batch ceilings for native schedules, per shape (simulated at the 10M cap).
    #[derive(Clone, Copy)]
    enum Shape {
        Linear,
        CliffLinearCancelAuth,
        Milestone4BothAuth,
    }
    let make = |n: usize, tag: u8, shape: Shape| -> (Vec<Actor>, Wire<VestingMessage>) {
        let items = (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                b[31] = 0x78;
                let (kind, cancel_authority, milestone_authority) = match shape {
                    Shape::Linear => (
                        ScheduleKind::Linear {
                            start_ts: 5_000_000,
                            end_ts: 6_000_000,
                        },
                        None,
                        None,
                    ),
                    Shape::CliffLinearCancelAuth => (
                        ScheduleKind::CliffLinear {
                            start_ts: 5_000_000,
                            cliff_ts: 5_500_000,
                            end_ts: 7_000_000,
                            cliff_amount: 250,
                        },
                        Some(AccountId::new([0xC1; 32])),
                        None,
                    ),
                    Shape::Milestone4BothAuth => (
                        ScheduleKind::Milestone {
                            tranches: vec![
                                MilestoneTranche {
                                    amount: 250,
                                    unlocked: false,
                                    unlocked_at_ms: None,
                                };
                                4
                            ],
                        },
                        Some(AccountId::new([0xC1; 32])),
                        Some(AccountId::new([0xD1; 32])),
                    ),
                };
                BatchRecipient {
                    beneficiary: AccountId::new(b),
                    total_amount: 1_000,
                    kind,
                    cancelable: true,
                    transferable: true,
                    cancel_authority,
                    milestone_authority,
                }
            })
            .collect();
        let params = BatchCreateParams {
            batch_id: [tag; 32],
            asset: Asset::Native,
            creator_holding: creator,
            refund_holding: creator,
            broker: None,
            items,
        };
        (
            chain.native_batch_actors(creator, &params, false),
            Wire::Program(VestingMessage::BatchCreate(Box::new(params))),
        )
    };
    let fits = |n: usize, tag: u8, shape: Shape| -> (u64, bool, usize) {
        let (a, w) = make(n, tag, shape);
        let (cyc, r) =
            chain.measure_public(Actor::new(creator, chain.vesting), &a, &[&creator_k], &w);
        let bytes = borsh::to_vec(&chain.build_public_tx(
            Actor::new(creator, chain.vesting),
            &a,
            &[&creator_k],
            &w,
        ))
        .unwrap()
        .len();
        if let Err(e) = &r {
            assert!(
                matches!(e, LeeError::OutOfGas { .. }),
                "unexpected batch failure {e:?}"
            );
        }
        (cyc, r.is_ok(), bytes)
    };
    for (shape, name, tag) in [
        (Shape::Linear, "Linear", 0xE0u8),
        (Shape::CliffLinearCancelAuth, "CliffLinear+Soft1", 0xE4),
        (Shape::Milestone4BothAuth, "Milestone4+Soft1/2", 0xE8),
    ] {
        let (mut lo, mut hi) = (1usize, 256usize);
        while fits(hi, tag, shape).1 {
            lo = hi;
            hi *= 2;
        }
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if fits(mid, tag + 1, shape).1 {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let (cyc, ok, bytes) = fits(lo, tag + 2, shape);
        assert!(ok);
        let (cyc_over, ok_over, _) = fits(lo + 1, tag + 3, shape);
        assert!(!ok_over);
        assert!(lo >= 100, "native {name} N_max {lo} below 100");
        eprintln!(
            "NATIVE BatchCreate({name} N_max={lo}) = {cyc} cycles ({:.2}%), tx_bytes={bytes}, N_max+1 charged={cyc_over}",
            cyc as f64 / 100_000.0
        );
    }
    eprintln!(
        "NATIVE CreateSchedule       = {cyc_create} cycles ({:.2}%)",
        cyc_create as f64 / 100_000.0
    );
    eprintln!(
        "NATIVE ClaimPublic          = {cyc_claim} cycles ({:.2}%)",
        cyc_claim as f64 / 100_000.0
    );
    eprintln!(
        "NATIVE ClaimExact (private) = {cyc_claim_priv} public cycles ({:.2}%)",
        cyc_claim_priv as f64 / 100_000.0
    );
    eprintln!(
        "NATIVE Cancel               = {cyc_cancel} cycles ({:.2}%)",
        cyc_cancel as f64 / 100_000.0
    );
}

/// The signer-authority checks the 24 Nov review listed as missing:
/// - `AsPda` from the PDA's own program with the right seed but no grant on the delivery: 35;
/// - every user operation sent as the PDA without a grant, through an inherited grant (another
///   program) or with a seed that does not derive it: 35 each, state byte-identical;
/// - `AsPda` succeeds for `ClaimExact`, `TransferBeneficiary`, `BatchCreate` and `WithdrawFees`;
/// - admin operations relayed by another program, even when the admin signs: refused, unchanged;
/// - forged `Internal`, `StateReply` and clock-reply messages sent by another program to a
///   schedule: refused, unchanged;
/// - user operations (and `AsPda`) that arrive as asynchronous messages from another program
///   (LEZ's mailbox path) even when the right account signs: 35, unchanged.
#[test]
fn sec_signer_authority_review_gaps() {
    let user_k = key(230);
    let creator_k = key(231);
    let user = account(&user_k);
    let creator = account(&creator_k);
    let seed = PdaSeed::new([0x6e; 32]);
    let wrong_seed = PdaSeed::new([0x6f; 32]);
    let pda = AccountId::for_public_pda(&RELAY_A, &seed);
    let mut chain = TestChain::new_funded(
        1_000_000,
        &[(user, 1_000), (creator, 10_000_000), (pda, 5_000_000)],
    );
    let as_pda = |s: PdaSeed, call: PdaCall| {
        wire(VestingMessage::AsPda {
            seed: *s.as_bytes(),
            call: Box::new(call),
        })
    };

    // A schedule whose beneficiary and cancel authority are the PDA.
    let mut p = linear_params(0x41, Asset::Native, creator, pda, 1_000_000);
    p.cancel_authority = Some(pda);
    let sched = schedule_pda(chain.vesting, &creator, &p.salt);
    let escrow = single_escrow_pda(chain.vesting, &sched);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &chain.native_create_actors(creator, &p, false),
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(p.clone()))),
        )
        .expect("schedule for the PDA");
    chain.tick(1_500_000);

    // 1) Every user operation, sent as the PDA in the three ways that must fail.
    let item = BatchRecipient {
        beneficiary: user,
        total_amount: 1_000,
        kind: ScheduleKind::Linear {
            start_ts: 1_000_000,
            end_ts: 2_000_000,
        },
        cancelable: true,
        transferable: true,
        cancel_authority: None,
        milestone_authority: None,
    };
    let calls: Vec<(&str, PdaCall)> = vec![
        (
            "ClaimPublic",
            PdaCall::ClaimPublic {
                schedule_id: sched,
                destination: user,
                amount: None,
            },
        ),
        (
            "ClaimExact",
            PdaCall::ClaimExact {
                schedule_id: sched,
                destination: user,
                amount: 1,
                effective_ts: 0,
            },
        ),
        (
            "TransferBeneficiary",
            PdaCall::TransferBeneficiary {
                schedule_id: sched,
                new_beneficiary: user,
            },
        ),
        ("Cancel", PdaCall::Cancel { schedule_id: sched }),
        (
            "MakeNonCancelable",
            PdaCall::MakeNonCancelable { schedule_id: sched },
        ),
        (
            "SignalMilestone",
            PdaCall::SignalMilestone {
                schedule_id: sched,
                milestone_index: 0,
            },
        ),
        (
            "CreateSchedule",
            PdaCall::CreateSchedule(Box::new(linear_params(
                0x42,
                Asset::Native,
                pda,
                user,
                1_000,
            ))),
        ),
        (
            "BatchCreate",
            PdaCall::BatchCreate(Box::new(BatchCreateParams {
                batch_id: [0x43; 32],
                asset: Asset::Native,
                creator_holding: pda,
                refund_holding: pda,
                broker: None,
                items: vec![item.clone()],
            })),
        ),
        (
            "WithdrawFees",
            PdaCall::WithdrawFees {
                asset: Asset::Native,
                destination: user,
                amount: 1,
            },
        ),
    ];
    for (name, call) in &calls {
        let before = chain.state.clone();
        // a) the owning program and the right seed, but no grant on the delivery
        let res = chain.submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(seed, call.clone()),
            vec![],
            &[Actor::new(sched, chain.vesting), clock_actor()],
        );
        assert_exit_code(&res, 35);
        assert!(chain.state == before, "{name}: no grant changed state");
        // b) a grant inherited by another program, which forwards AsPda
        let inner = RelayMessage::Forward {
            to: Actor::new(pda, chain.vesting),
            message: as_pda(seed, call.clone()),
            seeds: vec![],
        };
        let res = chain.submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, RELAY_B),
            borsh::to_vec(&inner).unwrap(),
            vec![seed],
            &[
                Actor::new(pda, chain.vesting),
                Actor::new(sched, chain.vesting),
                clock_actor(),
            ],
        );
        assert_exit_code(&res, 35);
        assert!(
            chain.state == before,
            "{name}: inherited grant changed state"
        );
        // c) the owning program with a seed that does not derive the PDA
        let res = chain.submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(wrong_seed, call.clone()),
            vec![wrong_seed],
            &[Actor::new(sched, chain.vesting), clock_actor()],
        );
        assert_exit_code(&res, 35);
        assert!(chain.state == before, "{name}: wrong seed changed state");
        eprintln!("[SEC_PDA_NEG] {name}: no grant, inherited grant, wrong seed -> 35, unchanged");
    }

    // 2) AsPda succeeds for the operations not covered by the earlier test.
    // ClaimExact as the beneficiary PDA, to a public destination.
    let creator_before = chain.native_balance(creator);
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(
                seed,
                PdaCall::ClaimExact {
                    schedule_id: sched,
                    destination: creator,
                    amount: 100_000,
                    effective_ts: 1_500_000,
                },
            ),
            vec![seed],
            &[
                Actor::new(sched, chain.vesting),
                Actor::new(escrow, NATIVE),
                Actor::new(creator, NATIVE),
            ],
        )
        .expect("PDA ClaimExact");
    assert_eq!(chain.schedule(sched).claimed_amount, 100_000);
    assert_eq!(chain.native_balance(creator), creator_before + 100_000);
    // TransferBeneficiary as the beneficiary PDA.
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(
                seed,
                PdaCall::TransferBeneficiary {
                    schedule_id: sched,
                    new_beneficiary: user,
                },
            ),
            vec![seed],
            &[Actor::new(sched, chain.vesting)],
        )
        .expect("PDA TransferBeneficiary");
    assert_eq!(chain.schedule(sched).beneficiary, user);
    // BatchCreate as the creating PDA, funded from its own native balance.
    let bp = BatchCreateParams {
        batch_id: [0x44; 32],
        asset: Asset::Native,
        creator_holding: pda,
        refund_holding: pda,
        broker: None,
        items: vec![item.clone(), item],
    };
    let b_escrow = batch_escrow_pda(chain.vesting, &pda, &bp.batch_id);
    let mut extra = chain.native_batch_actors(pda, &bp, false);
    extra.retain(|a| *a != Actor::new(pda, chain.vesting));
    let pda_before = chain.native_balance(pda);
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(seed, PdaCall::BatchCreate(Box::new(bp))),
            vec![seed],
            &extra,
        )
        .expect("PDA BatchCreate");
    assert_eq!(chain.native_balance(b_escrow), 2_000);
    assert_eq!(chain.native_balance(pda), pda_before - 2_000);
    // WithdrawFees as the treasury PDA.
    let cfg = config_pda(chain.vesting);
    chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[
                Actor::new(chain.vesting, chain.vesting),
                Actor::new(cfg, chain.vesting),
            ],
            &[&key(100)],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: Some(chain.token),
                fee_bps: 50,
                fee_treasury: Some(pda),
            }),
        )
        .expect("fee switch on, treasury = PDA");
    let fp = linear_params(0x45, Asset::Native, creator, user, 200_000);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &chain.native_create_actors(creator, &fp, true),
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(fp))),
        )
        .expect("native create with a fee");
    let fv = fee_vault_pda(chain.vesting, &Asset::Native.key());
    assert_eq!(chain.native_balance(fv), 1_000);
    let creator_before = chain.native_balance(creator);
    chain
        .submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(
                seed,
                PdaCall::WithdrawFees {
                    asset: Asset::Native,
                    destination: creator,
                    amount: 1_000,
                },
            ),
            vec![seed],
            &[
                Actor::new(cfg, chain.vesting),
                Actor::new(fv, NATIVE),
                Actor::new(creator, NATIVE),
            ],
        )
        .expect("PDA WithdrawFees");
    assert_eq!(chain.native_balance(fv), 0);
    assert_eq!(chain.native_balance(creator), creator_before + 1_000);

    // 3) Admin operations relayed by another program are refused even when the admin signs.
    for (name, message) in [
        (
            "Configure",
            wire(VestingMessage::Configure {
                token_program_id: Some(chain.token),
                fee_bps: 100,
                fee_treasury: Some(user),
            }),
        ),
        (
            "Renounce",
            borsh::to_vec(&admin_op::<VestingMessage>(AdminOp::Renounce)).unwrap(),
        ),
    ] {
        let before = chain.state.clone();
        let res = chain.submit_via_relay(
            RELAY_A,
            &key(100),
            Actor::new(chain.vesting, chain.vesting),
            message,
            vec![],
            &[Actor::new(cfg, chain.vesting)],
        );
        assert!(res.is_err(), "relayed admin {name} accepted");
        assert!(chain.state == before, "relayed admin {name} changed state");
        eprintln!("[SEC_ADMIN_RELAY] {name} relayed by another program -> refused: {res:?}");
    }
    assert_eq!(chain.config().fee_bps, 50, "fee unchanged");

    // 4) Forged continuations and internal messages from another program are refused.
    let sched_state = chain
        .state
        .get_account_by_id(sched)
        .data
        .actor_state(chain.vesting)
        .clone();
    for (name, bytes) in [
        (
            "Internal::ClaimPublic",
            borsh::to_vec(&escapement_core::Internal::ClaimPublic {
                destination: user,
                amount: None,
            })
            .unwrap(),
        ),
        (
            "StateReply",
            borsh::to_vec(&lee_core::program::StateReply { state: sched_state }).unwrap(),
        ),
        (
            "clock Reply::Timestamp",
            borsh::to_vec(&clock_core::Reply::Timestamp(u64::MAX)).unwrap(),
        ),
    ] {
        let before = chain.state.clone();
        let res = chain.submit_via_relay(
            RELAY_A,
            &user_k,
            Actor::new(sched, chain.vesting),
            bytes,
            vec![],
            &[Actor::new(escrow, NATIVE), clock_actor()],
        );
        assert!(res.is_err(), "forged {name} accepted");
        assert!(chain.state == before, "forged {name} changed state");
        eprintln!("[SEC_FORGED] {name} from another program -> refused: {res:?}");
    }

    // 5) A user operation that reaches Escapement as an asynchronous message from another program
    //    (LEZ's mailbox path: to a declared public actor it runs in the same transaction, from the
    //    sending program, with no grant passed on) is refused like a relayed one, even when the
    //    right account signs; so is AsPda sent that way by the PDA's own program.
    let p5 = linear_params(0x46, Asset::Native, creator, user, 1_000);
    let async_cases = vec![
        (
            "ClaimPublic, the beneficiary signing",
            &user_k,
            Actor::new(user, chain.vesting),
            wire(VestingMessage::ClaimPublic {
                schedule_id: sched,
                destination: user,
                amount: None,
            }),
            vec![
                Actor::new(sched, chain.vesting),
                Actor::new(escrow, NATIVE),
                Actor::new(user, NATIVE),
                clock_actor(),
            ],
        ),
        (
            "CreateSchedule, the creator signing",
            &creator_k,
            Actor::new(creator, chain.vesting),
            wire(VestingMessage::CreateSchedule(Box::new(p5.clone()))),
            chain.native_create_actors(creator, &p5, true),
        ),
        (
            "AsPda Cancel from the PDA's own program",
            &user_k,
            Actor::new(pda, chain.vesting),
            as_pda(seed, PdaCall::Cancel { schedule_id: sched }),
            vec![
                Actor::new(sched, chain.vesting),
                Actor::new(escrow, NATIVE),
                Actor::new(creator, NATIVE),
                clock_actor(),
            ],
        ),
    ];
    for (name, signer_k, to, msg, extra) in async_cases {
        let before = chain.state.clone();
        let res = chain.submit_via_relay_async(RELAY_A, signer_k, to, msg, &extra);
        assert_exit_code(&res, 35);
        assert!(chain.state == before, "async {name} changed state");
        eprintln!("[SEC_ASYNC] {name}, as an async message from another program -> 35, unchanged");
    }
    // The same claim signed directly still succeeds.
    chain
        .submit_public(
            Actor::new(user, chain.vesting),
            &[
                Actor::new(user, chain.vesting),
                Actor::new(sched, chain.vesting),
                Actor::new(escrow, NATIVE),
                Actor::new(user, NATIVE),
                clock_actor(),
            ],
            &[&user_k],
            &Wire::Program(VestingMessage::ClaimPublic {
                schedule_id: sched,
                destination: user,
                amount: None,
            }),
        )
        .expect("direct claim by the beneficiary still succeeds");
}

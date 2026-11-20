//! Real-ELF integration, privacy, invariant, and cycle-benchmark suite for Escapement on LEZ v0.4.0-rc3.
//!
//! Runs the real compiled RISC Zero guest ELFs (`ESCAPEMENT_ELF`, `TOKEN_ELF`, `CLOCK_ELF`)
//! through LEZ v0.4.0-rc3's `V03State`, `simulate_public_transaction`, and `execute_and_prove`.

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
        BeneficiaryTransferred, Cancelled, Claimed, FeeConfigUpdated, MadeNonCancelable,
        MilestoneSignaled, ScheduleCreated, VestingEvent,
    },
    schedule_pda, single_escrow_pda, BatchCreateParams, BatchRecipient, BrokerFee, Config,
    CreateScheduleParams, Message as VestingMessage, MilestoneTranche, ScheduleAccount,
    ScheduleKind, VestingActorState,
};
use escapement_methods::ESCAPEMENT_ELF;
use lee::{
    error::LeeError,
    privacy_preserving_transaction::{
        circuit::{
            execute_and_prove, simulate_privacy_preserving_transaction, simulate_public_transaction,
            ProgramCatalog, Simulation,
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
    program::TransactionEvent,
    AuthorizationSecretKey, Commitment, EncryptionScheme, PrivacyPreservingCircuitOutput,
    ProvingInput, RegularKey, RootCall, SenderPresentation, SharedSecretKey, WitnessKind,
};
use lez_admin_authority::{admin_op, AdminOp};
use lez_authority::Wire;
use token_core::{Message as TokenMessage, TokenHolding, TokenState};
use token_methods::TOKEN_ELF;

const MAX_GAS_EXEC: u64 = 10_000_000;

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
fn assert_exit_code<T: std::fmt::Debug>(res: &Result<T, LeeError>, expected_code: u32) -> u64 {
    match res {
        Err(LeeError::ProgramExitedWithCode { code, cycles }) if *code == expected_code => {
            assert!(
                *cycles > 0 && *cycles < MAX_GAS_EXEC,
                "expected metered cycles in (0, {MAX_GAS_EXEC}), got {cycles}"
            );
            *cycles
        }
        other => panic!("expected ProgramExitedWithCode {{ code: {expected_code} }}, got {other:?}"),
    }
}

fn events_of<E: VestingEvent + borsh::BorshDeserialize>(events: &[TransactionEvent]) -> Vec<E> {
    let want = escapement_core::event::selector(E::NAME);
    events
        .iter()
        .filter(|e| e.event.selector == want)
        .map(|e| borsh::from_slice(&e.event.data).expect("event payload decodes"))
        .collect()
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

    fn balance(&self, token_prog: AccountId) -> u128 {
        let acct = self.account.as_ref().expect("private account committed");
        match TokenState::decode(acct.data.actor_state(token_prog)) {
            Some(TokenState::Holding(TokenHolding { balance, .. })) => balance,
            other => panic!("expected private token holding, got {other:?}"),
        }
    }
}

struct TestChain {
    state: V03State,
    vesting: AccountId,
    token: AccountId,
    block_id: u64,
    timestamp_ms: u64,
}

impl TestChain {
    fn new(initial_ts_ms: u64) -> Self {
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
            ])
            .with_public_accounts([(
                CLOCK_PROGRAM_ACCOUNT_ID,
                Account::default()
                    .with_actor_state(clock_account_id(), clock_data.to_bytes().into()),
            )]);

        let mut chain = Self {
            state,
            vesting,
            token,
            block_id: 1,
            timestamp_ms: initial_ts_ms,
        };
        // Initialize admin (deployer) and configure token_program_id once.
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
        ]
        .into_iter()
        .map(|(id, elf)| {
            (
                id,
                Program::new(elf.to_vec().into()).expect("guest loads"),
            )
        })
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

    fn tick(&mut self, next_ts_ms: u64) {
        self.block_id += 1;
        self.timestamp_ms = next_ts_ms;
        self.submit_public(
            clock_actor(),
            &[clock_actor()],
            &[],
            &clock_core::Message::Tick {
                timestamp: next_ts_ms,
                block_id: self.block_id,
            },
        )
        .expect("clock tick succeeds");
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

    fn transfer_public(
        &mut self,
        from_key: &PrivateKey,
        to: AccountId,
        amount: u128,
    ) {
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
        match TokenState::decode(self.state.get_account_by_id(holder).data.actor_state(self.token)) {
            Some(TokenState::Holding(h)) => h.balance,
            other => panic!("expected holding at {holder:?}, got {other:?}"),
        }
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
            Actor::new(params.token_definition, self.token),
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
            Actor::new(params.token_definition, self.token),
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

    fn init_private_holding(&mut self, wallet: &mut PrivateWallet, def: AccountId) {
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
        let tx_msg = PrivateTxMessage::from_circuit_output(Vec::new(), output.clone());
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
    }

    /// Executes `ClaimExact` in a single PPTX with a fresh blinded alias `dest.id().blinded(&factor)`.
    fn claim_private_blinded(
        &mut self,
        beneficiary_key: &PrivateKey,
        schedule_id: AccountId,
        dest: &mut PrivateWallet,
        blinding_factor: [u8; 32],
        amount: u128,
        effective_ts: u64,
        promote_credit: bool,
    ) -> Result<(PrivacyPreservingCircuitOutput, Vec<TransactionEvent>, u64), LeeError> {
        let beneficiary_id = account(beneficiary_key);
        let sched = self.schedule(schedule_id);
        let alias = dest.id().blinded(&blinding_factor);

        let root = Actor::new(beneficiary_id, self.vesting);
        let public = [
            root,
            Actor::new(schedule_id, self.vesting),
            Actor::new(sched.escrow_account, self.token),
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
        witness.kind = WitnessKind::Regular(RegularKey::Nullifying(dest.keys.nsk()));
        witness.address_openings.insert(blinding_factor);

        let wire = Wire::Program(VestingMessage::ClaimExact {
            schedule_id,
            destination: alias,
            amount,
            effective_ts,
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
        let token_prog = self.token;
        let pub_cycles = simulate_privacy_preserving_transaction(
            &proving_input,
            &sim,
            &catalog,
            |_| SenderPresentation::Canonical,
            |_, body| {
                promote_credit
                    && body.to.account_id == alias
                    && body.to.program_account_id == token_prog
            },
        )?;

        let (output, proof) = execute_and_prove(
            proving_input,
            &sim,
            &catalog,
            |_| SenderPresentation::Canonical,
            |_, body| {
                promote_credit
                    && body.to.account_id == alias
                    && body.to.program_account_id == token_prog
            },
            no_seal,
        )?;

        let nonces = vec![(beneficiary_id, self.state.get_account_by_id(beneficiary_id).nonce)];
        let tx_msg = PrivateTxMessage::from_circuit_output(nonces, output.clone());
        let tx_ws = PrivateWitnessSet::for_message(&tx_msg, proof, &[beneficiary_key]);
        let diff = ValidatedStateDiff::from_privacy_preserving_transaction(
            &PrivacyPreservingTransaction::new(tx_msg, tx_ws),
            &self.state,
            self.block_id,
            self.timestamp_ms,
        )?;
        let events = self.state.apply_state_diff(diff)?;
        decrypt_update(&output, dest);
        Ok((output, events, pub_cycles))
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

// ============================================================================
// SPIKE S-1: 1-tx blinded-alias promoted private token claim + atomicity
// ============================================================================

#[test]
fn s1_private_claim_blinded_alias_single_tx_and_unlinkability() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(1);
    let creator_k = key(2);
    let benef_k = key(3);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);

    chain.create_token(&def_k, &creator_k, 1_000_000);

    let params = CreateScheduleParams {
        salt: [0x11; 32],
        token_definition: def,
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

    // 1) Uninitialized private holding fails atomically (R1), leaving escrow & claimed untouched.
    let mut uninit_priv = PrivateWallet::new(71);
    let before = chain.state.clone();
    let err = chain.claim_private_blinded(&benef_k, sched_id, &mut uninit_priv, [0xA1; 32], 10_000, 2_000_000, true);
    assert_refused(&err, "recipient has no token holding; initialize it first");
    assert_eq!(chain.state, before);
    assert_eq!(chain.token_balance(escrow_id), 100_000);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 0);

    // 2) Initialize private holding, then test omitted promotion -> fails atomically (UnboundAsyncDestination).
    let mut dest_priv = PrivateWallet::new(72);
    chain.init_private_holding(&mut dest_priv, def);
    let before = chain.state.clone();
    let err = chain.claim_private_blinded(&benef_k, sched_id, &mut dest_priv, [0xB1; 32], 10_000, 2_000_000, false);
    assert!(
        matches!(err, Err(LeeError::UnboundAsyncDestination { .. })),
        "unpromoted blinded alias must fail atomically with UnboundAsyncDestination, got {err:?}"
    );
    assert_eq!(chain.state, before);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 0);
    assert_eq!(dest_priv.balance(chain.token), 0);

    // 3) Retry with promotion -> succeeds in ONE transaction!
    let f1 = [0xC1; 32];
    let (out1, ev1, cycles1) = chain
        .claim_private_blinded(&benef_k, sched_id, &mut dest_priv, f1, 15_000, 2_000_000, true)
        .expect("blinded-alias private claim succeeds in 1 tx");
    assert!(out1.execution.async_messages.is_empty(), "zero mailbox publications");
    assert_eq!(chain.state.publications_from(0).count(), 0);
    assert_eq!(dest_priv.balance(chain.token), 15_000);
    assert_eq!(chain.token_balance(escrow_id), 85_000);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 15_000);

    // Verify public Claimed event emitted, zero Transferred event, and real dest_priv.id() NEVER appears!
    let claimed_evs = events_of::<Claimed>(&ev1);
    assert_eq!(claimed_evs.len(), 1);
    assert_eq!(claimed_evs[0].amount, 15_000);
    assert_eq!(claimed_evs[0].total_claimed, 15_000);
    assert!(
        ev1.iter()
            .all(|e| e.account_id == chain.vesting),
        "private token::increase_balance must emit zero Transferred events"
    );
    let serialized_pub = borsh::to_vec(&out1.execution.boundary).unwrap();
    let serialized_ev = borsh::to_vec(&ev1).unwrap();
    assert!(
        !serialized_pub.windows(32).any(|w| w == dest_priv.id().value()),
        "real private AccountId leaked in boundary!"
    );
    assert!(
        !serialized_ev.windows(32).any(|w| w == dest_priv.id().value()),
        "real private AccountId leaked in events!"
    );

    // 4) Second private claim into the SAME private account uses a distinct unlinkable alias!
    let f2 = [0xC2; 32];
    assert_ne!(dest_priv.id().blinded(&f1), dest_priv.id().blinded(&f2));
    let (out2, _, _) = chain
        .claim_private_blinded(&benef_k, sched_id, &mut dest_priv, f2, 10_000, 2_000_000, true)
        .expect("second private claim to same private account succeeds");
    assert!(out2.execution.async_messages.is_empty());
    assert_eq!(dest_priv.balance(chain.token), 25_000);
    assert_eq!(chain.token_balance(escrow_id), 75_000);
    assert_eq!(chain.schedule(sched_id).claimed_amount, 25_000);
    eprintln!("[S-1] blinded-alias private claim public cycles = {cycles1}");
}

// ============================================================================
// SPIKE S-1 REAL PROOF (`RISC0_DEV_MODE=0`) — run explicitly with --ignored
// ============================================================================

#[test]
#[ignore]
fn s1_real_proof_dev_mode_0() {
    assert_ne!(
        std::env::var("RISC0_DEV_MODE").unwrap_or_default(),
        "1",
        "s1_real_proof_dev_mode_0 must run with RISC0_DEV_MODE=0"
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
        token_definition: def,
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
    chain.init_private_holding(&mut dest_priv, def);
    let init_s = t_init.elapsed().as_secs_f64();

    // Advance halfway (50,000 claimable).
    chain.tick(1_500_000);
    let t_claim = Instant::now();
    let (out, evs, pub_cycles) = chain
        .claim_private_blinded(&benef_k, sched_id, &mut dest_priv, [0xEE; 32], 50_000, 1_500_000, true)
        .expect("real-proof private claim succeeds");
    let claim_s = t_claim.elapsed().as_secs_f64();

    assert!(out.execution.async_messages.is_empty());
    assert_eq!(dest_priv.balance(chain.token), 50_000);
    assert_eq!(events_of::<Claimed>(&evs).len(), 1);
    let prog = Program::new(Cow::Borrowed(ESCAPEMENT_ELF)).unwrap();
    eprintln!(
        "[REAL_PROOF_DEV_MODE_0] escapement_image_id={:?} init_holding_s={init_s:.2} private_claim_s={claim_s:.2} public_cycles={pub_cycles}",
        prog.id()
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
        token_definition: def,
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: benef,
        total_amount: 100_000,
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

    // At t = 1_200_000 (20% vested = 20_000), trying to claim with future effective_ts = 1_500_000 is REFUSED.
    chain.tick(1_200_000);
    let err = chain.claim_private_blinded(&benef_k, sched_id, &mut dest_priv, [1; 32], 50_000, 1_500_000, true);
    assert!(
        matches!(err, Err(LeeError::OutOfValidityWindow)),
        "future effective_ts must fail with OutOfValidityWindow, got {err:?}"
    );
    assert_eq!(dest_priv.balance(chain.token), 0);

    // Prove at effective_ts = 1_200_000, simulate 10 minutes passing before inclusion -> STILL SUCCEEDS!
    chain.tick(1_800_000);
    chain
        .claim_private_blinded(&benef_k, sched_id, &mut dest_priv, [2; 32], 20_000, 1_200_000, true)
        .expect("delayed private claim with past effective_ts never expires");
    assert_eq!(dest_priv.balance(chain.token), 20_000);

    // Cancel at live clock = 1_800_000 (80% vested = 80_000, 20_000 unvested refunded to creator).
    let cancel_actors = [
        Actor::new(creator, chain.vesting),
        Actor::new(sched_id, chain.vesting),
        clock_actor(),
        Actor::new(escrow_id, chain.token),
        Actor::new(creator, chain.token),
    ];
    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &cancel_actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::Cancel {
                schedule_id: sched_id,
            }),
        )
        .expect("cancel succeeds");
    let c_evs = events_of::<Cancelled>(&evs);
    assert_eq!(c_evs.len(), 1);
    assert_eq!(c_evs[0].vested_at_cancel, 80_000);
    assert_eq!(c_evs[0].refunded_amount, 20_000);
    assert_eq!(chain.token_balance(creator), 920_000);
    assert_eq!(chain.token_balance(escrow_id), 60_000);

    // Advance far past end_ts -> beneficiary can claim remaining 60_000 privately, but 60_001 is REFUSED (exit code 27).
    chain.tick(9_000_000);
    let over = chain.claim_private_blinded(&benef_k, sched_id, &mut dest_priv, [3; 32], 60_001, 9_000_000, true);
    assert_exit_code(&over, 27);
    chain
        .claim_private_blinded(&benef_k, sched_id, &mut dest_priv, [4; 32], 60_000, 9_000_000, true)
        .expect("post-cancel vested tokens remain privately claimable");
    assert_eq!(dest_priv.balance(chain.token), 80_000);
    assert_eq!(chain.token_balance(escrow_id), 0);
}

// ============================================================================
// SPIKE S-3: lez-admin-authority v0.2.0 fee switch, caps, handover & renounce
// ============================================================================

#[test]
fn s3_lez_admin_authority_fee_switch_and_immutability() {
    let mut chain = TestChain::new(1_000_000);
    let deployer_k = key(100);
    let new_admin_k = key(31);
    let outsider_k = key(32);
    let treasury_k = key(33);
    let broker_k = key(34);
    let def_k = key(35);
    let creator_k = key(36);
    let benef_k = key(37);

    let cfg = config_pda(chain.vesting);
    let def = account(&def_k);
    let creator = account(&creator_k);
    let treasury = account(&treasury_k);
    let broker = account(&broker_k);

    chain.create_token(&def_k, &creator_k, 1_000_000);
    chain.init_public_holding(&treasury_k, def);
    chain.init_public_holding(&broker_k, def);

    // Non-admin refused on Configure.
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
        &[Actor::new(chain.vesting, chain.vesting), Actor::new(cfg, chain.vesting)],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: Some(AccountId::new([0x99; 32])),
            fee_bps: 0,
            fee_treasury: None,
        }),
    );
    assert_exit_code(&res, 9);

    // Fee cap > 100 bps refused (exit code 7).
    let res = chain.submit_public(
        Actor::new(chain.vesting, chain.vesting),
        &[Actor::new(chain.vesting, chain.vesting), Actor::new(cfg, chain.vesting)],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 101,
            fee_treasury: Some(treasury),
        }),
    );
    assert_exit_code(&res, 7);

    // Set 50 bps (0.50%) protocol fee -> succeeds and emits FeeConfigUpdated.
    let evs = chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[Actor::new(chain.vesting, chain.vesting), Actor::new(cfg, chain.vesting)],
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

    // Create schedule of 10,001 with 50 bps protocol fee (ceil = 51) + 100 bps broker fee (ceil = 101).
    let params = CreateScheduleParams {
        salt: [0x33; 32],
        token_definition: def,
        creator_holding: creator,
        refund_holding: creator,
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
            holding: broker,
            bps: 100,
        }),
    };
    let actors = chain.create_schedule_actors(creator, &params, &[treasury]);
    let sched_id = schedule_pda(chain.vesting, &creator, &params.salt);
    let escrow_id = single_escrow_pda(chain.vesting, &sched_id);
    chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &actors,
            &[&creator_k],
            &Wire::Program(VestingMessage::CreateSchedule(Box::new(params))),
        )
        .expect("fee-bearing schedule created");
    assert_eq!(chain.token_balance(escrow_id), 10_001);
    assert_eq!(chain.token_balance(treasury), 51);
    assert_eq!(chain.token_balance(broker), 101);
    assert_eq!(chain.token_balance(creator), 1_000_000 - 10_001 - 51 - 101);

    // Two-step Nominate -> Accept -> Renounce.
    let new_admin = account(&new_admin_k);
    chain
        .submit_public(
            Actor::new(chain.vesting, chain.vesting),
            &[Actor::new(chain.vesting, chain.vesting), Actor::new(cfg, chain.vesting)],
            &[&deployer_k],
            &admin_op::<VestingMessage>(AdminOp::Nominate { next: new_admin }),
        )
        .expect("nominate succeeds");
    chain
        .submit_public(
            Actor::new(new_admin, chain.vesting),
            &[Actor::new(new_admin, chain.vesting), Actor::new(cfg, chain.vesting)],
            &[&new_admin_k],
            &admin_op::<VestingMessage>(AdminOp::Accept { pda_seed: None }),
        )
        .expect("accept succeeds");
    // Old admin is now refused.
    let old = chain.submit_public(
        Actor::new(chain.vesting, chain.vesting),
        &[Actor::new(chain.vesting, chain.vesting), Actor::new(cfg, chain.vesting)],
        &[&deployer_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 0,
            fee_treasury: None,
        }),
    );
    assert_refused(&old, "E103");
    // New admin sets fee back to 0 and renounces permanently.
    chain
        .submit_public(
            Actor::new(new_admin, chain.vesting),
            &[Actor::new(new_admin, chain.vesting), Actor::new(cfg, chain.vesting)],
            &[&new_admin_k],
            &Wire::Program(VestingMessage::Configure {
                token_program_id: None,
                fee_bps: 0,
                fee_treasury: None,
            }),
        )
        .expect("new admin resets fee to 0");
    chain
        .submit_public(
            Actor::new(new_admin, chain.vesting),
            &[Actor::new(new_admin, chain.vesting), Actor::new(cfg, chain.vesting)],
            &[&new_admin_k],
            &admin_op::<VestingMessage>(AdminOp::Renounce),
        )
        .expect("renounce succeeds");
    let after_renounce = chain.submit_public(
        Actor::new(new_admin, chain.vesting),
        &[Actor::new(new_admin, chain.vesting), Actor::new(cfg, chain.vesting)],
        &[&new_admin_k],
        &Wire::Program(VestingMessage::Configure {
            token_program_id: None,
            fee_bps: 10,
            fee_treasury: Some(treasury),
        }),
    );
    assert_refused(&after_renounce, "E102");
}

// ============================================================================
// Full lifecycle: Cliff, Linear, Milestone, Soft-1/2 authorities, F4, R4, Donation
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

    let def = account(&def_k);
    let creator = account(&creator_k);
    let benef = account(&benef_k);
    let benef2 = account(&benef2_k);
    let cancel_auth = account(&cancel_auth_k);
    let ms_auth = account(&ms_auth_k);

    chain.create_token(&def_k, &creator_k, 1_000_000);
    chain.init_public_holding(&benef_k, def);
    chain.init_public_holding(&benef2_k, def);
    chain.init_public_holding(&donor_k, def);
    chain.transfer_public(&creator_k, account(&donor_k), 5_000);

    // 1. Milestone schedule with exclusive delegated milestone_authority (Soft-2) & cancel_authority (Soft-1)
    let ms_params = CreateScheduleParams {
        salt: [0x44; 32],
        token_definition: def,
        creator_holding: creator,
        refund_holding: creator,
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

    // Creator is REFUSED from signalling milestone when milestone_authority is delegated (Soft-2, exit code 13)!
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

    // Delegated milestone_authority signals tranche 0 -> succeeds and emits MilestoneSignaled.
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
    assert_eq!(events_of::<MilestoneSignaled>(&evs)[0].amount_unlocked, 20_000);

    // Double-signalling same tranche is deterministically rejected (R4, exit code 25).
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
    assert_eq!(events_of::<BeneficiaryTransferred>(&evs)[0].new_beneficiary, benef2);

    // Old beneficiary is now refused on claim (exit code 13).
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

    // Creator is REFUSED from cancelling when cancel_authority is delegated (Soft-1, exit code 13).
    let creator_cancel = chain.submit_public(
        Actor::new(creator, chain.vesting),
        &[
            Actor::new(creator, chain.vesting),
            Actor::new(ms_sched, chain.vesting),
            clock_actor(),
            Actor::new(ms_escrow, chain.token),
            Actor::new(creator, chain.token),
        ],
        &[&creator_k],
        &Wire::Program(VestingMessage::Cancel {
            schedule_id: ms_sched,
        }),
    );
    assert_exit_code(&creator_cancel, 13);

    // Delegated cancel_authority cancels -> 40,000 unvested returns strictly to creator's pinned refund_holding.
    let creator_before = chain.token_balance(creator);
    chain
        .submit_public(
            Actor::new(cancel_auth, chain.vesting),
            &[
                Actor::new(cancel_auth, chain.vesting),
                Actor::new(ms_sched, chain.vesting),
                clock_actor(),
                Actor::new(ms_escrow, chain.token),
                Actor::new(creator, chain.token),
            ],
            &[&cancel_auth_k],
            &Wire::Program(VestingMessage::Cancel {
                schedule_id: ms_sched,
            }),
        )
        .expect("delegated cancel succeeds");
    assert_eq!(chain.token_balance(creator), creator_before + 40_000);

    // New beneficiary benef2 claims the exact 20,000 unlocked tranche publicly!
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
        .expect("new beneficiary claims unlocked milestone");
    assert_eq!(chain.token_balance(benef2), 20_000);
    // Escrow holds only the 5,000 unsolicited donation, zero schedule funds left!
    assert_eq!(chain.token_balance(ms_escrow), 5_000);

    // 2. Cliff+Linear: pre-cliff error displays exact cliff_ts (U7); MakeNonCancelable irreversible (F3); non-transferable (F4).
    let cl_params = CreateScheduleParams {
        salt: [0x45; 32],
        token_definition: def,
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

    // Pre-cliff claim exits with code 26 (cycle-metered, NOT full-budget panic) and core reports exact next_unlock_ts = 3_000_000!
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
    eprintln!("[METERED_REFUSAL] Pre-cliff ClaimPublic exit code 26 metered {pre_cycles} cycles (vs 10,000,000 panic cap)");

    // Non-transferable rejects transfer (exit code 21).
    let nt = chain.submit_public(
        Actor::new(benef, chain.vesting),
        &[Actor::new(benef, chain.vesting), Actor::new(cl_sched, chain.vesting)],
        &[&benef_k],
        &Wire::Program(VestingMessage::TransferBeneficiary {
            schedule_id: cl_sched,
            new_beneficiary: benef2,
        }),
    );
    assert_exit_code(&nt, 21);

    // MakeNonCancelable is one-way irreversible.
    let evs = chain
        .submit_public(
            Actor::new(creator, chain.vesting),
            &[Actor::new(creator, chain.vesting), Actor::new(cl_sched, chain.vesting)],
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
// Batch creation (F5), concurrent batch claims (R3), exact cycle & N_max bench (P2)
// ============================================================================

#[test]
fn batch_create_concurrent_claims_and_exact_ceiling_benchmark() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(51);
    let creator_k = key(52);
    let def = account(&def_k);
    let creator = account(&creator_k);
    chain.create_token(&def_k, &creator_k, 100_000_000);

    // Measure single CreateSchedule cycles.
    let b0_k = key(60);
    chain.init_public_holding(&b0_k, def);
    let single_params = CreateScheduleParams {
        salt: [0x51; 32],
        token_definition: def,
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
    let (cyc_create, r) = chain.measure_public(Actor::new(creator, chain.vesting), &single_actors, &[&creator_k], &single_wire);
    r.expect("create sim ok");
    chain.submit_public(Actor::new(creator, chain.vesting), &single_actors, &[&creator_k], &single_wire).unwrap();

    // Measure ClaimPublic, TransferBeneficiary, MakeNonCancelable, Cancel cycles.
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
    let (cyc_claim_pub, r) = chain.measure_public(Actor::new(account(&b0_k), chain.vesting), &claim_pub_actors, &[&b0_k], &claim_pub_wire);
    r.expect("claim_pub sim ok");
    chain.submit_public(Actor::new(account(&b0_k), chain.vesting), &claim_pub_actors, &[&b0_k], &claim_pub_wire).unwrap();

    let mut p0 = PrivateWallet::new(81);
    chain.init_private_holding(&mut p0, def);
    let (_, _, cyc_claim_priv) = chain
        .claim_private_blinded(&b0_k, single_sched, &mut p0, [0xD1; 32], 15_000, 2_000_000, true)
        .unwrap();

    let b1_k = key(61);
    let xfer_wire = Wire::Program(VestingMessage::TransferBeneficiary {
        schedule_id: single_sched,
        new_beneficiary: account(&b1_k),
    });
    let xfer_actors = [Actor::new(account(&b0_k), chain.vesting), Actor::new(single_sched, chain.vesting)];
    let (cyc_transfer, r) = chain.measure_public(Actor::new(account(&b0_k), chain.vesting), &xfer_actors, &[&b0_k], &xfer_wire);
    r.expect("transfer sim ok");
    chain.submit_public(Actor::new(account(&b0_k), chain.vesting), &xfer_actors, &[&b0_k], &xfer_wire).unwrap();

    let cancel_actors = [
        Actor::new(creator, chain.vesting),
        Actor::new(single_sched, chain.vesting),
        clock_actor(),
        Actor::new(single_escrow, chain.token),
        Actor::new(creator, chain.token),
    ];
    let cancel_wire = Wire::Program(VestingMessage::Cancel { schedule_id: single_sched });
    let (cyc_cancel, r) = chain.measure_public(Actor::new(creator, chain.vesting), &cancel_actors, &[&creator_k], &cancel_wire);
    r.expect("cancel sim ok");
    chain.submit_public(Actor::new(creator, chain.vesting), &cancel_actors, &[&creator_k], &cancel_wire).unwrap();

    // Measure MakeNonCancelable & SignalMilestone on a milestone schedule.
    let ms_params = CreateScheduleParams {
        salt: [0x52; 32],
        token_definition: def,
        creator_holding: creator,
        refund_holding: creator,
        beneficiary: account(&b0_k),
        total_amount: 20_000,
        kind: ScheduleKind::Milestone {
            tranches: vec![MilestoneTranche { amount: 20_000, unlocked: false, unlocked_at_ms: None }],
        },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        broker: None,
    };
    let ms_actors = chain.create_schedule_actors(creator, &ms_params, &[]);
    let ms_sched = schedule_pda(chain.vesting, &creator, &ms_params.salt);
    chain.submit_public(Actor::new(creator, chain.vesting), &ms_actors, &[&creator_k], &Wire::Program(VestingMessage::CreateSchedule(Box::new(ms_params)))).unwrap();
    let mnc_actors = [Actor::new(creator, chain.vesting), Actor::new(ms_sched, chain.vesting)];
    let mnc_wire = Wire::Program(VestingMessage::MakeNonCancelable { schedule_id: ms_sched });
    let (cyc_mnc, r) = chain.measure_public(Actor::new(creator, chain.vesting), &mnc_actors, &[&creator_k], &mnc_wire);
    r.expect("mnc sim ok");
    chain.submit_public(Actor::new(creator, chain.vesting), &mnc_actors, &[&creator_k], &mnc_wire).unwrap();

    let sig_actors = [Actor::new(creator, chain.vesting), Actor::new(ms_sched, chain.vesting), clock_actor()];
    let sig_wire = Wire::Program(VestingMessage::SignalMilestone { schedule_id: ms_sched, milestone_index: 0 });
    let (cyc_signal, r) = chain.measure_public(Actor::new(creator, chain.vesting), &sig_actors, &[&creator_k], &sig_wire);
    r.expect("signal sim ok");
    chain.submit_public(Actor::new(creator, chain.vesting), &sig_actors, &[&creator_k], &sig_wire).unwrap();

    // Batch of 8 recipients: verify concurrent public + private claims & cancel over one shared escrow.
    let batch_keys: Vec<PrivateKey> = (110u8..118u8).map(key).collect();
    for k in &batch_keys {
        chain.init_public_holding(k, def);
    }
    let batch_id = [0xBB; 32];
    let batch8 = BatchCreateParams {
        batch_id,
        token_definition: def,
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
    let (cyc_batch8, r) = chain.measure_public(Actor::new(creator, chain.vesting), &b8_actors, &[&creator_k], &b8_wire);
    r.expect("batch8 sim ok");
    let evs = chain.submit_public(Actor::new(creator, chain.vesting), &b8_actors, &[&creator_k], &b8_wire).unwrap();
    assert_eq!(events_of::<ScheduleCreated>(&evs).len(), 8);
    assert_eq!(chain.token_balance(b8_escrow), 360_000);

    // Advance to midpoint (50% vested): recipient 0 claims publicly, recipient 1 claims privately, recipient 2 cancelled!
    chain.tick(3_000_000);
    let s0 = batch_schedule_pda(chain.vesting, &creator, &batch_id, 0);
    let s1 = batch_schedule_pda(chain.vesting, &creator, &batch_id, 1);
    let s2 = batch_schedule_pda(chain.vesting, &creator, &batch_id, 2);

    chain.submit_public(
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
    ).unwrap();
    assert_eq!(chain.token_balance(account(&batch_keys[0])), 5_000);

    let mut priv1 = PrivateWallet::new(82);
    chain.init_private_holding(&mut priv1, def);
    chain.claim_private_blinded(&batch_keys[1], s1, &mut priv1, [0xE1; 32], 10_000, 3_000_000, true).unwrap();
    assert_eq!(priv1.balance(chain.token), 10_000);

    chain.submit_public(
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
    ).unwrap();
    // Conservation on shared batch escrow: 360,000 - 5,000 - 10,000 - 15,000 = 330,000.
    assert_eq!(chain.token_balance(b8_escrow), 330_000);

    // Binary search exact N_max for BatchCreate under MAX_GAS_EXEC = 10_000_000!
    let make_batch = |n: usize, tag: u8| -> (Vec<Actor>, Wire<VestingMessage>) {
        let bid = [tag; 32];
        let items = (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                b[31] = 0x77;
                BatchRecipient {
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
                }
            })
            .collect();
        let params = BatchCreateParams {
            batch_id: bid,
            token_definition: def,
            creator_holding: creator,
            refund_holding: creator,
            broker: None,
            items,
        };
        let actors = chain.batch_create_actors(creator, &params, &[]);
        (actors, Wire::Program(VestingMessage::BatchCreate(Box::new(params))))
    };

    let (actors1, w1) = make_batch(1, 0xA1);
    let (cyc_b1, r1) = chain.measure_public(Actor::new(creator, chain.vesting), &actors1, &[&creator_k], &w1);
    r1.expect("batch(1) fits");

    let mut lo = 1usize;
    let mut hi = 400usize;
    // Grow hi if needed until it fails OutOfGas.
    loop {
        let (a, w) = make_batch(hi, 0xA2);
        let (_, res) = chain.measure_public(Actor::new(creator, chain.vesting), &a, &[&creator_k], &w);
        if res.is_err() {
            break;
        }
        lo = hi;
        hi *= 2;
    }
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        let (a, w) = make_batch(mid, 0xA3);
        let (_, res) = chain.measure_public(Actor::new(creator, chain.vesting), &a, &[&creator_k], &w);
        if res.is_ok() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let (a_max, w_max) = make_batch(lo, 0xA4);
    let (cyc_max, r_max) = chain.measure_public(Actor::new(creator, chain.vesting), &a_max, &[&creator_k], &w_max);
    r_max.expect("N_max passes");
    let tx_max_bytes = borsh::to_vec(&chain.build_public_tx(Actor::new(creator, chain.vesting), &a_max, &[&creator_k], &w_max)).unwrap().len();

    let (a_over, w_over) = make_batch(lo + 1, 0xA5);
    let (cyc_over, r_over) = chain.measure_public(Actor::new(creator, chain.vesting), &a_over, &[&creator_k], &w_over);
    assert!(r_over.is_err(), "N_max + 1 must fail 10M gas cap");

    let prog = Program::new(Cow::Borrowed(ESCAPEMENT_ELF)).unwrap();
    eprintln!("=== MEASURED LEZ v0.4.0-rc3 CYCLE REPORT (MAX_GAS_EXEC = 10,000,000) ===");
    eprintln!("ESCAPEMENT_ELF_BYTES={}", ESCAPEMENT_ELF.len());
    eprintln!("ESCAPEMENT_IMAGE_ID={:?}", prog.id());
    eprintln!("CreateSchedule       = {cyc_create} cycles ({:.2}%)", cyc_create as f64 / 100_000.0);
    eprintln!("ClaimPublic          = {cyc_claim_pub} cycles ({:.2}%)", cyc_claim_pub as f64 / 100_000.0);
    eprintln!("ClaimExact (private) = {cyc_claim_priv} public cycles ({:.2}%)", cyc_claim_priv as f64 / 100_000.0);
    eprintln!("Cancel               = {cyc_cancel} cycles ({:.2}%)", cyc_cancel as f64 / 100_000.0);
    eprintln!("MakeNonCancelable    = {cyc_mnc} cycles ({:.2}%)", cyc_mnc as f64 / 100_000.0);
    eprintln!("SignalMilestone      = {cyc_signal} cycles ({:.2}%)", cyc_signal as f64 / 100_000.0);
    eprintln!("TransferBeneficiary  = {cyc_transfer} cycles ({:.2}%)", cyc_transfer as f64 / 100_000.0);
    eprintln!("BatchCreate(1)       = {cyc_b1} cycles ({:.2}%)", cyc_b1 as f64 / 100_000.0);
    eprintln!("BatchCreate(8)       = {cyc_batch8} cycles ({:.2}%)", cyc_batch8 as f64 / 100_000.0);
    eprintln!("BatchCreate(N_max={lo}) = {cyc_max} cycles ({:.2}%), tx_bytes={tx_max_bytes}", cyc_max as f64 / 100_000.0);
    eprintln!("BatchCreate(N_max+1={}) = REFUSED ({cyc_over} charged cycles, err={r_over:?})", lo + 1);
}

// ============================================================================
// Handler-driven stateful conservation invariant suite (ethskills/testing)
// ============================================================================

#[test]
fn stateful_handler_conservation_invariant_suite() {
    let mut chain = TestChain::new(1_000_000);
    let def_k = key(70);
    let creator_k = key(71);
    let donor_k = key(72);
    let def = account(&def_k);
    let creator = account(&creator_k);
    chain.create_token(&def_k, &creator_k, 100_000_000);
    chain.init_public_holding(&donor_k, def);
    chain.transfer_public(&creator_k, account(&donor_k), 1_000_000);

    // Track every live schedule, its escrow, and any external unsolicited donations.
    struct Tracked {
        sched_id: AccountId,
        escrow_id: AccountId,
        benef_key: PrivateKey,
        priv_wallet: PrivateWallet,
        last_claimed: u128,
        was_non_cancelable: bool,
        was_cancelled: bool,
    }
    let mut tracked: Vec<Tracked> = Vec::new();
    let mut donations_per_escrow: BTreeMap<AccountId, u128> = BTreeMap::new();

    // Seed 4 single schedules (cliff+linear, linear, milestone, non-cancelable) + 1 batch of 4 schedules.
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
                    MilestoneTranche { amount: 15_000, unlocked: false, unlocked_at_ms: None },
                    MilestoneTranche { amount: 20_000, unlocked: false, unlocked_at_ms: None },
                    MilestoneTranche { amount: 25_000, unlocked: false, unlocked_at_ms: None },
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

    for (idx, (salt, bk, amt, kind, cancelable, transferable)) in single_specs.into_iter().enumerate() {
        chain.init_public_holding(&bk, def);
        let mut pw = PrivateWallet::new(150 + idx as u8);
        chain.init_private_holding(&mut pw, def);
        let params = CreateScheduleParams {
            salt,
            token_definition: def,
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
        let actors = chain.create_schedule_actors(creator, &params, &[]);
        let sid = schedule_pda(chain.vesting, &creator, &salt);
        let eid = single_escrow_pda(chain.vesting, &sid);
        chain.submit_public(Actor::new(creator, chain.vesting), &actors, &[&creator_k], &Wire::Program(VestingMessage::CreateSchedule(Box::new(params)))).unwrap();
        tracked.push(Tracked {
            sched_id: sid,
            escrow_id: eid,
            benef_key: bk,
            priv_wallet: pw,
            last_claimed: 0,
            was_non_cancelable: !cancelable,
            was_cancelled: false,
        });
    }

    // Add a batch of 4 schedules sharing one batch escrow.
    let bid = [0xF0; 32];
    let batch_bks: Vec<PrivateKey> = (125u8..129u8).map(key).collect();
    for k in &batch_bks {
        chain.init_public_holding(k, def);
    }
    let batch_params = BatchCreateParams {
        batch_id: bid,
        token_definition: def,
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
    let b_actors = chain.batch_create_actors(creator, &batch_params, &[]);
    let b_escrow = batch_escrow_pda(chain.vesting, &creator, &bid);
    chain.submit_public(Actor::new(creator, chain.vesting), &b_actors, &[&creator_k], &Wire::Program(VestingMessage::BatchCreate(Box::new(batch_params)))).unwrap();
    for (i, bk) in batch_bks.into_iter().enumerate() {
        let mut pw = PrivateWallet::new(160 + i as u8);
        chain.init_private_holding(&mut pw, def);
        tracked.push(Tracked {
            sched_id: batch_schedule_pda(chain.vesting, &creator, &bid, i as u32),
            escrow_id: b_escrow,
            benef_key: bk,
            priv_wallet: pw,
            last_claimed: 0,
            was_non_cancelable: false,
            was_cancelled: false,
        });
    }

    // Deterministic PRNG driving 64 valid bounded handler operations across time steps.
    let mut rng: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut next_u64 = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut ops_attempted = 0u32;
    let mut ops_succeeded = 0u32;

    for step in 0..64u64 {
        // Advance time monotonically every few steps up past end_ts.
        if step % 3 == 0 {
            let delta = 120_000 + (next_u64() % 180_000);
            let next_t = chain.timestamp_ms + delta;
            chain.tick(next_t);
        }
        let idx = (next_u64() as usize) % tracked.len();
        let action = next_u64() % 6;
        let sched = chain.schedule(tracked[idx].sched_id);
        let now = chain.timestamp_ms;

        match action {
            0 | 1 => {
                // Public claim (partial or full) when claimable > 0.
                let avail = escapement_core::math::claimable_at(&sched, now);
                if avail > 0 {
                    ops_attempted += 1;
                    let req = if action == 0 { Some((avail / 2).max(1)) } else { None };
                    let b_id = account(&tracked[idx].benef_key);
                    let actors = [
                        Actor::new(b_id, chain.vesting),
                        Actor::new(tracked[idx].sched_id, chain.vesting),
                        clock_actor(),
                        Actor::new(tracked[idx].escrow_id, chain.token),
                        Actor::new(b_id, chain.token),
                    ];
                    chain.submit_public(
                        Actor::new(b_id, chain.vesting),
                        &actors,
                        &[&tracked[idx].benef_key],
                        &Wire::Program(VestingMessage::ClaimPublic {
                            schedule_id: tracked[idx].sched_id,
                            destination: b_id,
                            amount: req,
                        }),
                    ).expect("bounded public claim succeeds");
                    ops_succeeded += 1;
                }
            }
            2 => {
                // Private blinded-alias claim when claimable > 0.
                let avail = escapement_core::math::claimable_at(&sched, now);
                if avail > 0 {
                    ops_attempted += 1;
                    let amt = (avail / 3).max(1);
                    let mut factor = [0u8; 32];
                    factor[0..8].copy_from_slice(&step.to_le_bytes());
                    factor[8..16].copy_from_slice(&(idx as u64).to_le_bytes());
                    let bk = tracked[idx].benef_key.clone();
                    let sid = tracked[idx].sched_id;
                    chain
                        .claim_private_blinded(&bk, sid, &mut tracked[idx].priv_wallet, factor, amt, now, true)
                        .expect("bounded private claim succeeds");
                    ops_succeeded += 1;
                }
            }
            3 => {
                // Signal next locked milestone if milestone schedule & uncancelled.
                if sched.cancelled.is_none() {
                    if let ScheduleKind::Milestone { ref tranches } = sched.kind {
                        if let Some((mi, _)) = tranches.iter().enumerate().find(|(_, t)| !t.unlocked) {
                            ops_attempted += 1;
                            let actors = [
                                Actor::new(creator, chain.vesting),
                                Actor::new(tracked[idx].sched_id, chain.vesting),
                                clock_actor(),
                            ];
                            chain.submit_public(
                                Actor::new(creator, chain.vesting),
                                &actors,
                                &[&creator_k],
                                &Wire::Program(VestingMessage::SignalMilestone {
                                    schedule_id: tracked[idx].sched_id,
                                    milestone_index: mi as u8,
                                }),
                            ).expect("milestone signal succeeds");
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
                        chain.submit_public(
                            Actor::new(creator, chain.vesting),
                            &actors,
                            &[&creator_k],
                            &Wire::Program(VestingMessage::Cancel {
                                schedule_id: tracked[idx].sched_id,
                            }),
                        ).expect("bounded cancel succeeds");
                        ops_succeeded += 1;
                    }
                }
            }
            _ => {
                // Unsolicited donation into escrow (must not break conservation accounting!).
                ops_attempted += 1;
                let gift = 137u128;
                chain.transfer_public(&donor_k, tracked[idx].escrow_id, gift);
                *donations_per_escrow.entry(tracked[idx].escrow_id).or_insert(0) += gift;
                ops_succeeded += 1;
            }
        }

        // Assert ALL strict invariants after EVERY step!
        let mut expected_by_escrow: BTreeMap<AccountId, u128> = BTreeMap::new();
        for t in &mut tracked {
            let s = chain.schedule(t.sched_id);
            let v = escapement_core::math::vested_at(&s, chain.timestamp_ms);
            // 1. Boundedness & claimed monotonicity.
            assert!(s.claimed_amount >= t.last_claimed, "claimed decreased");
            assert!(s.claimed_amount <= v, "claimed exceeded vested");
            assert!(v <= s.total_amount, "vested exceeded total");
            t.last_claimed = s.claimed_amount;

            // 2. Irreversibility of non-cancelable and cancelled.
            if t.was_non_cancelable {
                assert!(!s.cancelable, "non-cancelable reversed!");
            }
            if !s.cancelable {
                t.was_non_cancelable = true;
            }
            if t.was_cancelled {
                assert!(s.cancelled.is_some(), "cancelled reversed!");
            }
            if let Some(rec) = s.cancelled {
                assert_eq!(rec.vested_at_cancel + rec.refunded_amount, s.total_amount);
                assert_eq!(v, rec.vested_at_cancel);
                t.was_cancelled = true;
            }

            let refunded = s.cancelled.map_or(0, |r| r.refunded_amount);
            let remaining = s.total_amount - s.claimed_amount - refunded;
            *expected_by_escrow.entry(t.escrow_id).or_insert(0) += remaining;
        }
        // 3. STRICT EQUALITY conservation per escrow (not one-sided <=).
        for (escrow_id, expected_remaining) in expected_by_escrow {
            let donated = donations_per_escrow.get(&escrow_id).copied().unwrap_or(0);
            assert_eq!(
                chain.token_balance(escrow_id),
                expected_remaining + donated,
                "strict escrow conservation violated at step {step}"
            );
        }
    }
    assert!(ops_attempted >= 20, "invariant handler must exercise deep state");
    assert_eq!(ops_succeeded, ops_attempted, "handler revert rate must be 0%");
    eprintln!("[INVARIANTS] {ops_succeeded}/{ops_attempted} stateful ops passed, strict conservation held on every step");
}

// ============================================================================
// Adversarial 20-claim privacy linkability suite
// ============================================================================

#[test]
fn adversarial_20_claim_privacy_linkability_suite() {
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

    for (i, bk) in benef_keys.iter().enumerate() {
        chain.init_private_holding(&mut priv_wallets[i], def);
        let params = CreateScheduleParams {
            salt: [0x80 + i as u8; 32],
            token_definition: def,
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
        chain.submit_public(Actor::new(creator, chain.vesting), &actors, &[&creator_k], &Wire::Program(VestingMessage::CreateSchedule(Box::new(params)))).unwrap();
        sched_ids.push(sid);
    }

    let real_priv_ids: Vec<[u8; 32]> = priv_wallets.iter().map(|w| *w.id().value()).collect();
    let mut observed_aliases: BTreeSet<AccountId> = BTreeSet::new();

    for round in 1u64..=4u64 {
        let ts = 1_000_000 + round * 1_000_000;
        chain.tick(ts);
        for i in 0..5usize {
            let mut factor = [0u8; 32];
            factor[0] = round as u8;
            factor[1] = i as u8;
            factor[31] = 0xAA;
            let (out, evs, _) = chain
                .claim_private_blinded(&benef_keys[i], sched_ids[i], &mut priv_wallets[i], factor, 10_000, ts, true)
                .expect("private claim succeeds");
            assert!(out.execution.async_messages.is_empty());

            // Collect every public byte an observer can read.
            let pub_bytes = [
                borsh::to_vec(&out.execution.boundary).unwrap(),
                borsh::to_vec(&out.execution.public_root).unwrap(),
                borsh::to_vec(&evs).unwrap(),
            ]
            .concat();
            for real_id in &real_priv_ids {
                assert!(
                    !pub_bytes.windows(32).any(|w| w == real_id),
                    "real private AccountId leaked in public bytes on round {round} wallet {i}"
                );
            }
            // Extract destination alias from PublicToPrivate boundary delivery.
            let mut found_alias = None;
            for step in &out.execution.boundary {
                if let BoundaryStep::PublicToPrivate(del) = step {
                    found_alias = Some(del.envelope.to.account_id);
                }
            }
            let alias = found_alias.expect("PublicToPrivate credit present");
            assert!(
                observed_aliases.insert(alias),
                "alias reused across claims — linkability leak!"
            );
        }
    }

    assert_eq!(observed_aliases.len(), 20, "all 20 private claim aliases must be distinct");
    for w in &priv_wallets {
        assert_eq!(w.balance(chain.token), 40_000);
    }
    eprintln!("[PRIVACY_20] 20/20 private claims verified: 0 real private IDs leaked, 20/20 pairwise-distinct blinded aliases, 5/5 wallets reconciled");
}

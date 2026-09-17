//! By-proposal deploys driven by a **real SNS governance canister**.
//!
//! Every other test in this suite stands in the governance canister's shoes with
//! an ordinary dev identity. That proves our guard compares principals, and
//! nothing else. It cannot catch the things that only appear when
//! `ic-sns-governance` is the one making the call:
//!
//! - whether a generic nervous system function pointed at
//!   `commit_proposed_state` / `validate_commit_proposed_state` is accepted at
//!   registration, and whether our method signatures are the shapes governance
//!   expects;
//! - whether the payload governance forwards — a raw candid blob it never
//!   inspects — decodes as the `text` our method takes;
//! - whether an adopted proposal actually reaches us and lands.
//!
//! Those are wiring mistakes that pass every unit test and fail the first time a
//! DAO tries it, which is the worst possible moment to find them.
//!
//! ## How this runs without bazel, the ic monorepo, or dfx
//!
//! `icp network start` is PocketIC, and the fixture's `nns: true` makes it boot
//! with NNS governance, an SNS subnet, and SNS-W preloaded with the SNS wasms. So
//! a real SNS is already installable; it just has to be asked for by NNS
//! governance, which is the only principal SNS-W accepts `deploy_new_sns` from.
//! PocketIC will send a message as any principal, so the test asks *as* NNS
//! governance. Nothing about the SNS that comes back is a mock.
//!
//! The swap is deliberately never run. `ic-sns-governance` blocks six proposal
//! actions before a swap completes, and neither of the two this test needs is
//! among them — an `ExecuteGenericNervousSystemFunction` is refused pre-swap only
//! when it targets an SNS or registered dapp canister, and the asset canister
//! here is neither. Skipping the swap removes the single largest piece of
//! scaffolding while changing nothing about the code path under test.

use candid::{CandidType, Decode, Encode, Principal};
use e2e::{
    LocalNetwork, ProposedState, canister_state_hash, frontend_canister_id, http_fetch, icp_cmd,
    pocketic_instance, proposed_state, setup_project,
};
use pocket_ic::PocketIc;
use serde::Deserialize;

/// SNS-W, at its fixed NNS id. Holds the SNS wasms and builds an SNS from them.
const SNS_WASM: &str = "qaa6y-5yaaa-aaaaa-aaafa-cai";
/// NNS governance, the only principal SNS-W will deploy an SNS for.
const NNS_GOVERNANCE: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";

// ── The slice of the SNS-W and SNS governance interfaces this test drives ─────
//
// Hand-written rather than depended on: the `ic-*` crates that define them are
// not published, and pulling in the monorepo to get them would cost far more
// than the fields used here. Candid matches record fields by name hash, so a
// struct carrying a subset encodes correctly and every omitted `opt` field
// arrives as null — which is exactly what the unset knobs below should be.

#[derive(CandidType)]
struct DeployNewSnsRequest {
    sns_init_payload: Option<SnsInitPayload>,
}

#[derive(CandidType, Deserialize, Debug)]
struct DeployNewSnsResponse {
    canisters: Option<SnsCanisterIds>,
    error: Option<SnsWasmError>,
}

#[derive(CandidType, Deserialize, Debug)]
struct SnsCanisterIds {
    root: Option<Principal>,
    governance: Option<Principal>,
    ledger: Option<Principal>,
    swap: Option<Principal>,
    index: Option<Principal>,
}

#[derive(CandidType, Deserialize, Debug)]
struct SnsWasmError {
    message: String,
}

#[derive(CandidType)]
struct SnsInitPayload {
    token_symbol: Option<String>,
    token_name: Option<String>,
    token_logo: Option<String>,
    name: Option<String>,
    description: Option<String>,
    url: Option<String>,
    logo: Option<String>,
    fallback_controller_principal_ids: Vec<String>,
    initial_token_distribution: Option<InitialTokenDistribution>,
    min_participants: Option<u64>,
    min_direct_participation_icp_e8s: Option<u64>,
    max_direct_participation_icp_e8s: Option<u64>,
    min_participant_icp_e8s: Option<u64>,
    max_participant_icp_e8s: Option<u64>,
    swap_start_timestamp_seconds: Option<u64>,
    swap_due_timestamp_seconds: Option<u64>,
    neuron_basket_construction_parameters: Option<NeuronBasketConstructionParameters>,
    nns_proposal_id: Option<u64>,
    neurons_fund_participation: Option<bool>,
    transaction_fee_e8s: Option<u64>,
    proposal_reject_cost_e8s: Option<u64>,
    neuron_minimum_stake_e8s: Option<u64>,
    neuron_minimum_dissolve_delay_to_vote_seconds: Option<u64>,
    max_dissolve_delay_seconds: Option<u64>,
    max_neuron_age_seconds_for_age_bonus: Option<u64>,
    max_dissolve_delay_bonus_percentage: Option<u64>,
    max_age_bonus_percentage: Option<u64>,
    initial_voting_period_seconds: Option<u64>,
    wait_for_quiet_deadline_increase_seconds: Option<u64>,
    initial_reward_rate_basis_points: Option<u64>,
    final_reward_rate_basis_points: Option<u64>,
    reward_rate_transition_duration_seconds: Option<u64>,
}

#[derive(CandidType)]
enum InitialTokenDistribution {
    FractionalDeveloperVotingPower(FractionalDeveloperVotingPower),
}

#[derive(CandidType)]
struct FractionalDeveloperVotingPower {
    developer_distribution: Option<DeveloperDistribution>,
    treasury_distribution: Option<TreasuryDistribution>,
    swap_distribution: Option<SwapDistribution>,
}

#[derive(CandidType)]
struct DeveloperDistribution {
    developer_neurons: Vec<NeuronDistribution>,
}

#[derive(CandidType)]
struct NeuronDistribution {
    controller: Option<Principal>,
    stake_e8s: u64,
    memo: u64,
    dissolve_delay_seconds: u64,
    vesting_period_seconds: Option<u64>,
}

#[derive(CandidType)]
struct TreasuryDistribution {
    total_e8s: u64,
}

#[derive(CandidType)]
struct SwapDistribution {
    total_e8s: u64,
    initial_swap_amount_e8s: u64,
}

#[derive(CandidType)]
struct NeuronBasketConstructionParameters {
    count: u64,
    dissolve_delay_interval_seconds: u64,
}

#[derive(CandidType)]
struct ManageNeuron {
    subaccount: Vec<u8>,
    command: Option<Command>,
}

#[derive(CandidType)]
enum Command {
    MakeProposal(Proposal),
}

#[derive(CandidType)]
struct Proposal {
    title: String,
    url: String,
    summary: String,
    action: Option<Action>,
}

#[derive(CandidType)]
enum Action {
    AddGenericNervousSystemFunction(NervousSystemFunction),
    ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction),
}

#[derive(CandidType)]
struct NervousSystemFunction {
    id: u64,
    name: String,
    description: Option<String>,
    function_type: Option<FunctionType>,
}

#[derive(CandidType)]
enum FunctionType {
    GenericNervousSystemFunction(GenericNervousSystemFunction),
}

#[derive(CandidType)]
struct GenericNervousSystemFunction {
    target_canister_id: Option<Principal>,
    target_method_name: Option<String>,
    validator_canister_id: Option<Principal>,
    validator_method_name: Option<String>,
    topic: Option<Topic>,
}

#[derive(CandidType)]
enum Topic {
    DappCanisterManagement,
}

#[derive(CandidType)]
struct ExecuteGenericNervousSystemFunction {
    function_id: u64,
    payload: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug)]
struct ManageNeuronResponse {
    command: Option<CommandResponse>,
}

/// Only the two arms this test can receive. A response carrying any other arm
/// fails to decode, which is the correct outcome: it would mean the proposal did
/// something other than what was asked.
#[derive(CandidType, Deserialize, Debug)]
enum CommandResponse {
    Error(GovernanceError),
    MakeProposal(GetProposal),
}

#[derive(CandidType, Deserialize, Debug)]
struct GovernanceError {
    error_message: String,
    error_type: i32,
}

#[derive(CandidType, Deserialize, Debug)]
struct GetProposal {
    proposal_id: Option<ProposalId>,
}

#[derive(CandidType, Deserialize, Debug)]
struct ProposalId {
    id: u64,
}

/// The subaccount identifying a neuron staked by `controller` with `memo`, as
/// `ic-nervous-system-common` derives it. Reproduced here because the developer
/// neuron the SNS is created with has no id until it exists, and this test has to
/// name it to propose.
fn neuron_subaccount(controller: Principal, memo: u64) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let domain = b"neuron-stake";
    let mut hasher = Sha256::new();
    hasher.update([domain.len() as u8]);
    hasher.update(domain);
    hasher.update(controller.as_slice());
    hasher.update(memo.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Build an SNS whose only voting neuron belongs to `developer`.
///
/// Values follow `SnsInitPayload::with_valid_values_for_testing_post_execution`
/// from the ic monorepo — they exist to satisfy validation, not to be sensible.
/// The one that matters here is the single developer neuron: pre-swap it holds
/// all the voting power, so a proposal it makes is adopted the moment it votes.
fn sns_init_payload(developer: Principal) -> SnsInitPayload {
    const ONE_MONTH_SECONDS: u64 = 30 * 24 * 60 * 60;
    SnsInitPayload {
        token_symbol: Some("TEST".to_string()),
        token_name: Some("PlaceHolder".to_string()),
        token_logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
        name: Some("AssetCanisterGovernanceTest".to_string()),
        description: Some("Exercises by-proposal asset deploys".to_string()),
        url: Some("https://internetcomputer.org/".to_string()),
        logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
        fallback_controller_principal_ids: vec![developer.to_text()],
        initial_token_distribution: Some(InitialTokenDistribution::FractionalDeveloperVotingPower(
            FractionalDeveloperVotingPower {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: vec![NeuronDistribution {
                        controller: Some(developer),
                        stake_e8s: 100_000_000,
                        memo: 0,
                        // Comfortably over the minimum to vote, so the neuron can
                        // propose as soon as the SNS exists.
                        dissolve_delay_seconds: ONE_MONTH_SECONDS * 6,
                        vesting_period_seconds: None,
                    }],
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 10_000_000_000,
                    initial_swap_amount_e8s: 10_000_000_000,
                }),
            },
        )),
        min_participants: Some(5),
        min_direct_participation_icp_e8s: Some(12_300_000_000),
        max_direct_participation_icp_e8s: Some(65_000_000_000),
        min_participant_icp_e8s: Some(6_500_000_000),
        max_participant_icp_e8s: Some(65_000_000_000),
        swap_start_timestamp_seconds: Some(10_000_000),
        swap_due_timestamp_seconds: Some(10_086_400),
        neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
            count: 5,
            dissolve_delay_interval_seconds: 10_001,
        }),
        nns_proposal_id: Some(10),
        neurons_fund_participation: Some(false),
        transaction_fee_e8s: Some(10_000),
        proposal_reject_cost_e8s: Some(100_000_000),
        neuron_minimum_stake_e8s: Some(100_000_000),
        neuron_minimum_dissolve_delay_to_vote_seconds: Some(ONE_MONTH_SECONDS),
        max_dissolve_delay_seconds: Some(ONE_MONTH_SECONDS * 12),
        max_neuron_age_seconds_for_age_bonus: Some(ONE_MONTH_SECONDS * 12),
        max_dissolve_delay_bonus_percentage: Some(100),
        max_age_bonus_percentage: Some(25),
        initial_voting_period_seconds: Some(4 * 24 * 60 * 60),
        wait_for_quiet_deadline_increase_seconds: Some(2 * 24 * 60 * 60),
        initial_reward_rate_basis_points: Some(0),
        final_reward_rate_basis_points: Some(0),
        reward_rate_transition_duration_seconds: Some(0),
    }
}

/// Submit a proposal from the developer neuron, returning its id or the error
/// governance answered with.
fn try_propose(
    pic: &PocketIc,
    governance: Principal,
    developer: Principal,
    action: Action,
) -> Result<u64, String> {
    let arg = Encode!(&ManageNeuron {
        subaccount: neuron_subaccount(developer, 0),
        command: Some(Command::MakeProposal(Proposal {
            title: "Asset canister governance test".to_string(),
            url: "https://internetcomputer.org/".to_string(),
            summary: "Submitted by the certified-assets e2e suite".to_string(),
            action: Some(action),
        })),
    })
    .expect("encode manage_neuron");

    let reply = pic
        .update_call(governance, developer, "manage_neuron", arg)
        .expect("manage_neuron call");
    let response = Decode!(&reply, ManageNeuronResponse).expect("decode manage_neuron response");

    match response.command {
        Some(CommandResponse::MakeProposal(GetProposal {
            proposal_id: Some(id),
        })) => Ok(id.id),
        Some(CommandResponse::Error(e)) => Err(e.error_message),
        other => panic!("unexpected manage_neuron response: {other:?}"),
    }
}

/// [`try_propose`], failing the test with governance's own message.
fn propose(pic: &PocketIc, governance: Principal, developer: Principal, action: Action) -> u64 {
    try_propose(pic, governance, developer, action)
        .unwrap_or_else(|e| panic!("proposal rejected by governance: {e}"))
}

/// The whole flow, with a real SNS governance canister doing the committing.
#[test]
fn an_adopted_sns_proposal_publishes_the_prepared_state() {
    let tmp = setup_project("sns");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    // Publish a first version the ordinary way, so there is something live to
    // watch stay put while a prepare waits for its vote.
    icp_cmd(project).arg("deploy").assert().success();
    let v1 = http_fetch(project, "/index.html").text().unwrap();
    let v1_hash = hex::encode(canister_state_hash(project));

    let asset_canister =
        Principal::from_text(frontend_canister_id(project)).expect("frontend canister id");
    let developer =
        Principal::from_text(e2e::identity_principal(project)).expect("identity principal");

    // Attach to the PocketIC instance behind the network, and have NNS
    // governance ask SNS-W for an SNS. Only NNS governance may; PocketIC is what
    // lets the test be it.
    let (server_url, instance_id) = pocketic_instance(project);
    let pic = PocketIc::new_from_existing_instance(
        server_url.parse().expect("pocketic server url"),
        instance_id,
        None,
    );

    let reply = pic
        .update_call(
            Principal::from_text(SNS_WASM).unwrap(),
            Principal::from_text(NNS_GOVERNANCE).unwrap(),
            "deploy_new_sns",
            Encode!(&DeployNewSnsRequest {
                sns_init_payload: Some(sns_init_payload(developer)),
            })
            .expect("encode deploy_new_sns"),
        )
        .expect("deploy_new_sns call");
    let deployed = Decode!(&reply, DeployNewSnsResponse).expect("decode deploy_new_sns");
    assert!(
        deployed.error.is_none(),
        "SNS-W refused to deploy: {:?}",
        deployed.error
    );
    let governance = deployed
        .canisters
        .as_ref()
        .and_then(|c| c.governance)
        .unwrap_or_else(|| panic!("no governance canister in {deployed:?}"));

    // Hand commit rights to that governance canister — as a controller, before
    // anything else, which is the ordering the docs insist on.
    icp_cmd(project)
        .args([
            "canister",
            "call",
            "frontend",
            "set_governance",
            &format!("(opt principal \"{governance}\")"),
        ])
        .assert()
        .success();

    // Prepare a change. Nothing should move until the DAO says so.
    std::fs::write(
        project.join("dist/index.html"),
        "<!DOCTYPE html><html><body>adopted by the DAO</body></html>",
    )
    .unwrap();
    icp_cmd(project).arg("deploy").assert().success();

    let staged = match proposed_state(project) {
        ProposedState::Staged {
            prospective_state_hash,
            ..
        } => prospective_state_hash,
        other => panic!("expected a staged batch, got {other:?}"),
    };
    assert_eq!(
        http_fetch(project, "/index.html").text().unwrap(),
        v1,
        "the prepare must not have published anything"
    );
    assert_eq!(hex::encode(canister_state_hash(project)), v1_hash);

    // Register the generic function — the step that would reject our method
    // signatures if they were the wrong shape.
    const FUNCTION_ID: u64 = 1_000;
    propose(
        &pic,
        governance,
        developer,
        Action::AddGenericNervousSystemFunction(NervousSystemFunction {
            id: FUNCTION_ID,
            name: "Commit prepared frontend state".to_string(),
            description: Some("Publishes a prepared asset state change".to_string()),
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(asset_canister),
                    target_method_name: Some("commit_proposed_state".to_string()),
                    validator_canister_id: Some(asset_canister),
                    validator_method_name: Some("validate_commit_proposed_state".to_string()),
                    topic: Some(Topic::DappCanisterManagement),
                },
            )),
        }),
    );

    // Before the real one: a payload the canister did not stage must be refused
    // at *submission*. Governance calls our validator to render every proposal,
    // so an Err from it stops the proposal existing at all. This is what proves
    // the validator is genuinely wired in rather than bypassed — and that a
    // mistyped hash cannot reach a vote.
    let rejected = try_propose(
        &pic,
        governance,
        developer,
        Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
            function_id: FUNCTION_ID,
            payload: Encode!(&"00".repeat(32)).expect("encode a wrong state hash"),
        }),
    )
    .expect_err("a hash the canister did not stage must not be proposable");
    assert!(
        rejected.contains("the prepared batch commits to"),
        "governance should surface our validator's own words, got: {rejected}"
    );

    // Execute it with the staged hash as payload. Governance validates via our
    // validator, then forwards these exact bytes to `commit_proposed_state`.
    propose(
        &pic,
        governance,
        developer,
        Action::ExecuteGenericNervousSystemFunction(ExecuteGenericNervousSystemFunction {
            function_id: FUNCTION_ID,
            payload: Encode!(&staged).expect("encode the state hash payload"),
        }),
    );

    // Proposal execution is asynchronous within governance; give it the ticks it
    // needs to run the call rather than racing it.
    for _ in 0..40 {
        if hex::encode(canister_state_hash(project)) == staged {
            break;
        }
        pic.tick();
    }

    assert_eq!(
        hex::encode(canister_state_hash(project)),
        staged,
        "the canister must report exactly the hash the DAO adopted"
    );
    assert_eq!(
        http_fetch(project, "/index.html").text().unwrap(),
        "<!DOCTYPE html><html><body>adopted by the DAO</body></html>",
        "the adopted content must be what the gateway now serves"
    );
    assert!(matches!(proposed_state(project), ProposedState::None));
}

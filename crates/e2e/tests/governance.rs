//! By-proposal deploys, end to end through the real `icp` CLI and the local HTTP
//! gateway.
//!
//! The unit tests in `canister-core` cover the state machine. What only an e2e
//! test can show is the claim the whole feature rests on: that the hash a
//! *prepare* reports is the hash a voter computes from the source build with
//! `state-hash`, and the hash the canister reports once the proposal executes.
//! Three separate computations — the plugin's upload compiled to `wasm32-wasip2`,
//! the canister's fold over its own stored state, and `asset-prep` compiled
//! natively — have to agree on one number, or a voter is approving something
//! other than what goes live.
//!
//! The approver is set to the test's own identity so it can play the part of the
//! governance canister; on a real SNS that principal is the governance canister,
//! and the call arrives the same way.

use e2e::{
    LocalNetwork, ProposedState, canister_state_hash, committed_doc, documented_calls, http_fetch,
    icp_cmd, identity_principal, proposed_state, setup_example,
};
use reqwest::StatusCode;

/// Run `icp canister call frontend <method> <args>` and return its stdout.
fn call(project: &std::path::Path, method: &str, args: &str) -> String {
    let out = icp_cmd(project)
        .args(["canister", "call", "frontend", method, args])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8_lossy(&out).to_string()
}

fn call_fails(project: &std::path::Path, method: &str, args: &str) -> String {
    let out = icp_cmd(project)
        .args(["canister", "call", "frontend", method, args])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    String::from_utf8_lossy(&out).to_string()
}

/// The 64-hex `prospective_state_hash` of the staged batch.
fn prospective_hash(project: &std::path::Path) -> String {
    match proposed_state(project) {
        ProposedState::Staged {
            prospective_state_hash,
            ..
        } => prospective_state_hash,
        other => panic!("expected a staged batch, got {other:?}"),
    }
}

fn state_hash_of_dist(project: &std::path::Path) -> String {
    let dist = project.join("dist");
    let dist = dist.to_str().expect("dist path is utf-8");
    hex::encode(
        asset_prep::state_hash_for_dir(dist, &asset_prep::Compressors::canonical())
            .expect("compute state hash from dist"),
    )
}

/// The full release cycle: publish v1 normally, turn governance on, prepare v2,
/// confirm v1 is still what the world sees, then commit and confirm v2 is.
#[test]
fn a_prepared_deploy_goes_live_only_when_committed() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let v1_body = http_fetch(project, "/index.html").text().unwrap();
    let v1_hash = hex::encode(canister_state_hash(project));

    // Hand commit rights to this test's own identity, standing in for an SNS
    // governance canister.
    let approver = identity_principal(project);
    call(
        project,
        "set_governance",
        &format!("(opt principal \"{approver}\")"),
    );

    // Change the site and deploy. In governance mode this only prepares.
    let index = project.join("dist/index.html");
    let v2_source = "<!DOCTYPE html><html><body>version two</body></html>";
    std::fs::write(&index, v2_source).unwrap();
    icp_cmd(project).arg("deploy").assert().success();

    // Nothing an outside observer can see has moved.
    assert_eq!(
        http_fetch(project, "/index.html").text().unwrap(),
        v1_body,
        "a prepare must not change what the gateway serves"
    );
    assert_eq!(
        hex::encode(canister_state_hash(project)),
        v1_hash,
        "the live hash stays valid and verifiable during the voting period"
    );

    // The staged hash is exactly what a voter computes from the source build.
    let staged = prospective_hash(project);
    assert_eq!(
        staged,
        state_hash_of_dist(project),
        "the proposal payload must be reproducible from dist/ with `state-hash`"
    );
    assert_ne!(staged, v1_hash);

    // A proposal carrying the wrong hash must not commit anything.
    let err = call_fails(
        project,
        "commit_proposed_state",
        &format!("(\"{}\")", "0".repeat(64)),
    );
    assert!(
        err.contains("mismatch") || err.contains("state hash"),
        "{err}"
    );
    assert_eq!(http_fetch(project, "/index.html").text().unwrap(), v1_body);

    // The validator renders the real payload for voters, naming the hash they
    // must reproduce. (Assert on the rendered text, not the variant tag: the
    // test wasm carries no candid metadata, so the CLI prints `Ok`/`Err` as
    // field hashes.)
    let rendered = call(
        project,
        "validate_commit_proposed_state",
        &format!("(\"{staged}\")"),
    );
    assert!(rendered.contains(&staged), "{rendered}");
    assert!(rendered.contains("state-hash"), "{rendered}");

    // And it refuses a payload the staged batch does not commit to, so a
    // proposal carrying the wrong hash cannot even be submitted.
    let wrong = call(
        project,
        "validate_commit_proposed_state",
        &format!("(\"{}\")", "0".repeat(64)),
    );
    assert!(wrong.contains("the prepared batch commits to"), "{wrong}");

    // Execute the proposal.
    call(project, "commit_proposed_state", &format!("(\"{staged}\")"));

    let served = http_fetch(project, "/index.html");
    assert_eq!(served.status(), StatusCode::OK);
    assert_eq!(served.text().unwrap(), v2_source);
    assert_eq!(
        hex::encode(canister_state_hash(project)),
        staged,
        "after execution the canister reports exactly the hash that was voted on"
    );
    assert_eq!(proposed_state(project), ProposedState::None);
}

/// What the operator actually sees. The unit tests pin the wording; this proves
/// it survives the whole path — sync-core compiled to `wasm32-wasip2`, the host's
/// stderr capture, and the CLI — because a deploy that silently reads as
/// successful is how someone ships a frontend that nobody voted on.
#[test]
fn a_prepare_tells_the_operator_it_is_not_live() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let approver = identity_principal(project);
    call(
        project,
        "set_governance",
        &format!("(opt principal \"{approver}\")"),
    );

    std::fs::write(
        project.join("dist/index.html"),
        "<!DOCTYPE html><html><body>awaiting a vote</body></html>",
    )
    .unwrap();

    let out = icp_cmd(project).arg("deploy").assert().success();
    let shown = String::from_utf8_lossy(&out.get_output().stderr).to_string();

    assert!(shown.contains("nothing is live yet"), "{shown}");
    assert!(
        !shown.contains("synced"),
        "a prepare must not read as a completed deploy: {shown}"
    );
    // The hash the operator is told to propose must be the one the canister
    // staged, or they would propose a payload the commit then rejects.
    assert!(shown.contains(&prospective_hash(project)), "{shown}");

    // And a second deploy explains the block instead of looking like a
    // colleague's sync that will clear on its own.
    let out = icp_cmd(project).arg("deploy").assert().failure();
    let shown = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(
        shown.contains("awaiting its governance proposal"),
        "{shown}"
    );
    assert!(shown.contains("discard_proposed_state"), "{shown}");
}

/// A staged batch holds the sync lock until it is resolved, and `discard` is the
/// escape hatch a rejected proposal needs — without it the release train stalls.
#[test]
fn a_rejected_proposal_is_cleared_by_discarding() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();
    let v1_body = http_fetch(project, "/index.html").text().unwrap();

    let approver = identity_principal(project);
    call(
        project,
        "set_governance",
        &format!("(opt principal \"{approver}\")"),
    );

    std::fs::write(
        project.join("dist/index.html"),
        "<!DOCTYPE html><html><body>rejected</body></html>",
    )
    .unwrap();
    icp_cmd(project).arg("deploy").assert().success();

    // A second deploy can't start while a batch awaits its proposal.
    icp_cmd(project).arg("deploy").assert().failure();

    call(project, "discard_proposed_state", "()");
    assert_eq!(proposed_state(project), ProposedState::None);
    assert_eq!(
        http_fetch(project, "/index.html").text().unwrap(),
        v1_body,
        "discarding leaves the live site untouched"
    );

    // And the train moves again.
    let v3 = "<!DOCTYPE html><html><body>version three</body></html>";
    std::fs::write(project.join("dist/index.html"), v3).unwrap();
    icp_cmd(project).arg("deploy").assert().success();
    let staged = prospective_hash(project);
    call(project, "commit_proposed_state", &format!("(\"{staged}\")"));
    assert_eq!(http_fetch(project, "/index.html").text().unwrap(), v3);
}

/// The governance methods a *human* calls, all of which `docs/governance.md`
/// must show in a form that runs. `commit_proposed_state` and its validator are
/// deliberately absent: nobody types those — governance calls them when a
/// proposal executes — and the cycle test above covers both.
const METHODS: [&str; 4] = [
    "set_governance",
    "governance",
    "proposed_state",
    "discard_proposed_state",
];

/// Run the `icp canister call` snippets the governance doc prints, exactly as
/// written — the same guard `protection.rs` applies to its own document, for the
/// same reason (#116: a doc shipped a call form the canister rejected).
#[test]
fn documented_calls_are_accepted_by_the_canister() {
    let tmp = setup_example("static-site");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    let approver = identity_principal(project);
    let mut covered = std::collections::BTreeSet::new();
    for (method, args) in documented_calls(&committed_doc("docs/governance.md"), &METHODS) {
        // The doc names an example SNS governance canister; this test has to
        // remain able to call its own canister, so substitute its identity.
        let args = if method == "set_governance" && args.contains("opt principal") {
            format!("(opt principal \"{approver}\")")
        } else {
            args.clone()
        };
        eprintln!("docs/governance.md: icp canister call frontend {method} '{args}'");
        call(project, &method, &args);
        covered.insert(method);
    }

    assert_eq!(
        covered.into_iter().collect::<Vec<_>>(),
        {
            let mut all = METHODS.to_vec();
            all.sort_unstable();
            all
        },
        "the docs must show a runnable form of every governance method",
    );

    // The validators a DAO registers alongside `authorize`/`deauthorize`. Nobody
    // types these, but an SNS generic function is rejected without a
    // `validator_method_name`, so if they were missing or mis-shaped the DAO
    // could not manage its syncing principals by proposal at all — and nothing
    // else in the suite would notice. Checked here rather than in a test of
    // their own because this network is already up.
    let subject = "aaaaa-aa";
    let rendered = call(
        project,
        "validate_authorize",
        &format!("(principal \"{subject}\")"),
    );
    assert!(rendered.contains(subject), "{rendered}");
    assert!(rendered.contains("sync assets"), "{rendered}");

    let rendered = call(
        project,
        "validate_deauthorize",
        &format!("(principal \"{subject}\")"),
    );
    assert!(rendered.contains(subject), "{rendered}");
    assert!(rendered.contains("Revoke"), "{rendered}");
}

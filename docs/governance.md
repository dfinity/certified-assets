---
title: "Deploys by proposal"
description: "Put frontend updates under DAO control: a developer prepares, a governance proposal commits, and voters approve a hash they can reproduce from source"
sidebar:
  order: 8
---

By default, anyone [authorized to sync](overview.md) can change what your canister
serves. For a DAO-controlled app that is the wrong shape: the frontend is part of
what the DAO governs, so a change should take effect only when a proposal
**adopted by voters** executes.

**Governance mode** splits a deploy into two halves:

1. a developer **prepares** — content is uploaded, but nothing that is served
   changes; and
2. a governance canister **commits** — in one message, everything changes at once.

Between the two, the canister serves exactly what it served before. The developer
cannot shorten, skip, or partially apply that gap.

The whole thing is off unless you turn it on. With no approver set, everything in
the rest of these docs behaves exactly as written.

## What voters actually approve

The proposal payload is a single number: the **state hash** the canister will
report once the batch is committed — the same 64-hex-character value described in
[Verifying contents](verifying-contents.md).

That matters because it is the one artifact in this flow a voter can produce
**independently**, offline, from public source:

```sh
git checkout v1.4.0
npm ci && npm run build
state-hash ./dist
# 8150a65e854b9bbb…
```

If that line matches the proposal's payload, the voter knows precisely what the
canister will serve after execution — every asset, its headers, its content type,
its content, and the redirect rules. Not a summary of a change, but a complete
description of the result. Anyone can re-check it after execution too, since
`state_hash` is a public update call.

> **Reproducible builds are the prerequisite.** A voter can only verify the hash
> if your build is byte-reproducible from a tagged commit. A build that embeds a
> timestamp, an absolute path, or a random bundle salt will produce a different
> hash on every machine, and the payload becomes unverifiable. This is worth
> fixing before you adopt by-proposal deploys, not after.

## Setup

Governance mode needs one setting: the **approver**, the principal allowed to
commit. Under an SNS this is the **governance** canister — not root.

> **Why governance and not root.** SNS root is the sole controller of your dapp
> canisters, but root only performs canister management; it never relays an
> arbitrary method call. A proposal that calls a method on your asset canister is
> executed by SNS *governance*, calling directly. So governance is the principal
> that arrives at this canister, and it is the one to name here.
>
> Because of that, the approver is also accepted wherever a controller is —
> notably `authorize` and `deauthorize`. Without that, a DAO could never grant or
> rotate a developer's sync access on its own asset canister.

```sh
# As a controller (under an SNS: by proposal, since root is the controller).
icp canister call frontend set_governance '(opt principal "rrkah-fqaaa-aaaaa-aaaaq-cai")'

# Confirm. Public, so anyone can check who may change this canister's content.
icp canister call frontend governance '()'
```

Then register two SNS generic nervous-system functions, exactly as you would for
any other by-proposal method:

| | |
|---|---|
| `target_canister_id` | your asset canister |
| `target_method_name` | `commit_proposed_state` |
| `validator_method_name` | `validate_commit_proposed_state` |

The validator renders the payload for voters: the state hash, how many assets the
commit touches, and how to reproduce the hash from source.

## The release flow

**1. Prepare.** The developer deploys as usual. In governance mode the sync
prepares instead of publishing:

```sh
icp deploy
```

Nothing served changes. `state_hash` still returns the old value, and keeps
returning it for the whole voting period, so the *live* site stays verifiable
while the *next* one waits.

**2. Read off the hash.**

```sh
icp canister call frontend proposed_state '()'
# Staged { prospective_state_hash = "8150a65e…"; changed_assets = 12; … }
```

It should equal `state-hash ./dist` for the build you just prepared. If it
doesn't, something differs between what you built and what you uploaded — stop
and find out what before proposing.

**3. Propose**, with that hash as the payload, and publish the tag and build
steps in the proposal summary so voters can reproduce it.

**4. The proposal executes.** Governance calls `commit_proposed_state`, and the
new content goes live in that one message.

```sh
icp canister call frontend state_hash '()'   # now the proposed hash
```

**5. If the proposal is rejected**, clear the batch — otherwise it keeps blocking
further deploys:

```sh
icp canister call frontend discard_proposed_state '()'
```

This is authorized like a sync, so the developer who prepared the batch can clean
up without another proposal.

## Things to know

**A prepared batch blocks further syncs.** Only one can be staged at a time; a
second `icp deploy` reports the canister busy. That is deliberate — it is the same
guarantee that makes the proposal's hash binding — but it means a forgotten batch
stalls your release train. `discard_proposed_state` is the way out.

**Prepared content costs storage while it waits.** The content is uploaded at
prepare time and sits in the canister for the whole voting period, on top of the
content still being served. Budget for roughly double during a vote, and discard
rejected batches promptly.

**A commit is all-or-nothing.** It runs in a single message: if any precondition
fails, or it runs out of instructions, it traps and the message is rolled back —
the canister is left exactly as it was and the proposal is marked failed. It never
half-applies.

The per-message instruction limit is what bounds how large a single commit can be.
The work is metadata and re-certification only — no content is copied and no hash
is recomputed — which measures at roughly 1.3M instructions per changed asset, so
the ceiling is in the tens of thousands of changed assets. Ordinary frontend
updates are nowhere near it.

**The commit traps instead of returning an error.** SNS governance discards a
target method's reply and records any reply as success, so an error return would
show an adopted proposal as *executed* while nothing happened. Trapping is the
only failure this canister can report that governance will surface.

**Upgrades are safe mid-vote.** A prepared batch is stable state, so it survives a
canister upgrade and is still committable afterwards.

**`proposed_state` is a query.** Use it as a convenience for operators and voters,
not as proof: the binding check is the one `commit_proposed_state` performs on the
replicated path, and the number to trust is the one you reproduced from source.

**Turning governance off** restores ordinary publish-on-sync behaviour, so a DAO
can hand a canister back. It is refused while a batch is prepared; discard first.

## Migrating from the old asset canister

If you are coming from `dfx deploy --by-proposal` and the SDK's asset canister,
the flow is the same shape with two differences: the payload is a state hash you
reproduce from source rather than a batch evidence digest, and you propose *after*
preparing rather than computing evidence on the canister.

The move itself is a one-time, disruptive migration — stable-memory layouts are
not compatible, so it is a reinstall, not an upgrade:

1. Upgrade the wasm with `UpgradeSnsControlledCanister`, pointed at a
   [release](https://github.com/dfinity/certified-assets/releases)
   `canister-release.wasm.gz`, using **reinstall** mode. This wipes the canister's
   state.
2. Re-grant developer sync access with `authorize` (the old `Prepare` grants do
   not carry over).
3. `set_governance` to your SNS governance canister.
4. Replace the old generic functions (`commit_proposed_batch`, `grant_permission`,
   `revoke_permission`) with the two above plus `authorize`/`deauthorize`.
5. Re-deploy the site in full: the first prepare uploads every asset, and the
   first commit publishes them.

The canister and the `icp-cli` sync plugin ship as a version-locked pair, and
`state-hash-cli` must match them, so plan each canister upgrade as its own
proposal.

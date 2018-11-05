// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![cfg(feature = "testing")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/parsec"
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

extern crate maidsafe_utilities;
extern crate parsec;
#[macro_use]
extern crate proptest;
extern crate rand;
#[macro_use]
extern crate unwrap;

use maidsafe_utilities::log;
use parsec::dev_utils::proptest::{arbitrary_delay, ScheduleOptionsStrategy, ScheduleStrategy};
use parsec::dev_utils::{
    DelayDistribution, Environment, MaliceEvent, RngChoice, Schedule, ScheduleOptions,
};
use parsec::mock::{PeerId, Transaction, NAMES};
use proptest::prelude::ProptestConfig;
use proptest::test_runner::FileFailurePersistence;
use rand::Rng;
use std::collections::BTreeMap;

// Alter the seed here to reproduce failures
static SEED: RngChoice = RngChoice::SeededRandom;

#[test]
fn minimal_network() {
    // 4 is the minimal network size for which the super majority is less than it.
    let num_peers = 4;
    let mut env = Environment::new(SEED);

    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            genesis_size: num_peers,
            opaque_to_add: 1,
            votes_before_gossip: true,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn multiple_votes_before_gossip() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);

    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            opaque_to_add: num_observations,
            votes_before_gossip: true,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn multiple_votes_during_gossip() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);

    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            opaque_to_add: num_observations,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn duplicate_vote_is_reduced_to_single() {
    let mut env = Environment::new(SEED);

    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            votes_before_gossip: true,
            prob_vote_duplication: 0.5,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_third_never_gossip() {
    let num_peers = 10;
    let num_observations = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(SEED);

    let mut failures = BTreeMap::new();
    let _ = failures.insert(0, num_faulty);
    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            genesis_size: num_peers,
            opaque_to_add: num_observations,
            deterministic_failures: failures,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_third_terminate_concurrently() {
    let num_peers = 10;
    let num_observations = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(SEED);

    let mut failures = BTreeMap::new();
    let _ = failures.insert(env.rng.gen_range(10, 50), num_faulty);
    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            genesis_size: num_peers,
            opaque_to_add: num_observations,
            deterministic_failures: failures,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_nodes_terminate_at_random_points() {
    let num_peers = 10;
    let num_observations = 10;
    let prob_failure = 0.05;
    let mut env = Environment::new(SEED);
    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            genesis_size: num_peers,
            opaque_to_add: num_observations,
            prob_failure,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn random_schedule_no_delays() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);
    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            opaque_to_add: num_observations,
            delay_distr: DelayDistribution::Constant(0),
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn add_many_peers() {
    let mut env = Environment::new(SEED);

    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            genesis_size: 2,
            peers_to_add: 3,
            opaque_to_add: 0,
            ..Default::default()
        }).finish();

    unwrap!(env.network.execute_schedule(schedule));
}

#[test]
fn add_peers_and_vote() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut names = NAMES.iter();
    let mut env = Environment::new(SEED);

    let schedule = Schedule::build(&mut env)
        .with_observation_schedule(
            names.by_ref().take(4).cloned().map(PeerId::new).collect(),
            vec![
                // 1. Add a peer and then a transaction a bit later.
                (50, AddPeer(PeerId::new(unwrap!(names.next())))),
                (200, Opaque(Transaction::new("one"))),
                // 2. Add a peer and a transaction at the same time.
                (400, AddPeer(PeerId::new(unwrap!(names.next())))),
                (400, Opaque(Transaction::new("two"))),
            ],
        ).finish();

    unwrap!(env.network.execute_schedule(schedule));
}

#[test]
fn remove_one_peer() {
    let mut env = Environment::new(SEED);
    let schedule = Schedule::build(&mut env)
        .with_options(&ScheduleOptions {
            genesis_size: 6,
            peers_to_remove: 1,
            ..Default::default()
        }).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn remove_many_peers_at_once() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut env = Environment::new(SEED);
    let schedule = Schedule::build(&mut env)
        .with_observation_schedule(
            NAMES.iter().take(10).cloned().map(PeerId::new).collect(),
            vec![
                (50, RemovePeer(PeerId::new("Judy"))),
                (50, RemovePeer(PeerId::new("Iris"))),
                (50, RemovePeer(PeerId::new("Hank"))),
                (500, Opaque(Transaction::new("whatever"))),
            ],
        ).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn fail_add_remove() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut env = Environment::new(SEED);
    let schedule = Schedule::build(&mut env)
        .with_observation_schedule(
            NAMES.iter().take(7).cloned().map(PeerId::new).collect(),
            vec![
                // In this test we start with 7 peers.
                // One fails and one drops, which leaves us with 5 out of 7, and later out of 6,
                // active - just enough to be a supermajority.
                // Then, we add one peer, and drop one again. Then active peers try to reach
                // consensus on an opaque payload.
                // If this succeeds, this proves that the added peer became a full voter. Were this
                // not the case, we would be left with 4 out of 6 voters, which would stall the
                // section.
                (10, Fail(PeerId::new("Alice"))),
                (20, RemovePeer(PeerId::new("Bob"))),
                (200, AddPeer(PeerId::new("Hank"))),
                (1000, RemovePeer(PeerId::new("Carol"))),
                (1500, Opaque(Transaction::new("whatever"))),
            ],
        ).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
#[ignore]
fn fork() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut env = Environment::new(SEED);
    let mut names = NAMES.iter();

    let genesis = names.by_ref().take(4).cloned().map(PeerId::new).collect();
    let malicious_peer = PeerId::new(unwrap!(names.next()));

    let transaction0 = env.rng.gen();
    let transaction1 = env.rng.gen();
    let transaction2 = env.rng.gen();

    let schedule = Schedule::build(&mut env)
        .with_observation_schedule(
            genesis,
            vec![
                (10, AddPeer(malicious_peer.clone())),
                (100, Opaque(transaction0)),
                (200, Opaque(transaction1)),
                (300, Opaque(transaction2)),
            ],
        ).with_malice_schedule(
            malicious_peer,
            vec![
                (50, MaliceEvent::Fork),
                (100, MaliceEvent::Fork),
                (150, MaliceEvent::Fork),
            ],
        ).finish();

    let result = env.network.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
        cases: 5,
        ..Default::default()
    })]

    #[test]
    fn agreement_under_various_conditions((mut env, sched) in ScheduleStrategy {
        opts: ScheduleOptionsStrategy {
            num_peers: (4..=10).into(),
            num_observations: (1..=10).into(),
            local_step: (0.01..=1.0).into(),
            recv_trans: (0.001..0.5).into(),
            failure: (0.0..1.0).into(),
            vote_duplication: (0.0..0.5).into(),
            delay_distr: arbitrary_delay(0..10, 0.0..10.0),
        },
    }) {
        let _ = log::init(true);

        let result = env.network.execute_schedule(sched);
        assert!(result.is_ok(), "{:?}", result);
    }
}

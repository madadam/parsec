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
#[cfg(not(feature = "malice-detection"))]
use parsec::dev_utils::{ConsensusError, Network};
use parsec::dev_utils::{
    DelayDistribution, Environment, ObservationSchedule, RngChoice, Sampling, Schedule,
    ScheduleOptions,
};
use parsec::mock::{PeerId, Transaction, NAMES};
use parsec::ConsensusMode;
use proptest::prelude::ProptestConfig;
use proptest::test_runner::FileFailurePersistence;
use rand::Rng;
use std::collections::BTreeMap;

// Alter the seed here to reproduce failures
// static SEED: RngChoice = RngChoice::SeededRandom;
static SEED: RngChoice = RngChoice::Seeded([2330657697, 2112756150, 1776685349, 566375539]);

#[test]
fn minimal_network() {
    // 4 is the minimal network size for which the super majority is less than it.
    let num_peers = 4;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: 1,
        votes_before_gossip: true,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn multiple_votes_before_gossip() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        opaque_to_add: num_observations,
        votes_before_gossip: true,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn multiple_votes_during_gossip() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        opaque_to_add: num_observations,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn duplicate_vote_is_reduced_to_single() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        votes_before_gossip: true,
        prob_vote_duplication: 0.5,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
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
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        deterministic_failures: failures,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
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
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        deterministic_failures: failures,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_nodes_terminate_at_random_points() {
    let num_peers = 10;
    let num_observations = 10;
    let prob_failure = 0.05;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        prob_failure,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn random_schedule_no_delays() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        opaque_to_add: num_observations,
        delay_distr: DelayDistribution::Constant(0),
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn add_many_peers() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 2,
        peers_to_add: 8,
        opaque_to_add: 0,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    unwrap!(
        env.network
            .execute_schedule(&mut env.rng, schedule, &options)
    );
}

#[test]
fn add_few_peers_and_vote() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut names = NAMES.iter();
    let mut env = Environment::new(SEED);

    let obs_schedule = ObservationSchedule {
        genesis: names.by_ref().take(4).cloned().map(PeerId::new).collect(),
        schedule: vec![
            // 1. Add a peer and then a transaction a bit later.
            (50, AddPeer(PeerId::new(unwrap!(names.next())))),
            (200, Opaque(Transaction::new("one"))),
            // 2. Add a peer and a transaction at the same time.
            (400, AddPeer(PeerId::new(unwrap!(names.next())))),
            (400, Opaque(Transaction::new("two"))),
        ],
    };

    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    unwrap!(
        env.network
            .execute_schedule(&mut env.rng, schedule, &options)
    );
}

#[test]
fn add_many_peers_and_vote() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 2,
        peers_to_add: 8,
        opaque_to_add: 10,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    unwrap!(
        env.network
            .execute_schedule(&mut env.rng, schedule, &options)
    );
}

#[test]
fn remove_one_peer() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 6,
        peers_to_remove: 1,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn remove_many_peers_at_once() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut env = Environment::new(SEED);
    let obs_schedule = ObservationSchedule {
        genesis: NAMES.iter().take(10).cloned().map(PeerId::new).collect(),
        schedule: vec![
            (50, RemovePeer(PeerId::new("Judy"))),
            (50, RemovePeer(PeerId::new("Iris"))),
            (50, RemovePeer(PeerId::new("Hank"))),
            (500, Opaque(Transaction::new("whatever"))),
        ],
    };
    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn fail_add_remove() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut env = Environment::new(SEED);
    let obs_schedule = ObservationSchedule {
        genesis: NAMES.iter().take(7).cloned().map(PeerId::new).collect(),
        schedule: vec![
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
    };
    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    let result = env
        .network
        .execute_schedule(&mut env.rng, schedule, &options);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn consensus_mode_single() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let options = ScheduleOptions {
        genesis_size: 4,
        peers_to_add: 4,
        peers_to_remove: 4,
        opaque_to_add: 10,
        opaque_voters: Sampling::Constant(1),
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    unwrap!(
        env.network
            .execute_schedule(&mut env.rng, schedule, &options)
    );
}

#[test]
fn extensive_dynamic_membership() {
    use parsec::dev_utils::ObservationEvent::*;

    let max_num_nodes = 12;
    let min_num_nodes = 6;
    let genesis_size = 4;
    let initial_size = 9;
    // one in X chance to add a node
    let chance_to_add = 3;
    // max X nodes to be removed at once
    let remove_at_once = 2;

    let all_names: Vec<&str> = NAMES.iter().by_ref().take(max_num_nodes).cloned().collect();
    let mut names = all_names.iter();
    let mut env = Environment::new(SEED);

    let mut live_nodes: Vec<&str> = names.by_ref().take(genesis_size).cloned().collect();
    let genesis = live_nodes.iter().map(|name| PeerId::new(name)).collect();

    let mut schedule = vec![];
    let mut step = 0;
    while live_nodes.len() < initial_size {
        step += 50;
        let name = unwrap!(names.next());
        schedule.push((step, AddPeer(PeerId::new(name))));
        live_nodes.push(name);
    }

    loop {
        if env.rng.gen_weighted_bool(chance_to_add) {
            if let Some(name) = names.next() {
                step += 200;
                schedule.push((step, AddPeer(PeerId::new(name))));
                live_nodes.push(name);
            }
        }

        if live_nodes.len() > min_num_nodes {
            step += 300;
            for _ in 0..env.rng.gen_range(1, remove_at_once + 1) {
                let num_of_nodes = live_nodes.len();
                let removed_peer = live_nodes.remove(env.rng.gen_range(0, num_of_nodes));
                schedule.push((step, RemovePeer(PeerId::new(removed_peer))));
            }
        } else {
            break;
        }
    }

    let obs_schedule = ObservationSchedule { genesis, schedule };
    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    unwrap!(
        env.network
            .execute_schedule(&mut env.rng, schedule, &options)
    );
}

// This test encounters performance problems when malice-detection is enabled, hence we only
// execute it when the feature is disabled.
// TODO: remove this after MAID-3270 is completed.
#[cfg(not(feature = "malice-detection"))]
// TODO: remove this after MAID-3164 is completed.
#[ignore]
#[test]
fn consensus_with_forks() {
    // We use a single seed that is known to generate a gossip pattern showcasing the problem.
    let mut env = Environment::new(RngChoice::SeededXor([
        3_138_683_280,
        3_174_364_583,
        1_286_743_511,
        1_450_990_187,
    ]));
    let names = vec!["Alice", "Bob", "Carol", "Dave", "Eric"];
    env.network = Network::from_graphs(
        ConsensusMode::Supermajority,
        names.clone().into_iter().map(PeerId::new).collect(),
        names,
    );

    let options = ScheduleOptions {
        genesis_size: 5,
        opaque_to_add: 0,
        ..Default::default()
    };

    let mut schedule = Schedule::new(&mut env, &options);

    // We only expect two opaque blocks to get consensused: `OpaquePayload(one)` and
    // `OpaquePayload(two)` from the graphs - the default value also takes genesis into account,
    // which will get omitted here.
    schedule.min_observations = 2;
    schedule.max_observations = 2;

    // The test framework uses agreed blocks to calculate the list of valid voters. The first block
    // in regular tests is Genesis and it is used to initialise the list. This test starts its
    // execution after Genesis was consensused, but the peers are initialised with empty
    // consensused blocks lists, so the Genesis block will never appear there. This will cause the
    // peer list not to be initialised properly, which will cause InvalidSignatory errors even
    // during correct executions.
    match env
        .network
        .execute_schedule(&mut env.rng, schedule, &options)
    {
        Ok(()) | Err(ConsensusError::InvalidSignatory { .. }) => (),
        x => panic!("Unexpected test result: {:?}", x),
    }
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
            recv_trans: (0.001..0.5).into(),
            failure: (0.0..1.0).into(),
            vote_duplication: (0.0..0.5).into(),
            delay_distr: arbitrary_delay(0..10, 0.0..10.0),
        },
    }) {
        let _ = log::init(true);

        let result = env.network.execute_schedule(&mut env.rng, sched, &ScheduleOptions::default());
        assert!(result.is_ok(), "{:?}", result);
    }
}

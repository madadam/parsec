// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    block::Block,
    dev_utils::{parse_test_dot_file, Record, TestIterator},
    error::Error,
    gossip::{Event, Graph, GraphSnapshot},
    id::{Proof, PublicId},
    meta_voting::MetaElectionSnapshot,
    mock::{self, PeerId, Transaction},
    observation::{ConsensusMode, Observation},
    parsec::TestParsec,
    peer_list::{PeerListSnapshot, PeerState},
};
use std::collections::BTreeSet;

type TestPeer = TestParsec<Transaction, PeerId>;

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    peer_list: PeerListSnapshot<PeerId>,
    events: GraphSnapshot,
    meta_election: MetaElectionSnapshot<PeerId>,
    consensused_blocks: Vec<Block<Transaction, PeerId>>,
}

impl Snapshot {
    fn new(parsec: &TestPeer) -> Self {
        Snapshot {
            peer_list: PeerListSnapshot::new(parsec.peer_list(), parsec.graph()),
            events: GraphSnapshot::new(parsec.graph()),
            meta_election: MetaElectionSnapshot::new(
                parsec.meta_election(),
                parsec.graph(),
                parsec.peer_list(),
            ),
            consensused_blocks: parsec.consensused_blocks().cloned().collect(),
        }
    }
}

fn nth_event<P: PublicId>(graph: &Graph<P>, n: usize) -> &Event<P> {
    unwrap!(graph.iter_from(n).next()).inner()
}

#[test]
fn from_existing() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let parsec = TestParsec::<Transaction, _>::from_existing(
        our_id.clone(),
        &peers,
        &peers,
        ConsensusMode::Supermajority,
    );

    // Existing section + us
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len() + 1);

    // The gossip graph should be initially empty.
    assert_eq!(parsec.graph().len(), 0);
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't be empty")]
fn from_existing_requires_non_empty_genesis_group() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &BTreeSet::new(),
        &peers,
        ConsensusMode::Supermajority,
    );
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't already contain us")]
fn from_existing_requires_that_genesis_group_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group = peers.iter().cloned().collect();
    let section = peers.into_iter().skip(1).collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &genesis_group,
        &section,
        ConsensusMode::Supermajority,
    );
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't be empty")]
fn from_existing_requires_non_empty_section() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let genesis_group = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &genesis_group,
        &BTreeSet::new(),
        ConsensusMode::Supermajority,
    );
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't already contain us")]
fn from_existing_requires_that_section_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group = peers.iter().skip(1).cloned().collect();
    let section = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(
        our_id,
        &genesis_group,
        &section,
        ConsensusMode::Supermajority,
    );
}

#[test]
fn from_genesis() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let peers = peers.into_iter().collect();

    let parsec = TestParsec::<Transaction, _>::from_genesis(
        our_id.clone(),
        &peers,
        ConsensusMode::Supermajority,
    );
    // the peer_list should contain the entire genesis group
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len());
    // initial event + genesis_observation
    assert_eq!(parsec.graph().len(), 2);
    let initial_event = nth_event(parsec.graph(), 0);
    assert_eq!(*parsec.event_creator_id(&initial_event), our_id);
    assert!(initial_event.is_initial());
    let genesis_observation = nth_event(parsec.graph(), 1);
    assert_eq!(*parsec.event_creator_id(&genesis_observation), our_id);
    match parsec.event_payload(&genesis_observation) {
        Some(payload) => {
            assert_eq!(*payload, Observation::Genesis(peers));
        }
        None => panic!("Expected observation, but event carried no vote"),
    }
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group must contain us")]
fn from_genesis_requires_the_genesis_group_contains_us() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_genesis(
        our_id.clone(),
        &peers,
        ConsensusMode::Supermajority,
    );
}

#[test]
fn from_parsed_contents() {
    let input_file = "0.dot";
    let parsed_contents = parse_test_dot_file(input_file);
    let parsed_contents_comparison = parse_test_dot_file(input_file);
    let parsec = TestParsec::from_parsed_contents(parsed_contents);
    assert_eq!(parsed_contents_comparison.graph, *parsec.graph());
    assert_eq!(
        parsed_contents_comparison.meta_election,
        *parsec.meta_election()
    );

    let parsed_contents_other = parse_test_dot_file("1.dot");
    assert_ne!(parsed_contents_other.graph, *parsec.graph());
    assert_ne!(parsed_contents_other.meta_election, *parsec.meta_election());
}

#[test]
fn add_peer() {
    // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to add Fred is reached in E_25, so pop this event for now.
    let e_25 = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);
    let genesis_group: BTreeSet<_> = alice
        .peer_list()
        .all_ids()
        .map(|(_, id)| id.clone())
        .collect();

    let alice_id = PeerId::new("Alice");
    let fred_id = PeerId::new("Fred");

    assert!(!alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == fred_id));

    let alice_snapshot = Snapshot::new(&alice);

    // Try calling `create_gossip()` for a peer which doesn't exist yet.
    assert_eq!(alice.create_gossip(&fred_id), Err(Error::UnknownPeer));
    assert_eq!(alice_snapshot, Snapshot::new(&alice));

    // Now add E_25, which should result in Alice adding Fred.
    let _e_25_index = unwrap!(alice.add_event(e_25));
    assert!(alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == fred_id));

    // Construct Fred's Parsec instance.
    let mut fred = TestParsec::from_existing(
        fred_id.clone(),
        &genesis_group,
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    // Now pass a valid initial request from Alice to Fred.  The generated response would
    // normally only contain Fred's initial event, and the one recording receipt of Alice's
    // request.  However this graph doesn't represent the state it would be in if Alice were
    // actually sending such a request - it should have an event by Alice as the latest.  We
    // really only need to check here though that Fred doesn't respond with the full graph.
    let message = unwrap!(alice.create_gossip(&fred_id));
    let response = unwrap!(fred.handle_request(&alice_id, message));
    assert!(response.packed_events.len() < fred.graph().len());
}

#[test]
fn remove_peer() {
    // Generated with RNG seed: [1048220270, 1673192006, 3171321266, 2580820785].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to remove Eric is reached in the last event of Alice.
    let a_last = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);

    let eric_id = PeerId::new("Eric");
    let eric_index = unwrap!(alice.peer_list().get_index(&eric_id));

    assert!(alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == eric_id));
    assert_ne!(
        alice.peer_list().peer_state(eric_index),
        PeerState::inactive()
    );

    // Add event now which shall result in Alice removing Eric.
    unwrap!(alice.add_event(a_last));
    assert_eq!(
        alice.peer_list().peer_state(eric_index),
        PeerState::inactive()
    );

    // Try calling `create_gossip()` for Eric shall result in error.
    assert_eq!(
        alice.create_gossip(&eric_id),
        Err(Error::InvalidPeerState {
            required: PeerState::VOTE | PeerState::RECV,
            actual: PeerState::inactive()
        })
    );

    // Construct Eric's parsec instance.
    let mut section: BTreeSet<_> = alice
        .peer_list()
        .all_ids()
        .map(|(_, id)| id.clone())
        .collect();
    let _ = section.remove(&eric_id);
    let mut eric = TestParsec::<Transaction, _>::from_existing(
        eric_id.clone(),
        &section,
        &section,
        ConsensusMode::Supermajority,
    );

    // Peer state is (VOTE | SEND) when created from existing. Need to update the states to
    // (VOTE | SEND | RECV).
    for peer_id in &section {
        eric.change_peer_state(peer_id, PeerState::RECV);
    }

    // Eric can no longer gossip to anyone.
    assert_eq!(
        eric.create_gossip(&PeerId::new("Alice")),
        Err(Error::InvalidSelfState {
            required: PeerState::SEND,
            actual: PeerState::RECV
        })
    );
}

#[test]
fn unpolled_observations() {
    // Generated with RNG seed: [3016139397, 1416620722, 2110786801, 3768414447], but using
    // Alice-002.dot to get the dot file where we get consensus on `Add(Eric)`.
    let mut alice_contents = parse_test_dot_file("alice.dot");
    let a_17 = unwrap!(alice_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(alice_contents);

    // `Add(Eric)` should still be unpolled since A_17 would be the first gossip event to
    // reach consensus on `Add(Eric)`, but it was removed from the graph.
    assert!(alice.has_unpolled_observations());

    // Since we haven't called `poll()` yet, our vote for `Add(Eric)` should be returned by
    // `our_unpolled_observations()`.
    let add_eric = Observation::Add {
        peer_id: PeerId::new("Eric"),
        related_info: vec![],
    };
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should have no effect to unpolled observations.
    assert!(alice.poll().is_none());
    assert!(alice.has_unpolled_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Have Alice process A_17 to get consensus on `Add(Eric)`.
    unwrap!(alice.add_event(a_17));

    // Since we haven't call `poll()` again yet, should still return our vote for `Add(Eric)`.
    assert!(alice.has_unpolled_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should return none.
    unwrap!(alice.poll());
    assert!(alice.poll().is_none());
    assert!(alice.our_unpolled_observations().next().is_none());
    assert!(!alice.has_unpolled_observations());

    // Vote for a new observation and check it is returned as unpolled, and that
    // `has_unpolled_observations()` returns `true` again.
    let vote = Observation::OpaquePayload(Transaction::new("ABCD"));
    unwrap!(alice.vote_for(vote.clone()));

    assert!(alice.has_unpolled_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), vote);

    // Reset, and re-run, this time adding Alice's vote early to check that it is returned in
    // the correct order, i.e. after `Add(Eric)` at the point where `Add(Eric)` is consensused
    // but has not been returned by `poll()`.
    alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
    unwrap!(alice.vote_for(vote.clone()));
    let mut unpolled_observations = alice.our_unpolled_observations();
    assert_eq!(*unwrap!(unpolled_observations.next()), add_eric);
    assert_eq!(*unwrap!(unpolled_observations.next()), vote);
    assert!(unpolled_observations.next().is_none());
}

#[test]
fn our_unpolled_observations_with_consensus_mode_single() {
    let mut alice = Record::from(parse_test_dot_file("alice.dot")).play();

    let block = unwrap!(alice.poll());
    if let Observation::Genesis(_) = block.payload() {
    } else {
        panic!();
    }

    let block = unwrap!(alice.poll());
    assert!(block.payload().is_opaque());
    assert_eq!(
        block.proofs().iter().map(Proof::public_id).only(),
        alice.our_pub_id()
    );

    // Bob's vote is still in, but should not be returned here, as it's not "ours" (from Alice's
    // point of view).
    assert_eq!(alice.our_unpolled_observations().next(), None);
}

#[test]
fn gossip_after_fork() {
    let alice_id = PeerId::new("Alice");
    let bob_id = PeerId::new("Bob");

    let genesis_group = btree_set![
        alice_id.clone(),
        bob_id.clone(),
        PeerId::new("Carol"),
        PeerId::new("Dave")
    ];

    let mut alice = TestParsec::from_genesis(
        alice_id.clone(),
        &genesis_group,
        ConsensusMode::Supermajority,
    );

    // Alice creates couple of valid events.
    let a_1_index = unwrap!(alice.peer_list().our_events().next());
    let a_1_hash = *unwrap!(alice.graph().get(a_1_index)).hash();

    let a_2 = unwrap!(alice.new_event_from_observation(
        a_1_index,
        Observation::OpaquePayload(Transaction::new("one")),
    ));
    let a_2_hash = *a_2.hash();
    let a_2_index = unwrap!(alice.add_event(a_2));

    let a_3 = unwrap!(alice.new_event_from_observation(
        a_2_index,
        Observation::OpaquePayload(Transaction::new("two")),
    ));
    let a_3_hash = *a_3.hash();
    let a_3_packed = alice.pack_event(&a_3);
    unwrap!(alice.unpack_and_add_event(a_3_packed));

    let mut bob =
        TestParsec::from_genesis(bob_id.clone(), &genesis_group, ConsensusMode::Supermajority);

    // Alice sends a gossip request to Bob and receives a response back.
    let req = unwrap!(alice.create_gossip(&bob_id));
    let res = unwrap!(bob.handle_request(&alice_id, req));
    unwrap!(alice.handle_response(&bob_id, res));

    // Now Bob has a_0, a_1, a_2 and a_3 and Alice knows it.
    assert!(bob.graph().contains(&a_1_hash));
    assert!(bob.graph().contains(&a_2_hash));
    assert!(bob.graph().contains(&a_3_hash));

    // Alice creates a fork.
    let a_2_fork = unwrap!(alice.new_event_from_observation(
        a_1_index,
        Observation::OpaquePayload(Transaction::new("two-fork")),
    ));
    let a_2_fork_hash = *a_2_fork.hash();
    unwrap!(alice.add_event(a_2_fork));

    // Alice sends another gossip request to Bob.
    let req = unwrap!(alice.create_gossip(&bob_id));
    let _ = unwrap!(bob.handle_request(&alice_id, req));

    // Verify that Bob now has the forked event.
    assert!(bob.graph().contains(&a_2_fork_hash));
}

#[test]
fn sees() {
    // This graph contains a fork.
    let alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));

    let a2 = unwrap!(alice.graph().find_by_short_name("A_2"));
    let a3 = unwrap!(alice.graph().find_by_short_name("A_3"));
    let b2 = unwrap!(alice.graph().find_by_short_name("B_2"));
    let c1 = unwrap!(alice.graph().find_by_short_name("C_1"));
    let c2_0 = unwrap!(alice.graph().find_by_short_name("C_2,0"));
    let c2_1 = unwrap!(alice.graph().find_by_short_name("C_2,1"));

    // Simple no fork cases:
    assert!(a3.sees(a3));
    assert!(a3.sees(a2));
    assert!(a3.sees(b2));

    // A2 cannot prove the fork because it has only the first side of it in its ancestry.
    assert!(a2.sees(c1));
    assert!(a2.sees(c2_0));
    assert!(!a2.sees(c2_1));

    // Similarly, B2 has only the second side of the fork in its ancestry and so cannot prove it
    // either.
    assert!(b2.sees(c1));
    assert!(!b2.sees(c2_0));
    assert!(b2.sees(c2_1));

    // A3, on the other hand, has both sides of the fork in its ancestry and so can prove it.
    assert!(!a3.sees(c1));
    assert!(!a3.sees(c2_0));
    assert!(!a3.sees(c2_1));
}

#[test]
fn routing_aggressive_churn() {
    // This test is based on graphs generated by running the `aggressive_churn` test in routing.
    // Routing revision: 9bcaf8d46
    // RNG seed: [52656022, 3489497706, 2516765719, 1572938488]

    let contents0 = parse_test_dot_file("PublicIdnamecf701f-001.dot");
    let mut peer0 = TestParsec::from_parsed_contents(contents0);

    let contents1 = parse_test_dot_file("PublicIdnamef03cef-001.dot");
    let mut peer1 = TestParsec::from_parsed_contents(contents1);

    let request = unwrap!(peer0.create_gossip(peer1.our_pub_id()));
    let _ = unwrap!(peer1.handle_request(peer0.our_pub_id(), request));
}

#[cfg(feature = "malice-detection")]
mod handle_malice {
    use super::*;
    use crate::{
        dev_utils::{parse_test_dot_file, ParsedContents},
        gossip::{Event, EventHash},
        id::SecretId,
        mock::{self, Transaction},
        network_event::NetworkEvent,
        observation::Malice,
        peer_list::{PeerIndex, PeerList, PeerState},
        PackedEvent, Request, Response,
    };
    use itertools::Itertools;

    fn take_packed_events<T: NetworkEvent, S: SecretId>(
        peer: &TestParsec<T, S>,
        n: usize,
    ) -> Vec<PackedEvent<T, S::PublicId>> {
        peer.graph()
            .iter()
            .map(|event| unwrap!(event.inner().pack(peer.event_context())))
            .take(n)
            .collect()
    }

    // Returns iterator over all votes cast by the given node.
    fn our_votes<T: NetworkEvent, S: SecretId>(
        parsec: &TestParsec<T, S>,
    ) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        parsec
            .peer_list()
            .our_events()
            .filter_map(move |index| parsec.graph().get(index))
            .filter_map(move |event| parsec.event_payload(event.inner()))
    }

    // Add the peers to the `PeerList` as the genesis group.
    fn add_genesis_group<S: SecretId>(
        peer_list: &mut PeerList<S>,
        genesis: &BTreeSet<S::PublicId>,
    ) {
        for peer_id in genesis {
            if let Some(index) = peer_list.get_index(peer_id) {
                peer_list.change_peer_state(index, PeerState::active())
            } else {
                let _ = peer_list.add_peer(peer_id.clone(), PeerState::active());
            }
        }
    }

    #[test]
    fn genesis_event_not_after_initial() {
        // Generated with RNG seed: [926181213, 2524489310, 392196615, 406869071].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents
            .peer_list
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();
        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // Simulate Dave creating unexpected genesis.
        let dave_id = PeerId::new("Dave");
        let mut dave_contents = ParsedContents::new(dave_id.clone());

        dave_contents
            .peer_list
            .change_peer_state(PeerIndex::OUR, PeerState::active());
        add_genesis_group(&mut dave_contents.peer_list, &genesis);

        let d_0 = Event::new_initial(dave_contents.event_context());
        let d_0_index = dave_contents.add_event(d_0);

        let d_1 = unwrap!(dave_contents.new_event_from_observation(
            d_0_index,
            Observation::OpaquePayload(Transaction::new("dave's malicious vote")),
        ));
        let d_1_index = dave_contents.add_event(d_1);

        let d_2 = unwrap!(
            dave_contents.new_event_from_observation(d_1_index, Observation::Genesis(genesis),)
        );
        let d_2_hash = *d_2.hash();
        let _ = dave_contents.add_event(d_2);

        let mut dave = TestParsec::from_parsed_contents(dave_contents);

        // Dave sends malicious gossip to Alice.
        let request = unwrap!(dave.create_gossip(&alice_id));
        unwrap!(alice.handle_request(&dave_id, request));

        // Verify that Alice detected the malice and accused Dave.
        let (offender, hash) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match *payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::UnexpectedGenesis(hash),
                } => Some((offender.clone(), hash)),
                _ => None,
            })
            .next());

        assert_eq!(offender, dave_id);
        assert_eq!(hash, d_2_hash);
    }

    #[test]
    fn genesis_event_creator_not_genesis_member() {
        // Generated with RNG seed: [848911612, 2362592349, 3178199135, 2458552022].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents
            .peer_list
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();

        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // This is needed so the AddPeer(Eric) is consensused.
        unwrap!(alice.restart_consensus());

        // Simulate Eric creating unexpected genesis.
        let eric_id = PeerId::new("Eric");
        let mut eric_contents = ParsedContents::new(eric_id.clone());

        eric_contents
            .peer_list
            .change_peer_state(PeerIndex::OUR, PeerState::active());
        add_genesis_group(&mut eric_contents.peer_list, &genesis);

        let e_0 = Event::new_initial(eric_contents.event_context());
        let e_0_index = eric_contents.add_event(e_0);

        let e_1 = unwrap!(
            eric_contents.new_event_from_observation(e_0_index, Observation::Genesis(genesis),)
        );
        let e_1_hash = *e_1.hash();
        let _ = eric_contents.add_event(e_1);

        let mut eric = TestParsec::from_parsed_contents(eric_contents);

        // Eric sends malicious gossip to Alice.
        let request = unwrap!(eric.create_gossip(&alice_id));
        unwrap!(alice.handle_request(&eric_id, request));

        // Verify that Alice detected the malice and accused Eric.
        let (offender, hash) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match *payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::UnexpectedGenesis(hash),
                } => Some((offender.clone(), hash)),
                _ => None,
            })
            .next());

        assert_eq!(offender, eric_id);
        assert_eq!(hash, e_1_hash);
    }

    fn initialise_genesis_parsecs(count: usize) -> Vec<TestPeer> {
        let genesis_ids = mock::create_ids(count).into_iter().collect::<BTreeSet<_>>();
        genesis_ids
            .iter()
            .map(|id| {
                TestParsec::from_genesis(id.clone(), &genesis_ids, ConsensusMode::Supermajority)
            })
            .collect()
    }

    // Asserts that these and only these accusations have been made by `peer`.
    fn assert_peer_has_accused(
        peer: &TestPeer,
        mut expected_accusations: Vec<(&PeerId, &Malice<Transaction, PeerId>)>,
    ) {
        expected_accusations.sort();
        let mut actual_accusations = our_votes(peer)
            .filter_map(|payload| match payload {
                Observation::Accusation { offender, malice } => Some((offender, malice)),
                _ => None,
            })
            .collect_vec();
        actual_accusations.sort();
        assert_eq!(expected_accusations, actual_accusations);
    }

    #[test]
    fn missing_genesis_event() {
        let (mut alice, mut bob) =
            unwrap!(initialise_genesis_parsecs(2).into_iter().collect_tuple());

        // Pop Alice's last event, which is her genesis vote.
        let (_, genesis_event) = unwrap!(alice.remove_last_event());
        match unwrap!(alice.event_payload(&genesis_event)) {
            Observation::Genesis(_) => (),
            _ => panic!("This should be Alice's genesis vote."),
        }

        // Create request from Alice to Bob.
        let request = unwrap!(alice.create_gossip(bob.our_pub_id()));
        let alice_initial_hash = *nth_event(alice.graph(), 0).hash();
        let alice_requesting_hash = *nth_event(alice.graph(), 1).hash();

        // Send request.
        unwrap!(bob.handle_request(alice.our_pub_id(), request));
        assert!(bob.graph().contains(&alice_initial_hash));
        assert!(bob.graph().contains(&alice_requesting_hash));

        // Verify that Bob detected and accused Alice of malice.
        let expected_malice = Malice::MissingGenesis(alice_requesting_hash);
        assert_peer_has_accused(&bob, vec![(alice.our_pub_id(), &expected_malice)]);
    }

    #[test]
    fn incorrect_genesis_event() {
        let (mut alice, mut bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        // Pop Alice's last event, which is her genesis vote, and replace with a vote for a
        // different genesis group.
        let _ = unwrap!(alice.remove_last_event());
        let invalid_genesis = btree_set![
            alice.our_pub_id().clone(),
            bob.our_pub_id().clone(),
            PeerId::new("Derp")
        ];
        unwrap!(alice.vote_for(Observation::Genesis(invalid_genesis)));

        // Create request from Alice to Carol.
        let request = unwrap!(alice.create_gossip(carol.our_pub_id()));
        let alice_initial_hash = *nth_event(alice.graph(), 0).hash();
        let alice_genesis_hash = *nth_event(alice.graph(), 1).hash();
        let alice_requesting_hash = *nth_event(alice.graph(), 2).hash();

        // Send request.  Alice's genesis should be rejected as invalid.
        assert_eq!(
            carol.handle_request(alice.our_pub_id(), request),
            Err(Error::InvalidEvent)
        );

        // Carol's graph shouldn't contain Alice's genesis because of the rejection.
        assert!(carol.graph().contains(&alice_initial_hash));
        assert!(!carol.graph().contains(&alice_genesis_hash));
        assert!(!carol.graph().contains(&alice_requesting_hash));

        // Carol should have a pending accusation against Alice's event.
        assert_eq!(carol.pending_accusations().len(), 1);
        let alice_index = unwrap!(carol.get_peer_index(alice.our_pub_id()));
        let alice_genesis_packed = unwrap!(nth_event(alice.graph(), 1).pack(alice.event_context()));
        let pending_accusation = &carol.pending_accusations()[0];
        assert_eq!(alice_index, pending_accusation.0);
        let expected_malice = Malice::IncorrectGenesis(Box::new(alice_genesis_packed));
        assert_eq!(expected_malice, pending_accusation.1);

        // Carol should make the actual vote when handling her next incoming gossip message; a
        // request from Bob in this case.
        let request = unwrap!(bob.create_gossip(carol.our_pub_id()));
        let _ = unwrap!(carol.handle_request(bob.our_pub_id(), request));
        assert_peer_has_accused(&carol, vec![(alice.our_pub_id(), &expected_malice)]);
        assert!(carol.pending_accusations().is_empty());
    }

    fn assert_handling_invalid_response(
        sender: &mut TestPeer,
        receiver: &mut TestPeer,
        invalid_resp_msg: Response<Transaction, PeerId>,
        expected_malice: &Malice<Transaction, PeerId>,
        invalid_hash: &EventHash,
    ) {
        assert_eq!(
            receiver.handle_response(sender.our_pub_id(), invalid_resp_msg),
            Err(Error::InvalidEvent)
        );

        assert!(!receiver.graph().contains(invalid_hash));

        // Handling a valid request shall flush the pending accusations.
        let request = unwrap!(sender.create_gossip(receiver.our_pub_id()));
        assert!(receiver
            .handle_request(sender.our_pub_id(), request)
            .is_ok());
        assert_peer_has_accused(&receiver, vec![(sender.our_pub_id(), expected_malice)]);
    }

    fn packed_req_event(
        peer: &TestPeer,
        self_parent: EventHash,
        other_parent: EventHash,
    ) -> PackedEvent<Transaction, PeerId> {
        PackedEvent::new_request(peer.our_pub_id().clone(), self_parent, other_parent)
    }

    #[test]
    fn invalid_request_wrong_recipient() {
        let (mut alice, mut bob, carol, mut dave) =
            unwrap!(initialise_genesis_parsecs(4).into_iter().collect_tuple());

        // Create request from Alice to Carol, but sent to Bob.
        let request_msg = unwrap!(alice.create_gossip(carol.our_pub_id()));
        let alice_requesting_hash = *nth_event(alice.graph(), 2).hash();

        // Bob shall not create response for that request, but can put Alice's requesting event into
        // its graph.
        assert_eq!(
            bob.handle_request(alice.our_pub_id(), request_msg),
            Err(Error::InvalidMessage)
        );
        assert!(bob.graph().contains(&alice_requesting_hash));

        // Have Bob create an invalid `Request` event.  (Bob should not use Alice's
        // `Requesting(Carol)` event as an other-parent for his `Request` event.)
        let b_1_hash = *nth_event(bob.graph(), 1).hash();
        let invalid_req = packed_req_event(&bob, b_1_hash, alice_requesting_hash);
        let invalid_req_hash = invalid_req.compute_hash();
        let mut packed_events = take_packed_events(&bob, bob.graph().len());
        packed_events.push(invalid_req.clone());
        let invalid_response_msg = Response { packed_events };

        let expected_malice = Malice::InvalidRequest(Box::new(invalid_req));

        assert_handling_invalid_response(
            &mut bob,
            &mut alice,
            invalid_response_msg.clone(),
            &expected_malice,
            &invalid_req_hash,
        );

        assert_handling_invalid_response(
            &mut bob,
            &mut dave,
            invalid_response_msg,
            &expected_malice,
            &invalid_req_hash,
        );
    }

    #[test]
    fn invalid_request_wrong_type_of_other_parent() {
        let (mut alice, mut bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        // Send request from Alice to Bob.
        let request_msg = unwrap!(alice.create_gossip(bob.our_pub_id()));
        let a_1 = nth_event(alice.graph(), 1);
        assert!(
            !a_1.is_requesting()
            "A_1 should not be a 'Requesting(Bob)' event to ensure a 'Request' using this as its \
             other-parent is invalid.",
        );

        assert!(bob.handle_request(alice.our_pub_id(), request_msg).is_ok());

        // Have Bob create an invalid Request event.  (Bob should not use Alice's second last
        // event (`A_1`) as an other-parent for his Request event, as it is not a
        // `Requesting(Bob)` event.)
        let b_1_hash = *nth_event(bob.graph(), 1).hash();
        let invalid_req = packed_req_event(&bob, b_1_hash, *a_1.hash());
        let invalid_req_hash = invalid_req.compute_hash();

        let expected_malice = Malice::InvalidRequest(Box::new(invalid_req.clone()));

        let mut packed_events = take_packed_events(&bob, 2);
        packed_events.push(invalid_req.clone());
        let invalid_response_msg = Response { packed_events };

        assert_handling_invalid_response(
            &mut bob,
            &mut alice,
            invalid_response_msg,
            &expected_malice,
            &invalid_req_hash,
        );

        packed_events = take_packed_events(&bob, 5);
        packed_events.push(invalid_req);
        // Knowledge of Alice and Bob, and the invalid_req.
        let invalid_response_msg = Response { packed_events };

        assert_handling_invalid_response(
            &mut bob,
            &mut carol,
            invalid_response_msg,
            &expected_malice,
            &invalid_req_hash,
        );
    }

    #[test]
    fn duplicate_requests() {
        let (mut alice, mut bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        // Send request from Alice to Bob.
        let request_msg = unwrap!(alice.create_gossip(bob.our_pub_id()));
        let mut response_msg = unwrap!(bob.handle_request(alice.our_pub_id(), request_msg));

        // Have Bob create an invalid Request event.  (Bob has already assigned a Request
        // to the `Requesting(Bob)`, hence can not use it again.)
        let b_last = nth_event(bob.graph(), bob.graph().len() - 1);
        let alice_requesting = unwrap!(bob.graph().get(unwrap!(b_last.other_parent())));
        let invalid_req = packed_req_event(&bob, *b_last.hash(), *alice_requesting.hash());
        let invalid_req_hash = invalid_req.compute_hash();
        let expected_malice = Malice::InvalidRequest(Box::new(invalid_req.clone()));

        response_msg.packed_events.push(invalid_req.clone());
        assert_handling_invalid_response(
            &mut bob,
            &mut alice,
            response_msg,
            &expected_malice,
            &invalid_req_hash,
        );

        let mut packed_events = take_packed_events(&bob, bob.graph().len());
        packed_events.push(invalid_req);
        let invalid_response_msg = Response { packed_events };
        assert_handling_invalid_response(
            &mut bob,
            &mut carol,
            invalid_response_msg,
            &expected_malice,
            &invalid_req_hash,
        );
    }

    fn packed_resp_event(
        peer: &TestPeer,
        self_parent: EventHash,
        other_parent: EventHash,
    ) -> PackedEvent<Transaction, PeerId> {
        PackedEvent::new_response(peer.our_pub_id().clone(), self_parent, other_parent)
    }

    #[test]
    fn invalid_response_wrong_recipient() {
        let (mut alice, mut bob, mut carol, mut dave) =
            unwrap!(initialise_genesis_parsecs(4).into_iter().collect_tuple());

        // Send request from Alice to Bob.
        let request_msg = unwrap!(alice.create_gossip(bob.our_pub_id()));
        assert!(bob.handle_request(alice.our_pub_id(), request_msg).is_ok());

        // If the response be sent to Carol, a response event shall not be created.
        let packed_events = take_packed_events(&bob, bob.graph().len());
        assert_eq!(
            carol.handle_response(bob.our_pub_id(), Response { packed_events }),
            Err(Error::InvalidMessage)
        );
        assert!(!carol.graph().iter().any(|event| event.is_response()));

        // Have Carol create an invalid Response event.  (Carol should not use Bob's Request event
        // as an other-parent for her Response event since the other-parent of Bob's Request wasn't
        // created by her.)
        let c_1_hash = *nth_event(carol.graph(), 1).hash();
        let bob_request = unwrap!(nth_event(bob.graph(), 5).pack(bob.event_context()));
        let bob_request_hash = bob_request.compute_hash();
        let invalid_resp = packed_resp_event(&carol, c_1_hash, bob_request_hash);
        let invalid_resp_hash = invalid_resp.compute_hash();
        let expected_malice = Malice::InvalidResponse(Box::new(invalid_resp.clone()));

        let mut packed_events = take_packed_events(&carol, 2);
        packed_events.push(bob_request);
        packed_events.push(invalid_resp.clone());
        let invalid_response_msg = Response { packed_events };
        assert_handling_invalid_response(
            &mut carol,
            &mut bob,
            invalid_response_msg,
            &expected_malice,
            &invalid_resp_hash,
        );

        packed_events = take_packed_events(&bob, 8);
        packed_events.push(invalid_resp);
        // Knowledge of Alice, Bob and Carol, and the invalid_resp.
        let invalid_response_msg = Response { packed_events };
        assert_handling_invalid_response(
            &mut carol,
            &mut dave,
            invalid_response_msg,
            &expected_malice,
            &invalid_resp_hash,
        );
    }

    #[test]
    fn invalid_response_wrong_type_of_other_parent() {
        let (mut alice, mut bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        // Send request from Alice to Bob.
        let request_msg = unwrap!(alice.create_gossip(bob.our_pub_id()));
        assert!(bob.handle_request(alice.our_pub_id(), request_msg).is_ok());

        // Have Alice create an invalid Response event.  (Alice should not use Bob's second last
        // event as an other-parent for her Response event, as it is not a Request event.)
        let b_1 = nth_event(bob.graph(), 1);
        assert!(
            !b_1.is_request()
            "B_1 should not be a Request event to ensure a 'Response' using this as its \
             other-parent is invalid.",
        );
        let a_last_hash = *nth_event(alice.graph(), alice.graph().len() - 1).hash();
        let invalid_resp = packed_resp_event(&alice, a_last_hash, *b_1.hash());
        let invalid_resp_hash = invalid_resp.compute_hash();
        let expected_malice = Malice::InvalidResponse(Box::new(invalid_resp.clone()));

        let invalid_response_msg = Response {
            packed_events: vec![invalid_resp.clone()],
        };
        assert_handling_invalid_response(
            &mut alice,
            &mut bob,
            invalid_response_msg,
            &expected_malice,
            &invalid_resp_hash,
        );

        let mut packed_events = take_packed_events(&bob, 6);
        packed_events.push(invalid_resp);
        // Knowledge of Alice and Bob, and the invalid_resp.
        let invalid_response_msg = Response { packed_events };
        assert_handling_invalid_response(
            &mut alice,
            &mut carol,
            invalid_response_msg,
            &expected_malice,
            &invalid_resp_hash,
        );
    }

    #[test]
    fn duplicate_responses() {
        let (mut alice, mut bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        // Send request from Alice to Bob.
        let request_msg = unwrap!(alice.create_gossip(bob.our_pub_id()));
        let response_msg = unwrap!(bob.handle_request(alice.our_pub_id(), request_msg));

        assert!(alice
            .handle_response(bob.our_pub_id(), response_msg)
            .is_ok());

        // Have Alice create an invalid Response event.  (Alice has already assigned a Response
        // to the Request, hence can not use it again.)
        let valid_resp =
            unwrap!(nth_event(alice.graph(), alice.graph().len() - 1).pack(alice.event_context()));
        let a_last_event_hash = valid_resp.compute_hash();
        let bob_request_hash = *unwrap!(valid_resp.other_parent());
        let invalid_resp = packed_resp_event(&alice, a_last_event_hash, bob_request_hash);
        let invalid_resp_hash = invalid_resp.compute_hash();
        let expected_malice = Malice::InvalidResponse(Box::new(invalid_resp.clone()));

        let invalid_response_msg = Response {
            packed_events: vec![valid_resp, invalid_resp.clone()],
        };
        assert_handling_invalid_response(
            &mut alice,
            &mut bob,
            invalid_response_msg,
            &expected_malice,
            &invalid_resp_hash,
        );

        let mut packed_events = take_packed_events(&alice, alice.graph().len());
        packed_events.push(invalid_resp);
        let invalid_response_msg = Response { packed_events };
        assert_handling_invalid_response(
            &mut alice,
            &mut carol,
            invalid_response_msg,
            &expected_malice,
            &invalid_resp_hash,
        );
    }

    #[test]
    fn duplicate_votes() {
        // Generated with RNG seed: [1353978636, 426502568, 2862743769, 1583787884].
        //
        // Carol has already voted for "ABCD".  Create two new duplicate votes by Carol for this
        // opaque payload.
        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));

        let duplicated_payload = Observation::OpaquePayload(Transaction::new("ABCD"));
        let first_duplicate = unwrap!(carol
            .new_event_from_observation(carol.our_last_event_index(), duplicated_payload.clone()));

        let first_duplicate_clone = unwrap!(carol
            .new_event_from_observation(carol.our_last_event_index(), duplicated_payload.clone()));
        let first_duplicate_clone_packed = carol.pack_event(&first_duplicate_clone);

        let first_duplicate_hash = *first_duplicate.hash();
        let first_duplicate_index = unwrap!(carol.add_event(first_duplicate));
        let second_duplicate =
            unwrap!(carol.new_event_from_observation(first_duplicate_index, duplicated_payload));
        let second_duplicate_packed = carol.pack_event(&second_duplicate);

        // Check that the first duplicate triggers an accusation by Alice, but that the
        // duplicate is still added to the graph.
        let mut alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let carols_valid_vote_hash = *unwrap!(alice.graph().find_by_short_name("C_5")).hash();
        unwrap!(alice.unpack_and_add_event(first_duplicate_clone_packed));

        let carol_index = unwrap!(alice.peer_list().get_index(carol.our_pub_id()));
        let expected_accusations = vec![(
            carol_index,
            Malice::DuplicateVote(carols_valid_vote_hash, first_duplicate_hash),
        )];
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&first_duplicate_hash));

        // Check that the second one doesn't trigger any further accusation, but is also added
        // to the graph.
        let second_duplicate_hash = *second_duplicate.hash();
        unwrap!(alice.unpack_and_add_event(second_duplicate_packed));
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&second_duplicate_hash));
    }

    // This will be used to hold four peers initialised to support malice and accomplice testing:
    //   * Alice (malicious - falsely accuses Carol)
    //   * Bob (accomplice),
    //   * Dave (peer to test).
    //
    // The struct will also hold the hash of Alice's accusation, and the hash of Bob's sync event
    // where he'll be detectable as an accomplice.
    struct AccompliceEnvironment {
        invalid_accusation_hash: EventHash,
        accomplice_event_hash: EventHash,
        alice: TestPeer,
        bob: TestPeer,
        dave: TestPeer,
    }

    impl AccompliceEnvironment {
        fn new() -> Self {
            let (mut alice, mut bob, mut carol, dave) =
                unwrap!(initialise_genesis_parsecs(4).into_iter().collect_tuple());

            // Put Carol's events into Alice's graph, and have Alice make a false accusation of
            // forking by Carol's last event.
            let mut message = unwrap!(carol.create_gossip(alice.our_pub_id()));
            let invalid_accusation_hash =
                alice.handle_request_make_false_accusation(carol.our_pub_id(), message);

            // Alice gossips to Bob, but Bob acting as Alice's accomplice ignores Alice's invalid
            // accusation.
            message = unwrap!(alice.create_gossip(bob.our_pub_id()));
            bob.handle_request_as_accomplice(alice.our_pub_id(), message);

            // Bob's `Request` event he just created will be the one linked to any detected
            // accomplice accusation.
            let accomplice_event_hash =
                *unwrap!(bob.graph().get(bob.our_last_event_index())).hash();

            AccompliceEnvironment {
                invalid_accusation_hash,
                accomplice_event_hash,
                alice,
                bob,
                dave,
            }
        }

        fn alice_id(&self) -> &PeerId {
            self.alice.our_pub_id()
        }

        fn bob_id(&self) -> &PeerId {
            self.bob.our_pub_id()
        }

        fn dave_id(&self) -> &PeerId {
            self.dave.our_pub_id()
        }

        fn assert_dave_accused_alice_only(&self) {
            assert!(self.dave.graph().contains(&self.invalid_accusation_hash));
            let expected_malice = Malice::InvalidAccusation(self.invalid_accusation_hash);
            assert_peer_has_accused(&self.dave, vec![(self.alice_id(), &expected_malice)]);
        }

        fn assert_dave_accused_alice_and_bob(&self) {
            assert!(self.dave.graph().contains(&self.invalid_accusation_hash));
            let invalid_accusation = Malice::InvalidAccusation(self.invalid_accusation_hash);
            let accomplice_accusation = Malice::Accomplice(
                self.accomplice_event_hash,
                Box::new(invalid_accusation.clone()),
            );
            let expected_malice = vec![
                (self.alice_id(), &invalid_accusation),
                (self.bob_id(), &accomplice_accusation),
            ];
            assert_peer_has_accused(&self.dave, expected_malice);
        }
    }

    #[test]
    // Alice has falsely accused Carol of creating a fork.  Dave will detect this when Alice gossips
    // to him.
    fn invalid_accusation() {
        let mut env = AccompliceEnvironment::new();
        let alice_id = env.alice_id().clone();
        let dave_id = env.dave_id().clone();

        // Send gossip from Alice to Dave.
        let message = unwrap!(env.alice.create_gossip(&dave_id));
        unwrap!(env.dave.handle_request(&alice_id, message));

        // Dave's events should contain Alice's accusation, and he should have made an accusation
        // against Alice's invalid event.
        env.assert_dave_accused_alice_only();
    }

    #[test]
    // Alice has falsely accused Carol of creating a fork.  Bob knows this, but as an accomplice,
    // hasn't accused Alice of `InvalidAccusation`.  Dave will detect this when Bob gossips to him.
    fn accomplice_basic() {
        let mut env = AccompliceEnvironment::new();
        let bob_id = env.bob_id().clone();
        let dave_id = env.dave_id().clone();

        // Send gossip from Bob to Dave.
        let message = unwrap!(env.bob.create_gossip(&dave_id));
        unwrap!(env.dave.handle_request(&bob_id, message));

        // Dave's events should contain Alice's accusation, and he should have made an accusation
        // against Alice's invalid event and against Bob as an accomplice.
        env.assert_dave_accused_alice_and_bob();
    }

    #[test]
    // Alice has falsely accused Carol of creating a fork.  Bob knows this, but as an accomplice,
    // hasn't accused Alice of `InvalidAccusation`.  Dave will detect Alice's malicious behaviour
    // when she gossips to him, and will later detect Bob as an accomplice when he gossips to him.
    // In addition to that, Dave shall not accuse accomplice against Bob more than once during the
    // later on gossips.
    fn accomplice_separate() {
        let mut env = AccompliceEnvironment::new();
        let alice_id = env.alice_id().clone();
        let bob_id = env.bob_id().clone();
        let dave_id = env.dave_id().clone();

        // Send gossip from Alice to Dave.
        let mut message = unwrap!(env.alice.create_gossip(&dave_id));
        unwrap!(env.dave.handle_request(&alice_id, message));
        env.assert_dave_accused_alice_only();

        // Send gossip from Bob to Dave.
        message = unwrap!(env.bob.create_gossip(&dave_id));
        unwrap!(env.dave.handle_request(&bob_id, message));

        // Send gossip from Bob to Dave again.
        message = unwrap!(env.bob.create_gossip(&dave_id));
        unwrap!(env.dave.handle_request(&bob_id, message));

        // Dave's events should contain Alice's accusation, and he should have made an accusation
        // against Alice's invalid event and against Bob as an accomplice. The accomplice accusation
        // against Bob shall only happen once.
        env.assert_dave_accused_alice_and_bob();
    }

    #[test]
    fn basic_fork() {
        // Generated with RNG seed: [1573595827, 2035773878, 1331264098, 154770609].
        //
        // In this scenario, Alice creates two descendants of A_20 and sends one of them to Bob,
        // and the other one to Dave. When Bob gossips to Dave afterwards, Dave is made aware of
        // both sides of the fork and should raise an accusation.
        let mut alice0 = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let mut bob = TestParsec::from_parsed_contents(parse_test_dot_file("bob.dot"));
        let message0 = unwrap!(alice0.create_gossip(bob.our_pub_id()));
        unwrap!(bob.handle_request(alice0.our_pub_id(), message0));

        let mut alice1 = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let mut dave = TestParsec::from_parsed_contents(parse_test_dot_file("dave.dot"));
        let message1 = unwrap!(alice1.create_gossip(dave.our_pub_id()));
        unwrap!(dave.handle_request(alice1.our_pub_id(), message1));

        // Bob and Dave have different notions of which event is the 21st one by Alice - here
        // we save the hashes of these two events that could be considered A_21.
        let bob_a_21_hash = *unwrap!(bob.graph().find_by_short_name("A_21")).hash();
        let dave_a_21_hash = *unwrap!(dave.graph().find_by_short_name("A_21")).hash();
        assert_ne!(bob_a_21_hash, dave_a_21_hash);

        // Bob doesn't know Dave's A_21, and Dave doesn't know Bob's.
        assert!(!bob.graph().contains(&dave_a_21_hash));
        assert!(!dave.graph().contains(&bob_a_21_hash));

        // Send gossip from Bob to Dave.
        let message = unwrap!(bob.create_gossip(dave.our_pub_id()));
        unwrap!(dave.handle_request(bob.our_pub_id(), message));
        // Dave should now be aware of the other branch of the fork.
        assert!(dave.graph().contains(&bob_a_21_hash));

        // Verify that Dave detected malice and accused Alice of it.
        let expected_malice = Malice::Fork(*unwrap!(bob.graph().find_by_short_name("A_20")).hash());
        assert_peer_has_accused(&dave, vec![(alice0.our_pub_id(), &expected_malice)]);
    }

    #[test]
    //             A_3,0     A_3,1
    //               |         |
    //    A_2,0    A_2,1 ------+
    //      |        |
    //     A_1 ------+
    //      |
    //     A_0
    //
    // Fork accusations should be made against A_1 and A_2,1.
    fn second_fork_on_branch_of_first_fork_four_peers() {
        let (alice, mut bob, mut carol, mut dave) =
            unwrap!(initialise_genesis_parsecs(4).into_iter().collect_tuple());

        let alice_id = alice.our_pub_id().clone();
        let bob_id = bob.our_pub_id().clone();
        let carol_id = carol.our_pub_id().clone();
        let dave_id = dave.our_pub_id().clone();

        // [A_0, A_1, A_2,0] will be sent to Bob.
        let a_0 = unwrap!(nth_event(alice.graph(), 0).pack(alice.event_context()));
        let a_1 = unwrap!(nth_event(alice.graph(), 1).pack(alice.event_context()));
        let a_2_0 =
            PackedEvent::new_requesting(alice_id.clone(), bob_id.clone(), a_1.compute_hash());
        let mut request = Request {
            packed_events: vec![a_0.clone(), a_1.clone(), a_2_0.clone()],
        };
        unwrap!(bob.handle_request(&alice_id, request.clone()));

        // [A_0, A_1, A_2,1, A_3,0] will be sent to Carol.
        let a_2_1 = PackedEvent::new_observation(
            alice_id.clone(),
            a_1.compute_hash(),
            Observation::OpaquePayload(Transaction::new("For fork's sake")),
        );
        let a_3_0 =
            PackedEvent::new_requesting(alice_id.clone(), carol_id.clone(), a_2_1.compute_hash());
        request.packed_events = vec![a_0.clone(), a_1.clone(), a_2_1.clone(), a_3_0.clone()];
        unwrap!(carol.handle_request(&alice_id, request.clone()));

        // [A_0, A_1, A_2,1, A_3,1] will be sent to Dave.
        let a_3_1 =
            PackedEvent::new_requesting(alice_id.clone(), dave_id.clone(), a_2_1.compute_hash());
        request.packed_events = vec![a_0.clone(), a_1.clone(), a_2_1.clone(), a_3_1.clone()];
        unwrap!(dave.handle_request(&alice_id, request));

        // Send a request from Dave to Carol.  Carol should accuse A_2_1.  Don't send the response.
        request = unwrap!(dave.create_gossip(&carol_id));
        unwrap!(carol.handle_request(&dave_id, request));
        assert!(carol.graph().contains(&a_3_1.compute_hash()));
        let expected_malice_a_2_1 = Malice::Fork(a_2_1.compute_hash());
        assert_peer_has_accused(&carol, vec![(&alice_id, &expected_malice_a_2_1)]);

        // Send a request from Dave to Bob.  Bob should accuse A_1.  Don't send the response.
        request = unwrap!(dave.create_gossip(&bob_id));
        unwrap!(bob.handle_request(&dave_id, request));
        assert!(bob.graph().contains(&a_2_1.compute_hash()));
        let expected_malice_a_1 = Malice::Fork(a_1.compute_hash());
        assert_peer_has_accused(&bob, vec![(&alice_id, &expected_malice_a_1)]);

        // Send a request from Carol to Bob and send the response.  Bob should accuse A_2_1 and
        // Carol should accuse A_1.
        request = unwrap!(carol.create_gossip(&bob_id));
        let response = unwrap!(bob.handle_request(&carol_id, request));
        assert!(bob.graph().contains(&a_3_0.compute_hash()));
        assert!(bob.graph().contains(&a_3_1.compute_hash()));
        let both_accusations = vec![
            (&alice_id, &expected_malice_a_1),
            (&alice_id, &expected_malice_a_2_1),
        ];
        assert_peer_has_accused(&bob, both_accusations.clone());
        unwrap!(carol.handle_response(&bob_id, response));
        assert!(carol.graph().contains(&a_2_0.compute_hash()));
        assert_peer_has_accused(&carol, both_accusations.clone());

        // Send a request from Bob to Dave.  Dave should make both accusations.
        request = unwrap!(bob.create_gossip(&dave_id));
        unwrap!(dave.handle_request(&bob_id, request));
        assert!(dave.graph().contains(&a_3_0.compute_hash()));
        assert!(dave.graph().contains(&a_2_0.compute_hash()));
        assert_peer_has_accused(&dave, both_accusations.clone());
    }

    #[test]
    //    A_3,0    A_3,1     A_3,2
    //      |        |         |
    //    A_2,0    A_2,1 ------+
    //      |        |
    //     A_1 ------+
    //      |
    //     A_0
    //
    // Fork accusations should be made against A_1 and A_2,1.
    //
    // This is also a regression test which validated the issue raised at
    // https://github.com/maidsafe/parsec/pull/295#discussion_r273378041
    fn second_fork_on_branch_of_first_fork_three_peers() {
        let (alice, mut bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        let alice_id = alice.our_pub_id().clone();
        let bob_id = bob.our_pub_id().clone();
        let carol_id = carol.our_pub_id().clone();

        // [A_0, A_1, A_2,0, A_3,0] will be sent to Bob first.
        let a_0 = unwrap!(nth_event(alice.graph(), 0).pack(alice.event_context()));
        let a_1 = unwrap!(nth_event(alice.graph(), 1).pack(alice.event_context()));
        let a_2_0 = PackedEvent::new_observation(
            alice_id.clone(),
            a_1.compute_hash(),
            Observation::OpaquePayload(Transaction::new("LHS")),
        );
        let a_2_1 = PackedEvent::new_observation(
            alice_id.clone(),
            a_1.compute_hash(),
            Observation::OpaquePayload(Transaction::new("RHS")),
        );
        let a_3_0 =
            PackedEvent::new_requesting(alice_id.clone(), bob_id.clone(), a_2_0.compute_hash());
        let a_3_1 =
            PackedEvent::new_requesting(alice_id.clone(), bob_id.clone(), a_2_1.compute_hash());
        let mut request = Request {
            packed_events: vec![a_0.clone(), a_1.clone(), a_2_0.clone(), a_3_0.clone()],
        };
        unwrap!(bob.handle_request(&alice_id, request.clone()));

        // [A_0, A_1, A_2,1, A_3,1] will be sent to Bob second.  Bob should accuse A_1.
        request.packed_events = vec![a_0.clone(), a_1.clone(), a_2_1.clone(), a_3_1.clone()];
        unwrap!(bob.handle_request(&alice_id, request.clone()));

        assert!(bob.graph().contains(&a_2_0.compute_hash()));
        assert!(bob.graph().contains(&a_2_1.compute_hash()));
        let expected_malice_a_1 = Malice::Fork(a_1.compute_hash());
        assert_peer_has_accused(&bob, vec![(&alice_id, &expected_malice_a_1)]);

        // [A_0, A_1, A_2,1, A_3,2] will be sent to Carol.
        let a_3_2 =
            PackedEvent::new_requesting(alice_id.clone(), carol_id.clone(), a_2_1.compute_hash());
        request.packed_events = vec![a_0.clone(), a_1.clone(), a_2_1.clone(), a_3_2.clone()];
        unwrap!(carol.handle_request(&alice_id, request));

        // Send a request from Bob to Carol.  Carol should accuse A_1 and A_2_1.
        request = unwrap!(bob.create_gossip(&carol_id));
        let response = unwrap!(carol.handle_request(&bob_id, request));
        assert!(carol.graph().contains(&a_2_0.compute_hash()));
        assert!(carol.graph().contains(&a_2_1.compute_hash()));
        assert!(carol.graph().contains(&a_3_0.compute_hash()));
        assert!(carol.graph().contains(&a_3_1.compute_hash()));
        assert!(carol.graph().contains(&a_3_2.compute_hash()));
        let expected_malice_a_2_1 = Malice::Fork(a_2_1.compute_hash());
        let both_accusations = vec![
            (&alice_id, &expected_malice_a_1),
            (&alice_id, &expected_malice_a_2_1),
        ];
        assert_peer_has_accused(&carol, both_accusations.clone());

        // Send the response from Carol to Bob.  Bob should now accuse A_2_1 also.
        unwrap!(bob.handle_response(&carol_id, response));
        assert!(bob.graph().contains(&a_3_0.compute_hash()));
        assert!(bob.graph().contains(&a_3_1.compute_hash()));
        assert!(bob.graph().contains(&a_3_2.compute_hash()));
        assert_peer_has_accused(&bob, both_accusations.clone());
    }

    #[test]
    //    A_2,0    A_2,1    A_2,2
    //      |        |        |
    //      +------ A_1 ------+
    //               |
    //              A_0
    //
    // Fork accusations should be made against A_1 only.
    fn triple_fork() {
        let (alice, mut bob, mut carol, mut dave) =
            unwrap!(initialise_genesis_parsecs(4).into_iter().collect_tuple());

        let alice_id = alice.our_pub_id().clone();
        let bob_id = bob.our_pub_id().clone();
        let carol_id = carol.our_pub_id().clone();
        let dave_id = dave.our_pub_id().clone();

        // [A_0, A_1, A_2,0] will be sent to Bob.
        let a_0 = unwrap!(nth_event(alice.graph(), 0).pack(alice.event_context()));
        let a_1 = unwrap!(nth_event(alice.graph(), 1).pack(alice.event_context()));
        let a_2_0 =
            PackedEvent::new_requesting(alice_id.clone(), bob_id.clone(), a_1.compute_hash());
        let mut request = Request {
            packed_events: vec![a_0.clone(), a_1.clone(), a_2_0.clone()],
        };
        unwrap!(bob.handle_request(&alice_id, request.clone()));

        // [A_0, A_1, A_2,1] will be sent to Carol.
        let a_2_1 =
            PackedEvent::new_requesting(alice_id.clone(), carol_id.clone(), a_1.compute_hash());
        request.packed_events = vec![a_0.clone(), a_1.clone(), a_2_1.clone()];
        unwrap!(carol.handle_request(&alice_id, request.clone()));

        // [A_0, A_1, A_2,2] will be sent to Dave.
        let a_2_2 =
            PackedEvent::new_requesting(alice_id.clone(), dave_id.clone(), a_1.compute_hash());
        request.packed_events = vec![a_0.clone(), a_1.clone(), a_2_2.clone()];
        unwrap!(dave.handle_request(&alice_id, request));

        // Send a request from Bob to Carol and send the response.  Bob and Carol should accuse A_1.
        request = unwrap!(bob.create_gossip(&carol_id));
        let mut response = unwrap!(carol.handle_request(&bob_id, request));
        assert!(carol.graph().contains(&a_2_0.compute_hash()));
        let expected_malice = Malice::Fork(a_1.compute_hash());
        let expected_accusation = vec![(&alice_id, &expected_malice)];
        assert_peer_has_accused(&carol, expected_accusation.clone());
        unwrap!(bob.handle_response(&carol_id, response));
        assert!(bob.graph().contains(&a_2_1.compute_hash()));
        assert_peer_has_accused(&bob, expected_accusation.clone());

        // Send a request from Dave to Carol and send the response.  Dave should accuse A_1.  Carol
        // should not make any further accusations.
        request = unwrap!(dave.create_gossip(&carol_id));
        response = unwrap!(carol.handle_request(&dave_id, request));
        assert!(carol.graph().contains(&a_2_2.compute_hash()));
        assert_peer_has_accused(&carol, expected_accusation.clone());
        unwrap!(dave.handle_response(&carol_id, response));
        assert!(dave.graph().contains(&a_2_0.compute_hash()));
        assert!(dave.graph().contains(&a_2_1.compute_hash()));
        assert_peer_has_accused(&dave, expected_accusation.clone());
    }

    #[derive(PartialEq)]
    enum InvalidCreatorFor {
        SelfParent,
        OtherParent,
    }

    fn invalid_parent_creator_test(test_type: InvalidCreatorFor) {
        let (mut alice, bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        // Create invalid B_2 by Bob - either a `Request` event with other-parent as his first event
        // or an `Observation` with self-parent as Carol's second event.
        let b_0 = nth_event(bob.graph(), 0);
        let b_1 = nth_event(bob.graph(), 1);
        let b_2_packed = if test_type == InvalidCreatorFor::OtherParent {
            PackedEvent::new_request(bob.our_pub_id().clone(), *b_1.hash(), *b_0.hash())
        } else {
            PackedEvent::new_observation(
                bob.our_pub_id().clone(),
                *nth_event(carol.graph(), 1).hash(),
                Observation::OpaquePayload(Transaction::new("ABCD")),
            )
        };

        if test_type == InvalidCreatorFor::SelfParent {
            // Put Carol's events into Alice's graph, so she does have the event indicated as the
            // self-parent of Bob's invalid event.
            let message = unwrap!(carol.create_gossip(alice.our_pub_id()));
            let _ = unwrap!(alice.handle_request(carol.our_pub_id(), message));
        }

        // Send Bob's message to Alice.  B_2 should be rejected as invalid.
        let message = Request {
            packed_events: vec![
                unwrap!(b_0.pack(bob.event_context())),
                unwrap!(b_1.pack(bob.event_context())),
                b_2_packed.clone(),
            ],
        };
        assert_eq!(
            alice.handle_request(bob.our_pub_id(), message),
            Err(Error::InvalidEvent)
        );

        // Alice's graph shouldn't contain B_2.
        assert!(alice.graph().contains(b_0.hash()));
        assert!(alice.graph().contains(b_1.hash()));
        assert!(!alice.graph().contains(&b_2_packed.compute_hash()));

        // Alice should have a pending accusation against Bob's event.
        assert_eq!(alice.pending_accusations().len(), 1);
        let bob_index = unwrap!(alice.get_peer_index(bob.our_pub_id()));
        let pending_accusation = &alice.pending_accusations()[0];
        assert_eq!(bob_index, pending_accusation.0);
        let expected_malice = if test_type == InvalidCreatorFor::OtherParent {
            Malice::OtherParentBySameCreator(Box::new(b_2_packed))
        } else {
            Malice::SelfParentByDifferentCreator(Box::new(b_2_packed))
        };
        assert_eq!(expected_malice, pending_accusation.1);

        // Alice should make the actual vote when handling her next incoming gossip message; a
        // request from Carol in this case.
        let request = unwrap!(carol.create_gossip(alice.our_pub_id()));
        let _ = unwrap!(alice.handle_request(carol.our_pub_id(), request));
        assert_peer_has_accused(&alice, vec![(bob.our_pub_id(), &expected_malice)]);
        assert!(alice.pending_accusations().is_empty());
    }

    #[test]
    fn self_parent_by_different_creator() {
        invalid_parent_creator_test(InvalidCreatorFor::SelfParent);
    }

    #[test]
    fn other_parent_by_same_creator() {
        invalid_parent_creator_test(InvalidCreatorFor::OtherParent);
    }

    #[test]
    fn premature_gossip() {
        // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
        // Copied from add_peer
        let mut parsed_contents = parse_test_dot_file("alice.dot");

        // The final decision to add Frank is reached in E_25, so we remove this event.
        let _e_25 = unwrap!(parsed_contents.remove_last_event());

        let mut alice = TestParsec::from_parsed_contents(parsed_contents);
        let genesis_group: BTreeSet<_> = alice
            .peer_list()
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();

        let alice_id = PeerId::new("Alice");
        let fred_id = PeerId::new("Fred");
        assert!(!alice
            .peer_list()
            .all_ids()
            .any(|(_, peer_id)| *peer_id == fred_id));

        let alice_snapshot = Snapshot::new(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_eq!(alice.create_gossip(&fred_id), Err(Error::UnknownPeer));
        assert_eq!(alice_snapshot, Snapshot::new(&alice));

        // We'll modify Alice's peer list to allow her to create gossip for Fred
        alice.add_peer(fred_id.clone(), PeerState::RECV | PeerState::VOTE);

        // Construct Fred's Parsec instance.
        let mut fred = TestParsec::from_existing(
            fred_id.clone(),
            &genesis_group,
            &genesis_group,
            ConsensusMode::Supermajority,
        );

        // Check that Fred has no events that Alice has
        assert!(alice
            .graph()
            .iter()
            .all(|ev| !fred.graph().contains(ev.inner().hash())));

        // Now Alice will prematurely gossip to Fred
        let request = unwrap!(alice.create_gossip(&fred_id));
        let result = fred.handle_request(&alice_id, request);

        // check that Fred detected premature gossip
        assert_eq!(result, Err(Error::PrematureGossip));

        // Check that Fred has all the events that Alice has
        assert!(alice
            .graph()
            .iter()
            .all(|ev| fred.graph().contains(ev.inner().hash())));
    }

    #[test]
    fn missing_self_parent() {
        let (mut alice, mut bob) =
            unwrap!(initialise_genesis_parsecs(2).into_iter().collect_tuple());

        // Request message contains `[Initial, Genesis, Requesting]`.
        let mut request = unwrap!(alice.create_gossip(bob.our_pub_id()));
        // Remove Alice's genesis event, which is the self-parent for her `Requesting` one.
        let _ = request.packed_events.remove(1);
        let hashes = request
            .packed_events
            .iter()
            .map(PackedEvent::compute_hash)
            .collect_vec();
        assert_eq!(2, hashes.len());
        // Assert we did actually remove the self-parent from the message.
        assert!(!hashes.contains(&unwrap!(request.packed_events[1].self_parent())));

        assert_eq!(
            bob.handle_request(alice.our_pub_id(), request),
            Err(Error::UnknownSelfParent)
        );

        // Verify that the invalid event has not been added to Bob.
        assert!(bob.graph().contains(&hashes[0]));
        assert!(!bob.graph().contains(&hashes[1]));
    }

    #[test]
    fn missing_other_parent() {
        let (mut alice, mut bob, mut carol) =
            unwrap!(initialise_genesis_parsecs(3).into_iter().collect_tuple());

        // Put Bob's events into Alice's graph.
        let message = unwrap!(bob.create_gossip(alice.our_pub_id()));
        let _ = unwrap!(alice.handle_request(bob.our_pub_id(), message));

        // Create a request message from Alice to Carol, and remove a packed event which is
        // an other-parent for one of the other events.
        let mut request = unwrap!(alice.create_gossip(carol.our_pub_id()));
        let invalid_event = unwrap!(request
            .packed_events
            .iter()
            .rev()
            .find(|packed_event| packed_event.other_parent().is_some()));
        let invalid_event_hash = invalid_event.compute_hash();
        let other_parent_hash = *unwrap!(invalid_event.other_parent());
        request
            .packed_events
            .retain(|packed_event| packed_event.compute_hash() != other_parent_hash);

        assert_eq!(
            carol.handle_request(alice.our_pub_id(), request),
            Err(Error::UnknownOtherParent)
        );

        // Verify that the invalid event has not been added to Bob.
        assert!(!carol.graph().contains(&invalid_event_hash));
    }
}

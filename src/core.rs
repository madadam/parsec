// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
#[cfg(test)]
use dev_utils::ParsedContents;
use dump_graph;
use error::{Error, Result};
use gossip::{graph, Event, PackedEvent};
use hash::Hash;
#[cfg(test)]
use id::PublicId;
use id::SecretId;
use meta_voting::{MetaElectionHandle, MetaElections, MetaEvent, MetaEventBuilder, MetaVote, Step};
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use observation::Observation;
use peer_list::{PeerList, PeerState};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{iter, u64};
use vote::Vote;

pub type IsInterestingEventFn<P> =
    fn(peers_that_did_vote: &BTreeSet<P>, peers_that_can_vote: &BTreeSet<P>) -> bool;

/// Returns whether `small` is more than two thirds of `large`.
pub fn is_more_than_two_thirds(small: usize, large: usize) -> bool {
    3 * small > 2 * large
}

/// Function which can be used as `is_interesting_event` in
/// [`Parsec::new()`](struct.Parsec.html#method.new) and which returns `true` if there are >2/3
/// `did_vote` which are members of `can_vote`.
pub fn is_supermajority<P: Ord>(did_vote: &BTreeSet<P>, can_vote: &BTreeSet<P>) -> bool {
    let valid_did_vote_count = can_vote.intersection(did_vote).count();
    is_more_than_two_thirds(valid_did_vote_count, can_vote.len())
}

pub(crate) struct Core<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // Gossip events created locally and received from other peers.
    events: BTreeMap<Hash, Event<T, S::PublicId>>,
    // Information about observations stored in the graph, mapped to their hashes.
    observations: BTreeMap<Hash, ObservationInfo>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_elections: MetaElections<T, S::PublicId>,
    is_interesting_event: IsInterestingEventFn<S::PublicId>,
}

impl<T: NetworkEvent, S: SecretId> Core<T, S> {
    /// Creates a new `Core` for a peer with the given ID and genesis peer IDs (ours included).
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut core = Self::empty(our_id, genesis_group, is_interesting_event);

        for peer_id in genesis_group {
            core.peer_list
                .add_peer(peer_id.clone(), PeerState::active());
            core.peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned())
        }

        core.meta_elections
            .initialise_current_election(core.peer_list.all_ids(), Hash::ZERO);

        // Add initial event.
        let event = Event::new_initial(&core.peer_list);
        if let Err(error) = core.add_event(event) {
            log_or_panic!(
                "{:?} initialising Core failed when adding initial event: {:?}",
                core.our_pub_id(),
                error
            );
        }

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let self_parent_hash = core.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            genesis_observation,
            &core.events,
            &core.peer_list,
        );

        if let Err(error) = core.add_event(event) {
            log_or_panic!(
                "{:?} initialising Core failed when adding the genesis observation: {:?}",
                core.our_pub_id(),
                error,
            );
        }

        core
    }

    /// Creates a new `Core` for a peer that is joining an existing section.
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        if genesis_group.is_empty() {
            log_or_panic!("Genesis group can't be empty");
        }

        if genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group can't already contain us");
        }

        if section.is_empty() {
            log_or_panic!("Section can't be empty");
        }

        if section.contains(our_id.public_id()) {
            log_or_panic!("Section can't already contain us");
        }

        let our_public_id = our_id.public_id().clone();
        let mut core = Self::empty(our_id, genesis_group, is_interesting_event);

        // Add ourselves.
        core.peer_list
            .add_peer(our_public_id.clone(), PeerState::RECV);

        // Add the genesis group.
        for peer_id in genesis_group {
            core.peer_list
                .add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND)
        }

        // Add the current section members.
        for peer_id in section {
            if genesis_group.contains(peer_id) {
                continue;
            }

            core.peer_list.add_peer(peer_id.clone(), PeerState::SEND)
        }

        // Initialise everyone's membership list.
        for peer_id in iter::once(&our_public_id)
            .chain(genesis_group)
            .chain(section)
        {
            core.peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned())
        }

        core.meta_elections
            .initialise_current_election(core.peer_list.all_ids(), Hash::ZERO);

        let initial_event = Event::new_initial(&core.peer_list);
        if let Err(error) = core.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Core failed when adding initial event: {:?}",
                core.our_pub_id(),
                error
            );
        }

        core
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        dump_graph::init();

        Self {
            peer_list: PeerList::new(our_id),
            events: BTreeMap::new(),
            consensused_blocks: VecDeque::new(),
            observations: BTreeMap::new(),
            meta_elections: MetaElections::new(genesis_group.clone()),
            is_interesting_event,
        }
    }

    /// Public id of this node.
    pub fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_pub_id()
    }

    /// Steps the algorithm and returns the next stable block, if any.
    ///
    /// Once we have been removed (i.e. a block with payload `Observation::Remove(our_id)` has been
    /// made stable), then no further blocks will be enqueued.  So, once `poll()` returns such a
    /// block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Checks if the given `observation` has already been voted for by us.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        self.events.values().any(|event| {
            event.creator() == self.our_pub_id() && event
                .vote()
                .map_or(false, |voted| voted.payload() == observation)
        })
    }

    /// Check if there are any observation that have been voted for but not yet consensused.
    pub fn has_unconsensused_observations(&self) -> bool {
        self.observations.values().any(|info| !info.consensused)
    }

    /// Returns observations voted for by us which haven't been returned by `poll` yet.
    /// This includes observations that are either not yet consensused or that are already
    /// consensused, but not yet popped out of the consensus queue.
    ///
    /// The observations are sorted first by the consensus order, then by the vote order.
    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.our_consensused_observations()
            .chain(self.our_unconsensused_observations())
    }

    /// Unpack single packed event and update the set of forking peers if fork is detected.
    /// Returns `None` if the event is already present in the graph.
    pub fn unpack_event(
        &self,
        packed_event: PackedEvent<T, S::PublicId>,
        forking_peers: &mut BTreeSet<S::PublicId>,
    ) -> Result<Option<Event<T, S::PublicId>>> {
        let event = Event::unpack(packed_event, &self.events, &self.peer_list, &forking_peers)?;
        if let Some(event) = event {
            if self
                .peer_list
                .events_by_index(event.creator(), event.index())
                .next()
                .is_some()
            {
                let _ = forking_peers.insert(event.creator().clone());
            }

            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    /// Return all the events in the graph mapped by their hashes.
    pub fn events(&self) -> &BTreeMap<Hash, Event<T, S::PublicId>> {
        &self.events
    }

    /// Returns the events this node thinks that the peer with `peer_id` needs.  If `peer_id` is
    /// `None`, all known gossip events are returned.
    pub fn events_to_gossip(&self, peer_id: Option<&S::PublicId>) -> Vec<&Event<T, S::PublicId>> {
        let last_event = peer_id
            .and_then(|peer_id| self.peer_list.last_event(peer_id))
            .and_then(|hash| self.get_known_event(hash).ok());

        let mut events: Vec<_> = if let Some(last_event) = last_event {
            // Events to include in the result. Initially start with including everything...
            let mut inclusion_list = vec![true; self.events.len()];

            // ...then exclude events that are ancestors of `last_event`, because the peer
            // already has them.
            for event in graph::ancestors(&self.events, last_event) {
                inclusion_list[event.order()] = false;
            }

            self.events
                .values()
                .filter(|event| inclusion_list[event.order()])
                .collect()
        } else {
            self.events.values().collect()
        };

        events.sort_by_key(|event| event.order());
        events
    }

    /// Must only be used for events which have already been added to our graph.
    pub fn get_known_event(&self, event_hash: &Hash) -> Result<&Event<T, S::PublicId>> {
        self.events.get(event_hash).ok_or_else(|| {
            log_or_panic!(
                "{:?} doesn't have event {:?}",
                self.our_pub_id(),
                event_hash
            );
            Error::Logic
        })
    }

    /// Does the graph contain event with the given hash?
    pub fn has_event(&self, event_hash: &Hash) -> bool {
        self.events.contains_key(event_hash)
    }

    /// Gets the self-parent of the given event.
    pub fn self_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.self_parent().and_then(|hash| self.events.get(hash))
    }

    /// Gets the other-parent of the given event.
    pub fn other_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.other_parent().and_then(|hash| self.events.get(hash))
    }

    /// Adds the event into the gossip graph.
    pub fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<()> {
        self.peer_list.add_event(&event)?;
        let event_hash = *event.hash();
        let is_initial = event.is_initial();

        if let Some(observation) = event.vote().map(Vote::payload) {
            let info = self
                .observations
                .entry(observation.create_hash())
                .or_insert_with(ObservationInfo::default);

            if event.creator() == self.peer_list.our_pub_id() {
                info.created_by_us = true;
            }
        }

        let _ = self.events.insert(event_hash, event);

        if is_initial {
            return Ok(());
        }

        self.initialise_membership_list(&event_hash);
        self.process_event(&event_hash)
    }

    pub fn our_last_event_hash(&self) -> Hash {
        if let Some(hash) = self.peer_list.last_event(self.our_pub_id()) {
            *hash
        } else {
            log_or_panic!(
                "{:?} has no last event hash.\n{:?}\n",
                self.our_pub_id(),
                self.peer_list
            );
            Hash::ZERO
        }
    }

    pub fn peer_list(&self) -> &PeerList<S> {
        &self.peer_list
    }

    pub fn confirm_peer_state(&self, peer_id: &S::PublicId, required: PeerState) -> Result<()> {
        let actual = self.peer_list.peer_state(peer_id);
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} detected invalid state of {:?} (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                peer_id,
                required,
                actual,
            );
            Err(Error::InvalidPeerState { required, actual })
        }
    }

    pub fn confirm_self_state(&self, required: PeerState) -> Result<()> {
        let actual = self.peer_list.our_state();
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} has invalid state (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                required,
                actual,
            );
            Err(Error::InvalidSelfState { required, actual })
        }
    }

    pub fn change_peer_state(&mut self, peer_id: &S::PublicId, state: PeerState) {
        self.peer_list.change_peer_state(peer_id, state);
    }

    pub fn restart_consensus(&mut self) {
        self.meta_elections
            .restart_current_election(self.peer_list.all_ids());

        let mut ordered_hashes: Vec<_> = self
            .events
            .values()
            .map(|event| (*event.hash(), event.order()))
            .collect();
        ordered_hashes.sort_by_key(|&(_, order)| order);

        for (hash, _) in ordered_hashes {
            let _ = self.process_event(&hash);
        }
    }

    fn our_consensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.consensused_blocks
            .iter()
            .filter(move |block| {
                let hash = block.create_payload_hash();
                self.observations
                    .get(&hash)
                    .map(|info| info.created_by_us)
                    .unwrap_or(false)
            }).map(|block| block.payload())
    }

    fn our_unconsensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.peer_list
            .our_events()
            .filter_map(move |hash| self.get_known_event(hash).ok())
            .filter_map(|event| event.vote().map(Vote::payload))
            .filter(move |observation| {
                let hash = observation.create_hash();
                self.observations
                    .get(&hash)
                    .map(|info| !info.consensused)
                    .unwrap_or(false)
            })
    }

    fn process_event(&mut self, event_hash: &Hash) -> Result<()> {
        // let short_name = self.get_known_event(event_hash).unwrap().short_name();
        // println!("{:?} processing {:?}", self.our_pub_id(), short_name);

        // Skip processing if we've been removed.
        if self.peer_list.our_state() == PeerState::inactive() {
            return Ok(());
        }

        let elections: Vec<_> = self.meta_elections.all().collect();
        for election in elections {
            self.advance_meta_election(election, event_hash)?;
        }

        let creator = self.get_known_event(event_hash)?.creator().clone();

        if let Some(payload) = self.compute_consensus(MetaElectionHandle::CURRENT, event_hash) {
            // println!(
            //     "{:?} SELF-CONSENSUS on {:?} in {:?}",
            //     self.our_pub_id(),
            //     payload,
            //     short_name,
            // );

            self.output_consensus_info(&payload);

            self.handle_self_consensus(&payload);

            let peer_consensus = creator != *self.our_pub_id()
                && self.meta_elections.undecided_by(&creator).next().is_none();

            let prev_election = self.meta_elections.new_election(
                payload.clone(),
                self.peer_list.voter_ids().cloned().collect(),
            );

            self.meta_elections
                .mark_as_decided(prev_election, self.peer_list.our_pub_id());

            if peer_consensus {
                self.meta_elections.mark_as_decided(prev_election, &creator);
                self.handle_peer_consensus(&creator, &payload);
            }

            let block = self.create_block(payload.clone())?;
            self.consensused_blocks.push_back(block);
            self.mark_observation_as_consensused(&payload);
            self.restart_consensus();
        }

        if creator != *self.our_pub_id() {
            let elections: Vec<_> = self.meta_elections.undecided_by(&creator).collect();
            for election in elections {
                if let Some(payload) = self.compute_consensus(election, event_hash) {
                    // println!(
                    //     "{:?} PEER-CONSENSUS by {:?} on {:?} in {:?}",
                    //     self.our_pub_id(),
                    //     creator,
                    //     payload,
                    //     short_name,
                    // );

                    self.meta_elections.mark_as_decided(election, &creator);
                    self.handle_peer_consensus(&creator, &payload);
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    fn output_consensus_info(&self, payload: &Observation<T, S::PublicId>) {
        use log::LogLevel;

        dump_graph::to_file(
            self.our_pub_id(),
            &self.events,
            self.meta_elections.current_meta_events(),
            &self.peer_list,
        );

        if log_enabled!(LogLevel::Info) {
            info!(
                "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
                self.our_pub_id(),
                self.meta_elections.consensus_history().len(),
                payload,
                payload.create_hash()
            )
        }
    }

    fn mark_observation_as_consensused(&mut self, payload: &Observation<T, S::PublicId>) {
        let payload_hash = payload.create_hash();
        if let Some(info) = self.observations.get_mut(&payload_hash) {
            info.consensused = true;
        } else {
            log_or_panic!(
                "{:?} doesn't know about observation with hash {:?}",
                self.peer_list.our_pub_id(),
                payload_hash
            );
        }
    }

    /// Handles consensus reached by us.
    fn handle_self_consensus(&mut self, observation: &Observation<T, S::PublicId>) {
        match *observation {
            Observation::Add(ref peer_id) => self.handle_add_peer(peer_id),
            Observation::Remove(ref peer_id) => self.handle_remove_peer(peer_id),
            Observation::Accusation {
                ref offender,
                ref malice,
            } => {
                info!(
                    "{:?} removing {:?} due to consensus on accusation of malice {:?}",
                    self.our_pub_id(),
                    offender,
                    malice
                );

                self.handle_remove_peer(offender)
            }
            Observation::Genesis(_) | Observation::OpaquePayload(_) => (),
        }
    }

    fn handle_add_peer(&mut self, peer_id: &S::PublicId) {
        // - If we are already full member of the section, we can start sending gossips to
        //   the new peer from this moment.
        // - If we are the new peer, we must wait for the other members to send gossips to
        //   us first.
        //
        // To distinguish between the two, we check whether everyone we reached consensus on
        // adding also reached consensus on adding us.
        let recv = self
            .peer_list
            .iter()
            .filter(|&(id, peer)| {
                // Peers that can vote, which means we got consensus on adding them.
                peer.state().can_vote() &&
                        // Excluding the peer being added.
                        *id != *peer_id &&
                        // And excluding us.
                        *id != *self.our_pub_id()
            }).all(|(_, peer)| {
                // Peers that can receive, which implies they've already sent us at least
                // one message which implies they've already reached consensus on adding us.
                peer.state().can_recv()
            });

        let state = if recv {
            PeerState::VOTE | PeerState::SEND | PeerState::RECV
        } else {
            PeerState::VOTE | PeerState::SEND
        };

        if self.peer_list.has_peer(peer_id) {
            self.peer_list.change_peer_state(peer_id, state);
        } else {
            self.peer_list.add_peer(peer_id.clone(), state);
        }
    }

    fn handle_remove_peer(&mut self, peer_id: &S::PublicId) {
        self.peer_list.remove_peer(peer_id);
        self.meta_elections.handle_peer_removed(peer_id);
    }

    // Handle consensus reached by other peer.
    fn handle_peer_consensus(
        &mut self,
        peer_id: &S::PublicId,
        payload: &Observation<T, S::PublicId>,
    ) {
        trace!(
            "{:?} detected that {:?} reached consensus on {:?}",
            self.our_pub_id(),
            peer_id,
            payload
        );

        match *payload {
            Observation::Add(ref other_peer_id) => self
                .peer_list
                .add_to_peer_membership_list(peer_id, other_peer_id.clone()),
            Observation::Remove(ref other_peer_id) => self
                .peer_list
                .remove_from_peer_membership_list(peer_id, other_peer_id.clone()),
            Observation::Accusation { ref offender, .. } => self
                .peer_list
                .remove_from_peer_membership_list(peer_id, offender.clone()),
            _ => (),
        }
    }

    fn advance_meta_election(
        &mut self,
        election: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Result<()> {
        if self
            .meta_elections
            .meta_event(election, event_hash)
            .is_some()
        {
            return Ok(());
        }

        let (meta_event, creator) = {
            let event = self.get_known_event(event_hash)?;
            let mut builder = MetaEvent::build(election, event);

            self.set_interesting_content(&mut builder);
            self.set_observees(&mut builder);
            self.set_meta_votes(&mut builder)?;

            (builder.finish(), event.creator().clone())
        };

        self.meta_elections
            .add_meta_event(election, *event_hash, creator, meta_event);

        Ok(())
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn set_interesting_content(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) {
        let peers_that_can_vote = self.voters(builder.election());

        let indexed_payloads_map: BTreeMap<_, _> = self
            .peer_list
            .iter()
            .flat_map(|(_peer_id, peer)| {
                peer.events().filter_map(|hash| {
                    self.events
                        .get(hash)
                        .and_then(|event| event.vote().map(|vote| vote.payload()))
                })
            }).filter(|&this_payload| {
                self.meta_elections.is_interesting_content_candidate(
                    builder.election(),
                    builder.event().creator(),
                    this_payload,
                )
            }).filter_map(|this_payload| {
                let peers_that_did_vote = self.ancestors_carrying_payload(
                    &peers_that_can_vote,
                    builder.event(),
                    this_payload,
                );
                if (self.is_interesting_event)(
                    &peers_that_did_vote.keys().cloned().collect(),
                    &peers_that_can_vote,
                ) {
                    Some((
                        this_payload.clone(),
                        peers_that_did_vote
                            .get(builder.event().creator())
                            .cloned()
                            // Sometimes the interesting event's creator won't have voted for the
                            // payload that became interesting - in such a case we would like it
                            // sorted at the end of the "queue"
                            .unwrap_or(u64::MAX),
                    ))
                } else {
                    None
                }
            }).collect();

        let mut indexed_payloads: Vec<_> = indexed_payloads_map.into_iter().collect();
        indexed_payloads.sort_by_key(|&(_, index)| index);

        let payloads = indexed_payloads
            .into_iter()
            .map(|(payload, _index)| payload)
            .collect();

        builder.set_interesting_content(payloads);
    }

    fn ancestors_carrying_payload(
        &self,
        voters: &BTreeSet<S::PublicId>,
        event: &Event<T, S::PublicId>,
        payload: &Observation<T, S::PublicId>,
    ) -> BTreeMap<S::PublicId, u64> {
        let sees_vote_for_same_payload = |&(_, event_hash): &(u64, _)| {
            self.get_known_event(event_hash)
                .ok()
                .map_or(false, |that_event| {
                    Some(payload) == that_event.vote().map(Vote::payload) && event.sees(that_event)
                })
        };

        self.peer_list
            .iter()
            .filter(|(peer_id, _)| voters.contains(peer_id))
            .filter_map(|(peer_id, peer)| {
                peer.indexed_events()
                    .find(sees_vote_for_same_payload)
                    .map(|(index, _)| (peer_id.clone(), index))
            }).collect()
    }

    fn set_observees(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) {
        let observees = self
            .meta_elections
            .interesting_events(builder.election())
            .filter_map(|(peer, hashes)| {
                let old_hash = hashes.front()?;
                let old_event = self.get_known_event(old_hash).ok()?;
                if self.strongly_sees(builder.election(), builder.event(), old_event) {
                    Some(peer)
                } else {
                    None
                }
            }).cloned()
            .collect();

        builder.set_observees(observees);
    }

    fn set_meta_votes(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) -> Result<()> {
        let voters = self.voters(builder.election());

        let parent_meta_votes = builder
            .event()
            .self_parent()
            .and_then(|parent_hash| {
                self.meta_elections
                    .meta_votes(builder.election(), parent_hash)
            }).and_then(|parent_meta_votes| {
                if !parent_meta_votes.is_empty() {
                    Some(parent_meta_votes)
                } else {
                    None
                }
            });

        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        if let Some(parent_meta_votes) = parent_meta_votes {
            for (peer_id, parent_event_votes) in parent_meta_votes {
                let new_meta_votes = {
                    let other_votes = self.collect_other_meta_votes(
                        builder.election(),
                        &voters,
                        &peer_id,
                        builder.event(),
                    );
                    let coin_tosses = self.toss_coins(
                        builder.election(),
                        &voters,
                        &peer_id,
                        &parent_event_votes,
                        builder.event(),
                    )?;

                    MetaVote::next(
                        &parent_event_votes,
                        &other_votes,
                        &coin_tosses,
                        voters.len(),
                    )
                };

                builder.add_meta_votes(peer_id.clone(), new_meta_votes);
            }
        } else if self.is_observer(builder) {
            // Start meta votes for this event.
            for peer_id in &voters {
                let other_votes = self.collect_other_meta_votes(
                    builder.election(),
                    &voters,
                    peer_id,
                    builder.event(),
                );
                let initial_estimate = builder.has_observee(peer_id);

                builder.add_meta_votes(
                    peer_id.clone(),
                    MetaVote::new(initial_estimate, &other_votes, voters.len()),
                );
            }
        };

        trace!(
            "{:?} has set the meta votes for {:?}",
            self.our_pub_id(),
            builder.event()
        );

        Ok(())
    }

    fn is_observer(&self, builder: &MetaEventBuilder<T, S::PublicId>) -> bool {
        // An event is an observer if it has a supermajority of observees and its self-parent
        // does not.
        let voter_count = self.voter_count(builder.election());

        if !is_more_than_two_thirds(builder.observee_count(), voter_count) {
            return false;
        }

        let self_parent = if let Some(self_parent) = self.self_parent(builder.event()) {
            self_parent
        } else {
            log_or_panic!(
                "{:?} has event {:?} with observations, but not self-parent",
                self.our_pub_id(),
                builder.event()
            );
            return false;
        };

        // If self-parent is initial, we don't have to check its meta-event, as we already know it
        // can not have any observees. Also, we don't assign meta-events to initial events anyway.
        if self_parent.is_initial() {
            return true;
        }

        if let Some(meta_parent) = self
            .meta_elections
            .meta_event(builder.election(), self_parent.hash())
        {
            !is_more_than_two_thirds(meta_parent.observees.len(), voter_count)
        } else {
            log_or_panic!(
                "{:?} doesn't have meta-event for event {:?} (self-parent of {:?}) in meta-election {:?}",
                self.our_pub_id(),
                self_parent,
                builder.event().hash(),
                builder.election(),
            );

            false
        }
    }

    fn toss_coins(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        parent_votes: &[MetaVote],
        event: &Event<T, S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(election, voters, peer_id, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        event: &Event<T, S::PublicId>,
    ) -> Result<Option<bool>> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                // This should never happen as estimates get cleared only in increase step when the
                // step is Step::GenuineFlip and the round gets incremented.
                log_or_panic!(
                    "{:?} missing parent vote estimates at round 0.",
                    self.our_pub_id()
                );
                return Err(Error::Logic);
            }
            parent_vote.round - 1
        } else if parent_vote.step == Step::GenuineFlip {
            parent_vote.round
        } else {
            return Ok(None);
        };
        let round_hash = if let Some(hashes) = self.meta_elections.round_hashes(election, peer_id) {
            hashes[round].value()
        } else {
            log_or_panic!("{:?} missing round hash.", self.our_pub_id());
            return Err(Error::Logic);
        };

        // Get the gradient of leadership.
        let mut peer_id_hashes: Vec<_> = self
            .peer_list
            .peer_id_hashes()
            .filter(|(peer_id, _)| voters.contains(peer_id))
            .collect();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.1, &rhs.1));

        // Try to get the "most-leader"'s aux value.
        let creator = &peer_id_hashes[0].0;
        if let Some(creator_event_index) = event.last_ancestors().get(creator) {
            if let Some(aux_value) =
                self.aux_value(election, creator, *creator_event_index, peer_id, round)
            {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(election, round, event) {
            for (creator, _) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors().get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(election, creator, *creator_event_index, peer_id, round)
                    {
                        return Ok(Some(aux_value));
                    }
                }
            }
        }

        Ok(None)
    }

    // Returns the aux value for the given peer, created by `creator`, at the given round and at
    // the genuine flip step.
    fn aux_value(
        &self,
        election: MetaElectionHandle,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_since_round_and_step(
            election,
            creator,
            creator_event_index,
            peer_id,
            round,
            &Step::GenuineFlip,
        ).first()
        .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through events created by the peer until passed `responsiveness_threshold`
    // response events and sees if the peer had its `aux_value` set at this round.  If so, returns
    // `true`.
    fn stop_waiting(
        &self,
        election: MetaElectionHandle,
        round: usize,
        event: &Event<T, S::PublicId>,
    ) -> bool {
        let mut event_hash = Some(event.hash());
        let mut response_count = 0;
        let responsiveness_threshold = self.responsiveness_threshold(election);

        loop {
            if let Some(event) = event_hash.and_then(|hash| self.get_known_event(hash).ok()) {
                if event.is_response() {
                    response_count += 1;
                    if response_count == responsiveness_threshold {
                        break;
                    }
                }
                event_hash = event.self_parent();
            } else {
                return false;
            }
        }
        let hash = match event_hash {
            Some(hash) => hash,
            None => {
                log_or_panic!("{:?} event_hash was None.", self.our_pub_id());
                return false;
            }
        };
        self.meta_elections
            .meta_votes(election, &hash)
            .and_then(|meta_votes| meta_votes.get(event.creator()))
            .map_or(false, |event_votes| {
                event_votes
                    .iter()
                    .any(|meta_vote| meta_vote.round == round && meta_vote.aux_value.is_some())
            })
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.  Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        election: MetaElectionHandle,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
        step: &Step,
    ) -> Vec<MetaVote> {
        let hash = if let Some(hash) = self
            .peer_list
            .unique_event_by_index(creator, creator_event_index)
        {
            hash
        } else {
            return vec![];
        };

        self.meta_elections
            .meta_votes(election, hash)
            .and_then(|meta_votes| meta_votes.get(peer_id))
            .map(|meta_votes| {
                meta_votes
                    .iter()
                    .filter(|meta_vote| {
                        meta_vote.round > round
                            || meta_vote.round == round && meta_vote.step >= *step
                    }).cloned()
                    .collect()
            }).unwrap_or_else(|| vec![])
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by `peer_id`.
    fn collect_other_meta_votes(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        event: &Event<T, S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        voters
            .iter()
            .filter(|voter_id| *voter_id != event.creator())
            .filter_map(|creator| {
                event
                    .last_ancestors()
                    .get(creator)
                    .map(|creator_event_index| {
                        self.meta_votes_since_round_and_step(
                            election,
                            creator,
                            *creator_event_index,
                            &peer_id,
                            0,
                            &Step::ForcedTrue,
                        )
                    })
            }).collect()
    }

    // Initialise the membership list of the creator of the given event to the same membership list
    // the creator of the other-parent had at the time of the other-parent's creation. Do nothing if
    // the event is not request or response or if the membership list is already initialised.
    fn initialise_membership_list(&mut self, event_hash: &Hash) {
        let (creator, changes) = {
            let event = if let Ok(event) = self.get_known_event(event_hash) {
                event
            } else {
                return;
            };

            if event.creator() == self.our_pub_id() {
                return;
            }

            if self
                .peer_list
                .is_peer_membership_list_initialised(event.creator())
            {
                return;
            }

            let other_parent_creator = if let Some(other_parent) = self.other_parent(event) {
                other_parent.creator()
            } else {
                return;
            };

            // Collect all changes to `other_parent_creator`'s membership list seen by `event`.
            let changes: Vec<_> = self
                .peer_list
                .peer_membership_list_changes(other_parent_creator)
                .iter()
                .take_while(|(index, _)| {
                    self.peer_list
                        .events_by_index(other_parent_creator, *index)
                        .filter_map(|hash| self.get_known_event(hash).ok())
                        .any(|other_event| event.sees(other_event))
                }).map(|(_, change)| change.clone())
                .collect();
            (event.creator().clone(), changes)
        };

        for change in changes {
            self.peer_list.change_peer_membership_list(&creator, change);
        }
    }

    // List of voters for the given meta-election.
    fn voters(&self, election: MetaElectionHandle) -> BTreeSet<S::PublicId> {
        self.meta_elections
            .voters(election)
            .cloned()
            .unwrap_or_else(|| self.peer_list.voter_ids().cloned().collect())
    }

    // Number of voters for the given meta-election.
    fn voter_count(&self, election: MetaElectionHandle) -> usize {
        self.meta_elections
            .voters(election)
            .map(|voters| voters.len())
            .unwrap_or_else(|| self.peer_list.voters().count())
    }

    fn compute_consensus(
        &self,
        election: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Option<Observation<T, S::PublicId>> {
        let last_meta_votes = self.meta_elections.meta_votes(election, event_hash)?;
        let decided_meta_votes = last_meta_votes.iter().filter_map(|(id, event_votes)| {
            event_votes.last().and_then(|v| v.decision).map(|v| (id, v))
        });

        if decided_meta_votes.clone().count() < self.voter_count(election) {
            return None;
        }

        self.meta_elections
            .decided_payload(election)
            .cloned()
            .or_else(|| self.compute_payload_for_consensus(election, decided_meta_votes))
    }

    fn compute_payload_for_consensus<'a, I>(
        &self,
        election: MetaElectionHandle,
        decided_meta_votes: I,
    ) -> Option<Observation<T, S::PublicId>>
    where
        I: IntoIterator<Item = (&'a S::PublicId, bool)>,
        S::PublicId: 'a,
    {
        let payloads: Vec<_> = decided_meta_votes
            .into_iter()
            .filter_map(|(id, decision)| {
                if decision {
                    self.meta_elections
                        .first_interesting_content_by(election, &id)
                        .cloned()
                } else {
                    None
                }
            }).collect();

        payloads
            .iter()
            .max_by(|lhs_payload, rhs_payload| {
                let lhs_count = payloads
                    .iter()
                    .filter(|payload_carried| lhs_payload == payload_carried)
                    .count();
                let rhs_count = payloads
                    .iter()
                    .filter(|payload_carried| rhs_payload == payload_carried)
                    .count();
                lhs_count.cmp(&rhs_count)
            }).cloned()
    }

    fn create_block(&self, payload: Observation<T, S::PublicId>) -> Result<Block<T, S::PublicId>> {
        let votes = self
            .events
            .values()
            .filter_map(|event| {
                event.vote().and_then(|vote| {
                    if *vote.payload() == payload {
                        Some((event.creator().clone(), vote.clone()))
                    } else {
                        None
                    }
                })
            }).collect();

        Block::new(payload, &votes)
    }

    // Returns the number of peers that created events which are seen by event X (descendant) and
    // see event Y (ancestor). This means number of peers through which there is a directed path
    // between x and y, excluding peers contains fork.
    fn num_peers_created_events_seen_by_x_that_can_see_y(
        &self,
        x: &Event<T, S::PublicId>,
        y: &Event<T, S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .iter()
            .filter(|(peer_id, &event_index)| {
                for event_hash in self.peer_list.events_by_index(peer_id, event_index) {
                    if let Ok(event) = self.get_known_event(event_hash) {
                        if x.sees(event) && event.sees(y) {
                            return true;
                        }
                    }
                }
                false
            }).count()
    }

    // Returns whether event X can strongly see the event Y during the evaluation of the given election.
    fn strongly_sees(
        &self,
        election: MetaElectionHandle,
        x: &Event<T, S::PublicId>,
        y: &Event<T, S::PublicId>,
    ) -> bool {
        is_more_than_two_thirds(
            self.num_peers_created_events_seen_by_x_that_can_see_y(x, y),
            self.voter_count(election),
        )
    }

    // Get the responsiveness threshold based on the current number of peers.
    fn responsiveness_threshold(&self, election: MetaElectionHandle) -> usize {
        (self.voter_count(election) as f64).log2().ceil() as usize
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Core<T, S> {
    fn drop(&mut self) {
        if ::std::thread::panicking() {
            dump_graph::to_file(
                self.our_pub_id(),
                &self.events,
                self.meta_elections.current_meta_events(),
                &self.peer_list,
            );
        }
    }
}

#[cfg(test)]
impl Core<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(parsed_contents: ParsedContents) -> Self {
        let mut core = Self::empty(parsed_contents.our_id, &BTreeSet::new(), is_supermajority);

        // Populate `observations` cache using `interesting_content`, to support partial graphs...
        for meta_event in parsed_contents.meta_events.values() {
            for payload in &meta_event.interesting_content {
                let hash = payload.create_hash();
                let _ = core.observations.insert(hash, ObservationInfo::default());
            }
        }

        // ..and also the payloads carried by events.
        let our_pub_id = core.our_pub_id().clone();
        for event in parsed_contents.events.values() {
            if let Some(payload) = event.vote().map(Vote::payload) {
                let observation = core
                    .observations
                    .entry(payload.create_hash())
                    .or_insert_with(ObservationInfo::default);

                if *event.creator() == our_pub_id {
                    observation.created_by_us = true;
                }
            }
        }

        let creators: BTreeMap<_, _> = parsed_contents
            .events
            .values()
            .map(|event| (*event.hash(), event.creator().clone()))
            .collect();

        core.events = parsed_contents.events;
        core.meta_elections = MetaElections::new_from_parsed(
            parsed_contents.peer_list.voter_ids(),
            parsed_contents.meta_events,
            creators,
        );
        core.peer_list = parsed_contents.peer_list;
        core
    }
}

#[derive(Default)]
pub(crate) struct ObservationInfo {
    pub consensused: bool,
    pub created_by_us: bool,
}

// Initialise membership lists of all peers.
// TODO: remove this when membership lists are handled by the dot parser itself.
#[cfg(test)]
pub(crate) fn initialise_membership_lists<T: NetworkEvent, S: SecretId>(core: &mut Core<T, S>) {
    let peer_ids: Vec<_> = core.peer_list.all_ids().cloned().collect();
    for peer_id in &peer_ids {
        core.peer_list
            .initialise_peer_membership_list(peer_id, peer_ids.clone());
    }
}

#[cfg(test)]
pub(crate) fn nth_event<T: NetworkEvent, P: PublicId>(
    events: &BTreeMap<Hash, Event<T, P>>,
    n: usize,
) -> &Event<T, P> {
    unwrap!(events.values().find(|event| event.order() == n))
}

#[cfg(test)]
pub(crate) fn add_peer<T: NetworkEvent, S: SecretId>(
    core: &mut Core<T, S>,
    peer_id: S::PublicId,
    state: PeerState,
) {
    core.peer_list.add_peer(peer_id, state)
}

#[cfg(test)]
pub(crate) mod functional_tests {
    use super::*;
    use dev_utils::parse_test_dot_file;
    use mock::{self, Transaction};

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct Snapshot {
        peer_list: BTreeMap<PeerId, (PeerState, BTreeMap<u64, Hash>)>,
        events: BTreeSet<Hash>,
        consensused_blocks: VecDeque<Block<Transaction, PeerId>>,
        meta_events: BTreeMap<Hash, MetaEvent<Transaction, PeerId>>,
    }

    impl Snapshot {
        pub fn new(core: &Core<Transaction, PeerId>) -> Self {
            let peer_list = core
                .peer_list
                .iter()
                .map(|(peer_id, peer)| {
                    (
                        peer_id.clone(),
                        (
                            peer.state(),
                            peer.indexed_events()
                                .map(|(index, hash)| (index, *hash))
                                .collect(),
                        ),
                    )
                }).collect();
            let events = core.events.keys().cloned().collect();

            Snapshot {
                peer_list,
                events,
                consensused_blocks: core.consensused_blocks.clone(),
                meta_events: core.meta_elections.current_meta_events().clone(),
            }
        }
    }

    #[test]
    fn from_existing() {
        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let core =
            Core::<Transaction, _>::from_existing(our_id.clone(), &peers, &peers, is_supermajority);

        // Existing section + us
        assert_eq!(core.peer_list.all_ids().count(), peers.len() + 1);

        // Only the initial event should be in the gossip graph.
        assert_eq!(core.events.len(), 1);
        let event = unwrap!(core.events.values().next());
        assert_eq!(*event.creator(), our_id);
        assert!(event.is_initial());
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group can't be empty")]
    fn from_existing_requires_non_empty_genesis_group() {
        use mock;

        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let _ = Core::<Transaction, _>::from_existing(
            our_id,
            &BTreeSet::new(),
            &peers,
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group can't already contain us")]
    fn from_existing_requires_that_genesis_group_does_not_contain_us() {
        use mock;

        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let genesis_group = peers.iter().cloned().collect();
        let section = peers.into_iter().skip(1).collect();

        let _ = Core::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &section,
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Section can't be empty")]
    fn from_existing_requires_non_empty_section() {
        use mock;

        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let genesis_group = peers.into_iter().collect();

        let _ = Core::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &BTreeSet::new(),
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Section can't already contain us")]
    fn from_existing_requires_that_section_does_not_contain_us() {
        use mock;

        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let genesis_group = peers.iter().skip(1).cloned().collect();
        let section = peers.into_iter().collect();

        let _ = Core::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &section,
            is_supermajority,
        );
    }

    #[test]
    fn from_genesis() {
        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let peers = peers.into_iter().collect();

        let core = Core::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
        // the peer_list should contain the entire genesis group
        assert_eq!(core.peer_list.all_ids().count(), peers.len());
        // initial event + genesis_observation
        assert_eq!(core.events.len(), 2);
        let initial_event = nth_event(&core.events, 0);
        assert_eq!(*initial_event.creator(), our_id);
        assert!(initial_event.is_initial());
        let genesis_observation = nth_event(&core.events, 1);
        assert_eq!(*genesis_observation.creator(), our_id);
        match &genesis_observation.vote() {
            Some(vote) => {
                assert_eq!(*vote.payload(), Observation::Genesis(peers));
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

        let _ = Core::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
    }

    #[test]
    fn from_parsed_contents() {
        let input_file = "0.dot";
        let parsed_contents = parse_test_dot_file(input_file);
        let parsed_contents_comparison = parse_test_dot_file(input_file);
        let core = Core::from_parsed_contents(parsed_contents);
        assert_eq!(parsed_contents_comparison.events, core.events);
        assert_eq!(
            &parsed_contents_comparison.meta_events,
            core.meta_elections.current_meta_events()
        );

        let parsed_contents_other = parse_test_dot_file("1.dot");
        assert_ne!(parsed_contents_other.events, core.events);
        assert_ne!(
            &parsed_contents_other.meta_events,
            core.meta_elections.current_meta_events()
        );
    }
}

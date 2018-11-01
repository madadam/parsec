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
use gossip::{graph, Event, PackedEvent, Request, Response};
use hash::Hash;
use id::SecretId;
use meta_voting::{MetaElectionHandle, MetaElections, MetaEvent, MetaEventBuilder, MetaVote, Step};
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use observation::{Malice, Observation};
use peer_list::{PeerList, PeerState};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{iter, mem, u64};
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

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
///
/// Most public functions return an error if called after the owning node has been removed, i.e.
/// a block with payload `Observation::Remove(our_id)` has been made stable.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
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
    // Accusations to raise at the end of the processing of current gossip message.
    pending_accusations: Vec<(S::PublicId, Malice)>,
    is_interesting_event: IsInterestingEventFn<S::PublicId>,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut parsec = Self::empty(our_id, genesis_group, is_interesting_event);

        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::active());
            parsec
                .peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned())
        }

        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids(), Hash::ZERO);

        // Add initial event.
        let event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let self_parent_hash = parsec.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            genesis_observation,
            &parsec.events,
            &parsec.peer_list,
        );

        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding the genesis observation: {:?}",
                parsec.our_pub_id(),
                error,
            );
        }

        parsec
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
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
        let mut parsec = Self::empty(our_id, genesis_group, is_interesting_event);

        // Add ourselves.
        parsec
            .peer_list
            .add_peer(our_public_id.clone(), PeerState::RECV);

        // Add the genesis group.
        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND)
        }

        // Add the current section members.
        for peer_id in section {
            if genesis_group.contains(peer_id) {
                continue;
            }

            parsec.peer_list.add_peer(peer_id.clone(), PeerState::SEND)
        }

        // Initialise everyone's membership list.
        for peer_id in iter::once(&our_public_id)
            .chain(genesis_group)
            .chain(section)
        {
            parsec
                .peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned())
        }

        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids(), Hash::ZERO);

        let initial_event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        parsec
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
            pending_accusations: vec![],
        }
    }

    /// Adds a vote for `observation`.  Returns an error if we have already voted for this.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<()> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        let self_parent_hash = self.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            observation,
            &self.events,
            &self.peer_list,
        );
        self.add_event(event)
    }

    /// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
    /// that peer needs.  If `peer_id` is `None`, a message containing all known gossip events is
    /// returned.  If `peer_id` is `Some` and the given peer is not an active node, an error is
    /// returned.
    pub fn create_gossip(&self, peer_id: Option<&S::PublicId>) -> Result<Request<T, S::PublicId>> {
        self.confirm_self_state(PeerState::SEND)?;

        if let Some(recipient_id) = peer_id {
            // We require `PeerState::VOTE` in addition to `PeerState::RECV` here, because if the
            // peer does not have `PeerState::VOTE`, it means we haven't yet reached consensus on
            // adding them to the section so we shouldn't contact them yet.
            self.confirm_peer_state(recipient_id, PeerState::VOTE | PeerState::RECV)?;

            if self.peer_list.last_event(recipient_id).is_some() {
                debug!(
                    "{:?} creating gossip request for {:?}",
                    self.our_pub_id(),
                    recipient_id
                );

                return self
                    .events_to_gossip_to_peer(recipient_id)
                    .map(Request::new);
            }
        }

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        let mut events: Vec<_> = self.events.values().collect();
        events.sort_by_key(|event| event.order());
        Ok(Request::new(events))
    }

    /// Handles a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid or if `src` has been removed already.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>> {
        debug!(
            "{:?} received gossip request from {:?}",
            self.our_pub_id(),
            src
        );
        let forking_peers = self.unpack_and_add_events(src, req.packed_events)?;
        self.create_sync_event(src, true, &forking_peers)?;
        self.create_accusation_events()?;
        self.events_to_gossip_to_peer(src).map(Response::new)
    }

    /// Handles a received `Response` from `src` peer.  Returns `Err` if the response was not valid
    /// or if `src` has been removed already.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<()> {
        debug!(
            "{:?} received gossip response from {:?}",
            self.our_pub_id(),
            src
        );
        let forking_peers = self.unpack_and_add_events(src, resp.packed_events)?;
        self.create_sync_event(src, false, &forking_peers)?;
        self.create_accusation_events()
    }

    /// Steps the algorithm and returns the next stable block, if any.
    ///
    /// Once we have been removed (i.e. a block with payload `Observation::Remove(our_id)` has been
    /// made stable), then no further blocks will be enqueued.  So, once `poll()` returns such a
    /// block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Check if we can vote (that is, we have reached a consensus on us being full member of the
    /// section).
    pub fn can_vote(&self) -> bool {
        self.peer_list.peer_state(self.our_pub_id()).can_vote()
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

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_hash: &Hash) -> Result<&Event<T, S::PublicId>> {
        self.events.get(event_hash).ok_or_else(|| {
            log_or_panic!(
                "{:?} doesn't have event {:?}",
                self.our_pub_id(),
                event_hash
            );
            Error::Logic
        })
    }

    fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_pub_id()
    }

    fn confirm_peer_state(&self, peer_id: &S::PublicId, required: PeerState) -> Result<()> {
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

    fn confirm_self_state(&self, required: PeerState) -> Result<()> {
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

    fn our_last_event_hash(&self) -> Hash {
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

    fn self_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.self_parent().and_then(|hash| self.events.get(hash))
    }

    fn other_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.other_parent().and_then(|hash| self.events.get(hash))
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

        // If self-parent is initial, we don't have to check it's meta-event, as we already know it
        // can not have any observations. Also, we don't assign meta-events to initial events anyway.
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

    fn unpack_and_add_events(
        &mut self,
        src: &S::PublicId,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<BTreeSet<S::PublicId>> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src, PeerState::SEND)?;

        // We have received at least one gossip from the sender, so they can now receive gossips
        // from us as well.
        self.peer_list.change_peer_state(src, PeerState::RECV);

        let mut prev_forking_peers = BTreeSet::new();
        for packed_event in packed_events {
            if let Some(event) = Event::unpack(
                packed_event,
                &self.events,
                &self.peer_list,
                &prev_forking_peers,
            )? {
                if self
                    .peer_list
                    .events_by_index(event.creator(), event.index())
                    .next()
                    .is_some()
                {
                    let _ = prev_forking_peers.insert(event.creator().clone());
                }
                self.add_event(event)?;
            }
        }
        Ok(prev_forking_peers)
    }

    fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<()> {
        let our = event.creator() == self.our_pub_id();
        if !our {
            self.detect_malice_before_process(&event)?;
        }

        self.peer_list.add_event(&event)?;
        let event_hash = *event.hash();
        let is_initial = event.is_initial();

        if let Some(observation) = event.vote().map(Vote::payload) {
            let info = self
                .observations
                .entry(observation.create_hash())
                .or_insert_with(ObservationInfo::default);

            if our {
                info.created_by_us = true;
            }
        }

        let _ = self.events.insert(event_hash, event);

        if is_initial {
            return Ok(());
        }

        self.initialise_membership_list(&event_hash);
        self.process_event(&event_hash)?;

        if !our {
            self.detect_malice_after_process(&event_hash);
        }

        Ok(())
    }

    fn process_event(&mut self, event_hash: &Hash) -> Result<()> {
        let elections: Vec<_> = self.meta_elections.all().collect();
        for election in elections {
            self.advance_meta_election(election, event_hash)?;
        }

        let creator = self.get_known_event(event_hash)?.creator().clone();

        if let Some(payload) = self.compute_consensus(MetaElectionHandle::CURRENT, event_hash) {
            self.output_consensus_info(&payload);

            let restart = self.handle_self_consensus(&payload) == PostConsensusAction::Continue;
            if creator != *self.our_pub_id() {
                self.handle_peer_consensus(&creator, &payload);
            }

            let prev_election = self.meta_elections.new_election(
                payload.clone(),
                self.peer_list.voter_ids().cloned().collect(),
            );

            self.meta_elections
                .mark_as_decided(prev_election, self.peer_list.our_pub_id());
            self.meta_elections.mark_as_decided(prev_election, &creator);

            let block = self.create_block(payload.clone())?;
            self.consensused_blocks.push_back(block);
            self.mark_observation_as_consensused(&payload);

            if restart {
                self.restart_consensus();
            }
        } else if creator != *self.our_pub_id() {
            let undecided: Vec<_> = self.meta_elections.undecided_by(&creator).collect();
            for election in undecided {
                if let Some(payload) = self.compute_consensus(election, event_hash) {
                    self.meta_elections.mark_as_decided(election, &creator);
                    self.handle_peer_consensus(&creator, &payload);
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
                self.meta_elections.consensus_history().len() - 1,
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
    fn handle_self_consensus(
        &mut self,
        observation: &Observation<T, S::PublicId>,
    ) -> PostConsensusAction {
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
            Observation::Genesis(_) | Observation::OpaquePayload(_) => {
                PostConsensusAction::Continue
            }
        }
    }

    fn handle_add_peer(&mut self, peer_id: &S::PublicId) -> PostConsensusAction {
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

        PostConsensusAction::Continue
    }

    fn handle_remove_peer(&mut self, peer_id: &S::PublicId) -> PostConsensusAction {
        self.peer_list.remove_peer(peer_id);
        self.meta_elections.handle_peer_removed(peer_id);

        if *peer_id == *self.our_pub_id() {
            PostConsensusAction::Stop
        } else {
            PostConsensusAction::Continue
        }
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
        let mut events = self.peer_list.events_by_index(creator, creator_event_index);

        // Check whether it has at least one item
        let event = if let Some(event) = events.next() {
            event
        } else {
            return vec![];
        };

        if events.next().is_some() {
            // Fork
            return vec![];
        }

        self.meta_elections
            .meta_votes(election, event)
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

    fn restart_consensus(&mut self) {
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

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Result<()> {
        let self_parent = *self
            .peer_list
            .last_event(self.our_pub_id())
            .ok_or_else(|| {
                log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
                Error::Logic
            })?;
        let other_parent = *self.peer_list.last_event(src).ok_or_else(|| {
            log_or_panic!("{:?} missing {:?} last event hash.", self.our_pub_id(), src);
            Error::Logic
        })?;
        let sync_event = if is_request {
            Event::new_from_request(
                self_parent,
                other_parent,
                &self.events,
                &self.peer_list,
                forking_peers,
            )
        } else {
            Event::new_from_response(
                self_parent,
                other_parent,
                &self.events,
                &self.peer_list,
                forking_peers,
            )
        };
        self.add_event(sync_event)
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(
        &self,
        peer_id: &S::PublicId,
    ) -> Result<Vec<&Event<T, S::PublicId>>> {
        let last_event = if let Some(event_hash) = self.peer_list.last_event(peer_id) {
            self.get_known_event(event_hash)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_id);
            return Err(Error::Logic);
        };

        // Events to include in the result. Initially start with including everything...
        let mut inclusion_list = vec![true; self.events.len()];

        // ...then exclude events that are ancestors of `last_event`, because that are the events
        // that the peer already has,
        for event in graph::ancestors(&self.events, last_event) {
            inclusion_list[event.order()] = false;
        }

        let mut events: Vec<_> = self
            .events
            .values()
            .filter(|event| inclusion_list[event.order()])
            .collect();
        events.sort_by_key(|event| event.order());
        Ok(events)
    }

    // Get the responsiveness threshold based on the current number of peers.
    fn responsiveness_threshold(&self, election: MetaElectionHandle) -> usize {
        (self.voter_count(election) as f64).log2().ceil() as usize
    }

    fn detect_malice_before_process(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        // NOTE: `detect_incorrect_genesis` must come first.
        self.detect_incorrect_genesis(event)?;

        self.detect_unexpected_genesis(event);
        self.detect_missing_genesis(event);
        self.detect_duplicate_vote(event);
        self.detect_stale_other_parent(event);
        self.detect_fork(event);
        self.detect_invalid_accusation(event);

        // TODO: detect other forms of malice here

        Ok(())
    }

    fn detect_malice_after_process(&mut self, event_hash: &Hash) {
        self.detect_invalid_gossip_creator(event_hash);
    }

    // Detect if the event carries an `Observation::Genesis` that doesn't match what we'd expect.
    fn detect_incorrect_genesis(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        if let Some(Observation::Genesis(ref group)) = event.vote().map(Vote::payload) {
            if group.iter().collect::<BTreeSet<_>>() != self.genesis_group() {
                // Raise the accusation immediately and return an error, to prevent accepting
                // potentially large number of invalid / spam events into our graph.
                self.create_accusation_event(
                    event.creator().clone(),
                    Malice::IncorrectGenesis(*event.hash()),
                )?;
                return Err(Error::InvalidEvent);
            }
        }

        Ok(())
    }

    // Detect whether the event carries unexpected `Observation::Genesis`.
    fn detect_unexpected_genesis(&mut self, event: &Event<T, S::PublicId>) {
        let payload = if let Some(payload) = event.vote().map(Vote::payload) {
            payload
        } else {
            return;
        };

        let genesis_group = if let Observation::Genesis(ref group) = *payload {
            group
        } else {
            return;
        };

        // - the creator is not member of the genesis group, or
        // - the self-parent of the event is not initial event
        if !genesis_group.contains(event.creator()) || self
            .self_parent(event)
            .map_or(true, |self_parent| !self_parent.is_initial())
        {
            self.accuse(
                event.creator().clone(),
                Malice::UnexpectedGenesis(*event.hash()),
            );
        }
    }

    // Detect when the first event by a peer belonging to genesis doesn't carry genesis
    fn detect_missing_genesis(&mut self, event: &Event<T, S::PublicId>) {
        if event.index() != 1 {
            return;
        }

        if let Some(&Observation::Genesis(_)) = event.vote().map(Vote::payload) {
            return;
        }

        if self.genesis_group().contains(event.creator()) {
            self.accuse(
                event.creator().clone(),
                Malice::MissingGenesis(*event.hash()),
            );
        }
    }

    // Detect that if the event carries a vote, there is already one or more votes with the same
    // observation by the same creator.
    fn detect_duplicate_vote(&mut self, event: &Event<T, S::PublicId>) {
        let payload = if let Some(payload) = event.vote().map(Vote::payload) {
            payload
        } else {
            return;
        };

        let other_hash = {
            let mut duplicates = self
                .peer_list
                .peer_events(event.creator())
                .rev()
                .filter(|hash| {
                    self.get_known_event(hash)
                        .ok()
                        .and_then(|event| event.vote())
                        .map_or(false, |vote| vote.payload() == payload)
                }).take(2);

            let hash = if let Some(hash) = duplicates.next() {
                // One duplicate found - raise the accusation.
                hash
            } else {
                // No duplicates found - do not raise the accusation.
                return;
            };

            if duplicates.next().is_some() {
                // More than one duplicate found - the accusation should have already been raised,
                // so don't raise it again.
                return;
            }

            *hash
        };

        self.accuse(
            event.creator().clone(),
            Malice::DuplicateVote(other_hash, *event.hash()),
        );
    }

    // Detect if the event's other_parent older than first ancestor of self_parent.
    fn detect_stale_other_parent(&mut self, event: &Event<T, S::PublicId>) {
        let (other_parent_index, other_parent_creator) =
            if let Some(other_parent) = self.other_parent(event) {
                (other_parent.index(), other_parent.creator().clone())
            } else {
                return;
            };
        let self_parent_ancestor_index = if let Some(index) = self
            .self_parent(event)
            .and_then(|self_parent| self_parent.last_ancestors().get(&other_parent_creator))
        {
            *index
        } else {
            return;
        };
        if other_parent_index < self_parent_ancestor_index {
            self.accuse(
                event.creator().clone(),
                Malice::StaleOtherParent(*event.hash()),
            );
        }
    }

    // Detect whether the event incurs a fork.
    fn detect_fork(&mut self, event: &Event<T, S::PublicId>) {
        if self.peer_list.last_event(event.creator()) != event.self_parent() {
            if let Some(self_parent_hash) = event.self_parent() {
                self.accuse(event.creator().clone(), Malice::Fork(*self_parent_hash));
            }
        }
    }

    fn detect_invalid_accusation(&mut self, event: &Event<T, S::PublicId>) {
        let their_accusation = if let Some(&Observation::Accusation {
            ref offender,
            ref malice,
        }) = event.vote().map(Vote::payload)
        {
            (offender, malice)
        } else {
            return;
        };

        // First try to find the same accusation in our pending accusations...
        let found = self
            .pending_accusations
            .iter()
            .any(|&(ref our_offender, ref our_malice)| {
                their_accusation == (our_offender, our_malice)
            });
        if found {
            return;
        }

        // ...then in our events...
        let found = self
            .peer_list
            .our_events()
            .rev()
            .filter_map(|hash| self.get_known_event(hash).ok())
            .filter_map(|event| {
                if let Some(&Observation::Accusation {
                    ref offender,
                    ref malice,
                }) = event.vote().map(Vote::payload)
                {
                    Some((offender, malice))
                } else {
                    None
                }
            }).any(|our_accusation| their_accusation == our_accusation);
        if found {
            return;
        }

        // ..if not found, their accusation is invalid.
        self.accuse(
            event.creator().clone(),
            Malice::InvalidAccusation(*event.hash()),
        )
    }

    fn detect_invalid_gossip_creator(&mut self, event_hash: &Hash) {
        let offender = {
            let event = if let Ok(event) = self.get_known_event(event_hash) {
                event
            } else {
                return;
            };

            let parent = if let Some(parent) = self.self_parent(event) {
                parent
            } else {
                // Must be the initial event, so there is nothing to detect.
                return;
            };

            let membership_list = if let Some(list) = self
                .peer_list
                .peer_membership_list_snapshot_excluding_last_remove(event.creator(), event.index())
            {
                list
            } else {
                // The membership list is not yet initialised - skip the detection.
                return;
            };

            // Find an event X created by someone that the creator of `event` should not know about,
            // where X is seen by `event` but not seen by `event`'s parent. If there is such an
            // event, we raise the accusation.
            //
            // The reason why we filter out events seen by the parent is to prevent spamming
            // accusations of the same malice.
            let detected = self
                .peer_list
                .all_ids()
                .filter(|peer_id| !membership_list.contains(peer_id))
                .filter_map(|peer_id| {
                    event
                        .last_ancestors()
                        .get(peer_id)
                        .map(|index| (peer_id, *index))
                }).flat_map(|(peer_id, index)| self.peer_list.events_by_index(peer_id, index))
                .filter_map(|hash| self.get_known_event(hash).ok())
                .any(|invalid_event| !parent.is_descendant_of(invalid_event));
            if detected {
                Some(event.creator().clone())
            } else {
                None
            }
        };

        if let Some(offender) = offender {
            self.accuse(offender, Malice::InvalidGossipCreator(*event_hash))
        }
    }

    fn genesis_group(&self) -> BTreeSet<&S::PublicId> {
        self.events
            .values()
            .filter_map(|event| {
                if let Some(&Observation::Genesis(ref gen)) = event.vote().map(Vote::payload) {
                    Some(gen.iter().collect())
                } else {
                    None
                }
            }).next()
            .unwrap_or_else(|| self.peer_list.voter_ids().collect())
    }

    fn accuse(&mut self, offender: S::PublicId, malice: Malice) {
        self.pending_accusations.push((offender, malice));
    }

    fn create_accusation_event(&mut self, offender: S::PublicId, malice: Malice) -> Result<()> {
        let event = Event::new_from_observation(
            self.our_last_event_hash(),
            Observation::Accusation { offender, malice },
            &self.events,
            &self.peer_list,
        );
        self.add_event(event)
    }

    fn create_accusation_events(&mut self) -> Result<()> {
        let pending_accusations = mem::replace(&mut self.pending_accusations, vec![]);
        for (offender, malice) in pending_accusations {
            self.create_accusation_event(offender, malice)?;
        }

        Ok(())
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
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
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(parsed_contents: ParsedContents) -> Self {
        let mut parsec = Parsec::empty(parsed_contents.our_id, &BTreeSet::new(), is_supermajority);

        // Populate `observations` cache using `interesting_content`, to support partial graphs...
        for meta_event in parsed_contents.meta_events.values() {
            for payload in &meta_event.interesting_content {
                let hash = payload.create_hash();
                let _ = parsec.observations.insert(hash, ObservationInfo::default());
            }
        }

        // ..and also the payloads carried by events.
        let our_pub_id = parsec.our_pub_id().clone();
        for event in parsed_contents.events.values() {
            if let Some(payload) = event.vote().map(Vote::payload) {
                let observation = parsec
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

        parsec.events = parsed_contents.events;
        parsec.meta_elections = MetaElections::new_from_parsed(
            parsed_contents.peer_list.voter_ids(),
            parsed_contents.meta_events,
            creators,
        );
        parsec.peer_list = parsed_contents.peer_list;
        parsec
    }
}

#[derive(Default)]
struct ObservationInfo {
    consensused: bool,
    created_by_us: bool,
}

#[derive(PartialEq, Eq)]
enum PostConsensusAction {
    Continue,
    Stop,
}

#[cfg(test)]
mod functional_tests {
    use super::*;
    use dev_utils::{parse_dot_file_with_test_name, parse_test_dot_file};
    use gossip::{find_event_by_short_name, Event};
    use id::PublicId;
    use mock::{self, Transaction};
    use peer_list::PeerState;
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Snapshot {
        peer_list: BTreeMap<PeerId, (PeerState, BTreeMap<u64, Hash>)>,
        events: BTreeSet<Hash>,
        consensused_blocks: VecDeque<Block<Transaction, PeerId>>,
        meta_events: BTreeMap<Hash, MetaEvent<Transaction, PeerId>>,
    }

    impl Snapshot {
        fn new(parsec: &Parsec<Transaction, PeerId>) -> Self {
            let peer_list = parsec
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
            let events = parsec.events.keys().cloned().collect();

            Snapshot {
                peer_list,
                events,
                consensused_blocks: parsec.consensused_blocks.clone(),
                meta_events: parsec.meta_elections.current_meta_events().clone(),
            }
        }
    }

    macro_rules! assert_err {
        ($expected_error:pat, $result:expr) => {
            match $result {
                Err($expected_error) => (),
                unexpected => panic!(
                    "Expected {}, but got {:?}",
                    stringify!($expected_error),
                    unexpected
                ),
            }
        };
    }

    // Returns iterator over all votes cast by the given node.
    fn our_votes<T: NetworkEvent, S: SecretId>(
        parsec: &Parsec<T, S>,
    ) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        parsec
            .peer_list
            .our_events()
            .filter_map(move |hash| parsec.events.get(hash))
            .filter_map(|event| event.vote())
            .map(|vote| vote.payload())
    }

    // Add the peers to the `PeerList` as the genesis group.
    fn add_genesis_group<S: SecretId>(
        peer_list: &mut PeerList<S>,
        genesis: &BTreeSet<S::PublicId>,
    ) {
        for peer_id in genesis {
            if peer_list.has_peer(peer_id) {
                continue;
            }

            peer_list.add_peer(peer_id.clone(), PeerState::active());
            peer_list.initialise_peer_membership_list(peer_id, genesis.iter().cloned());
        }
    }

    // Initialise membership lists of all peers.
    // TODO: remove this when membership lists are handled by the dot parser itself.
    fn initialise_membership_lists<S: SecretId>(peer_list: &mut PeerList<S>) {
        let peer_ids: Vec<_> = peer_list.all_ids().cloned().collect();
        for peer_id in &peer_ids {
            peer_list.initialise_peer_membership_list(peer_id, peer_ids.clone());
        }
    }

    fn nth_event<T: NetworkEvent, P: PublicId>(
        events: &BTreeMap<Hash, Event<T, P>>,
        n: usize,
    ) -> &Event<T, P> {
        unwrap!(events.values().find(|event| event.order() == n))
    }

    #[test]
    fn from_existing() {
        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let parsec = Parsec::<Transaction, _>::from_existing(
            our_id.clone(),
            &peers,
            &peers,
            is_supermajority,
        );

        // Existing section + us
        assert_eq!(parsec.peer_list.all_ids().count(), peers.len() + 1);

        // Only the initial event should be in the gossip graph.
        assert_eq!(parsec.events.len(), 1);
        let event = unwrap!(parsec.events.values().next());
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

        let _ = Parsec::<Transaction, _>::from_existing(
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

        let _ = Parsec::<Transaction, _>::from_existing(
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

        let _ = Parsec::<Transaction, _>::from_existing(
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

        let _ = Parsec::<Transaction, _>::from_existing(
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

        let parsec =
            Parsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
        // the peer_list should contain the entire genesis group
        assert_eq!(parsec.peer_list.all_ids().count(), peers.len());
        // initial event + genesis_observation
        assert_eq!(parsec.events.len(), 2);
        let initial_event = nth_event(&parsec.events, 0);
        assert_eq!(*initial_event.creator(), our_id);
        assert!(initial_event.is_initial());
        let genesis_observation = nth_event(&parsec.events, 1);
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

        let _ = Parsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
    }

    #[test]
    fn from_parsed_contents() {
        let input_file = "0.dot";
        let parsed_contents = parse_test_dot_file(input_file);
        let parsed_contents_comparison = parse_test_dot_file(input_file);
        let parsec = Parsec::from_parsed_contents(parsed_contents);
        assert_eq!(parsed_contents_comparison.events, parsec.events);
        assert_eq!(
            &parsed_contents_comparison.meta_events,
            parsec.meta_elections.current_meta_events()
        );

        let parsed_contents_other = parse_test_dot_file("1.dot");
        assert_ne!(parsed_contents_other.events, parsec.events);
        assert_ne!(
            &parsed_contents_other.meta_events,
            parsec.meta_elections.current_meta_events()
        );
    }

    #[test]
    fn add_peer() {
        let mut parsed_contents = parse_test_dot_file("add_fred.dot");
        // Split out the events Eric would send to Alice.  These are the last seven events listed in
        // `parsed_contents.events_order`, i.e. B_14, C_14, D_14, D_15, B_15, C_15, E_14, and E_15.
        let mut final_events: Vec<_> = (0..8)
            .map(|_| unwrap!(parsed_contents.remove_latest_event()))
            .collect();
        final_events.reverse();

        let e_15 = unwrap!(final_events.pop());
        let e_14 = unwrap!(final_events.pop());

        // The final decision to add Fred is reached in C_15.
        let c_15 = unwrap!(final_events.pop());

        let mut alice = Parsec::from_parsed_contents(parsed_contents);
        initialise_membership_lists(&mut alice.peer_list);
        let genesis_group: BTreeSet<_> = alice.peer_list.all_ids().cloned().collect();

        let fred_id = PeerId::new("Fred");
        assert!(!alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));

        let alice_snapshot = Snapshot::new(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&fred_id)));
        assert_eq!(alice_snapshot, Snapshot::new(&alice));

        // Keep a copy of a request which will be used later in the test.  This request will not
        // include enough events to allow a joining peer to see "Fred" as a valid member.
        let deficient_message = unwrap!(alice.create_gossip(None));

        // Add events now as though Alice had received the request from Eric.  This should result in
        // Alice adding Fred.
        for event in final_events {
            unwrap!(alice.add_event(event));
            assert!(!alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));
        }

        unwrap!(alice.add_event(c_15));
        unwrap!(alice.add_event(e_14));
        unwrap!(alice.add_event(e_15));
        unwrap!(alice.create_sync_event(&PeerId::new("Eric"), true, &BTreeSet::new()));
        assert!(alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));

        // Construct Fred's Parsec instance.
        let mut fred =
            Parsec::from_existing(fred_id, &genesis_group, &genesis_group, is_supermajority);
        let fred_snapshot = Snapshot::new(&fred);

        // Create a "naughty Carol" instance where the graph only shows four peers existing before
        // adding Fred.
        parsed_contents = parse_test_dot_file("naughty_carol.dot");
        let naughty_carol = Parsec::from_parsed_contents(parsed_contents);
        let alice_id = PeerId::new("Alice");
        let malicious_message = unwrap!(naughty_carol.create_gossip(None));
        // TODO - re-enable once `handle_request` is fixed to match the expected behaviour by
        //        MAID-3066/3067.
        if false {
            assert_err!(
                Error::InvalidInitialRequest,
                fred.handle_request(&alice_id, malicious_message)
            );
        }
        assert_eq!(fred_snapshot, Snapshot::new(&fred));

        // TODO - re-enable once `handle_request` is fixed to match the expected behaviour by
        //        MAID-3066/3067.
        if false {
            // Pass the deficient message gathered earlier which will not be sufficient to allow
            // Fred to see himself getting added to the section.
            assert_err!(
                Error::InvalidInitialRequest,
                fred.handle_request(&alice_id, deficient_message)
            );
        }
        // TODO - depending on the outcome of the discussion on how to handle such an invalid
        //        request, the following check may be invalid.  This would be the case if we decide
        //        to accept the events, expecting a good peer will soon augment our knowledge up to
        //        at least the point where we see ourself being added.
        assert_eq!(fred_snapshot, Snapshot::new(&fred));

        // Now pass a valid initial request from Alice to Fred.  The generated response should only
        // contain Fred's initial event, and the one recording receipt of Alice's request.
        let message = unwrap!(alice.create_gossip(None));
        let response = unwrap!(fred.handle_request(&alice_id, message));
        assert_eq!(response.packed_events.len(), 2);
    }

    #[test]
    fn remove_peer() {
        let mut parsed_contents = parse_test_dot_file("remove_eric.dot");
        // The final decision to remove Eric is reached in the last event of Alice.
        let a_last = unwrap!(parsed_contents.remove_latest_event());

        let mut alice = Parsec::from_parsed_contents(parsed_contents);
        let eric_id = PeerId::new("Eric");

        assert!(alice.peer_list.all_ids().any(|peer_id| *peer_id == eric_id));
        assert_ne!(alice.peer_list.peer_state(&eric_id), PeerState::inactive());

        // Add event now which shall result in Alice removing Eric.
        unwrap!(alice.add_event(a_last));
        assert_eq!(alice.peer_list.peer_state(&eric_id), PeerState::inactive());

        // Try calling `create_gossip()` for Eric shall result in error.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&eric_id)));

        // Construct Eric's parsec instance.
        let mut section: BTreeSet<_> = alice.peer_list.all_ids().cloned().collect();
        let _ = section.remove(&eric_id);
        let mut eric = Parsec::<Transaction, _>::from_existing(
            eric_id.clone(),
            &section,
            &section,
            is_supermajority,
        );

        // Peer state is (VOTE | SEND) when created from existing. Need to update the states to
        // (VOTE | SEND | RECV).
        for peer_id in &section {
            eric.peer_list.change_peer_state(peer_id, PeerState::RECV);
        }

        // Eric can no longer gossip to anyone.
        assert_err!(
            Error::InvalidSelfState { .. },
            eric.create_gossip(Some(&PeerId::new("Alice")))
        );
    }

    #[test]
    fn handle_malice_genesis_event_not_after_initial() {
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents.peer_list.all_ids().cloned().collect();
        let mut alice = Parsec::from_parsed_contents(alice_contents);

        // Simulate Dave creating unexpected genesis.
        let dave_id = PeerId::new("Dave");
        let mut dave_contents = ParsedContents::new(dave_id.clone());

        dave_contents
            .peer_list
            .add_peer(dave_id.clone(), PeerState::active());
        add_genesis_group(&mut dave_contents.peer_list, &genesis);

        let d_0 = Event::<Transaction, _>::new_initial(&dave_contents.peer_list);
        let d_0_hash = *d_0.hash();
        dave_contents.add_event(d_0);

        let d_1 = Event::<Transaction, _>::new_from_observation(
            d_0_hash,
            Observation::OpaquePayload(Transaction::new("dave's malicious vote")),
            &dave_contents.events,
            &dave_contents.peer_list,
        );
        let d_1_hash = *d_1.hash();
        dave_contents.add_event(d_1);

        let d_2 = Event::<Transaction, _>::new_from_observation(
            d_1_hash,
            Observation::Genesis(genesis),
            &dave_contents.events,
            &dave_contents.peer_list,
        );
        let d_2_hash = *d_2.hash();
        dave_contents.add_event(d_2);

        let dave = Parsec::from_parsed_contents(dave_contents);

        // Dave sends malicious gossip to Alice.
        let request = unwrap!(dave.create_gossip(Some(&alice_id)));
        unwrap!(alice.handle_request(&dave_id, request));

        // Verify that Alice detected the malice and accused Dave.
        let (offender, hash) = unwrap!(
            our_votes(&alice)
                .filter_map(|payload| match *payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::UnexpectedGenesis(hash),
                    } => Some((offender.clone(), hash)),
                    _ => None,
                }).next()
        );

        assert_eq!(offender, dave_id);
        assert_eq!(hash, d_2_hash);
    }

    #[test]
    fn handle_malice_genesis_event_creator_not_genesis_member() {
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents.peer_list.all_ids().cloned().collect();

        let mut alice = Parsec::from_parsed_contents(alice_contents);
        initialise_membership_lists(&mut alice.peer_list);
        alice.restart_consensus(); // This is needed so the AddPeer(Eric) is consensused.

        // Simulate Eric creating unexpected genesis.
        let eric_id = PeerId::new("Eric");
        let mut eric_contents = ParsedContents::new(eric_id.clone());

        eric_contents
            .peer_list
            .add_peer(eric_id.clone(), PeerState::active());
        add_genesis_group(&mut eric_contents.peer_list, &genesis);

        let e_0 = Event::<Transaction, _>::new_initial(&eric_contents.peer_list);
        let e_0_hash = *e_0.hash();
        eric_contents.add_event(e_0);

        let e_1 = Event::<Transaction, _>::new_from_observation(
            e_0_hash,
            Observation::Genesis(genesis),
            &eric_contents.events,
            &eric_contents.peer_list,
        );
        let e_1_hash = *e_1.hash();
        eric_contents.add_event(e_1);

        let eric = Parsec::from_parsed_contents(eric_contents);

        // Eric sends malicious gossip to Alice.
        let request = unwrap!(eric.create_gossip(Some(&alice_id)));
        unwrap!(alice.handle_request(&eric_id, request));

        // Verify that Alice detected the malice and accused Eric.
        let (offender, hash) = unwrap!(
            our_votes(&alice)
                .filter_map(|payload| match *payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::UnexpectedGenesis(hash),
                    } => Some((offender.clone(), hash)),
                    _ => None,
                }).next()
        );

        assert_eq!(offender, eric_id);
        assert_eq!(hash, e_1_hash);
    }

    fn initialise_parsec(
        id: PeerId,
        genesis: BTreeSet<PeerId>,
        second_event: Option<Observation<Transaction, PeerId>>,
    ) -> Parsec<Transaction, PeerId> {
        let mut peer_contents = ParsedContents::new(id);
        for peer_id in &genesis {
            peer_contents
                .peer_list
                .add_peer(peer_id.clone(), PeerState::active());
        }
        add_genesis_group(&mut peer_contents.peer_list, &genesis);

        let ev_0 = Event::<Transaction, _>::new_initial(&peer_contents.peer_list);
        let ev_0_hash = *ev_0.hash();
        peer_contents.add_event(ev_0);
        let ev_1 = if let Some(obs_1) = second_event {
            Event::<Transaction, _>::new_from_observation(
                ev_0_hash,
                obs_1,
                &peer_contents.events,
                &peer_contents.peer_list,
            )
        } else {
            Event::<Transaction, _>::new_from_observation(
                ev_0_hash,
                Observation::Genesis(genesis),
                &peer_contents.events,
                &peer_contents.peer_list,
            )
        };
        peer_contents.add_event(ev_1);
        Parsec::from_parsed_contents(peer_contents)
    }

    #[test]
    fn handle_malice_missing_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let mut genesis = BTreeSet::new();
        let _ = genesis.insert(alice_id.clone());
        let _ = genesis.insert(dave_id.clone());

        // Create Alice where the first event is not a genesis event (malice)
        let alice = initialise_parsec(
            alice_id.clone(),
            genesis.clone(),
            Some(Observation::OpaquePayload(Transaction::new("Foo"))),
        );
        let a_0_hash = *nth_event(&alice.events, 0).hash();
        let a_1_hash = *nth_event(&alice.events, 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), genesis, None);
        assert!(!dave.events.contains_key(&a_0_hash));
        assert!(!dave.events.contains_key(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        unwrap!(dave.handle_request(&alice_id, message));
        assert!(dave.events.contains_key(&a_0_hash));
        assert!(dave.events.contains_key(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(
            our_votes(&dave)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::MissingGenesis(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn handle_malice_incorrect_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let mut genesis = BTreeSet::new();
        let _ = genesis.insert(alice_id.clone());
        let _ = genesis.insert(dave_id.clone());
        let mut false_genesis = BTreeSet::new();
        let _ = false_genesis.insert(alice_id.clone());
        let _ = false_genesis.insert(PeerId::new("Derp"));

        // Create Alice where the first event is an incorrect genesis event (malice)
        let alice = initialise_parsec(
            alice_id.clone(),
            genesis.clone(),
            Some(Observation::Genesis(false_genesis)),
        );
        let a_0_hash = *nth_event(&alice.events, 0).hash();
        let a_1_hash = *nth_event(&alice.events, 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), genesis, None);
        assert!(!dave.events.contains_key(&a_0_hash));
        assert!(!dave.events.contains_key(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        // Alice's genesis should be rejected as invalid
        assert_err!(Error::InvalidEvent, dave.handle_request(&alice_id, message));
        assert!(dave.events.contains_key(&a_0_hash));
        // Dave's events shouldn't contain Alice's genesis because of the rejection
        assert!(!dave.events.contains_key(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(
            our_votes(&dave)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::IncorrectGenesis(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn handle_malice_duplicate_votes() {
        // Carol has already voted for "ABCD".  Create two new duplicate votes by Carol for this
        // opaque payload.
        let mut carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        let first_duplicate = Event::new_from_observation(
            carol.our_last_event_hash(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            &carol.events,
            &carol.peer_list,
        );
        let first_duplicate_clone = Event::new_from_observation(
            carol.our_last_event_hash(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            &carol.events,
            &carol.peer_list,
        );

        let first_duplicate_hash = *first_duplicate.hash();
        let _ = carol.events.insert(first_duplicate_hash, first_duplicate);
        let second_duplicate = Event::new_from_observation(
            first_duplicate_hash,
            Observation::OpaquePayload(Transaction::new("ABCD")),
            &carol.events,
            &carol.peer_list,
        );

        // Check that the first duplicate triggers an accusation by Alice, but that the duplicate is
        // still added to the graph.
        let mut alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let carols_valid_vote_hash =
            *unwrap!(find_event_by_short_name(alice.events.values(), "C_7")).hash();
        unwrap!(alice.add_event(first_duplicate_clone));
        let expected_accusations = vec![(
            carol.our_pub_id().clone(),
            Malice::DuplicateVote(carols_valid_vote_hash, first_duplicate_hash),
        )];
        assert_eq!(alice.pending_accusations, expected_accusations);
        assert!(alice.events.contains_key(&first_duplicate_hash));

        // Check that the second one doesn't trigger any further accusation, but is also added to
        // the graph.
        let second_duplicate_hash = *second_duplicate.hash();
        unwrap!(alice.add_event(second_duplicate));
        assert_eq!(alice.pending_accusations, expected_accusations);
        assert!(alice.events.contains_key(&second_duplicate_hash));
    }

    #[test]
    fn handle_malice_stale_other_parent() {
        // Carol will create event C_4 with other-parent as B_1, despite having C_3 with other-
        // parent as B_2.
        let carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        let c_3_hash = *unwrap!(find_event_by_short_name(carol.events.values(), "C_3")).hash();
        let b_1_hash = *unwrap!(find_event_by_short_name(carol.events.values(), "B_1")).hash();

        let c_4 = Event::new_from_request(
            c_3_hash,
            b_1_hash,
            &carol.events,
            &carol.peer_list,
            &BTreeSet::new(),
        );
        let c_4_hash = *c_4.hash();

        // Check that adding C_4 triggers an accusation by Alice, but that C_4 is still added to the
        // graph.
        let mut alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        initialise_membership_lists(&mut alice.peer_list);

        let expected_accusations = vec![(
            carol.our_pub_id().clone(),
            Malice::StaleOtherParent(c_4_hash),
        )];
        unwrap!(alice.add_event(c_4));
        assert_eq!(alice.pending_accusations, expected_accusations);
        assert!(alice.events.contains_key(&c_4_hash));
    }

    #[test]
    fn handle_malice_invalid_accusation() {
        let mut alice_contents = parse_test_dot_file("alice.dot");

        let a_5_hash = *unwrap!(find_event_by_short_name(
            alice_contents.events.values(),
            "A_5"
        )).hash();
        let d_1_hash = *unwrap!(find_event_by_short_name(
            alice_contents.events.values(),
            "D_1"
        )).hash();

        // Create an invalid accusation from Alice
        let a_6 = Event::<Transaction, _>::new_from_observation(
            a_5_hash,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
            &alice_contents.events,
            &alice_contents.peer_list,
        );
        let a_6_hash = *a_6.hash();
        alice_contents.add_event(a_6);
        let alice = Parsec::from_parsed_contents(alice_contents);
        assert!(alice.events.contains_key(&a_6_hash));

        let mut carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        assert!(!carol.events.contains_key(&a_6_hash));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(carol.our_pub_id())));

        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.events.contains_key(&a_6_hash));

        // Verify that Carol detected malice and accused Alice of it.
        let (offender, hash) = unwrap!(
            our_votes(&carol)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::InvalidAccusation(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, a_6_hash);
    }

    #[test]
    fn handle_malice_invalid_gossip_creator() {
        // Alice reports gossip to Bob from Carol that isn’t in their section.
        let mut alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        initialise_membership_lists(&mut alice.peer_list);
        let mut bob = Parsec::from_parsed_contents(parse_test_dot_file("bob.dot"));
        initialise_membership_lists(&mut bob.peer_list);

        // Verify peer lists
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let mut alice_peer_list = PeerList::new(alice_id.clone());
        alice_peer_list.add_peer(alice_id.clone(), PeerState::active());
        alice_peer_list.add_peer(bob_id.clone(), PeerState::active());
        assert_eq!(
            alice.peer_list.peer_id_hashes().collect::<Vec<_>>(),
            alice_peer_list.peer_id_hashes().collect::<Vec<_>>()
        );
        let mut bob_peer_list = PeerList::new(bob_id.clone());
        bob_peer_list.add_peer(alice_id.clone(), PeerState::active());
        bob_peer_list.add_peer(bob_id.clone(), PeerState::active());
        assert_eq!(
            bob.peer_list.peer_id_hashes().collect::<Vec<_>>(),
            bob_peer_list.peer_id_hashes().collect::<Vec<_>>()
        );

        // Read the dot file again so we have a set of events we can manually add to Bob instead of
        // sending gossip.
        let mut alice_parsed_contents = parse_test_dot_file("alice.dot");

        // Carol is marked as active peer so that Bob's peer_list will accept C_0, but Carol is not
        // part of the membership_list
        let carol_id = PeerId::new("Carol");
        bob.peer_list.add_peer(carol_id, PeerState::active());
        let c_0_hash = *unwrap!(find_event_by_short_name(
            alice_parsed_contents.events.values(),
            "C_0"
        )).hash();
        let c_0 = unwrap!(alice_parsed_contents.events.remove(&c_0_hash));
        unwrap!(bob.peer_list.add_event(&c_0));

        // This malice is setup in two events.
        // A_2 has C_0 from Carol as other parent as Carol has gossiped to Alice. Carol is however
        // not part of the section and Alice should not have accepted it.
        let a_2_hash = *unwrap!(find_event_by_short_name(
            alice_parsed_contents.events.values(),
            "A_2"
        )).hash();
        let a_2 = unwrap!(alice_parsed_contents.events.remove(&a_2_hash));
        unwrap!(bob.add_event(a_2));

        // B_2 is the sync event created by Bob when he receives A_2 from Alice.
        let b_2_hash = *unwrap!(find_event_by_short_name(
            alice_parsed_contents.events.values(),
            "B_2"
        )).hash();
        let b_2 = unwrap!(alice_parsed_contents.events.remove(&b_2_hash));
        unwrap!(bob.add_event(b_2));

        // Bob should now have seen that Alice in A_2 incorrectly reported gossip from Carol. Check
        // that this triggers an accusation
        let expected_accusations = (
            alice.our_pub_id().clone(),
            Malice::InvalidGossipCreator(a_2_hash),
        );

        assert!(bob.pending_accusations.contains(&expected_accusations));
        assert!(bob.events.contains_key(&a_2_hash));
    }

    #[test]
    fn unpolled_and_unconsensused_observations() {
        let mut alice_contents = parse_test_dot_file("alice.dot");
        let b_17 = unwrap!(alice_contents.remove_latest_event());

        let mut alice = Parsec::from_parsed_contents(alice_contents);
        alice.restart_consensus(); // This is needed so the Genesis observation is consensused.

        // `Add(Eric)` should still be unconsensused since B_17 would be the first gossip event to
        // reach consensus on `Add(Eric)`, but it was removed from the graph.
        assert!(alice.has_unconsensused_observations());

        // Since we haven't called `poll()` yet, our votes for `Genesis` and `Add(Eric)` should be
        // returned by `our_unpolled_observations()`.
        let add_eric = Observation::Add(PeerId::new("Eric"));
        let genesis = Observation::Genesis(mock::create_ids(4).into_iter().collect());
        {
            let mut unpolled_observations = alice.our_unpolled_observations();
            assert_eq!(*unwrap!(unpolled_observations.next()), genesis);
            assert_eq!(*unwrap!(unpolled_observations.next()), add_eric);
            assert!(unpolled_observations.next().is_none());
        }

        // Call `poll()` and retry - should only return our vote for `Add(Eric)`.
        unwrap!(alice.poll());
        assert!(alice.poll().is_none());
        assert!(alice.has_unconsensused_observations());
        assert_eq!(alice.our_unpolled_observations().count(), 1);
        assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

        // Have Alice process B_17 to get consensus on `Add(Eric)`.
        unwrap!(alice.add_event(b_17));

        // Since we haven't call `poll()` again yet, should still return our vote for `Add(Eric)`.
        // However, `has_unconsensused_observations()` should now return false.
        assert!(!alice.has_unconsensused_observations());
        assert_eq!(alice.our_unpolled_observations().count(), 1);
        assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

        // Call `poll()` and retry - should return none.
        unwrap!(alice.poll());
        assert!(alice.poll().is_none());
        assert!(alice.our_unpolled_observations().next().is_none());

        // Vote for a new observation and check it is returned as unpolled, and that
        // `has_unconsensused_observations()` returns false again.
        let vote = Observation::OpaquePayload(Transaction::new("ABCD"));
        unwrap!(alice.vote_for(vote.clone()));

        assert!(alice.has_unconsensused_observations());
        assert_eq!(alice.our_unpolled_observations().count(), 1);
        assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), vote);

        // Reset, and re-run, this time adding Alice's vote early to check that it is returned in
        // the correct order, i.e. after `Add(Eric)` at the point where `Add(Eric)` is consensused
        // but has not been returned by `poll()`.
        alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        unwrap!(alice.vote_for(vote.clone()));
        alice.restart_consensus(); // `Add(Eric)` is now consensused.
        let mut unpolled_observations = alice.our_unpolled_observations();
        assert_eq!(*unwrap!(unpolled_observations.next()), genesis);
        assert_eq!(*unwrap!(unpolled_observations.next()), add_eric);
        assert_eq!(*unwrap!(unpolled_observations.next()), vote);
        assert!(unpolled_observations.next().is_none());
    }

    fn create_invalid_accusation() -> (Hash, Parsec<Transaction, PeerId>) {
        let mut alice_contents = parse_dot_file_with_test_name(
            "alice.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        );

        let a_10_hash = *unwrap!(find_event_by_short_name(
            alice_contents.events.values(),
            "A_10"
        )).hash();
        let d_1_hash = *unwrap!(find_event_by_short_name(
            alice_contents.events.values(),
            "D_1"
        )).hash();

        // Create an invalid accusation from Alice
        let a_11 = Event::<Transaction, _>::new_from_observation(
            a_10_hash,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
            &alice_contents.events,
            &alice_contents.peer_list,
        );
        let a_11_hash = *a_11.hash();
        alice_contents.add_event(a_11);
        let alice = Parsec::from_parsed_contents(alice_contents);
        assert!(alice.events.contains_key(&a_11_hash));
        (a_11_hash, alice)
    }

    fn verify_accused_accomplice(
        accuser: &Parsec<Transaction, PeerId>,
        suspect: &PeerId,
        event_hash: &Hash,
    ) {
        let (offender, hash) = unwrap!(
            our_votes(accuser)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::Accomplice(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(offender, suspect);
        assert_eq!(hash, event_hash);
    }

    #[test]
    #[ignore]
    // Carol received gossip from Bob, which should have raised an accomplice accusation against
    // Alice but didn't.
    fn handle_malice_accomplice() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.events.contains_key(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.events.contains_key(&invalid_accusation));

        let mut carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.events.contains_key(&invalid_accusation));

        // Send gossip from Bob to Carol, remove the accusation event
        let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        let accusation_event = unwrap!(message.packed_events.pop());
        let bob_last_hash = unwrap!(accusation_event.self_parent());
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.events.contains_key(&invalid_accusation));

        // Verify that Carol detected malice and accused Alice of `InvalidAccusation` and Bob of
        // `Accomplice`.
        let (offender, hash) = unwrap!(
            our_votes(&carol)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::InvalidAccusation(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, invalid_accusation);

        verify_accused_accomplice(&carol, bob.our_pub_id(), bob_last_hash);
    }

    #[test]
    #[ignore]
    // Carol received `invalid_accusation` from Alice first, then received gossip from Bob, which
    // should have raised an accomplice accusation against Alice but didn't.
    fn handle_malice_accomplice_separate() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.events.contains_key(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.events.contains_key(&invalid_accusation));

        let mut bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.events.contains_key(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.events.contains_key(&invalid_accusation));

        // Send gossip from Bob to Carol, remove the accusation event
        let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        let accusation_event = unwrap!(message.packed_events.pop());
        let bob_last_hash = unwrap!(accusation_event.self_parent());
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.events.contains_key(&invalid_accusation));

        // Verify that Carol detected malice and accused Bob of `Accomplice`.
        verify_accused_accomplice(&carol, bob.our_pub_id(), bob_last_hash);
    }

    #[test]
    #[ignore]
    // Carol received `invalid_accusation` from Alice first, then receive gossip from Bob, which
    // doesn't contain the malice of Alice. Carol shall not raise accusation against Bob.
    fn handle_malice_accomplice_negative() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.events.contains_key(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.events.contains_key(&invalid_accusation));

        let bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.events.contains_key(&invalid_accusation));

        // Send gossip from Bob to Carol
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));

        // Verify that Carol didn't accuse Bob of `Accomplice`.
        assert!(our_votes(&carol).all(|payload| match payload {
            Observation::Accusation {
                malice: Malice::Accomplice(_),
                ..
            } => false,
            _ => true,
        }));
    }

    #[test]
    fn gossip_after_fork() {
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");

        let mut genesis_group = BTreeSet::new();
        let _ = genesis_group.insert(alice_id.clone());
        let _ = genesis_group.insert(bob_id.clone());
        let _ = genesis_group.insert(PeerId::new("Carol"));
        let _ = genesis_group.insert(PeerId::new("Dave"));

        let mut alice = Parsec::from_genesis(alice_id.clone(), &genesis_group, is_supermajority);

        // Alice creates couple of valid events.
        let a_1_hash = *unwrap!(alice.peer_list.our_events().next());

        let a_2 = Event::new_from_observation(
            a_1_hash,
            Observation::OpaquePayload(Transaction::new("one")),
            &alice.events,
            &alice.peer_list,
        );
        let a_2_hash = *a_2.hash();
        unwrap!(alice.add_event(a_2));

        let a_3 = Event::new_from_observation(
            a_2_hash,
            Observation::OpaquePayload(Transaction::new("two")),
            &alice.events,
            &alice.peer_list,
        );
        let a_3_hash = *a_3.hash();
        unwrap!(alice.add_event(a_3));

        let mut bob = Parsec::from_genesis(bob_id.clone(), &genesis_group, is_supermajority);

        // Alice sends a gossip request to Bob and receives a response back.
        let req = unwrap!(alice.create_gossip(Some(&bob_id)));
        let res = unwrap!(bob.handle_request(&alice_id, req));
        unwrap!(alice.handle_response(&bob_id, res));

        // Now Bob has a_0, a_1, a_2 and a_3 and Alice knows it.
        assert!(bob.events.contains_key(&a_1_hash));
        assert!(bob.events.contains_key(&a_2_hash));
        assert!(bob.events.contains_key(&a_3_hash));

        // Alice creates a fork.
        let a_2_fork = Event::new_from_observation(
            a_1_hash,
            Observation::OpaquePayload(Transaction::new("two-fork")),
            &alice.events,
            &alice.peer_list,
        );
        let a_2_fork_hash = *a_2_fork.hash();
        unwrap!(alice.add_event(a_2_fork));

        // Alice sends another gossip request to Bob.
        let req = unwrap!(alice.create_gossip(Some(&bob_id)));
        let _ = unwrap!(bob.handle_request(&alice_id, req));

        // Verify that Bob now has the forked event.
        assert!(bob.events.contains_key(&a_2_fork_hash));
    }
}

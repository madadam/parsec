// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
use dump_graph;
use error::Error;
use gossip::{Event, PackedEvent, Request, Response};
use hash::Hash;
use id::SecretId;
use meta_vote::{MetaVote, Step};
use network_event::NetworkEvent;
use peer_list::PeerList;
use round_hash::RoundHash;
use serialise;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::iter;

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // Gossip events created locally and received from other peers.
    events: BTreeMap<Hash, Event<T, S::PublicId>>,
    // The sequence in which all gossip events were added to this `Parsec`.
    events_order: Vec<Hash>,
    // The hashes of events for each peer that have a non-empty set of `valid_blocks_carried`
    events_with_valid_blocks: BTreeMap<S::PublicId, VecDeque<Hash>>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // Hash of all payloads that were consensused ever
    consensus_history: Vec<Hash>,
    // The meta votes of the events.
    meta_votes: BTreeMap<Hash, BTreeMap<S::PublicId, Vec<MetaVote>>>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<S::PublicId, Vec<RoundHash>>,
    responsiveness_threshold: usize,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    pub fn new(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Self {
        let responsiveness_threshold = (genesis_group.len() as f64).log2().ceil() as usize;

        let mut peer_list = PeerList::new(our_id);
        let mut round_hashes = BTreeMap::new();
        let initial_hash = Hash::from([].as_ref());
        for peer_id in genesis_group.iter().cloned() {
            peer_list.add_peer(peer_id.clone());
            let round_hash = RoundHash::new(&peer_id, initial_hash);
            let _ = round_hashes.insert(peer_id, vec![round_hash]);
        }

        let mut parsec = Parsec {
            peer_list,
            events: BTreeMap::new(),
            events_order: vec![],
            events_with_valid_blocks: BTreeMap::new(),
            consensused_blocks: VecDeque::new(),
            consensus_history: vec![],
            meta_votes: BTreeMap::new(),
            round_hashes,
            responsiveness_threshold,
        };
        let initial_event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial_event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }
        dump_graph::init();
        parsec
    }

    /// Adds a vote for `network_event`.  Returns an error if we have already voted for this.
    pub fn vote_for(&mut self, network_event: T) -> Result<(), Error> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), network_event);
        if self.have_voted_for(&network_event) {
            return Err(Error::DuplicateVote);
        }
        let self_parent_hash = self.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            network_event,
            &self.events,
            &self.peer_list,
        );
        self.add_event(event)
    }

    /// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
    /// that peer needs.  If `peer_id` is `None`, a message containing all known gossip events is
    /// returned.  If `peer_id` is `Some` and the given peer is unknown to this node, an error is
    /// returned.
    pub fn create_gossip(
        &self,
        peer_id: Option<S::PublicId>,
    ) -> Result<Request<T, S::PublicId>, Error> {
        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );
        if let Some(recipient_id) = peer_id {
            if !self.peer_list.has_peer(&recipient_id) {
                return Err(Error::UnknownPeer);
            }
            if self.peer_list.last_event_hash(&recipient_id).is_some() {
                return self
                    .events_to_gossip_to_peer(&recipient_id)
                    .map(Request::new);
            }
        }
        let mut events = vec![];
        for event_hash in &self.events_order {
            events.push(self.get_known_event(event_hash)?);
        }
        Ok(Request::new(events.into_iter()))
    }

    /// Handles a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        debug!(
            "{:?} received gossip request from {:?}",
            self.our_pub_id(),
            src
        );
        self.unpack_and_add_events(req.packed_events)?;
        self.create_sync_event(src, true)?;
        self.events_to_gossip_to_peer(src).map(Response::new)
    }

    /// Handles a received `Response` from `src` peer.  Returns `Err` if the response was not valid.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        debug!(
            "{:?} received gossip response from {:?}",
            self.our_pub_id(),
            src
        );
        self.unpack_and_add_events(resp.packed_events)?;
        self.create_sync_event(src, false)
    }

    /// Steps the algorithm and returns the next stable block, if any.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Checks if the given `network_event` has already been voted for by us.
    pub fn have_voted_for(&self, network_event: &T) -> bool {
        self.events.values().any(|event| {
            event.creator() == self.our_pub_id() && event
                .vote()
                .map_or(false, |voted| voted.payload() == network_event)
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_hash: &Hash) -> Result<&Event<T, S::PublicId>, Error> {
        self.events.get(event_hash).ok_or_else(|| {
            log_or_panic!(
                "{:?} doesn't have event {:?}",
                self.our_pub_id(),
                event_hash
            );
            Error::Logic
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event_mut(
        &mut self,
        event_hash: &Hash,
    ) -> Result<&mut Event<T, S::PublicId>, Error> {
        let our_id = self.our_pub_id().clone();
        self.events.get_mut(event_hash).ok_or_else(|| {
            log_or_panic!("{:?} doesn't have event {:?}", our_id, event_hash);
            Error::Logic
        })
    }

    fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_id().public_id()
    }

    fn our_last_event_hash(&self) -> Hash {
        if let Some(hash) = self.peer_list.last_event_hash(self.our_pub_id()) {
            *hash
        } else {
            log_or_panic!("{:?} has no last event hash.", self.our_pub_id());
            Hash::from([].as_ref())
        }
    }

    fn self_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.self_parent().and_then(|hash| self.events.get(hash))
    }

    fn is_observer(&self, event: &Event<T, S::PublicId>) -> bool {
        self.peer_list.is_super_majority(event.observations.len())
    }

    fn unpack_and_add_events(
        &mut self,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<(), Error> {
        for packed_event in packed_events {
            if let Some(event) = Event::unpack(packed_event, &self.events, &self.peer_list)? {
                self.add_event(event)?;
            }
        }
        Ok(())
    }

    fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<(), Error> {
        self.peer_list.add_event(&event)?;
        let event_hash = *event.hash();
        let is_initial = event.is_initial();
        self.events_order.push(event_hash);
        let _ = self.events.insert(event_hash, event);
        if is_initial {
            return Ok(());
        }
        self.set_valid_blocks_carried(&event_hash)?;
        self.process_event(&event_hash)
    }

    fn process_event(&mut self, event_hash: &Hash) -> Result<(), Error> {
        self.set_observations(event_hash)?;
        self.set_meta_votes(event_hash)?;
        self.update_round_hashes(event_hash);
        if let Some(block) = self.next_stable_block() {
            dump_graph::to_file(self.our_pub_id(), &self.events, &self.meta_votes);
            self.clear_consensus_data(block.payload());
            let payload_hash = Hash::from(serialise(block.payload()).as_slice());
            info!(
                "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
                self.our_pub_id(),
                self.consensus_history.len(),
                block.payload(),
                payload_hash
            );
            self.consensus_history.push(payload_hash);
            self.consensused_blocks.push_back(block);
            self.restart_consensus(&payload_hash);
        }
        Ok(())
    }

    fn set_valid_blocks_carried(&mut self, event_hash: &Hash) -> Result<(), Error> {
        // Collect payloads from any block made valid by this event
        let valid_blocks_carried = {
            let event = self.get_known_event(event_hash)?;
            self.peer_list
                .iter()
                .flat_map(|(_peer, events)| {
                    events.iter().filter_map(|(_index, hash)| {
                        self.events
                            .get(hash)
                            .and_then(|event| event.vote().map(|vote| vote.payload()))
                    })
                }).filter(|&this_payload| !self.payload_is_already_carried(event, this_payload))
                .filter(|&this_payload| {
                    self.peer_list
                        .is_super_majority(self.n_ancestors_carrying_payload(event, this_payload))
                }).cloned()
                .collect::<BTreeSet<T>>()
        };
        if !valid_blocks_carried.is_empty() {
            let creator_id = self.get_known_event(event_hash)?.creator().clone();
            let _ = self
                .events_with_valid_blocks
                .entry(creator_id)
                .and_modify(|hashes| {
                    hashes.push_back(*event_hash);
                }).or_insert_with(|| iter::once(*event_hash).collect());
        }
        self.get_known_event_mut(event_hash)
            .map(|ref mut event| event.valid_blocks_carried = valid_blocks_carried)
    }

    fn payload_is_already_carried(&self, event: &Event<T, S::PublicId>, payload: &T) -> bool {
        let hashes = self.events_with_valid_blocks.get(event.creator());
        hashes.map_or(false, |hashes| {
            hashes.iter().any(|hash| {
                if let Ok(event) = self.get_known_event(hash) {
                    event.valid_blocks_carried.contains(payload)
                } else {
                    false
                }
            })
        })
    }

    fn n_ancestors_carrying_payload(&self, event: &Event<T, S::PublicId>, payload: &T) -> usize {
        let payload_already_reached_consensus = self
            .consensus_history
            .iter()
            .any(|payload_hash| *payload_hash == Hash::from(serialise(&payload).as_slice()));
        if payload_already_reached_consensus {
            return 0;
        }
        self.peer_list
            .iter()
            .filter(|(peer, events)| {
                events.iter().any(
                    |(index, event_hash)| match self.get_known_event(event_hash) {
                        Ok(that_event) => {
                            (Some(payload) == that_event.vote().map(|vote| vote.payload())
                                && (event
                                    .last_ancestors()
                                    .get(peer)
                                    .map_or(false, |last_index| last_index >= index)))
                        }
                        Err(_) => false,
                    },
                )
            }).count()
    }

    fn set_observations(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let observations = {
            let event = self.get_known_event(event_hash)?;
            self.events_with_valid_blocks
                .iter()
                .filter_map(|(peer, hashes)| {
                    let old_hash = hashes.front()?;
                    let old_event = self.get_known_event(old_hash).ok()?;
                    if self.strongly_sees(event, old_event) {
                        Some(peer)
                    } else {
                        None
                    }
                }).cloned()
                .collect()
        };
        self.get_known_event_mut(event_hash)
            .map(|ref mut event| event.observations = observations)
    }

    fn set_meta_votes(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let total_peers = self.peer_list.iter().count();
        let mut meta_votes = BTreeMap::new();
        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        {
            let event = self.get_known_event(event_hash)?;
            if let Some(parent_votes) = self
                .self_parent(event)
                .and_then(|parent| self.meta_votes.get(parent.hash()).cloned())
            {
                for (peer_id, parent_event_votes) in parent_votes {
                    let new_meta_votes = {
                        let other_votes = self.collect_other_meta_votes(&peer_id, event);
                        let coin_tosses = self.toss_coins(&peer_id, &parent_event_votes, event)?;
                        MetaVote::next(&parent_event_votes, &other_votes, &coin_tosses, total_peers)
                    };
                    let _ = meta_votes.insert(peer_id, new_meta_votes);
                }
            } else if self.is_observer(event) {
                // Start meta votes for this event.
                for peer_id in self.peer_list.all_ids() {
                    let other_votes = self.collect_other_meta_votes(peer_id, event);
                    let initial_estimate = event.observations.contains(peer_id);
                    let _ = meta_votes.insert(
                        peer_id.clone(),
                        MetaVote::new(initial_estimate, &other_votes, total_peers),
                    );
                }
            };
            trace!(
                "{:?} has set the meta votes for {:?}",
                self.our_pub_id(),
                event
            );
        }

        if !meta_votes.is_empty() {
            let _ = self.meta_votes.insert(*event_hash, meta_votes);
        }
        Ok(())
    }

    fn update_round_hashes(&mut self, event_hash: &Hash) {
        if let Some(meta_votes) = self.meta_votes.get(event_hash) {
            for (peer_id, event_votes) in meta_votes.iter() {
                for meta_vote in event_votes {
                    if let Some(hashes) = self.round_hashes.get_mut(&peer_id) {
                        while hashes.len() < meta_vote.round + 1 {
                            let next_round_hash = hashes[hashes.len() - 1].increment_round();
                            hashes.push(next_round_hash);
                        }
                    }
                }
            }
        }
    }

    fn toss_coins(
        &self,
        peer_id: &S::PublicId,
        parent_votes: &[MetaVote],
        event: &Event<T, S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>, Error> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(peer_id, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        event: &Event<T, S::PublicId>,
    ) -> Result<Option<bool>, Error> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                // This should never happen as estimates get cleared only in increase step when the
                // step is Step::GenuineFlip and the round gets incremented
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
        let round_hash = if let Some(hashes) = self.round_hashes.get(peer_id) {
            hashes[round].value()
        } else {
            log_or_panic!("{:?} missing round hash.", self.our_pub_id());
            return Err(Error::Logic);
        };

        // Get the gradient of leadership.
        let mut peer_id_hashes = self.peer_list.peer_id_hashes().clone();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.0, &rhs.0));

        // Try to get the "most-leader"'s aux value.
        let creator = &peer_id_hashes[0].1;
        if let Some(creator_event_index) = event.last_ancestors().get(creator) {
            if let Some(aux_value) = self.aux_value(creator, *creator_event_index, peer_id, round) {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(round, event) {
            for (_, creator) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors().get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(creator, *creator_event_index, peer_id, round)
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
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_since_round_and_step(
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
    fn stop_waiting(&self, round: usize, event: &Event<T, S::PublicId>) -> bool {
        let mut event_hash = Some(event.hash());
        let mut response_count = 0;
        loop {
            if let Some(event) = event_hash.and_then(|hash| self.get_known_event(hash).ok()) {
                if event.is_response() {
                    response_count += 1;
                    if response_count == self.responsiveness_threshold {
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
        self.meta_votes
            .get(&hash)
            .and_then(|meta_votes| meta_votes.get(event.creator()))
            .map_or(false, |event_votes| {
                event_votes
                    .iter()
                    .any(|meta_vote| meta_vote.round == round && meta_vote.aux_value.is_some())
            })
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.
    // Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
        step: &Step,
    ) -> Vec<MetaVote> {
        if let Some(event_hash) = self.peer_list.event_by_index(creator, creator_event_index) {
            if let Some(latest_votes) = self
                .meta_votes
                .get(event_hash)
                .and_then(|meta_votes| meta_votes.get(peer_id))
                .map(|meta_votes| {
                    meta_votes
                        .iter()
                        .filter(|meta_vote| {
                            meta_vote.round > round
                                || meta_vote.round == round && meta_vote.step >= *step
                        }).cloned()
                        .collect()
                }) {
                latest_votes
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by `peer_id`.
    fn collect_other_meta_votes(
        &self,
        peer_id: &S::PublicId,
        event: &Event<T, S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        let mut other_votes = vec![];
        for creator in self
            .peer_list
            .all_ids()
            .iter()
            .filter(|&id| *id != event.creator())
        {
            if let Some(meta_votes) =
                event
                    .last_ancestors()
                    .get(creator)
                    .map(|creator_event_index| {
                        self.meta_votes_since_round_and_step(
                            creator,
                            *creator_event_index,
                            &peer_id,
                            0,
                            &Step::ForcedTrue,
                        )
                    }) {
                other_votes.push(meta_votes)
            }
        }
        other_votes
    }

    fn next_stable_block(&mut self) -> Option<Block<T, S::PublicId>> {
        self.meta_votes
            .get(&self.our_last_event_hash())
            .and_then(|our_last_meta_votes| {
                let our_decided_meta_votes =
                    our_last_meta_votes.iter().filter_map(|(id, event_votes)| {
                        let vote = event_votes.last();
                        vote.and_then(|v| {
                            if v.decision.is_some() {
                                Some((id, v))
                            } else {
                                None
                            }
                        })
                    });
                if our_decided_meta_votes.clone().count() < self.peer_list.all_ids().len() {
                    None
                } else {
                    let elected_valid_blocks = our_decided_meta_votes
                        .filter_map(|(id, vote)| {
                            if vote.decision == Some(true) {
                                self.events_with_valid_blocks
                                    .get(&id)
                                    .and_then(|hashes| hashes.front())
                                    .and_then(|hash| self.get_known_event(&hash).ok())
                                    .map(|oldest_event| oldest_event.valid_blocks_carried.clone())
                            } else {
                                None
                            }
                        }).collect::<Vec<BTreeSet<T>>>();
                    // This is sorted by peer_ids, which should avoid ties when picking the event
                    // with the most represented payload.
                    let payloads = elected_valid_blocks
                        .iter()
                        .flat_map(|payloads_carried| payloads_carried)
                        .collect::<Vec<_>>();
                    let copied_payloads = payloads.clone();
                    copied_payloads
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
                        .and_then(|winning_payload| {
                            let votes = self
                                .events
                                .iter()
                                .filter_map(|(_hash, event)| {
                                    event.vote().and_then(|vote| {
                                        if vote.payload() == winning_payload {
                                            Some((event.creator().clone(), vote.clone()))
                                        } else {
                                            None
                                        }
                                    })
                                }).collect();
                            Block::new(winning_payload.clone(), &votes).ok()
                        })
                }
            })
    }

    fn clear_consensus_data(&mut self, payload: &T) {
        // Clear all leftover data from previous consensus
        self.round_hashes = BTreeMap::new();
        self.meta_votes = BTreeMap::new();

        let mut events_made_empty = vec![];
        for event in self.events.values_mut() {
            event.observations = BTreeSet::new();
            let removed = event.valid_blocks_carried.remove(payload);
            if removed && event.valid_blocks_carried.is_empty() {
                events_made_empty.push(*event.hash())
            }
        }
        for event_hash in &events_made_empty {
            if let Ok(id) = self
                .get_known_event(event_hash)
                .map(|event| event.creator().clone())
            {
                if let Some(hashes) = self.events_with_valid_blocks.get_mut(&id) {
                    hashes.retain(|hash| hash != event_hash);
                }
            }
        }
    }

    fn restart_consensus(&mut self, latest_block_hash: &Hash) {
        self.round_hashes = self
            .peer_list
            .all_ids()
            .iter()
            .map(|&peer_id| {
                let round_hash = RoundHash::new(peer_id, *latest_block_hash);
                (peer_id.clone(), vec![round_hash])
            }).collect();
        let events_hashes = self
            .events_order
            .iter()
            // Start from the oldest event with a valid block considering all creators' events.
            .skip_while(|hash| {
                self.get_known_event(&hash)
                    .ok()
                    .map_or(true, |event| event.valid_blocks_carried.is_empty())
            })
            .cloned()
            .collect::<Vec<_>>();
        for event_hash in &events_hashes {
            let _ = self.process_event(event_hash);
        }
    }

    // Returns the number of peers through which there is a directed path in the gossip graph
    // from event X (descendant) to event Y (ancestor).
    fn n_peers_with_directed_paths(
        &self,
        x: &Event<T, S::PublicId>,
        y: &Event<T, S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .iter()
            .filter(|(peer_id, &event_index)| {
                self.peer_list
                    .event_by_index(peer_id, event_index)
                    .and_then(|event_hash| self.get_known_event(event_hash).ok())
                    .map_or(false, |last_ancestor_of_x| last_ancestor_of_x.sees(y))
            }).count()
    }

    // Returns whether event X can strongly see the event Y.
    fn strongly_sees(&self, x: &Event<T, S::PublicId>, y: &Event<T, S::PublicId>) -> bool {
        self.peer_list
            .is_super_majority(self.n_peers_with_directed_paths(x, y))
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    fn create_sync_event(&mut self, src: &S::PublicId, is_request: bool) -> Result<(), Error> {
        let self_parent = *self
            .peer_list
            .last_event_hash(self.our_pub_id())
            .ok_or_else(|| {
                log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
                Error::Logic
            })?;
        let other_parent = *self.peer_list.last_event_hash(src).ok_or_else(|| {
            log_or_panic!("{:?} missing {:?} last event hash.", self.our_pub_id(), src);
            Error::Logic
        })?;
        let sync_event = if is_request {
            Event::new_from_request(self_parent, other_parent, &self.events, &self.peer_list)
        } else {
            Event::new_from_response(self_parent, other_parent, &self.events, &self.peer_list)
        };
        self.add_event(sync_event)
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(
        &self,
        peer_id: &S::PublicId,
    ) -> Result<impl Iterator<Item = &Event<T, S::PublicId>>, Error> {
        let peer_last_event = if let Some(event_hash) = self.peer_list.last_event_hash(peer_id) {
            self.get_known_event(event_hash)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_id);
            return Err(Error::Logic);
        };
        let mut last_ancestors_hashes = peer_last_event
            .last_ancestors()
            .iter()
            .filter_map(|(id, &index)| self.peer_list.event_by_index(id, index))
            .collect::<BTreeSet<_>>();
        // As `peer_id` isn't guaranteed to have `last_ancestor_hash` for all peers (which will
        // happen during the early stage when a node has not heard from all others), this may cause
        // the early events in `self.events_order` to be skipped mistakenly. To avoid this, if there
        // are any peers for which `peer_id` doesn't have a `last_ancestors` entry, add those peers'
        // oldest events we know about to the list of hashes.
        for (peer, events) in self.peer_list.iter() {
            if !peer_last_event.last_ancestors().contains_key(peer) {
                if let Some(hash) = events.get(&0) {
                    let _ = last_ancestors_hashes.insert(hash);
                }
            }
        }
        Ok(self
            .events_order
            .iter()
            .skip_while(move |hash| !last_ancestors_hashes.contains(hash))
            .filter_map(move |hash| self.get_known_event(hash).ok()))
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        if ::std::thread::panicking() {
            dump_graph::to_file(self.our_pub_id(), &self.events, &self.meta_votes);
        }
    }
}

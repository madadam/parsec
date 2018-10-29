// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_event::MetaEvent;
use super::meta_vote::MetaVote;
use hash::Hash;
use id::PublicId;
use network_event::NetworkEvent;
use observation::Observation;
use round_hash::RoundHash;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug};
use std::{iter, mem, usize};

/// Handle that uniquely identifies a `MetaElection`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub(crate) struct MetaElectionHandle(usize);

impl MetaElectionHandle {
    /// Handle to the current election.
    pub const CURRENT: Self = MetaElectionHandle(usize::MAX);
}

impl Debug for MetaElectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MetaElectionHandle(")?;

        if *self == Self::CURRENT {
            write!(f, "CURRENT")?
        } else {
            write!(f, "{}", self.0)?
        }

        write!(f, ")")
    }
}

#[serde(bound = "")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MetaElection<T: NetworkEvent, P: PublicId> {
    meta_events: BTreeMap<Hash, MetaEvent<T, P>>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<P, Vec<RoundHash>>,
    // Set of peers participating in this meta-election, i.e. all voters at the time this
    // meta-election has been created.
    all_voters: BTreeSet<P>,
    // Set of peers which we haven't yet detected deciding this meta-election.
    undecided_voters: BTreeSet<P>,
    // The hashes of events for each peer that have a non-empty set of `interesting_content`.
    interesting_events: BTreeMap<P, VecDeque<Hash>>,
    // Length of `MetaElections::consensus_history` at the time this meta-election was created.
    consensus_len: usize,
    // Payload decided by this meta-election.
    payload: Option<Observation<T, P>>,
}

impl<T: NetworkEvent, P: PublicId> MetaElection<T, P> {
    fn new(voters: BTreeSet<P>, consensus_len: usize) -> Self {
        MetaElection {
            meta_events: BTreeMap::new(),
            round_hashes: BTreeMap::new(),
            all_voters: voters.clone(),
            undecided_voters: voters,
            interesting_events: BTreeMap::new(),
            consensus_len,
            payload: None,
        }
    }

    fn initialise<'a, I>(&mut self, peer_ids: I, initial_hash: Hash)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        self.round_hashes = peer_ids
            .into_iter()
            .map(|peer_id| {
                let round_hash = RoundHash::new(peer_id, initial_hash);
                (peer_id.clone(), vec![round_hash])
            }).collect();

        // Clearing these caches is needed to be able to reprocess the whole graph outside of
        // consensus, which we sometimes need in tests.
        self.meta_events.clear();
        self.interesting_events.clear();
    }

    fn is_already_interesting_content(&self, creator: &P, payload: &Observation<T, P>) -> bool {
        self.interesting_events
            .get(creator)
            .map_or(false, |hashes| {
                hashes.iter().any(|hash| {
                    if let Some(meta_event) = self.meta_events.get(hash) {
                        meta_event.interesting_content.contains(payload)
                    } else {
                        false
                    }
                })
            })
    }
}

#[serde(bound = "")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MetaElections<T: NetworkEvent, P: PublicId> {
    // Index of next decided meta-election
    next_index: usize,
    // Current ongoing meta-election.
    current_election: MetaElection<T, P>,
    // Meta-elections that are already decided by us, but not by all the other peers.
    previous_elections: BTreeMap<MetaElectionHandle, MetaElection<T, P>>,
    // Hashes of the consensused blocks in the order they were consensused.
    consensus_history: Vec<Hash>,
}

impl<T: NetworkEvent, P: PublicId> MetaElections<T, P> {
    pub fn new(voters: BTreeSet<P>) -> Self {
        MetaElections {
            next_index: 0,
            current_election: MetaElection::new(voters, 0),
            previous_elections: BTreeMap::new(),
            consensus_history: Vec::new(),
        }
    }

    pub fn all<'a>(&'a self) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        self.previous_elections
            .keys()
            .cloned()
            .chain(iter::once(MetaElectionHandle::CURRENT))
    }

    /// Elections that were already decided by us, but not by the given peer.
    pub fn undecided_by<'a, 'b: 'a, 'c: 'a>(
        &'b self,
        peer_id: &'c P,
    ) -> impl Iterator<Item = MetaElectionHandle> + 'a {
        self.previous_elections
            .iter()
            .filter(move |(_, election)| election.undecided_voters.contains(peer_id))
            .map(|(handle, _)| *handle)
    }

    pub fn add_meta_event(
        &mut self,
        handle: MetaElectionHandle,
        event_hash: Hash,
        creator: P,
        meta_event: MetaEvent<T, P>,
    ) {
        let election = if let Some(election) = self.get_mut(handle) {
            election
        } else {
            return;
        };

        // Update round hashes.
        for (peer_id, event_votes) in &meta_event.meta_votes {
            let hashes = if let Some(hashes) = election.round_hashes.get_mut(&peer_id) {
                hashes
            } else {
                continue;
            };

            for meta_vote in event_votes {
                while hashes.len() < meta_vote.round + 1 {
                    let next_round_hash = hashes[hashes.len() - 1].increment_round();
                    hashes.push(next_round_hash);
                }
            }
        }

        // Update interesting events
        if !meta_event.interesting_content.is_empty() {
            election
                .interesting_events
                .entry(creator)
                .or_insert_with(VecDeque::new)
                .push_back(event_hash);
        }

        // Insert the meta-event itself.
        let _ = election.meta_events.insert(event_hash, meta_event);
    }

    pub fn meta_event(
        &self,
        handle: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Option<&MetaEvent<T, P>> {
        self.get(handle)
            .and_then(|election| election.meta_events.get(event_hash))
    }

    pub fn meta_votes(
        &self,
        handle: MetaElectionHandle,
        event_hash: &Hash,
    ) -> Option<&BTreeMap<P, Vec<MetaVote>>> {
        self.get(handle)
            .and_then(|election| election.meta_events.get(event_hash))
            .map(|meta_event| &meta_event.meta_votes)
    }

    pub fn round_hashes(&self, handle: MetaElectionHandle, peer_id: &P) -> Option<&Vec<RoundHash>> {
        self.get(handle).and_then(|e| e.round_hashes.get(peer_id))
    }

    /// Payload decided by the given meta-election, if any.
    pub fn decided_payload(&self, handle: MetaElectionHandle) -> Option<&Observation<T, P>> {
        self.get(handle)
            .and_then(|election| election.payload.as_ref())
    }

    /// List of voters participating in the given meta-election.
    pub fn voters(&self, handle: MetaElectionHandle) -> Option<&BTreeSet<P>> {
        self.get(handle).map(|election| &election.all_voters)
    }

    pub fn consensus_history(&self) -> &[Hash] {
        &self.consensus_history
    }

    pub fn interesting_events(
        &self,
        handle: MetaElectionHandle,
    ) -> impl Iterator<Item = (&P, &VecDeque<Hash>)> {
        self.get(handle)
            .into_iter()
            .flat_map(|election| &election.interesting_events)
    }

    pub fn first_interesting_content_by(
        &self,
        handle: MetaElectionHandle,
        creator: &P,
    ) -> Option<&Observation<T, P>> {
        let election = self.get(handle)?;
        let event_hash = election
            .interesting_events
            .get(creator)
            .and_then(VecDeque::front)?;
        let meta_event = election.meta_events.get(event_hash)?;

        meta_event.interesting_content.first()
    }

    /// Is the given payload candidate for being interesting from the point of view of an event by
    /// the given creator?
    pub fn is_interesting_content_candidate(
        &self,
        handle: MetaElectionHandle,
        creator: &P,
        payload: &Observation<T, P>,
    ) -> bool {
        let election = if let Some(election) = self.get(handle) {
            election
        } else {
            return false;
        };

        // Already interesting?
        if election.is_already_interesting_content(creator, payload) {
            return false;
        }

        // Already consensused?
        let hash = payload.create_hash();
        !self.consensus_history()[..election.consensus_len].contains(&hash)
    }

    /// Creates new election and returns handle of the previous election.
    pub fn new_election(
        &mut self,
        payload: Observation<T, P>,
        voters: BTreeSet<P>,
    ) -> MetaElectionHandle {
        let hash = payload.create_hash();
        self.consensus_history.push(hash);

        let new = MetaElection::new(voters, self.consensus_history.len());

        let mut previous = mem::replace(&mut self.current_election, new);
        previous.payload = Some(payload);

        let handle = self.next_handle();
        let _ = self.previous_elections.insert(handle, previous);

        handle
    }

    /// Mark the given election as decided by the given peer. If there are no more undecided peers,
    /// the election is removed.
    pub fn mark_as_decided(&mut self, handle: MetaElectionHandle, peer_id: &P) {
        if let Entry::Occupied(mut entry) = self.previous_elections.entry(handle) {
            let _ = entry.get_mut().undecided_voters.remove(peer_id);
            if entry.get().undecided_voters.is_empty() {
                let _ = entry.remove();
            }
        }

        // It's not an error to call this function on a meta-election that's already been removed.
    }

    pub fn handle_peer_removed(&mut self, peer_id: &P) {
        let _ = self.current_election.undecided_voters.remove(peer_id);

        let mut to_remove = Vec::new();
        for (handle, election) in &mut self.previous_elections {
            let _ = election.undecided_voters.remove(peer_id);
            if election.undecided_voters.is_empty() {
                to_remove.push(*handle);
            }
        }
        for handle in to_remove {
            let _ = self.previous_elections.remove(&handle);
        }
    }

    pub fn restart_current_election<'a, I>(&mut self, peer_ids: I)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let hash = self.consensus_history.last().cloned().unwrap_or(Hash::ZERO);
        self.current_election.initialise(peer_ids, hash);
    }

    pub fn initialise_current_election<'a, I>(&mut self, peer_ids: I, initial_hash: Hash)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        self.current_election.initialise(peer_ids, initial_hash);
    }

    pub fn current_meta_events(&self) -> &BTreeMap<Hash, MetaEvent<T, P>> {
        &self.current_election.meta_events
    }

    fn get(&self, handle: MetaElectionHandle) -> Option<&MetaElection<T, P>> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&self.current_election)
        } else if let Some(election) = self.previous_elections.get(&handle) {
            Some(election)
        } else {
            Self::not_found(handle);
            None
        }
    }

    fn get_mut(&mut self, handle: MetaElectionHandle) -> Option<&mut MetaElection<T, P>> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&mut self.current_election)
        } else if let Some(election) = self.previous_elections.get_mut(&handle) {
            Some(election)
        } else {
            Self::not_found(handle);
            None
        }
    }

    fn not_found(handle: MetaElectionHandle) {
        log_or_panic!("Meta-election at {:?} not found", handle);
    }

    fn next_handle(&mut self) -> MetaElectionHandle {
        let handle = MetaElectionHandle(self.next_index);

        if self.next_index == usize::MAX - 1 {
            self.next_index = 0;
        } else {
            self.next_index += 1;
        }

        handle
    }
}

#[cfg(test)]
impl<T: NetworkEvent, P: PublicId> MetaElections<T, P> {
    pub fn new_from_parsed<'a, I>(
        voters: I,
        meta_events: BTreeMap<Hash, MetaEvent<T, P>>,
        mut creators: BTreeMap<Hash, P>,
    ) -> Self
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let mut new = Self::new(voters.into_iter().cloned().collect());

        for (hash, meta_event) in &meta_events {
            if !meta_event.interesting_content.is_empty() {
                if let Some(creator) = creators.remove(hash) {
                    new.current_election
                        .interesting_events
                        .entry(creator)
                        .or_insert_with(VecDeque::new)
                        .push_back(*hash);
                }
            }
        }

        new.current_election.meta_events = meta_events;
        new
    }
}

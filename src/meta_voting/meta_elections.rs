// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_event::MetaEvent;
use super::meta_vote::MetaVote;
use gossip::EventIndex;
use id::PublicId;
use observation::ObservationHash;
use round_hash::RoundHash;
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Debug};
use std::{iter, mem, usize};

/// Handle that uniquely identifies a `MetaElection`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub(crate) struct MetaElectionHandle(pub(crate) usize);

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetaElection<P: PublicId> {
    pub(crate) meta_events: BTreeMap<EventIndex, MetaEvent<P>>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    pub(crate) round_hashes: BTreeMap<P, Vec<RoundHash>>,
    // Set of peers participating in this meta-election, i.e. all voters at the time this
    // meta-election has been created.
    pub(crate) all_voters: BTreeSet<P>,
    // Set of peers which we haven't yet detected deciding this meta-election.
    pub(crate) undecided_voters: BTreeSet<P>,
    // The indices of events for each peer that have a non-empty set of `interesting_content`.
    pub(crate) interesting_events: BTreeMap<P, VecDeque<EventIndex>>,
    // Length of `MetaElections::consensus_history` at the time this meta-election was created.
    pub(crate) consensus_len: usize,
    // Hash of the payload decided by this meta-election.
    pub(crate) payload_hash: Option<ObservationHash>,
    // Topological index of the first event processed in this meta-election.
    pub(crate) start_index: usize,
}

impl<P: PublicId> MetaElection<P> {
    fn new(voters: BTreeSet<P>, consensus_len: usize, start_index: usize) -> Self {
        MetaElection {
            meta_events: BTreeMap::new(),
            round_hashes: BTreeMap::new(),
            all_voters: voters.clone(),
            undecided_voters: voters,
            interesting_events: BTreeMap::new(),
            consensus_len,
            payload_hash: None,
            start_index,
        }
    }

    fn initialise<'a, I>(&mut self, peer_ids: I, initial_hash: ObservationHash)
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

    fn is_already_interesting(&self, creator: &P, payload_hash: &ObservationHash) -> bool {
        self.interesting_events
            .get(creator)
            .map_or(false, |indices| {
                indices.iter().any(|index| {
                    if let Some(meta_event) = self.meta_events.get(index) {
                        meta_event.interesting_content.contains(payload_hash)
                    } else {
                        false
                    }
                })
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetaElections<P: PublicId> {
    // Index of next decided meta-election
    next_index: usize,
    // Current ongoing meta-election.
    current_election: MetaElection<P>,
    // Meta-elections that are already decided by us, but not by all the other peers.
    previous_elections: BTreeMap<MetaElectionHandle, MetaElection<P>>,
    // Info of the consensused blocks' payloads in the order they were consensused.
    consensus_history: Vec<ConsensusInfo>,
}

impl<P: PublicId> MetaElections<P> {
    pub fn new(voters: BTreeSet<P>) -> Self {
        MetaElections {
            next_index: 0,
            current_election: MetaElection::new(voters, 0, 0),
            previous_elections: BTreeMap::new(),
            consensus_history: Vec::new(),
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn from_map_and_history(
        mut elections_map: BTreeMap<MetaElectionHandle, MetaElection<P>>,
        consensus_history: Vec<ConsensusInfo>,
    ) -> Self {
        let current_election = unwrap!(elections_map.remove(&MetaElectionHandle::CURRENT));
        MetaElections {
            next_index: consensus_history.len(),
            current_election,
            previous_elections: elections_map,
            consensus_history,
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

    pub fn preceding(&self, handle: MetaElectionHandle) -> Option<MetaElectionHandle> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.previous_elections
            .range((Unbounded, Excluded(&handle)))
            .rev()
            .map(|(handle, _)| *handle)
            .next()
    }

    pub fn add_meta_event(
        &mut self,
        handle: MetaElectionHandle,
        event_index: EventIndex,
        creator: P,
        meta_event: MetaEvent<P>,
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
                .push_back(event_index);
        }

        // Insert the meta-event itself.
        let _ = election.meta_events.insert(event_index, meta_event);
    }

    pub fn meta_event(
        &self,
        handle: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Option<&MetaEvent<P>> {
        self.get(handle)
            .and_then(|election| election.meta_events.get(&event_index))
    }

    pub fn meta_votes(
        &self,
        handle: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Option<&BTreeMap<P, Vec<MetaVote>>> {
        self.get(handle)
            .and_then(|election| election.meta_events.get(&event_index))
            .map(|meta_event| &meta_event.meta_votes)
    }

    pub fn round_hashes(&self, handle: MetaElectionHandle, peer_id: &P) -> Option<&Vec<RoundHash>> {
        self.get(handle).and_then(|e| e.round_hashes.get(peer_id))
    }

    /// Payload decided by the given meta-election, if any.
    pub fn decided_payload_hash(&self, handle: MetaElectionHandle) -> Option<&ObservationHash> {
        self.get(handle)
            .and_then(|election| election.payload_hash.as_ref())
    }

    /// List of voters participating in the given meta-election.
    pub fn voters(&self, handle: MetaElectionHandle) -> Option<&BTreeSet<P>> {
        self.get(handle).map(|election| &election.all_voters)
    }

    /// Number of voters participating in the given meta-election.
    pub fn voter_count(&self, handle: MetaElectionHandle) -> usize {
        self.get(handle)
            .map(|election| election.all_voters.len())
            .unwrap_or(0)
    }

    pub fn consensus_history(&self) -> &[ConsensusInfo] {
        &self.consensus_history
    }

    pub fn interesting_events(
        &self,
        handle: MetaElectionHandle,
    ) -> impl Iterator<Item = (&P, &VecDeque<EventIndex>)> {
        self.get(handle)
            .into_iter()
            .flat_map(|election| &election.interesting_events)
    }

    pub fn first_interesting_content_by(
        &self,
        handle: MetaElectionHandle,
        creator: &P,
    ) -> Option<&ObservationHash> {
        let election = self.get(handle)?;
        let event_hash = election
            .interesting_events
            .get(creator)
            .and_then(VecDeque::front)?;
        let meta_event = election.meta_events.get(event_hash)?;

        meta_event.interesting_content.first()
    }

    /// Is the payload with `payload_hash` carried by `carrier` candidate for being interesting from
    /// the point of view of an event by `creator`?
    /// Returns:
    ///     - `None`        - payload is definitely not interesting
    ///     - `Some(false)` - payload is potentially interesting and hasn't been consensused before
    ///     - `Some(true)`  - payload is potentially interesting and has been consensused before
    pub fn interesting_content_candidate_status(
        &self,
        handle: MetaElectionHandle,
        creator: &P,
        payload_hash: &ObservationHash,
        carrier: EventIndex,
    ) -> Option<bool> {
        let election = self.get(handle)?;

        // Already interesting?
        if election.is_already_interesting(creator, payload_hash) {
            return None;
        }

        // Already consensused?
        let mut consensused = false;
        for info in &self.consensus_history[..election.consensus_len] {
            if info.hash == *payload_hash {
                if info.carriers.contains(&carrier) {
                    // Consensused on the same event -> not interesting.
                    return None;
                } else {
                    // Consensused on different event.
                    consensused = true;
                }
            }
        }

        Some(consensused)
    }

    pub fn is_already_interesting(
        &self,
        handle: MetaElectionHandle,
        creator: &P,
        payload_hash: &ObservationHash,
    ) -> bool {
        self.get(handle)
            .map(|election| election.is_already_interesting(creator, payload_hash))
            .unwrap_or(false)
    }

    pub fn start_index(&self, handle: MetaElectionHandle) -> usize {
        self.get(handle).map(|e| e.start_index).unwrap_or(0)
    }

    /// Creates new election and returns handle of the previous election.
    pub fn new_election(
        &mut self,
        consensus_info: ConsensusInfo,
        voters: BTreeSet<P>,
        start_index: usize,
    ) -> MetaElectionHandle {
        let payload_hash = consensus_info.hash;
        self.consensus_history.push(consensus_info);

        let new = MetaElection::new(voters, self.consensus_history.len(), start_index);

        let mut previous = mem::replace(&mut self.current_election, new);
        previous.payload_hash = Some(payload_hash);

        let handle = self.next_handle();
        let _ = self.previous_elections.insert(handle, previous);

        handle
    }

    /// Mark the given election as decided by the given peer. If there are no more undecided peers,
    /// the election is removed.
    pub fn mark_as_decided(&mut self, handle: MetaElectionHandle, peer_id: &P) {
        trace!(
            "mark_as_decided: Marking meta-election {:?} as decided by {:?}",
            handle,
            peer_id
        );
        if let Entry::Occupied(mut entry) = self.previous_elections.entry(handle) {
            let _ = entry.get_mut().undecided_voters.remove(peer_id);
            if entry.get().undecided_voters.is_empty() {
                trace!("mark_as_decided: Removing meta-election {:?}", handle);
                let _ = entry.remove();
            }
        } else {
            Self::not_found(handle)
        }
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

    pub fn initialise_current_election<'a, I>(&mut self, peer_ids: I)
    where
        I: IntoIterator<Item = &'a P>,
        P: 'a,
    {
        let hash = self
            .consensus_history
            .last()
            .map(|info| info.hash)
            .unwrap_or(ObservationHash::ZERO);
        self.current_election.initialise(peer_ids, hash);
    }

    #[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
    pub fn current_meta_events(&self) -> &BTreeMap<EventIndex, MetaEvent<P>> {
        &self.current_election.meta_events
    }

    pub(crate) fn get(&self, handle: MetaElectionHandle) -> Option<&MetaElection<P>> {
        if handle == MetaElectionHandle::CURRENT {
            Some(&self.current_election)
        } else if let Some(election) = self.previous_elections.get(&handle) {
            Some(election)
        } else {
            Self::not_found(handle);
            None
        }
    }

    fn get_mut(&mut self, handle: MetaElectionHandle) -> Option<&mut MetaElection<P>> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConsensusInfo {
    pub hash: ObservationHash,
    pub carriers: BTreeSet<EventIndex>,
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::*;
    use gossip::{EventHash, Graph};
    use network_event::NetworkEvent;

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct MetaElectionsSnapshot<P: PublicId>(Vec<MetaElectionSnapshot<P>>);

    impl<P: PublicId> MetaElectionsSnapshot<P> {
        pub fn new<T: NetworkEvent>(
            meta_elections: &MetaElections<P>,
            graph: &Graph<T, P>,
        ) -> Self {
            MetaElectionsSnapshot(
                meta_elections
                    .all()
                    .filter_map(|handle| meta_elections.get(handle))
                    .map(|meta_election| MetaElectionSnapshot::new(meta_election, graph))
                    .collect(),
            )
        }
    }

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct MetaElectionSnapshot<P: PublicId> {
        meta_events: BTreeMap<EventHash, MetaEvent<P>>,
        round_hashes: BTreeMap<P, Vec<RoundHash>>,
        all_voters: BTreeSet<P>,
        interesting_events: BTreeMap<P, Vec<EventHash>>,
        consensus_len: usize,
        payload_hash: Option<ObservationHash>,
    }

    impl<P: PublicId> MetaElectionSnapshot<P> {
        pub fn new<T: NetworkEvent>(meta_election: &MetaElection<P>, graph: &Graph<T, P>) -> Self {
            let meta_events = meta_election
                .meta_events
                .iter()
                .filter_map(|(index, meta_event)| {
                    graph
                        .get(*index)
                        .map(|event| *event.hash())
                        .map(|hash| (hash, meta_event.clone()))
                }).collect();

            let interesting_events = meta_election
                .interesting_events
                .iter()
                .map(|(peer_id, indices)| {
                    let hashes = indices
                        .iter()
                        .filter_map(|index| graph.get(*index).map(|event| *event.hash()))
                        .collect();
                    (peer_id.clone(), hashes)
                }).collect();

            MetaElectionSnapshot {
                meta_events,
                round_hashes: meta_election.round_hashes.clone(),
                all_voters: meta_election.all_voters.clone(),
                interesting_events,
                consensus_len: meta_election.consensus_len,
                payload_hash: meta_election.payload_hash,
            }
        }
    }
}

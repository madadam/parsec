// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
use core::Core;
#[cfg(test)]
use dev_utils::ParsedContents;
use error::{Error, Result};
use gossip::{Event, PackedEvent, Request, Response};
use hash::Hash;
use id::SecretId;
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use observation::{Malice, Observation};
use peer_list::PeerState;
use std::collections::BTreeSet;
use std::mem;
use vote::Vote;

pub use core::{is_more_than_two_thirds, is_supermajority, IsInterestingEventFn};

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
///
/// Most public functions return an error if called after the owning node has been removed, i.e.
/// a block with payload `Observation::Remove(our_id)` has been made stable.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    core: Core<T, S>,
    // Accusations to raise at the end of the processing of current gossip message.
    pending_accusations: Vec<(S::PublicId, Malice)>,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        Self {
            core: Core::from_genesis(our_id, genesis_group, is_interesting_event),
            pending_accusations: vec![],
        }
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        Self {
            core: Core::from_existing(our_id, genesis_group, section, is_interesting_event),
            pending_accusations: vec![],
        }
    }

    /// Public id of this node.
    pub fn our_pub_id(&self) -> &S::PublicId {
        self.core.our_pub_id()
    }

    /// Adds a vote for `observation`.  Returns an error if we have already voted for this.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<()> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        let event = Event::new_from_observation(
            self.core.our_last_event_hash(),
            observation,
            self.core.events(),
            self.core.peer_list(),
        );
        self.add_event(event)
    }

    /// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
    /// that peer needs.  If `peer_id` is `None`, a message containing all known gossip events is
    /// returned.  If `peer_id` is `Some` and the given peer is not an active node, an error is
    /// returned.
    pub fn create_gossip(&self, peer_id: Option<&S::PublicId>) -> Result<Request<T, S::PublicId>> {
        self.confirm_self_state(PeerState::SEND)?;

        if let Some(ref recipient_id) = peer_id {
            // We require `PeerState::VOTE` in addition to `PeerState::RECV` here, because if the
            // peer does not have `PeerState::VOTE`, it means we haven't yet reached consensus on
            // adding them to the section so we shouldn't contact them yet.
            self.confirm_peer_state(recipient_id, PeerState::VOTE | PeerState::RECV)?;
        }

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        Ok(Request::new(self.core.events_to_gossip(peer_id)))
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

        Ok(Response::new(self.core.events_to_gossip(Some(src))))
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
        self.core.poll()
    }

    /// Check if we can vote (that is, we have reached a consensus on us being full member of the
    /// section).
    pub fn can_vote(&self) -> bool {
        self.core
            .peer_list()
            .peer_state(self.our_pub_id())
            .can_vote()
    }

    /// Checks if the given `observation` has already been voted for by us.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        self.core.have_voted_for(observation)
    }

    /// Check if there are any observation that have been voted for but not yet consensused.
    pub fn has_unconsensused_observations(&self) -> bool {
        self.core.has_unconsensused_observations()
    }

    /// Returns observations voted for by us which haven't been returned by `poll` yet.
    /// This includes observations that are either not yet consensused or that are already
    /// consensused, but not yet popped out of the consensus queue.
    ///
    /// The observations are sorted first by the consensus order, then by the vote order.
    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.core.our_unpolled_observations()
    }

    fn confirm_peer_state(&self, peer_id: &S::PublicId, required: PeerState) -> Result<()> {
        let actual = self.core.peer_list().peer_state(peer_id);
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
        let actual = self.core.peer_list().our_state();
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

    fn unpack_and_add_events(
        &mut self,
        src: &S::PublicId,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<BTreeSet<S::PublicId>> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src, PeerState::SEND)?;

        // We have received at least one gossip from the sender, so they can now receive gossips
        // from us as well.
        self.core.change_peer_state(src, PeerState::RECV);

        let mut forking_peers = BTreeSet::new();
        for packed_event in packed_events {
            if let Some(event) = self.core.unpack_event(packed_event, &mut forking_peers)? {
                self.add_event(event)?;
            }
        }

        Ok(forking_peers)
    }

    fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<()> {
        let our = event.creator() == self.our_pub_id();
        let event_hash = *event.hash();

        if !our {
            self.detect_malice_before_process(&event)?;
        }

        self.core.add_event(event)?;

        if !our {
            self.detect_malice_after_process(&event_hash);
        }

        Ok(())
    }

    fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Result<()> {
        let self_parent = self.core.our_last_event_hash();
        let other_parent = *self.core.peer_list().last_event(src).ok_or_else(|| {
            log_or_panic!("{:?} missing {:?} last event hash.", self.our_pub_id(), src);
            Error::Logic
        })?;

        let event = if is_request {
            Event::new_from_request(
                self_parent,
                other_parent,
                self.core.events(),
                self.core.peer_list(),
                forking_peers,
            )
        } else {
            Event::new_from_response(
                self_parent,
                other_parent,
                self.core.events(),
                self.core.peer_list(),
                forking_peers,
            )
        };

        self.add_event(event)
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
            .core
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
                .core
                .peer_list()
                .peer_events(event.creator())
                .rev()
                .filter(|hash| {
                    self.core
                        .get_known_event(hash)
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
            if let Some(other_parent) = self.core.other_parent(event) {
                (other_parent.index(), other_parent.creator().clone())
            } else {
                return;
            };
        let self_parent_ancestor_index = if let Some(index) = self
            .core
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
        if self.core.peer_list().last_event(event.creator()) != event.self_parent() {
            if let Some(self_parent_hash) = event.self_parent() {
                self.accuse(event.creator().clone(), Malice::Fork(*self_parent_hash));
            }
        }
    }

    fn detect_invalid_accusation(&mut self, event: &Event<T, S::PublicId>) {
        // We can't detect this type of malice for ourselves.
        if event.creator() == self.our_pub_id() {
            return;
        }

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
            .core
            .peer_list()
            .our_events()
            .rev()
            .filter_map(|hash| self.core.get_known_event(hash).ok())
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
            let event = if let Ok(event) = self.core.get_known_event(event_hash) {
                event
            } else {
                return;
            };

            let parent = if let Some(parent) = self.core.self_parent(event) {
                parent
            } else {
                // Must be the initial event, so there is nothing to detect.
                return;
            };

            let membership_list = if let Some(list) = self
                .core
                .peer_list()
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
            let detected =
                self.core
                    .peer_list()
                    .all_ids()
                    .filter(|peer_id| !membership_list.contains(peer_id))
                    .filter_map(|peer_id| {
                        event
                            .last_ancestors()
                            .get(peer_id)
                            .map(|index| (peer_id, *index))
                    }).flat_map(|(peer_id, index)| {
                        self.core.peer_list().events_by_index(peer_id, index)
                    }).filter_map(|hash| self.core.get_known_event(hash).ok())
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
        self.core
            .events()
            .values()
            .filter_map(|event| {
                if let Some(&Observation::Genesis(ref gen)) = event.vote().map(Vote::payload) {
                    Some(gen.iter().collect())
                } else {
                    None
                }
            }).next()
            .unwrap_or_else(|| self.core.peer_list().voter_ids().collect())
    }

    fn accuse(&mut self, offender: S::PublicId, malice: Malice) {
        self.pending_accusations.push((offender, malice));
    }

    fn create_accusation_event(&mut self, offender: S::PublicId, malice: Malice) -> Result<()> {
        let event = Event::new_from_observation(
            self.core.our_last_event_hash(),
            Observation::Accusation { offender, malice },
            self.core.events(),
            self.core.peer_list(),
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

#[cfg(test)]
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(parsed_contents: ParsedContents) -> Self {
        Self {
            core: Core::from_parsed_contents(parsed_contents),
            pending_accusations: vec![],
        }
    }
}

#[cfg(test)]
mod functional_tests {
    use super::*;
    use core::{self, functional_tests::Snapshot};
    use dev_utils::{parse_dot_file_with_test_name, parse_test_dot_file};
    use gossip::{find_event_by_short_name, Event};
    use mock::{self, Transaction};
    use peer_list::{PeerList, PeerState};

    fn snapshot(parsec: &Parsec<Transaction, PeerId>) -> Snapshot {
        Snapshot::new(&parsec.core)
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

    // Returns iterator over all votes cast by us.
    fn our_votes<T: NetworkEvent, S: SecretId>(
        parsec: &Parsec<T, S>,
    ) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        parsec
            .core
            .peer_list()
            .our_events()
            .filter_map(move |hash| parsec.core.get_known_event(hash).ok())
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
        core::initialise_membership_lists(&mut alice.core);
        let genesis_group: BTreeSet<_> = alice
            .core
            .peer_list()
            .all_ids()
            .into_iter()
            .cloned()
            .collect();

        let fred_id = PeerId::new("Fred");
        assert!(
            !alice
                .core
                .peer_list()
                .all_ids()
                .any(|peer_id| *peer_id == fred_id)
        );

        let alice_snapshot = snapshot(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&fred_id)));
        assert_eq!(alice_snapshot, snapshot(&alice));

        // Keep a copy of a request which will be used later in the test.  This request will not
        // include enough events to allow a joining peer to see "Fred" as a valid member.
        let deficient_message = unwrap!(alice.create_gossip(None));

        // Add events now as though Alice had received the request from Eric.  This should result in
        // Alice adding Fred.
        for event in final_events {
            unwrap!(alice.add_event(event));
            assert!(
                !alice
                    .core
                    .peer_list()
                    .all_ids()
                    .any(|peer_id| *peer_id == fred_id)
            );
        }

        unwrap!(alice.add_event(c_15));
        unwrap!(alice.add_event(e_14));
        unwrap!(alice.add_event(e_15));
        unwrap!(alice.create_sync_event(&PeerId::new("Eric"), true, &BTreeSet::new()));
        assert!(
            alice
                .core
                .peer_list()
                .all_ids()
                .any(|peer_id| *peer_id == fred_id)
        );

        // Construct Fred's Parsec instance.
        let mut fred =
            Parsec::from_existing(fred_id, &genesis_group, &genesis_group, is_supermajority);
        let fred_snapshot = snapshot(&fred);

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
        assert_eq!(fred_snapshot, snapshot(&fred));

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
        assert_eq!(fred_snapshot, snapshot(&fred));

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

        assert!(
            alice
                .core
                .peer_list()
                .all_ids()
                .any(|peer_id| *peer_id == eric_id)
        );
        assert_ne!(
            alice.core.peer_list().peer_state(&eric_id),
            PeerState::inactive()
        );

        // Add event now which shall result in Alice removing Eric.
        unwrap!(alice.add_event(a_last));
        assert_eq!(
            alice.core.peer_list().peer_state(&eric_id),
            PeerState::inactive()
        );

        // Try calling `create_gossip()` for Eric shall result in error.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&eric_id)));

        // Construct Eric's parsec instance.
        let mut section: BTreeSet<_> = alice.core.peer_list().all_ids().cloned().collect();
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
            eric.core.change_peer_state(peer_id, PeerState::RECV);
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
        core::initialise_membership_lists(&mut alice.core);
        alice.core.restart_consensus(); // This is needed so the AddPeer(Eric) is consensused.

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
        let a_0_hash = *core::nth_event(alice.core.events(), 0).hash();
        let a_1_hash = *core::nth_event(alice.core.events(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), genesis, None);
        assert!(!dave.core.has_event(&a_0_hash));
        assert!(!dave.core.has_event(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        unwrap!(dave.handle_request(&alice_id, message));
        assert!(dave.core.has_event(&a_0_hash));
        assert!(dave.core.has_event(&a_1_hash));

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
        let a_0_hash = *core::nth_event(alice.core.events(), 0).hash();
        let a_1_hash = *core::nth_event(alice.core.events(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), genesis, None);
        assert!(!dave.core.has_event(&a_0_hash));
        assert!(!dave.core.has_event(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        // Alice's genesis should be rejected as invalid
        assert_err!(Error::InvalidEvent, dave.handle_request(&alice_id, message));
        assert!(dave.core.has_event(&a_0_hash));
        // Dave's events shouldn't contain Alice's genesis because of the rejection
        assert!(!dave.core.has_event(&a_1_hash));

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
            carol.core.our_last_event_hash(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.core.events(),
            carol.core.peer_list(),
        );
        let first_duplicate_clone = Event::new_from_observation(
            carol.core.our_last_event_hash(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.core.events(),
            carol.core.peer_list(),
        );

        let first_duplicate_hash = *first_duplicate.hash();
        let _ = carol.core.add_event(first_duplicate);
        let second_duplicate = Event::new_from_observation(
            carol.core.our_last_event_hash(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.core.events(),
            carol.core.peer_list(),
        );

        // Check that the first duplicate triggers an accusation by Alice, but that the duplicate is
        // still added to the graph.
        let mut alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let carols_valid_vote_hash = *unwrap!(find_event_by_short_name(
            alice.core.events().values(),
            "C_7"
        )).hash();
        unwrap!(alice.add_event(first_duplicate_clone));
        let expected_accusations = vec![(
            carol.our_pub_id().clone(),
            Malice::DuplicateVote(carols_valid_vote_hash, first_duplicate_hash),
        )];
        assert_eq!(alice.pending_accusations, expected_accusations);
        assert!(alice.core.has_event(&first_duplicate_hash));

        // Check that the second one doesn't trigger any further accusation, but is also added to
        // the graph.
        let second_duplicate_hash = *second_duplicate.hash();
        unwrap!(alice.add_event(second_duplicate));
        assert_eq!(alice.pending_accusations, expected_accusations);
        assert!(alice.core.has_event(&second_duplicate_hash));
    }

    #[test]
    fn handle_malice_stale_other_parent() {
        // Carol will create event C_4 with other-parent as B_1, despite having C_3 with other-
        // parent as B_2.
        let carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        let c_3_hash = *unwrap!(find_event_by_short_name(
            carol.core.events().values(),
            "C_3"
        )).hash();
        let b_1_hash = *unwrap!(find_event_by_short_name(
            carol.core.events().values(),
            "B_1"
        )).hash();

        let c_4 = Event::new_from_request(
            c_3_hash,
            b_1_hash,
            carol.core.events(),
            carol.core.peer_list(),
            &BTreeSet::new(),
        );
        let c_4_hash = *c_4.hash();

        // Check that adding C_4 triggers an accusation by Alice, but that C_4 is still added to the
        // graph.
        let mut alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        core::initialise_membership_lists(&mut alice.core);

        let expected_accusations = vec![(
            carol.our_pub_id().clone(),
            Malice::StaleOtherParent(c_4_hash),
        )];
        unwrap!(alice.add_event(c_4));
        assert_eq!(alice.pending_accusations, expected_accusations);
        assert!(alice.core.has_event(&c_4_hash));
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
        assert!(alice.core.has_event(&a_6_hash));

        let mut carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        assert!(!carol.core.has_event(&a_6_hash));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(carol.our_pub_id())));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.core.has_event(&a_6_hash));

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
        core::initialise_membership_lists(&mut alice.core);
        let mut bob = Parsec::from_parsed_contents(parse_test_dot_file("bob.dot"));
        core::initialise_membership_lists(&mut bob.core);

        // Verify peer lists
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let mut alice_peer_list = PeerList::new(alice_id.clone());
        alice_peer_list.add_peer(alice_id.clone(), PeerState::active());
        alice_peer_list.add_peer(bob_id.clone(), PeerState::active());
        assert_eq!(
            alice.core.peer_list().peer_id_hashes().collect::<Vec<_>>(),
            alice_peer_list.peer_id_hashes().collect::<Vec<_>>()
        );
        let mut bob_peer_list = PeerList::new(bob_id.clone());
        bob_peer_list.add_peer(alice_id.clone(), PeerState::active());
        bob_peer_list.add_peer(bob_id.clone(), PeerState::active());
        assert_eq!(
            bob.core.peer_list().peer_id_hashes().collect::<Vec<_>>(),
            bob_peer_list.peer_id_hashes().collect::<Vec<_>>()
        );

        // Read the dot file again so we have a set of events we can manually add to Bob instead of
        // sending gossip.
        let mut alice_parsed_contents = parse_test_dot_file("alice.dot");

        // Carol is marked as active peer so that Bob's peer_list will accept C_0, but Carol is not
        // part of the membership_list
        let carol_id = PeerId::new("Carol");
        core::add_peer(&mut bob.core, carol_id, PeerState::active());
        let c_0_hash = *unwrap!(find_event_by_short_name(
            alice_parsed_contents.events.values(),
            "C_0"
        )).hash();
        let c_0 = unwrap!(alice_parsed_contents.events.remove(&c_0_hash));
        unwrap!(bob.add_event(c_0));

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
        assert!(bob.core.has_event(&a_2_hash));
    }

    #[test]
    fn unpolled_and_unconsensused_observations() {
        let mut alice_contents = parse_test_dot_file("alice.dot");
        let b_17 = unwrap!(alice_contents.remove_latest_event());

        let mut alice = Parsec::from_parsed_contents(alice_contents);
        alice.core.restart_consensus(); // This is needed so the Genesis observation is consensused.

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
        alice.core.restart_consensus(); // `Add(Eric)` is now consensused.
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
        assert!(alice.core.has_event(&a_11_hash));
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
        assert!(!bob.core.has_event(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.core.has_event(&invalid_accusation));

        let mut carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.core.has_event(&invalid_accusation));

        // Send gossip from Bob to Carol, remove the accusation event
        let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        let accusation_event = unwrap!(message.packed_events.pop());
        let bob_last_hash = unwrap!(accusation_event.self_parent());
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.core.has_event(&invalid_accusation));

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
        assert!(!carol.core.has_event(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.core.has_event(&invalid_accusation));

        let mut bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.core.has_event(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.core.has_event(&invalid_accusation));

        // Send gossip from Bob to Carol, remove the accusation event
        let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        let accusation_event = unwrap!(message.packed_events.pop());
        let bob_last_hash = unwrap!(accusation_event.self_parent());
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.core.has_event(&invalid_accusation));

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
        assert!(!carol.core.has_event(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.core.has_event(&invalid_accusation));

        let bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "parsec_functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.core.has_event(&invalid_accusation));

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
        let a_1_hash = *unwrap!(alice.core.peer_list().our_events().next());

        let a_2 = Event::new_from_observation(
            a_1_hash,
            Observation::OpaquePayload(Transaction::new("one")),
            &alice.core.events(),
            &alice.core.peer_list(),
        );
        let a_2_hash = *a_2.hash();
        unwrap!(alice.add_event(a_2));

        let a_3 = Event::new_from_observation(
            a_2_hash,
            Observation::OpaquePayload(Transaction::new("two")),
            &alice.core.events(),
            &alice.core.peer_list(),
        );
        let a_3_hash = *a_3.hash();
        unwrap!(alice.add_event(a_3));

        let mut bob = Parsec::from_genesis(bob_id.clone(), &genesis_group, is_supermajority);

        // Alice sends a gossip request to Bob and receives a response back.
        let req = unwrap!(alice.create_gossip(Some(&bob_id)));
        let res = unwrap!(bob.handle_request(&alice_id, req));
        unwrap!(alice.handle_response(&bob_id, res));

        // Now Bob has a_0, a_1, a_2 and a_3 and Alice knows it.
        assert!(bob.core.has_event(&a_1_hash));
        assert!(bob.core.has_event(&a_2_hash));
        assert!(bob.core.has_event(&a_3_hash));

        // Alice creates a fork.
        let a_2_fork = Event::new_from_observation(
            a_1_hash,
            Observation::OpaquePayload(Transaction::new("two-fork")),
            alice.core.events(),
            alice.core.peer_list(),
        );
        let a_2_fork_hash = *a_2_fork.hash();
        unwrap!(alice.add_event(a_2_fork));

        // Alice sends another gossip request to Bob.
        let req = unwrap!(alice.create_gossip(Some(&bob_id)));
        let _ = unwrap!(bob.handle_request(&alice_id, req));

        // Verify that Bob now has the forked event.
        assert!(bob.core.has_event(&a_2_fork_hash));
    }
}

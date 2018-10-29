// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for simulating malice in tests.

use block::Block;
use core::{self, Core};
use error::Result;
use gossip::{Event, PackedEvent};
use gossip::{Request, Response};
use hash::Hash;
use mock::{PeerId, Transaction};
use observation::Observation;
use peer_list::PeerState;
use rand::{Rng, SeedableRng, XorShiftRng};
use serialise;
use std::collections::BTreeSet;
use std::usize;

/// Scheduled malicious event.
#[derive(Clone, Debug)]
pub enum MaliceEvent {
    /// The next event created by the peer will be fork.
    Fork,
}

/// Implementation of the PARSEC algorithm that is capable of malice.
pub struct MaliciousParsec {
    core: Core<Transaction, PeerId>,
    scheduled_malice: Vec<(usize, MaliceEvent)>,
    next_malice: Option<MaliceEvent>,
    did_commit_malice: bool,
}

impl MaliciousParsec {
    pub fn from_existing(
        our_id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        section: &BTreeSet<PeerId>,
        mut scheduled_malice: Vec<(usize, MaliceEvent)>,
    ) -> Self {
        // Sort in descending order, so we can use `pop` to fetch the next event.
        scheduled_malice.sort_by_key(|&(step, _)| usize::MAX - step);

        Self {
            core: Core::from_existing(our_id, genesis_group, section, core::is_supermajority),
            scheduled_malice,
            next_malice: None,
            did_commit_malice: false,
        }
    }

    pub fn our_pub_id(&self) -> &PeerId {
        self.core.our_pub_id()
    }

    pub fn vote_for(&mut self, observation: Observation<Transaction, PeerId>) -> Result<()> {
        // println!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.core.confirm_self_state(PeerState::VOTE)?;

        let self_parent_hash = self.self_parent_for_next_event(&observation.create_hash());
        let event = Event::new_from_observation(
            self_parent_hash,
            observation,
            self.core.events(),
            self.core.peer_list(),
        );

        self.add_our_event(event)
    }

    pub fn have_voted_for(&self, observation: &Observation<Transaction, PeerId>) -> bool {
        self.core.have_voted_for(observation)
    }

    pub fn create_gossip(&self, peer_id: Option<&PeerId>) -> Result<Request<Transaction, PeerId>> {
        self.core.confirm_self_state(PeerState::SEND)?;
        if let Some(peer_id) = peer_id {
            self.core
                .confirm_peer_state(peer_id, PeerState::VOTE | PeerState::RECV)?;
        }

        // println!(
        //     "{:?} creating gossip request for {:?}",
        //     self.our_pub_id(),
        //     peer_id
        // );

        Ok(Request::new(self.core.events_to_gossip(peer_id)))
    }

    pub fn handle_request(
        &mut self,
        src: &PeerId,
        req: Request<Transaction, PeerId>,
    ) -> Result<Response<Transaction, PeerId>> {
        // println!(
        //     "{:?} received gossip request from {:?}",
        //     self.our_pub_id(),
        //     src
        // );

        let seed = Hash::from(serialise(&req).as_ref());
        let forking_peers = self.unpack_and_add_events(src, req.packed_events)?;
        self.create_sync_event(src, true, &forking_peers, &seed)?;

        Ok(Response::new(self.core.events_to_gossip(Some(src))))
    }

    pub fn handle_response(
        &mut self,
        src: &PeerId,
        res: Response<Transaction, PeerId>,
    ) -> Result<()> {
        // println!(
        //     "{:?} received gossip response from {:?}",
        //     self.our_pub_id(),
        //     src
        // );

        let seed = Hash::from(serialise(&res).as_ref());
        let forking_peers = self.unpack_and_add_events(src, res.packed_events)?;
        self.create_sync_event(src, false, &forking_peers, &seed)
    }

    pub fn poll(&mut self) -> Option<Block<Transaction, PeerId>> {
        self.core.poll()
    }

    pub fn prepare_malice(&mut self, step: usize) {
        if self.next_malice.is_none() && self
            .scheduled_malice
            .last()
            .map(|&(scheduled_step, _)| scheduled_step <= step)
            .unwrap_or(false)
        {
            self.next_malice = self.scheduled_malice.pop().map(|(_, event)| event);
        }
    }

    pub fn did_commit_malice(&self) -> bool {
        self.did_commit_malice
    }

    fn unpack_and_add_events(
        &mut self,
        src: &PeerId,
        packed_events: Vec<PackedEvent<Transaction, PeerId>>,
    ) -> Result<BTreeSet<PeerId>> {
        self.core.confirm_self_state(PeerState::RECV)?;
        self.core.confirm_peer_state(src, PeerState::SEND)?;
        self.core.change_peer_state(src, PeerState::RECV);

        let mut forking_peers = BTreeSet::new();
        for packed_event in packed_events {
            if let Some(event) = self.core.unpack_event(packed_event, &mut forking_peers)? {
                self.core.add_event(event)?;
            }
        }

        Ok(forking_peers)
    }

    fn create_sync_event(
        &mut self,
        src: &PeerId,
        is_request: bool,
        forking_peers: &BTreeSet<PeerId>,
        seed: &Hash,
    ) -> Result<()> {
        let self_parent = self.self_parent_for_next_event(seed);
        let other_parent = *unwrap!(
            self.core.peer_list().last_event(src),
            "{:?} missing {:?} last event hash.",
            self.our_pub_id(),
            src
        );

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

        self.add_our_event(event)
    }

    // Pick self-parent for the next event we create. Cause fork or other type of malice if
    // scheduled. Otherwise pick our last event.
    fn self_parent_for_next_event(&mut self, seed: &Hash) -> Hash {
        let mut rng = create_rng(seed);

        // First pick the index of the self-parent. If we have fork scheduled, pick a random one
        // between 0 (inclusive) and the last index (exclusive). Otherwise pick the last index.
        let index = {
            let mut indices = self
                .core
                .peer_list()
                .our_indexed_events()
                .rev()
                .map(|(index, _)| index);

            if let Some(MaliceEvent::Fork) = self.next_malice {
                let candidates: Vec<_> = indices.skip(1).collect();
                rng.choose(&candidates).cloned()
            } else {
                indices.next()
            }
        };

        let index = if let Some(index) = index { index } else { 0 };

        // Then if there are multiple events at the index (because of previous fork), randomly pick
        // one.
        let candidates: Vec<_> = self
            .core
            .peer_list()
            .events_by_index(self.our_pub_id(), index)
            .cloned()
            .collect();
        unwrap!(
            rng.choose(&candidates).cloned(),
            "{:?} has no events to pick self-parent from",
            self.our_pub_id()
        )
    }

    fn add_our_event(&mut self, event: Event<Transaction, PeerId>) -> Result<()> {
        if self.core.has_event(event.hash()) {
            return Ok(());
        }

        // Check malice
        let fork = self
            .core
            .peer_list()
            .last_events(self.our_pub_id())
            .all(|hash| event.self_parent() != Some(hash));
        if fork {
            self.next_malice = None;
            self.did_commit_malice = true;
        }

        self.core.add_event(event)
    }
}

// Create a random number generator seeded using the given hash.
fn create_rng(seed: &Hash) -> XorShiftRng {
    let bytes = seed.as_bytes();
    XorShiftRng::from_seed([
        u32_from_bytes(bytes[0], bytes[1], bytes[2], bytes[3]),
        u32_from_bytes(bytes[4], bytes[5], bytes[6], bytes[7]),
        u32_from_bytes(bytes[8], bytes[9], bytes[10], bytes[11]),
        u32_from_bytes(bytes[12], bytes[13], bytes[14], bytes[15]),
    ])
}

fn u32_from_bytes(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    (u32::from(b0) << 24) | (u32::from(b1) << 16) | (u32::from(b2) << 8) | u32::from(b3)
}

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
use rand::{Rng, SeedableRng, XorShiftRng};
use serialise;
use std::collections::BTreeSet;
use std::mem;
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
        }
    }

    pub fn our_pub_id(&self) -> &PeerId {
        self.core.our_pub_id()
    }

    pub fn vote_for(&mut self, observation: Observation<Transaction, PeerId>) -> Result<()> {
        let self_parent_hash = self.self_parent_for_next_event(&observation.create_hash());
        let event = Event::new_from_observation(
            self_parent_hash,
            observation,
            self.core.events(),
            self.core.peer_list(),
        );
        self.core.add_event(event)
    }

    pub fn have_voted_for(&self, observation: &Observation<Transaction, PeerId>) -> bool {
        self.core.have_voted_for(observation)
    }

    pub fn create_gossip(&self, peer_id: Option<&PeerId>) -> Result<Request<Transaction, PeerId>> {
        Ok(Request::new(self.core.events_to_gossip(peer_id)))
    }

    pub fn handle_request(
        &mut self,
        src: &PeerId,
        req: Request<Transaction, PeerId>,
    ) -> Result<Response<Transaction, PeerId>> {
        let seed = Hash::from(serialise(&req).as_ref());
        let forking_peers = self.unpack_and_add_events(req.packed_events)?;
        self.create_sync_event(src, true, &forking_peers, &seed)?;

        Ok(Response::new(self.core.events_to_gossip(Some(src))))
    }

    pub fn handle_response(
        &mut self,
        src: &PeerId,
        res: Response<Transaction, PeerId>,
    ) -> Result<()> {
        let seed = Hash::from(serialise(&res).as_ref());
        let forking_peers = self.unpack_and_add_events(res.packed_events)?;
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

    fn unpack_and_add_events(
        &mut self,
        packed_events: Vec<PackedEvent<Transaction, PeerId>>,
    ) -> Result<BTreeSet<PeerId>> {
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

        self.core.add_event(event)
    }

    // Pick self-parent for the next event we create. Cause fork or other type of malice if
    // scheduled. Otherwise pick our last event.
    fn self_parent_for_next_event(&mut self, seed: &Hash) -> Hash {
        let mut rng = create_rng(seed);

        // First pick the index of the self-parent. If we have fork scheduled, pick a random one
        // between 0 (inclusive) and the last index (exclusive). Otherwise pick the last index.
        let (index, fork) = {
            let mut indices = self
                .core
                .peer_list()
                .our_indexed_events()
                .map(|(index, _)| index);

            if let Some(MaliceEvent::Fork) = self.next_malice {
                let candidates: Vec<_> = indices.rev().skip(1).collect();
                (rng.choose(&candidates).cloned(), true)
            } else {
                (indices.next(), false)
            }
        };

        let index = if let Some(index) = index {
            if fork {
                self.next_malice = None;
            }

            index
        } else {
            0
        };

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
}

// Create a random number generator seeded using the given hash.
fn create_rng(seed: &Hash) -> XorShiftRng {
    let seed = [
        u32_from_bytes(&seed.as_bytes()[0..4]),
        u32_from_bytes(&seed.as_bytes()[4..8]),
        u32_from_bytes(&seed.as_bytes()[8..12]),
        u32_from_bytes(&seed.as_bytes()[12..16]),
    ];

    XorShiftRng::from_seed(seed)
}

#[allow(unsafe_code)]
#[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
fn u32_from_bytes(bytes: &[u8]) -> u32 {
    assert!(bytes.len() >= mem::size_of::<u32>());
    let ptr: *const _ = &bytes[0];
    unsafe { *(ptr as *const _) }
}

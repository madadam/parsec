// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::malice::{MaliceEvent, MaliciousParsec};
use super::Observation;
use block::Block;
use error::Result;
use gossip::{Request, Response};
use mock::{PeerId, Transaction};
use observation::Observation as ParsecObservation;
use parsec::{self, Parsec};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PeerStatus {
    Active,
    Pending,
    Removed,
    Failed,
}

pub struct Peer {
    /// The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    pub blocks: Vec<Block<Transaction, PeerId>>,
    pub status: PeerStatus,

    personality: Personality,
    votes_to_make: Vec<Observation>,
}

impl Peer {
    pub fn from_genesis(our_id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        Self {
            blocks: vec![],
            status: PeerStatus::Active,
            personality: Personality::Honest(Parsec::from_genesis(
                our_id,
                genesis_group,
                parsec::is_supermajority,
            )),
            votes_to_make: vec![],
        }
    }

    pub fn honest(
        our_id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        current_group: &BTreeSet<PeerId>,
    ) -> Self {
        Self {
            blocks: vec![],
            status: PeerStatus::Pending,
            personality: Personality::Honest(Parsec::from_existing(
                our_id,
                genesis_group,
                current_group,
                parsec::is_supermajority,
            )),
            votes_to_make: vec![],
        }
    }

    pub fn malicious(
        our_id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        current_group: &BTreeSet<PeerId>,
        malice_schedule: Vec<(usize, MaliceEvent)>,
    ) -> Self {
        Self {
            blocks: vec![],
            status: PeerStatus::Pending,
            personality: Personality::Malicious(MaliciousParsec::from_existing(
                our_id,
                genesis_group,
                current_group,
                malice_schedule,
            )),
            votes_to_make: vec![],
        }
    }

    pub fn id(&self) -> &PeerId {
        match self.personality {
            Personality::Honest(ref p) => p.our_pub_id(),
            Personality::Malicious(ref p) => p.our_pub_id(),
        }
    }

    pub fn vote_for(&mut self, observation: &Observation) {
        self.votes_to_make.push(observation.clone());
    }

    pub fn before_step(&mut self, step: usize) {
        match self.personality {
            Personality::Honest(ref mut p) => self
                .votes_to_make
                .retain(|obs| !p.have_voted_for(obs) && p.vote_for(obs.clone()).is_err()),
            Personality::Malicious(ref mut p) => {
                p.prepare_malice(step);
                self.votes_to_make
                    .retain(|obs| !p.have_voted_for(obs) && p.vote_for(obs.clone()).is_err());
            }
        }
    }

    pub fn poll(&mut self) {
        loop {
            let block = match self.personality {
                Personality::Honest(ref mut p) => p.poll(),
                Personality::Malicious(ref mut p) => p.poll(),
            };

            if let Some(block) = block {
                self.make_active_if_added(&block);
                self.blocks.push(block);
            } else {
                break;
            }
        }
    }

    pub fn create_gossip(&self, dst: &PeerId) -> Result<Request<Transaction, PeerId>> {
        match self.personality {
            Personality::Honest(ref p) => p.create_gossip(Some(dst)),
            Personality::Malicious(ref p) => p.create_gossip(Some(dst)),
        }
    }

    pub fn handle_request(
        &mut self,
        src: &PeerId,
        req: Request<Transaction, PeerId>,
    ) -> Result<Response<Transaction, PeerId>> {
        match self.personality {
            Personality::Honest(ref mut p) => p.handle_request(src, req),
            Personality::Malicious(ref mut p) => p.handle_request(src, req),
        }
    }

    pub fn handle_response(
        &mut self,
        src: &PeerId,
        res: Response<Transaction, PeerId>,
    ) -> Result<()> {
        match self.personality {
            Personality::Honest(ref mut p) => p.handle_response(src, res),
            Personality::Malicious(ref mut p) => p.handle_response(src, res),
        }
    }

    /// Returns self.blocks
    pub fn blocks(&self) -> &[Block<Transaction, PeerId>] {
        &self.blocks
    }

    /// Returns the payloads of `self.blocks` in the order in which they were returned by `poll()`.
    pub fn blocks_payloads(&self) -> Vec<&Observation> {
        self.blocks.iter().map(Block::payload).collect()
    }

    fn make_active_if_added(&mut self, block: &Block<Transaction, PeerId>) {
        if self.status == PeerStatus::Pending {
            if let ParsecObservation::Add(ref peer) = *block.payload() {
                if self.id() == peer {
                    self.status = PeerStatus::Active;
                }
            }
        }
    }
}

impl Debug for Peer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}: Blocks: {:?}", self.id(), self.blocks)
    }
}

enum Personality {
    Honest(Parsec<Transaction, PeerId>),
    Malicious(MaliciousParsec),
}

pub struct PeerStatuses(BTreeMap<PeerId, PeerStatus>);

impl PeerStatuses {
    /// Creates a new PeerStatuses struct with the given active peers
    pub fn new(names: &BTreeSet<PeerId>) -> PeerStatuses {
        PeerStatuses(
            names
                .into_iter()
                .map(|x| (x.clone(), PeerStatus::Active))
                .collect(),
        )
    }

    fn peers_by_status<F: Fn(&PeerStatus) -> bool>(
        &self,
        f: F,
    ) -> impl Iterator<Item = (&PeerId, &PeerStatus)> {
        self.0.iter().filter(move |&(_, status)| f(status))
    }

    fn choose_name_to_remove<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .peers_by_status(|s| *s == PeerStatus::Active || *s == PeerStatus::Failed)
            .map(|(id, _)| id)
            .collect();
        (*rng.choose(&names).unwrap()).clone()
    }

    fn choose_name_to_fail<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .peers_by_status(|s| *s == PeerStatus::Active)
            .map(|(id, _)| id)
            .collect();
        (*rng.choose(&names).unwrap()).clone()
    }

    fn num_active_peers(&self) -> usize {
        self.peers_by_status(|s| *s == PeerStatus::Active).count()
    }

    /// Returns an iterator through the list of the active peers
    pub fn active_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Active)
            .map(|(id, _)| id)
    }

    /// Returns an iterator through the list of the active peers
    pub fn present_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Active || *s == PeerStatus::Failed)
            .map(|(id, _)| id)
    }

    fn num_failed_peers(&self) -> usize {
        self.peers_by_status(|s| *s == PeerStatus::Failed).count()
    }

    /// Adds an active peer.
    pub fn add_peer(&mut self, p: PeerId) {
        let _ = self.0.insert(p, PeerStatus::Active);
    }

    // Randomly chooses a peer to remove. Only actually removes if removing won't cause the failed
    // peers to go over N/3.
    // Returns the removed peer's name if removing occurred.
    pub fn remove_random_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let mut active_peers = self.num_active_peers();
        let mut failed_peers = self.num_failed_peers();
        let name = self.choose_name_to_remove(rng);
        {
            let status = &self.0[&name];
            if *status == PeerStatus::Active {
                active_peers -= 1;
            } else if *status == PeerStatus::Failed {
                failed_peers -= 1;
            } else {
                return None;
            }
        }
        if 2 * failed_peers < active_peers && active_peers >= min_active {
            let status = self.0.get_mut(&name).unwrap();
            *status = PeerStatus::Removed;
            Some(name)
        } else {
            None
        }
    }

    /// Remove the given peer
    pub fn remove_peer(&mut self, peer: &PeerId) {
        let status = self.0.get_mut(peer).unwrap();
        *status = PeerStatus::Removed;
    }

    /// Randomly chooses a peer to fail. Only actually fails if it won't cause the failed peers to
    /// go over N/3.
    /// Returns the failed peer's name if failing occurred.
    pub fn fail_random_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let active_peers = self.num_active_peers() - 1;
        let failed_peers = self.num_failed_peers() + 1;
        if 2 * failed_peers < active_peers && active_peers >= min_active {
            let name = self.choose_name_to_fail(rng);
            let status = self.0.get_mut(&name).unwrap();
            *status = PeerStatus::Failed;
            Some(name)
        } else {
            None
        }
    }

    pub fn fail_peer(&mut self, peer: &PeerId) {
        let status = self.0.get_mut(peer).unwrap();
        *status = PeerStatus::Failed;
    }
}

impl Into<BTreeMap<PeerId, PeerStatus>> for PeerStatuses {
    fn into(self) -> BTreeMap<PeerId, PeerStatus> {
        self.0
    }
}

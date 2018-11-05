// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::peer::{Peer, PeerStatus};
use super::schedule::{RequestTiming, Schedule, ScheduleEvent};
use super::Observation;
use block::Block;
use error::Error;
use gossip::{Request, Response};
use mock::{PeerId, Transaction};
use observation::{Malice, Observation as ParsecObservation};
use parsec::is_supermajority;
use std::collections::{BTreeMap, BTreeSet};

enum Message {
    Request(Request<Transaction, PeerId>, usize),
    Response(Response<Transaction, PeerId>),
}

struct QueueEntry {
    pub sender: PeerId,
    pub message: Message,
    pub deliver_after: usize,
}

#[derive(Default)]
pub struct Network {
    pub peers: BTreeMap<PeerId, Peer>,
    genesis: BTreeSet<PeerId>,
    msg_queue: BTreeMap<PeerId, Vec<QueueEntry>>,
}

#[derive(Debug)]
pub struct BlocksOrder {
    peer: PeerId,
    order: Vec<Observation>,
}

#[derive(Debug)]
pub enum ConsensusError {
    DifferingBlocksOrder {
        order_1: BlocksOrder,
        order_2: BlocksOrder,
    },
    WrongBlocksNumber {
        expected: usize,
        got: usize,
    },
    WrongPeers {
        expected: BTreeMap<PeerId, PeerStatus>,
        got: BTreeMap<PeerId, PeerStatus>,
    },
    InvalidSignatory {
        observation: Observation,
        signatory: PeerId,
    },
    TooFewSignatures {
        observation: Observation,
        signatures: BTreeSet<PeerId>,
    },
    MissingAccusation(PeerId),
    InvalidAccusation {
        accuser: PeerId,
        accused: PeerId,
        malice: Malice,
    },
}

impl Network {
    /// Create an empty test network
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a test network with initial peers constructed from the given IDs
    pub fn with_peers<I: IntoIterator<Item = PeerId>>(all_ids: I) -> Self {
        let genesis_group = all_ids.into_iter().collect::<BTreeSet<_>>();
        let peers = genesis_group
            .iter()
            .map(|id| (id.clone(), Peer::from_genesis(id.clone(), &genesis_group)))
            .collect();
        Network {
            genesis: genesis_group,
            peers,
            msg_queue: BTreeMap::new(),
        }
    }

    fn active_honest_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers
            .values()
            .filter(|peer| !peer.is_malicious() && peer.status == PeerStatus::Active)
    }

    fn active_peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .values()
            .filter(|peer| peer.status == PeerStatus::Active)
            .map(|peer| peer.id())
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    fn blocks_all_in_sequence(&self) -> Result<(), ConsensusError> {
        let first_peer = unwrap!(self.active_honest_peers().next());
        let payloads = first_peer.blocks_payloads();
        if let Some(peer) = self
            .active_honest_peers()
            .find(|peer| peer.blocks_payloads() != payloads)
        {
            Err(ConsensusError::DifferingBlocksOrder {
                order_1: BlocksOrder {
                    peer: first_peer.id().clone(),
                    order: payloads.into_iter().cloned().collect(),
                },
                order_2: BlocksOrder {
                    peer: peer.id().clone(),
                    order: peer.blocks_payloads().into_iter().cloned().collect(),
                },
            })
        } else {
            Ok(())
        }
    }

    fn peer(&self, id: &PeerId) -> &Peer {
        unwrap!(self.peers.get(id))
    }

    fn peer_mut(&mut self, id: &PeerId) -> &mut Peer {
        unwrap!(self.peers.get_mut(id))
    }

    fn send_message(&mut self, src: PeerId, dst: &PeerId, message: Message, deliver_after: usize) {
        self.msg_queue
            .entry(dst.clone())
            .or_insert_with(Vec::new)
            .push(QueueEntry {
                sender: src,
                message,
                deliver_after,
            });
    }

    /// Handles incoming requests and responses
    fn handle_messages(&mut self, peer: &PeerId, step: usize) {
        if let Some(msgs) = self.msg_queue.remove(peer) {
            let (to_handle, rest) = msgs
                .into_iter()
                .partition(|entry| entry.deliver_after <= step);
            let _ = self.msg_queue.insert(peer.clone(), rest);
            for entry in to_handle {
                match entry.message {
                    Message::Request(req, resp_delay) => {
                        match self.peer_mut(peer).handle_request(&entry.sender, req) {
                            Ok(response) => {
                                self.send_message(
                                    peer.clone(),
                                    &entry.sender,
                                    Message::Response(response),
                                    step + resp_delay,
                                );
                            }
                            Err(Error::UnknownPeer)
                            | Err(Error::InvalidPeerState { .. })
                            | Err(Error::InvalidSelfState { .. }) => (),
                            Err(error) => panic!(
                                "{:?} failed to handle request from {:?}: {:?}",
                                peer, entry.sender, error
                            ),
                        }
                    }
                    Message::Response(resp) => {
                        match self.peer_mut(peer).handle_response(&entry.sender, resp) {
                            Ok(_)
                            | Err(Error::InvalidPeerState { .. })
                            | Err(Error::InvalidSelfState { .. }) => (),
                            Err(error) => panic!(
                                "{:?} failed to handle response from {:?}: {:?}",
                                peer, entry.sender, error
                            ),
                        }
                    }
                }
            }
        }
    }

    fn check_consensus_broken(&self) -> Result<(), ConsensusError> {
        let mut block_order = BTreeMap::new();
        for peer in self.active_honest_peers() {
            for (index, block) in peer.blocks_payloads().into_iter().enumerate() {
                if let Some((old_peer, old_index)) = block_order.insert(block, (peer, index)) {
                    if old_index != index {
                        // old index exists and isn't equal to the new one
                        return Err(ConsensusError::DifferingBlocksOrder {
                            order_1: BlocksOrder {
                                peer: peer.id().clone(),
                                order: peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                            order_2: BlocksOrder {
                                peer: old_peer.id().clone(),
                                order: old_peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn consensus_complete(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        num_expected_observations: usize,
    ) -> bool {
        self.check_consensus(expected_peers, num_expected_observations)
            .is_ok()
            && self.check_valid_accusations().is_ok()
    }

    /// Checks whether there is a right number of blocks and the blocks are in an agreeing order
    fn check_consensus(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        num_expected_observations: usize,
    ) -> Result<(), ConsensusError> {
        // Check the number of consensused blocks.
        // Skip accusations, because we can't predict in advance how many of those will be raised.
        let got = unwrap!(self.active_honest_peers().next())
            .blocks_payloads()
            .iter()
            .filter(|payload| match *payload {
                ParsecObservation::Accusation { .. } => false,
                _ => true,
            }).count();

        if num_expected_observations != got {
            return Err(ConsensusError::WrongBlocksNumber {
                expected: num_expected_observations,
                got,
            });
        }

        // Check peers.
        let got = self
            .peers
            .values()
            .map(|peer| (peer.id().clone(), peer.status))
            .collect();
        if *expected_peers != got {
            return Err(ConsensusError::WrongPeers {
                expected: expected_peers.clone(),
                got,
            });
        }

        // Check everybody has the same blocks in the same order.
        self.blocks_all_in_sequence()
    }

    fn check_block_signatories(
        block: &Block<Transaction, PeerId>,
        section: &BTreeSet<PeerId>,
    ) -> Result<(), ConsensusError> {
        let signatories: BTreeSet<_> = block
            .proofs()
            .into_iter()
            .map(|proof| proof.public_id())
            .collect();
        if let Some(&pub_id) = signatories.iter().find(|pub_id| !section.contains(pub_id)) {
            return Err(ConsensusError::InvalidSignatory {
                observation: block.payload().clone(),
                signatory: pub_id.clone(),
            });
        }
        if !is_supermajority(&signatories, &section.into_iter().collect()) {
            return Err(ConsensusError::TooFewSignatures {
                observation: block.payload().clone(),
                signatures: signatories.into_iter().cloned().collect(),
            });
        }
        Ok(())
    }

    /// Checks if the blocks are only signed by valid voters
    fn check_blocks_signatories(&self) -> Result<(), ConsensusError> {
        let blocks = self.active_honest_peers().next().unwrap().blocks();
        let mut valid_voters = BTreeSet::new();
        for block in blocks {
            match *block.payload() {
                ParsecObservation::Genesis(ref g) => {
                    // explicitly don't check signatories - the list of valid voters
                    // should be empty at this point
                    valid_voters = g.clone();
                }
                ParsecObservation::Add(ref p) => {
                    Self::check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.insert(p.clone());
                }
                ParsecObservation::Remove(ref p) => {
                    Self::check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.remove(p);
                }
                _ => {
                    Self::check_block_signatories(block, &valid_voters)?;
                }
            }
        }
        Ok(())
    }

    /// Checks that all malicious nodes have been accused.
    fn check_valid_accusations(&self) -> Result<(), ConsensusError> {
        let offenders = self
            .active_honest_peers()
            .next()
            .map(|peer| {
                peer.blocks_payloads()
                    .iter()
                    .filter_map(|payload| match payload {
                        ParsecObservation::Accusation { offender, .. } => Some(offender.clone()),
                        _ => None,
                    }).collect()
            }).unwrap_or_else(BTreeSet::new);

        for (peer_id, peer) in &self.peers {
            if peer.did_commit_malice() && !offenders.contains(peer_id) {
                return Err(ConsensusError::MissingAccusation(peer_id.clone()));
            }
        }

        Ok(())
    }

    /// Check that honest nodes have not been accused by other honest nodes.
    fn check_invalid_accusations(&self, peer_id: &PeerId) -> Result<(), ConsensusError> {
        let peer = self.peer(peer_id);

        // Accusations from malicious peers are "expected", so don't fail on them.
        if peer.is_malicious() {
            return Ok(());
        }

        // Fail if we find an accusation from honest peer against a peer that have not committed
        // malice yet.
        let invalid_accusation = peer.unpolled_accusations().find(|(offender, _)| {
            self.peers
                .get(offender)
                .map(|peer| !peer.did_commit_malice())
                .unwrap_or(false)
        });

        if let Some((offender, malice)) = invalid_accusation {
            return Err(ConsensusError::InvalidAccusation {
                accuser: peer.id().clone(),
                accused: offender.clone(),
                malice: malice.clone(),
            });
        } else {
            Ok(())
        }
    }

    /// Simulates the network according to the given schedule
    pub fn execute_schedule(&mut self, schedule: Schedule) -> Result<(), ConsensusError> {
        let Schedule {
            peers,
            num_observations,
            events,
        } = schedule;
        for event in events {
            match event {
                ScheduleEvent::Genesis(genesis_group) => {
                    let peers = genesis_group
                        .iter()
                        .map(|id| (id.clone(), Peer::from_genesis(id.clone(), &genesis_group)))
                        .collect();
                    self.peers = peers;
                    self.genesis = genesis_group;
                    // do a full reset while we're at it
                    self.msg_queue.clear();
                }
                ScheduleEvent::AddHonestPeer(peer) => {
                    let current_peers = self.active_peer_ids().cloned().collect();
                    let _ = self.peers.insert(
                        peer.clone(),
                        Peer::honest(peer.clone(), &self.genesis, &current_peers),
                    );
                }
                ScheduleEvent::AddMaliciousPeer(peer, schedule) => {
                    let current_peers = self.active_peer_ids().cloned().collect();
                    let _ = self.peers.insert(
                        peer.clone(),
                        Peer::malicious(peer.clone(), &self.genesis, &current_peers, schedule),
                    );
                }
                ScheduleEvent::RemovePeer(peer) => {
                    (*self.peer_mut(&peer)).status = PeerStatus::Removed;
                }
                ScheduleEvent::Fail(peer) => {
                    (*self.peer_mut(&peer)).status = PeerStatus::Failed;
                }
                ScheduleEvent::LocalStep {
                    global_step,
                    peer,
                    request_timing,
                } => {
                    self.peer_mut(&peer).before_step(global_step);
                    self.handle_messages(&peer, global_step);
                    self.peer_mut(&peer).poll();
                    self.check_invalid_accusations(&peer)?;

                    if let RequestTiming::DuringThisStep(req) = request_timing {
                        match self.peer(&peer).create_gossip(&req.recipient) {
                            Ok(request) => {
                                self.send_message(
                                    peer.clone(),
                                    &req.recipient,
                                    Message::Request(request, req.resp_delay),
                                    global_step + req.req_delay,
                                );
                            }
                            Err(Error::InvalidPeerState { .. })
                            | Err(Error::InvalidSelfState { .. }) => (),
                            Err(e) => panic!("{:?}", e),
                        }
                    }
                }
                ScheduleEvent::VoteFor(peer, observation) => {
                    self.peer_mut(&peer).vote_for(&observation);
                }
            }

            self.check_consensus_broken()?;
            if self.consensus_complete(&peers, num_observations) {
                break;
            }
        }

        self.check_consensus(&peers, num_observations)?;
        self.check_blocks_signatories()?;
        self.check_valid_accusations()
    }
}

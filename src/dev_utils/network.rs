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
use parsec::ConsensusMode;
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

pub struct Network {
    pub peers: BTreeMap<PeerId, Peer>,
    genesis: BTreeSet<PeerId>,
    msg_queue: BTreeMap<PeerId, Vec<QueueEntry>>,
    consensus_mode: ConsensusMode,
}

#[derive(Debug)]
pub struct BlocksOrder {
    peer: PeerId,
    order: Vec<BlockInfo>,
}

#[derive(Debug)]
pub struct BlockInfo {
    observation: Observation,
    voters: BTreeSet<PeerId>,
    excess: bool,
}

impl BlockInfo {
    fn new(block: &Block<Transaction, PeerId>) -> Self {
        Self {
            observation: block.payload().clone(),
            voters: block
                .proofs()
                .iter()
                .map(|proof| proof.public_id.clone())
                .collect(),
            excess: block.is_excess(),
        }
    }
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
    InvalidAccusation {
        accuser: PeerId,
        accused: PeerId,
        malice: Malice<Transaction, PeerId>,
    },
}

impl Network {
    /// Create an empty test network
    pub fn new(consensus_mode: ConsensusMode) -> Self {
        Network {
            peers: BTreeMap::new(),
            genesis: BTreeSet::new(),
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    /// Create a test network with initial peers constructed from the given IDs
    pub fn with_peers<I: IntoIterator<Item = PeerId>>(
        all_ids: I,
        consensus_mode: ConsensusMode,
    ) -> Self {
        let genesis_group = all_ids.into_iter().collect::<BTreeSet<_>>();
        let peers = genesis_group
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    Peer::from_genesis(id.clone(), &genesis_group, consensus_mode),
                )
            }).collect();
        Network {
            genesis: genesis_group,
            peers,
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    fn peers_with_status(&self, status: PeerStatus) -> impl Iterator<Item = &Peer> {
        self.peers
            .values()
            .filter(move |&peer| peer.status == status)
    }

    fn active_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers_with_status(PeerStatus::Active)
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    fn blocks_all_in_sequence(&self) -> Result<(), ConsensusError> {
        let first_peer = unwrap!(self.active_peers().next());
        let blocks = first_peer.blocks();
        if let Some(peer) = self.active_peers().find(|peer| peer.blocks() != blocks) {
            Err(ConsensusError::DifferingBlocksOrder {
                order_1: BlocksOrder {
                    peer: first_peer.id.clone(),
                    order: blocks.into_iter().map(BlockInfo::new).collect(),
                },
                order_2: BlocksOrder {
                    peer: peer.id.clone(),
                    order: peer.blocks().into_iter().map(BlockInfo::new).collect(),
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
        if self.peer(dst).status != PeerStatus::Active
            && self.peer(dst).status != PeerStatus::Pending
        {
            return;
        }
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
                    Message::Request(req, resp_delay) => match self
                        .peer_mut(peer)
                        .parsec
                        .handle_request(&entry.sender, req)
                    {
                        Ok(response) => {
                            self.send_message(
                                peer.clone(),
                                &entry.sender,
                                Message::Response(response),
                                step + resp_delay,
                            );
                        }
                        Err(Error::UnknownPeer) | Err(Error::InvalidPeerState { .. }) => (),
                        Err(e) => panic!("{:?}", e),
                    },
                    Message::Response(resp) => {
                        unwrap!(
                            self.peer_mut(peer)
                                .parsec
                                .handle_response(&entry.sender, resp)
                        );
                    }
                }
            }
        }
    }

    fn check_consensus_broken(&self) -> Result<(), ConsensusError> {
        let mut block_order = BTreeMap::new();
        for peer in self.active_peers() {
            for (index, block) in peer.blocks().into_iter().enumerate() {
                if let Some((old_peer, old_index)) = block_order.insert(block, (peer, index)) {
                    if old_index != index {
                        // old index exists and isn't equal to the new one
                        return Err(ConsensusError::DifferingBlocksOrder {
                            order_1: BlocksOrder {
                                peer: peer.id.clone(),
                                order: peer.blocks().into_iter().map(BlockInfo::new).collect(),
                            },
                            order_2: BlocksOrder {
                                peer: old_peer.id.clone(),
                                order: old_peer.blocks().into_iter().map(BlockInfo::new).collect(),
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
    }

    /// Checks whether there is a right number of blocks and the blocks are in an agreeing order
    fn check_consensus(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        num_expected_observations: usize,
    ) -> Result<(), ConsensusError> {
        // Check the number of consensused blocks (ignore excess blocks).
        let got = unwrap!(self.active_peers().next())
            .blocks()
            .iter()
            .filter(|block| !block.is_excess())
            .count();
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
            .map(|peer| (peer.id.clone(), peer.status))
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
        &self,
        block: &Block<Transaction, PeerId>,
        section: &BTreeSet<PeerId>,
    ) -> Result<(), ConsensusError> {
        let signatories: BTreeSet<_> = block
            .proofs()
            .into_iter()
            .map(|proof| proof.public_id().clone())
            .collect();
        if let Some(pub_id) = signatories.difference(section).next() {
            return Err(ConsensusError::InvalidSignatory {
                observation: block.payload().clone(),
                signatory: pub_id.clone(),
            });
        }

        let consensus_mode = if block.is_excess() {
            ConsensusMode::Single
        } else if let ParsecObservation::OpaquePayload(_) = *block.payload() {
            self.consensus_mode
        } else {
            ConsensusMode::Supermajority
        };
        let correct_signatories = consensus_mode.check(signatories.len(), section.len());
        if !correct_signatories {
            return Err(ConsensusError::TooFewSignatures {
                observation: block.payload().clone(),
                signatures: signatories,
            });
        }
        Ok(())
    }

    /// Checks if the blocks are only signed by valid voters
    fn check_blocks_signatories(&self) -> Result<(), ConsensusError> {
        let blocks = self.active_peers().next().unwrap().blocks();
        let mut valid_voters = BTreeSet::new();
        for block in blocks {
            match *block.payload() {
                ParsecObservation::Genesis(ref g) => {
                    // explicitly don't check signatories - the list of valid voters
                    // should be empty at this point
                    valid_voters = g.clone();
                }
                ParsecObservation::Add { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.insert(peer_id.clone());
                }
                ParsecObservation::Remove { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.remove(peer_id);
                }
                _ => {
                    self.check_block_signatories(block, &valid_voters)?;
                }
            }
        }
        Ok(())
    }

    /// Check that no node has been accused of malice.
    fn check_invalid_accusations(&self, peer_id: &PeerId) -> Result<(), ConsensusError> {
        let peer = self.peer(peer_id);

        let invalid_accusation = peer.unpolled_accusations().next();
        if let Some((offender, malice)) = invalid_accusation {
            return Err(ConsensusError::InvalidAccusation {
                accuser: peer.id.clone(),
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
                        .map(|id| {
                            (
                                id.clone(),
                                Peer::from_genesis(id.clone(), &genesis_group, self.consensus_mode),
                            )
                        }).collect();
                    self.peers = peers;
                    self.genesis = genesis_group;
                    // do a full reset while we're at it
                    self.msg_queue.clear();
                }
                ScheduleEvent::AddPeer(peer) => {
                    let current_peers = self
                        .peers
                        .values()
                        .filter(|peer| peer.status == PeerStatus::Active)
                        .map(|peer| peer.id.clone())
                        .collect();
                    let _ = self.peers.insert(
                        peer.clone(),
                        Peer::from_existing(
                            peer.clone(),
                            &self.genesis,
                            &current_peers,
                            self.consensus_mode,
                        ),
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
                    self.peer_mut(&peer).make_votes();
                    self.handle_messages(&peer, global_step);
                    self.peer_mut(&peer).poll();
                    self.check_invalid_accusations(&peer)?;

                    if let RequestTiming::DuringThisStep(req) = request_timing {
                        match self.peer(&peer).parsec.create_gossip(Some(&req.recipient)) {
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
        self.check_blocks_signatories()
    }
}

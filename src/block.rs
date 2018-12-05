// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use id::{Proof, PublicId};
use network_event::NetworkEvent;
use observation::Observation;
use std::collections::{BTreeMap, BTreeSet};
use vote::Vote;

/// A struct representing a collection of votes by peers for an `Observation`.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Block<T: NetworkEvent, P: PublicId> {
    payload: Observation<T, P>,
    proofs: BTreeSet<Proof<P>>,
    block_type: BlockType,
}

impl<T: NetworkEvent, P: PublicId> Block<T, P> {
    /// Creates a `Block` from `votes`.
    pub fn new(votes: &BTreeMap<P, Vote<T, P>>, block_type: BlockType) -> Result<Self, Error> {
        let payload = if let Some(vote) = votes.values().next() {
            vote.payload().clone()
        } else {
            return Err(Error::MissingVotes);
        };

        let proofs: Result<BTreeSet<_>, _> = votes
            .iter()
            .map(|(public_id, vote)| {
                if *vote.payload() == payload {
                    vote.create_proof(public_id)
                } else {
                    Err(Error::MismatchedPayload)
                }
            }).collect();
        let proofs = proofs?;

        Ok(Self {
            payload,
            proofs,
            block_type,
        })
    }

    /// Returns the payload of this block.
    pub fn payload(&self) -> &Observation<T, P> {
        &self.payload
    }

    /// Returns the proofs of this block.
    pub fn proofs(&self) -> &BTreeSet<Proof<P>> {
        &self.proofs
    }

    /// Returns iterator over ids of the peers that signed this block.
    pub fn signatories(&self) -> impl Iterator<Item = &P> {
        self.proofs.iter().map(|p| &p.public_id)
    }

    /// Type of this block: Regular or Excess
    pub fn block_type(&self) -> BlockType {
        self.block_type
    }

    /// Is this a regular block?
    pub fn is_regular(&self) -> bool {
        self.block_type == BlockType::Regular
    }

    /// Is this an excess block?
    pub fn is_excess(&self) -> bool {
        self.block_type == BlockType::Excess
    }

    /// Converts `vote` to a `Proof` and attempts to add it to the block.  Returns an error if
    /// `vote` is invalid (i.e. signature check fails or the `vote` is for a different network
    /// event), `Ok(true)` if the `Proof` wasn't previously held in this `Block`, or `Ok(false)` if
    /// it was previously held.
    pub fn add_vote(&mut self, peer_id: &P, vote: &Vote<T, P>) -> Result<bool, Error> {
        if &self.payload != vote.payload() {
            return Err(Error::MismatchedPayload);
        }
        let proof = vote.create_proof(peer_id)?;
        Ok(self.proofs.insert(proof))
    }

    /// Extract the payload and proofs from this block.
    pub fn into_payload_and_proofs(self) -> (Observation<T, P>, BTreeSet<Proof<P>>) {
        (self.payload, self.proofs)
    }
}

/// Type of a `Block`: Regular or Excess
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Debug)]
pub enum BlockType {
    /// Regular blocks are signed by the required number of peers.
    Regular,
    /// Excess blocks contain additional votes cast after the corresponding regular block was
    /// created.
    Excess,
}

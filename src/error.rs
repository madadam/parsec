// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::peer_list::PeerState;
use std::{
    fmt::{self, Display, Formatter},
    result,
};

/// Parsec error
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// Payload of a `Vote` doesn't match the payload of a `Block`.
    MismatchedPayload,
    /// Payload hash doesn't correspond to any payload known to us.
    UnknownPayload,
    /// Attempt to create a block with no votes.
    MissingVotes,
    /// Failed to verify signature.
    SignatureFailure,
    /// Peer is not known to our node.
    UnknownPeer,
    /// Peer is known to us, but has unexpected state.
    InvalidPeerState {
        /// State we require the peer to be in
        required: PeerState,
        /// Peers actual state
        actual: PeerState,
    },
    /// Our node is in unexpected state.
    InvalidSelfState {
        /// State we require us to be in
        required: PeerState,
        /// Our actual state
        actual: PeerState,
    },
    /// The given event is invalid or malformed.
    InvalidEvent,
    /// The event's self-parent is unknown to our node.
    UnknownSelfParent,
    /// The event's other-parent is unknown to our node.
    UnknownOtherParent,
    /// Our node has already voted for this network event.
    DuplicateVote,
    /// The peer sent a message to us before knowing we could handle it.
    PrematureGossip,
    /// The request or response is invalid.
    InvalidMessage,
    /// The request or response has already been handled by us.
    DuplicateMessage,
    /// Faild DKG process
    FailedDkg,
    /// We attempted to create a gossip but the recipient already knows everything we do.
    EmptyGossip,
    /// Logic error.
    Logic,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Error::MismatchedPayload => write!(
                f,
                "The payload of the vote doesn't match the payload of targeted block."
            ),
            Error::UnknownPayload => write!(
                f,
                "The payload hash doesn't correspond to any payload known to our node."
            ),
            Error::MissingVotes => write!(f, "Block cannot be created with no votes"),
            Error::SignatureFailure => write!(
                f,
                "The message or signature might be corrupted, or the signer is wrong."
            ),
            Error::UnknownPeer => write!(f, "The peer_id is not known to our node's peer_list."),
            Error::InvalidPeerState { required, actual } => write!(
                f,
                "The peer is in invalid state (required: {:?}, actual: {:?}).",
                required, actual
            ),
            Error::InvalidSelfState { required, actual } => write!(
                f,
                "Our node is in invalid state (required: {:?}, actual: {:?}).",
                required, actual
            ),
            Error::InvalidEvent => write!(f, "The given event is invalid or malformed."),
            Error::UnknownSelfParent => {
                write!(f, "The event's self-parent is unknown to this node.")
            }
            Error::UnknownOtherParent => {
                write!(f, "The event's other-parent is unknown to this node.")
            }
            Error::DuplicateVote => write!(f, "Our node has already voted for this network event."),
            Error::PrematureGossip => write!(
                f,
                "The peer did not know we could handle a message from it."
            ),
            Error::InvalidMessage => write!(f, "This non-empty message is invalid."),
            Error::DuplicateMessage => write!(f, "This message has already been handled."),
            Error::FailedDkg => write!(f, "The requested DKG could not proceed."),
            Error::EmptyGossip => write!(f, "The gossip message is empty"),
            Error::Logic => write!(
                f,
                "This is a logic error and represents a flaw in the code."
            ),
        }
    }
}

/// A specialised `Result` type for Parsec.
pub type Result<T> = result::Result<T, Error>;

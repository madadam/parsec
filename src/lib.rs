// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! This is an implementation of PARSEC (Protocol for Asynchronous, Reliable, Secure and Efficient
//! Consensus).  For details of the protocol, see
//! [the RFC](https://github.com/maidsafe/rfcs/tree/master/text/0049-parsec/0049-parsec.md) and
//! [the whitepaper](http://docs.maidsafe.net/Whitepapers/pdf/PARSEC.pdf).
//!
//! # What is a consensus protocol?
//!
//! Distributed systems consist of multiple processes, which we shall call "peers", which perform
//! calculations independently. Many distributed systems deal with some kind of state that is
//! shared between the peers. It is a big challenge in such a setting to make sure that all the
//! peers have the same notion of what this shared state is.
//!
//! Let us imagine a distributed system that controls some kinds of financial transactions. The
//! peers in the system maintain a record of who has how much money and when a client wants to
//! transfer some amount, they can contact any of them and place an order. A malicious party could
//! contact several peers and place different transfer orders, and if the peers can't agree about
//! their order, bad things can happen.
//!
//! For example, let us assume that Eve has £1000 and wants to cheat the system, so she contacts
//! one peer and tells it to transfer £1000 to Alice, then she contacts a second peer and tells it
//! to transfer £1000 to Bob. The system can't execute both orders, because Eve has insufficient
//! funds for that - the peers need to decide which of those two orders to approve, and all of them
//! have to make the same decision, or the shared state of account balances will no longer be
//! shared and the network will effectively split in two.
//!
//! This is where consensus protocols (or algorithms) come into play. They are sets of rules for
//! the peers to follow that let them _propose_ some values and make all the peers eventually
//! _decide_ on a value. They satisfy the following properties:
//!
//! * Validity - only a value proposed by a correct peer can be decided as the final value.
//! * Integrity - once a peer decides on a value, it never decides on another value.
//! * Agreement - all correct peers decide on the same value.
//! * Termination - all correct peers eventually decide on some value.
//!
//! Those properties talk of "correct" peers - that is because there is a class of consensus
//! protocols, called _Byzantine Fault Tolerant_ (BFT) protocols, that ensure all these properties
//! even if some peers in the system don't follow the protocol. Not following the protocol may come
//! in different flavours, for example, a peer can just fail and stop responding, or it might be
//! malicious and try to get other peers to disagree or to agree on some forged value. Correct
//! peers are the peers that follow the protocol, ie. they are neither failed, nor malicious.
//!
//! # Synchrony in consensus protocols
//!
//! Apart from whether a protocol is BFT or not, there is another important property of consensus
//! algorithms, and it is their synchrony assumptions.
//!
//! All consensus protocols require the peers in the system to exchange messages in order to arrive
//! at the final value. For example, the peers need to communicate the proposed values to each
//! other. However, no network works without delays and there is always some nonzero time interval
//! between the sending of a message and its reception. Various consensus protocols have various
//! limitations regarding these delays. There are a few main classes of protocols:
//!
//! * Synchronous - the delays in the network have to be bounded by a known value for the
//! properties mentioned above to hold. Such an assumption allows the peers to wait for a response
//! for a defined period. If they don't hear back from another peer during that period, they can
//! consider it failed.
//! * Partially synchronous - the delays in the network are assumed to be bounded, but the bound is
//! unknown. This means that we can't set a timeout ahead of time, so a different approach must be
//! taken. Timeouts are usually still employed, but a timeout doesn't necessarily mean a failure.
//! * Asynchronous - the delays in the network can be arbitrarily large. In fact, no assumptions
//! about them is made, the only assumption is that all messages are delivered eventually. In
//! particular, the delays can be controlled by a malicious adversary (for example, using a DDoS
//! attack).
//!
//! Protocols that work in an asynchronous setting are the most robust, and hence very much
//! desired. There are multiple such algorithms, but they are usually very complex or inefficient.
//!
//! # PARSEC
//!
//! The PARSEC consensus algorithm is Byzantine Fault Tolerant, and works under assumptions that
//! lie between partial synchrony and asynchrony (the precise synchrony assumption is still to be
//! determined). As such, it is suited for many cases where one would usually apply an asynchronous
//! protocol.
//!
//! In PARSEC, peers that are part of the system (often called a "section" in the code, after a
//! unit in SAFE Network) vote for transactions, and the output of the algorithm is a sequence of
//! blocks that contain these transactions in an agreed order.
//!
//! ## Usage
//!
//! The typical usage of the crate would consist of the following:
//!
//! * Calling [`Parsec::from_genesis`](struct.Parsec.html#method.from_genesis) if the peer is a
//! member of the initial section, or
//! [`Parsec::from_existing`](struct.Parsec.html#method.from_existing) if the peer joins an
//! existing section, to construct a `Parsec` instance.
//! * Calling [`Parsec::vote_for`](struct.Parsec.html#method.vote_for) whenever the peer is
//! supposed to vote for a transaction (be it an application-specific, opaque payload, or a section
//! mutation: a peer joining or being removed).
//! * Calling [`Parsec::create_gossip`](struct.Parsec.html#method.create_gossip) at random points
//! to exchange information with other peers. The function returns a message containing a gossip
//! request to be sent to the gossip partner.
//! * Calling [`Parsec::handle_request`](struct.Parsec.html#method.handle_request) when a gossip
//! request is received. This returns a response to be sent to the author of the request.
//! * Calling [`Parsec::handle_response`](struct.Parsec.html#method.handle_response) when a
//! response is received.
//! * Calling [`Parsec::poll`](struct.Parsec.html#method.poll) to see whether there are new agreed
//! blocks - this is typically called after `handle_request` or `handle_response` until it returns
//! `None`.
//!
//! The crate doesn't include any networking layer - sending and receiving messages is the
//! consumer's responsibility.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

#[cfg(any(test, feature = "dump-graphs", feature = "mock"))]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
#[cfg(any(test, feature = "testing"))]
extern crate pom;
#[cfg(feature = "testing")]
#[macro_use]
extern crate proptest as proptest_crate;
#[cfg(any(test, feature = "dump-graphs", feature = "mock"))]
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate tiny_keccak;
#[cfg(any(test, feature = "testing", feature = "dump-graphs"))]
#[macro_use]
extern crate unwrap;
#[cfg(any(test, feature = "mock"))]
extern crate safe_crypto;

mod block;
mod dump_graph;
mod error;
mod gossip;
mod hash;
mod id;
mod meta_voting;
mod network_event;
mod observation;
mod parsec;
mod peer_list;
mod round_hash;
mod vote;

#[cfg(all(test, feature = "mock"))]
mod functional_tests;

#[doc(hidden)]
#[cfg(any(test, feature = "testing"))]
pub mod dev_utils;

#[doc(hidden)]
/// **NOT FOR PRODUCTION USE**: Mock types which trivially implement the required Parsec traits.
///
/// This can be used to swap proper cryptographic functionality for inexpensive (in some cases
/// no-op) replacements.  This is useful to allow tests to run quickly, but should not be used
/// outside of testing code.
#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use block::{Block, BlockType};
#[cfg(feature = "dump-graphs")]
pub use dump_graph::DIR;
pub use error::{Error, Result};
pub use gossip::{EventHash, PackedEvent, Request, Response};
pub use id::{Proof, PublicId, SecretId};
pub use network_event::NetworkEvent;
pub use observation::{ConsensusMode, Malice, Observation};
pub use parsec::Parsec;
pub use vote::Vote;

use maidsafe_utilities::serialisation;
use serde::ser::Serialize;
use std::fmt::Debug;

fn serialise<T: Serialize + Debug>(data: &T) -> Vec<u8> {
    if let Ok(serialised) = serialisation::serialise(data) {
        serialised
    } else {
        log_or_panic!("Failed to serialise {:?}", data);
        vec![]
    }
}

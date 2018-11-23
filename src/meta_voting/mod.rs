// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod bool_set;
mod meta_elections;
mod meta_event;
mod meta_vote;
mod meta_vote_counts;

#[cfg(any(test, feature = "testing"))]
pub(crate) use self::bool_set::BoolSet;
#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) use self::meta_elections::snapshot::MetaElectionsSnapshot;
#[cfg(any(test, feature = "testing"))]
pub(crate) use self::meta_elections::MetaElection;
pub(crate) use self::meta_elections::{ConsensusInfo, MetaElectionHandle, MetaElections};
pub(crate) use self::meta_event::{MetaEvent, MetaEventBuilder};
#[cfg(feature = "dump-graphs")]
pub(crate) use self::meta_vote::MetaVotes;
pub(crate) use self::meta_vote::{MetaVote, Step};

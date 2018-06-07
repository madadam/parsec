// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::event::Event;
use gossip::packed_event::PackedEvent;
use id::PublicId;
use network_event::NetworkEvent;
use std::collections::BTreeMap;

/// A gossip request message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request<T: NetworkEvent, P: PublicId> {
    packed_events: Vec<PackedEvent<T, P>>,
}

impl<'a, T: 'a + NetworkEvent, P: 'a + PublicId> Request<T, P> {
    pub(crate) fn new<I: Iterator<Item = &'a Event<T, P>>>(events_iter: I) -> Self {
        Self {
            packed_events: events_iter.map(Event::pack).collect(),
        }
    }
}

impl<T: NetworkEvent, P: PublicId> Request<T, P> {
    pub(crate) fn unpack(self) -> Vec<Event<T, P>> {
        self.packed_events
            .into_iter()
            .filter_map(|packed| Event::unpack(packed).ok())
            .collect()
    }
}

/// A gossip response message.
#[serde(bound = "")]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response<T: NetworkEvent, P: PublicId> {
    packed_events: Vec<PackedEvent<T, P>>,
}

impl<'a, T: 'a + NetworkEvent, P: 'a + PublicId> Response<T, P> {
    pub(crate) fn new<I: Iterator<Item = &'a Event<T, P>>>(events_iter: I) -> Self {
        Self {
            packed_events: events_iter.map(Event::pack).collect(),
        }
    }
}

impl<T: NetworkEvent, P: PublicId> Response<T, P> {
    pub(crate) fn unpack(self) -> Vec<Event<T, P>> {
        self.packed_events
            .into_iter()
            .filter_map(|packed| Event::unpack(packed).ok())
            .collect()
    }
}

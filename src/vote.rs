// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use id::{Proof, PublicId, SecretId};
use network_event::NetworkEvent;
use observation::Observation;
use serialise;

/// A helper struct carrying an `Observation` and a signature of this `Observation`.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Vote<T: NetworkEvent, P: PublicId> {
    payload: Observation<T, P>,
    signature: P::Signature,
}

impl<T: NetworkEvent, P: PublicId> Vote<T, P> {
    /// Creates a `Vote` for `payload`.
    pub fn new<S: SecretId<PublicId = P>>(secret_id: &S, payload: Observation<T, P>) -> Self {
        let signature = secret_id.sign_detached(&serialise(&payload));
        Self { payload, signature }
    }

    /// Returns the payload being voted for.
    pub fn payload(&self) -> &Observation<T, P> {
        &self.payload
    }

    /// Returns the signature of this `Vote`'s payload.
    pub fn signature(&self) -> &P::Signature {
        &self.signature
    }

    /// Validates this `Vote`'s signature and payload against the given public ID.
    pub fn is_valid(&self, public_id: &P) -> bool {
        public_id.verify_signature(&self.signature, &serialise(&self.payload))
    }

    /// Creates a `Proof` from this `Vote`.  Returns `Err` if this `Vote` is not valid (i.e. if
    /// `!self.is_valid()`).
    pub fn create_proof(&self, public_id: P) -> Result<Proof<P>, Error> {
        if self.is_valid(&public_id) {
            return Ok(Proof {
                public_id,
                signature: self.signature.clone(),
            });
        }
        Err(Error::SignatureFailure)
    }
}

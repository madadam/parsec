// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use tiny_keccak;

const HASH_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; HASH_LEN]);

impl Hash {
    pub const ZERO: Self = Hash([0; HASH_LEN]);

    // Compares the distance of the arguments to `self`.  Returns `Less` if `lhs` is closer,
    // `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`.  (The XOR distance can only be
    // equal if the arguments are equal.)
    pub fn xor_cmp(&self, lhs: &Self, rhs: &Self) -> Ordering {
        for i in 0..HASH_LEN {
            if lhs.0[i] != rhs.0[i] {
                return Ord::cmp(&(lhs.0[i] ^ self.0[i]), &(rhs.0[i] ^ self.0[i]));
            }
        }
        Ordering::Equal
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for Hash {
    fn from(src: &'a [u8]) -> Self {
        Hash(tiny_keccak::sha3_256(src))
    }
}

impl Debug for Hash {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{:02x}{:02x}{:02x}{:02x}{:02x}..",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4]
        )
    }
}

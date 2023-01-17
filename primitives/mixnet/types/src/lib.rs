// This file is part of Substrate.

// Copyright (C) 2019-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Mixnet types used by both host and runtime.

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// Index of an authority in the authority list for a session.
pub type AuthorityIndex = u32;

/// X25519 public key used for key exchange between message senders and mixnodes (subset of
/// authorities). Authorities rotate and publish theirs on-chain every session, signed by a session
/// key. Message senders generate new keys for every message they send.
pub type KxPublic = [u8; 32];

#[derive(Decode, Encode)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
/// Mixnode information needed by message senders.
pub struct Mixnode {
	/// Index of mixnode in authority list. The session is implied by `kx_public`.
	pub authority_index: AuthorityIndex,
	/// Key-exchange public key for the mixnode.
	pub kx_public: KxPublic,
}

#[derive(Decode, Encode, PartialEq)]
/// Errors that may be returned when getting the key-exchange public key for a session.
pub enum KxPublicForSessionErr {
	/// The key for this session was discarded already.
	Discarded,
}

impl sp_std::fmt::Debug for KxPublicForSessionErr {
	fn fmt(&self, fmt: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		match self {
			KxPublicForSessionErr::Discarded => {
				write!(fmt, "The key pair was discarded due to age")
			},
		}
	}
}

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
pub use sp_core::offchain::OpaqueNetworkState;

#[derive(Decode, Encode)]
pub struct SessionStatus {
	/// Index of the current session. Should really be an `sp_session::SessionIndex`; it is a `u32` to
	/// avoid circular crate dependencies.
	pub current_index: u32,
	/// Are mixnode registrations for the next session closed? Once closed, the next mixnode set is
	/// fixed and will not change.
	pub next_registrations_closed: bool,
}

/// X25519 public key, for key exchange between message senders and mixnodes. Mixnodes rotate and
/// publish theirs on-chain every session. Message senders generate new keys for every message they
/// send.
pub type KxPublic = [u8; 32];

#[derive(Decode, Encode)]
/// Information published on-chain by each mixnode every session.
pub struct OpaqueMixnode {
	/// Key-exchange public key for the mixnode.
	pub kx_public: KxPublic,
	/// Mixnode network state (peer ID and multiaddrs).
	pub network_state: OpaqueNetworkState,
}

#[derive(Decode, Encode, PartialEq, Eq)]
/// Errors that may be returned when getting the key-exchange public key for a session.
pub enum KxPublicForSessionErr {
	/// The key for this session was discarded already.
	Discarded,
}

impl sp_std::fmt::Display for KxPublicForSessionErr {
	fn fmt(&self, fmt: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		match self {
			KxPublicForSessionErr::Discarded => {
				write!(fmt, "The key pair was discarded due to age")
			},
		}
	}
}

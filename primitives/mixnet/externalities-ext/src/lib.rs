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

//! Mixnet externalities extension for obtaining the key-exchange public keys for the local node.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_mixnet_types::{KxPublic, KxPublicForSessionError};

pub trait Mixnet: Send {
	/// Get the key-exchange public key for the local node in the specified session. Note that
	/// `session_index` should really be an `sp_session::SessionIndex`; it is a `u32` to avoid
	/// circular crate dependencies.
	fn kx_public_for_session(
		&self,
		session_index: u32,
	) -> Result<KxPublic, KxPublicForSessionError>;
}

#[cfg(feature = "std")]
sp_externalities::decl_extension! {
	/// The mixnet extension to retrieve the local node's key-exchange public keys.
	pub struct MixnetExt(Box<dyn Mixnet>);
}

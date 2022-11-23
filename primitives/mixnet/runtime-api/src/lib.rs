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

//! Runtime API for querying mixnet configuration.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_authority_discovery::AuthorityId as AuthorityDiscoveryId;
use sp_mixnet_types::Node;
use sp_session::SessionIndex;

sp_api::decl_runtime_apis! {
	pub trait MixnetApi {
		/// Get the index of the current session.
		fn current_session_index() -> SessionIndex;

		/// Get the authority discovery IDs for the previous session, in the original order (ie
		/// indexable by `AuthorityIndex`).
		fn prev_authority_discovery_ids() -> Vec<AuthorityDiscoveryId>;

		/// Get the authority discovery IDs for the current session, in the original order (ie
		/// indexable by `AuthorityIndex`).
		fn current_authority_discovery_ids() -> Vec<AuthorityDiscoveryId>;

		/// Get the authority discovery IDs for the next session, in the original order (ie
		/// indexable by `AuthorityIndex`).
		fn next_authority_discovery_ids() -> Vec<AuthorityDiscoveryId>;

		/// Get the mixnet node set for the current session. Message senders should always use this
		/// when sending messages. Mixnet nodes however should accept/forward messages constructed
		/// using the previous, current, or next node set. This is to allow for senders/nodes
		/// switching sessions at slightly different times, and for messages taking some time to
		/// traverse the mixnet.
		fn current_nodes() -> Vec<Node>;
	}
}

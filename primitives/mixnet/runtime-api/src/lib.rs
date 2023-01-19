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

use sp_mixnet_types::{OpaqueMixnode, SessionStatus};
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
	pub trait MixnetApi {
		/// Get the index of the current session and whether or not mixnode registrations for the next
		/// session are closed yet.
		fn session_status() -> SessionStatus;

        /// Get the mixnode set for the current session. Message senders should always use this
        /// when sending messages. Mixnodes however should accept/forward messages constructed
        /// using the previous, current, or next mixnode set, to the extent possible. This is to
		/// allow for senders/mixnodes switching sessions at slightly different times, and for
		/// messages taking some time to traverse the mixnet.
		fn current_mixnodes() -> Vec<OpaqueMixnode>;

		/// Returns the mixnodes currently registered for the next session. If
		/// `session_status().next_registrations_closed`, then this set is complete.
		fn next_mixnodes() -> Vec<OpaqueMixnode>;
	}
}

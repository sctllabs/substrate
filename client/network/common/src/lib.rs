// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Common data structures of the networking layer.

pub mod config;
pub mod error;
pub mod message;
pub mod protocol;
pub mod request_responses;
pub mod service;
pub mod sync;
pub mod utils;

/// Minimum Requirements for a Hash within Networking
pub trait ExHashT: std::hash::Hash + Eq + std::fmt::Debug + Clone + Send + Sync + 'static {}

impl<T> ExHashT for T where T: std::hash::Hash + Eq + std::fmt::Debug + Clone + Send + Sync + 'static
{}

use codec::{Decode, Encode};

// TODO move at proper place
/// Command for the mixnet worker.
pub enum MixnetCommand {
	/// Result of transaction to send back in mixnet.
	TransactionImportResult(Box<mixnet::SurbsPayload>, MixnetImportResult),
	/// Result of transaction to send back in mixnet.
	SendTransaction(
		Vec<u8>,
		mixnet::SendOptions,
		futures::channel::oneshot::Sender<Result<(), mixnet::Error>>,
	),
}

// TODO move at proper place
/// Result reported in surb for a transaction imported from a mixnet.
#[derive(Debug, Encode, Decode)]
pub enum MixnetImportResult {
	/// Succesfully managed transaction.
	Success,
	/// Could not decode.
	BadEncoding,
	/// Transaction is invalid.
	BadTransaction,
	/// Client error.
	Error,
	/// Import skipped.
	Skipped,
}

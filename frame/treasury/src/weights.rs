// This file is part of Substrate.

// Copyright (C) 2023 Parity Technologies (UK) Ltd.
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

//! Autogenerated weights for pallet_treasury
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-01-25, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `bm2`, CPU: `Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 1024

// Executed Command:
// ./target/production/substrate
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_treasury
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./frame/treasury/src/weights.rs
// --header=./HEADER-APACHE2
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_treasury.
pub trait WeightInfo {
	fn spend() -> Weight;
	fn propose_spend() -> Weight;
	fn reject_proposal() -> Weight;
	fn approve_proposal(p: u32, ) -> Weight;
	fn remove_approval() -> Weight;
	fn on_initialize_proposals(p: u32, ) -> Weight;
}

/// Weights for pallet_treasury using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	/// Storage: Treasury ProposalCount (r:1 w:1)
	/// Proof: Treasury ProposalCount (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// Storage: Treasury Proposals (r:0 w:1)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	fn spend() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1396`
		// Minimum execution time: 14_277 nanoseconds.
		Weight::from_parts(14_749_000, 1396)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	/// Storage: Treasury ProposalCount (r:1 w:1)
	/// Proof: Treasury ProposalCount (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	/// Storage: Treasury Proposals (r:0 w:1)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	fn propose_spend() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `175`
		//  Estimated: `499`
		// Minimum execution time: 23_297 nanoseconds.
		Weight::from_parts(23_585_000, 499)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: Treasury Proposals (r:1 w:1)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn reject_proposal() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `365`
		//  Estimated: `5186`
		// Minimum execution time: 23_996 nanoseconds.
		Weight::from_parts(24_548_000, 5186)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}
	/// Storage: Treasury Proposals (r:1 w:0)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// The range of component `p` is `[0, 99]`.
	fn approve_proposal(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `501 + p * (8 ±0)`
		//  Estimated: `3480`
		// Minimum execution time: 9_366 nanoseconds.
		Weight::from_parts(11_731_455, 3480)
			// Standard Error: 761
			.saturating_add(Weight::from_ref_time(21_665).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	fn remove_approval() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `127`
		//  Estimated: `897`
		// Minimum execution time: 7_012 nanoseconds.
		Weight::from_parts(7_270_000, 897)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	/// Storage: Treasury Deactivated (r:1 w:1)
	/// Proof: Treasury Deactivated (max_values: Some(1), max_size: Some(16), added: 511, mode: MaxEncodedLen)
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// Storage: Treasury Proposals (r:100 w:100)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	/// Storage: System Account (r:200 w:200)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	/// Storage: Bounties BountyApprovals (r:1 w:1)
	/// Proof: Bounties BountyApprovals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// The range of component `p` is `[0, 100]`.
	fn on_initialize_proposals(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `415 + p * (314 ±0)`
		//  Estimated: `2305 + p * (7789 ±0)`
		// Minimum execution time: 37_834 nanoseconds.
		Weight::from_parts(47_496_917, 2305)
			// Standard Error: 12_505
			.saturating_add(Weight::from_ref_time(26_902_474).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().reads((3_u64).saturating_mul(p.into())))
			.saturating_add(T::DbWeight::get().writes(3_u64))
			.saturating_add(T::DbWeight::get().writes((3_u64).saturating_mul(p.into())))
			.saturating_add(Weight::from_proof_size(7789).saturating_mul(p.into()))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	/// Storage: Treasury ProposalCount (r:1 w:1)
	/// Proof: Treasury ProposalCount (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// Storage: Treasury Proposals (r:0 w:1)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	fn spend() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `42`
		//  Estimated: `1396`
		// Minimum execution time: 14_277 nanoseconds.
		Weight::from_parts(14_749_000, 1396)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
	/// Storage: Treasury ProposalCount (r:1 w:1)
	/// Proof: Treasury ProposalCount (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	/// Storage: Treasury Proposals (r:0 w:1)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	fn propose_spend() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `175`
		//  Estimated: `499`
		// Minimum execution time: 23_297 nanoseconds.
		Weight::from_parts(23_585_000, 499)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	/// Storage: Treasury Proposals (r:1 w:1)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	/// Storage: System Account (r:1 w:1)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	fn reject_proposal() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `365`
		//  Estimated: `5186`
		// Minimum execution time: 23_996 nanoseconds.
		Weight::from_parts(24_548_000, 5186)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}
	/// Storage: Treasury Proposals (r:1 w:0)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// The range of component `p` is `[0, 99]`.
	fn approve_proposal(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `501 + p * (8 ±0)`
		//  Estimated: `3480`
		// Minimum execution time: 9_366 nanoseconds.
		Weight::from_parts(11_731_455, 3480)
			// Standard Error: 761
			.saturating_add(Weight::from_ref_time(21_665).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	fn remove_approval() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `127`
		//  Estimated: `897`
		// Minimum execution time: 7_012 nanoseconds.
		Weight::from_parts(7_270_000, 897)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	/// Storage: Treasury Deactivated (r:1 w:1)
	/// Proof: Treasury Deactivated (max_values: Some(1), max_size: Some(16), added: 511, mode: MaxEncodedLen)
	/// Storage: Treasury Approvals (r:1 w:1)
	/// Proof: Treasury Approvals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// Storage: Treasury Proposals (r:100 w:100)
	/// Proof: Treasury Proposals (max_values: None, max_size: Some(108), added: 2583, mode: MaxEncodedLen)
	/// Storage: System Account (r:200 w:200)
	/// Proof: System Account (max_values: None, max_size: Some(128), added: 2603, mode: MaxEncodedLen)
	/// Storage: Bounties BountyApprovals (r:1 w:1)
	/// Proof: Bounties BountyApprovals (max_values: Some(1), max_size: Some(402), added: 897, mode: MaxEncodedLen)
	/// The range of component `p` is `[0, 100]`.
	fn on_initialize_proposals(p: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `415 + p * (314 ±0)`
		//  Estimated: `2305 + p * (7789 ±0)`
		// Minimum execution time: 37_834 nanoseconds.
		Weight::from_parts(47_496_917, 2305)
			// Standard Error: 12_505
			.saturating_add(Weight::from_ref_time(26_902_474).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().reads((3_u64).saturating_mul(p.into())))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
			.saturating_add(RocksDbWeight::get().writes((3_u64).saturating_mul(p.into())))
			.saturating_add(Weight::from_proof_size(7789).saturating_mul(p.into()))
	}
}

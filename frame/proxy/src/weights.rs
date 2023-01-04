// This file is part of Substrate.

// Copyright (C) 2022 Parity Technologies (UK) Ltd.
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

//! Autogenerated weights for pallet_proxy
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-01-04, STEPS: `10`, REPEAT: 1, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! HOSTNAME: `6267FC`, CPU: `AMD Ryzen 5 PRO 3600 6-Core Processor`
//! EXECUTION: Some(Native), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 1024

// Executed Command:
// ./target/release/substrate
// benchmark
// pallet
// --chain=dev
// --steps=10
// --repeat=1
// --pallet=pallet_proxy
// --extrinsic=*
// --execution=native
// --heap-pages=4096
// --output=./frame/proxy/src/weights.rs
// --header=./HEADER-APACHE2
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_proxy.
pub trait WeightInfo {
	fn proxy(p: u32, ) -> Weight;
	fn proxy_announced(a: u32, p: u32, ) -> Weight;
	fn remove_announcement(a: u32, p: u32, ) -> Weight;
	fn reject_announcement(a: u32, p: u32, ) -> Weight;
	fn announce(a: u32, p: u32, ) -> Weight;
	fn add_proxy(p: u32, ) -> Weight;
	fn remove_proxy(p: u32, ) -> Weight;
	fn remove_proxies(p: u32, ) -> Weight;
	fn create_pure(p: u32, ) -> Weight;
	fn kill_pure(p: u32, ) -> Weight;
}

/// Weights for pallet_proxy using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	// Storage: Proxy Proxies (r:1 w:0)
	/// The range of component `p` is `[1, 31]`.
	fn proxy(p: u32, ) -> Weight {
		// Minimum execution time: 23_705 nanoseconds.
		Weight::from_ref_time(23_691_310)
			// Standard Error: 11_458
			.saturating_add(Weight::from_ref_time(57_152).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	// Storage: Proxy Proxies (r:1 w:0)
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn proxy_announced(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 40_207 nanoseconds.
		Weight::from_ref_time(40_126_099)
			// Standard Error: 47_650
			.saturating_add(Weight::from_ref_time(106_549).saturating_mul(a.into()))
			// Standard Error: 49_538
			.saturating_add(Weight::from_ref_time(16_586).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn remove_announcement(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 30_308 nanoseconds.
		Weight::from_ref_time(29_850_779)
			// Standard Error: 13_801
			.saturating_add(Weight::from_ref_time(83_388).saturating_mul(a.into()))
			// Standard Error: 14_348
			.saturating_add(Weight::from_ref_time(10_741).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn reject_announcement(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 29_747 nanoseconds.
		Weight::from_ref_time(29_501_296)
			// Standard Error: 13_508
			.saturating_add(Weight::from_ref_time(95_067).saturating_mul(a.into()))
			// Standard Error: 14_043
			.saturating_add(Weight::from_ref_time(14_565).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Proxies (r:1 w:0)
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn announce(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 35_527 nanoseconds.
		Weight::from_ref_time(34_856_531)
			// Standard Error: 16_754
			.saturating_add(Weight::from_ref_time(109_395).saturating_mul(a.into()))
			// Standard Error: 17_418
			.saturating_add(Weight::from_ref_time(70_873).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn add_proxy(p: u32, ) -> Weight {
		// Minimum execution time: 31_139 nanoseconds.
		Weight::from_ref_time(31_296_969)
			// Standard Error: 13_202
			.saturating_add(Weight::from_ref_time(56_358).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn remove_proxy(p: u32, ) -> Weight {
		// Minimum execution time: 31_039 nanoseconds.
		Weight::from_ref_time(31_040_160)
			// Standard Error: 7_291
			.saturating_add(Weight::from_ref_time(48_798).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn remove_proxies(p: u32, ) -> Weight {
		// Minimum execution time: 27_703 nanoseconds.
		Weight::from_ref_time(28_072_511)
			// Standard Error: 10_911
			.saturating_add(Weight::from_ref_time(67_757).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: unknown [0x3a65787472696e7369635f696e646578] (r:1 w:0)
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn create_pure(_p: u32, ) -> Weight {
		// Minimum execution time: 33_464 nanoseconds.
		Weight::from_ref_time(34_140_480)
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[0, 30]`.
	fn kill_pure(p: u32, ) -> Weight {
		// Minimum execution time: 29_456 nanoseconds.
		Weight::from_ref_time(30_332_887)
			// Standard Error: 47_773
			.saturating_add(Weight::from_ref_time(16_259).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	// Storage: Proxy Proxies (r:1 w:0)
	/// The range of component `p` is `[1, 31]`.
	fn proxy(p: u32, ) -> Weight {
		// Minimum execution time: 23_705 nanoseconds.
		Weight::from_ref_time(23_691_310)
			// Standard Error: 11_458
			.saturating_add(Weight::from_ref_time(57_152).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(1))
	}
	// Storage: Proxy Proxies (r:1 w:0)
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn proxy_announced(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 40_207 nanoseconds.
		Weight::from_ref_time(40_126_099)
			// Standard Error: 47_650
			.saturating_add(Weight::from_ref_time(106_549).saturating_mul(a.into()))
			// Standard Error: 49_538
			.saturating_add(Weight::from_ref_time(16_586).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().writes(2))
	}
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn remove_announcement(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 30_308 nanoseconds.
		Weight::from_ref_time(29_850_779)
			// Standard Error: 13_801
			.saturating_add(Weight::from_ref_time(83_388).saturating_mul(a.into()))
			// Standard Error: 14_348
			.saturating_add(Weight::from_ref_time(10_741).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(2))
	}
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn reject_announcement(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 29_747 nanoseconds.
		Weight::from_ref_time(29_501_296)
			// Standard Error: 13_508
			.saturating_add(Weight::from_ref_time(95_067).saturating_mul(a.into()))
			// Standard Error: 14_043
			.saturating_add(Weight::from_ref_time(14_565).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(2))
	}
	// Storage: Proxy Proxies (r:1 w:0)
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	/// The range of component `a` is `[0, 31]`.
	/// The range of component `p` is `[1, 31]`.
	fn announce(a: u32, p: u32, ) -> Weight {
		// Minimum execution time: 35_527 nanoseconds.
		Weight::from_ref_time(34_856_531)
			// Standard Error: 16_754
			.saturating_add(Weight::from_ref_time(109_395).saturating_mul(a.into()))
			// Standard Error: 17_418
			.saturating_add(Weight::from_ref_time(70_873).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(3))
			.saturating_add(RocksDbWeight::get().writes(2))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn add_proxy(p: u32, ) -> Weight {
		// Minimum execution time: 31_139 nanoseconds.
		Weight::from_ref_time(31_296_969)
			// Standard Error: 13_202
			.saturating_add(Weight::from_ref_time(56_358).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn remove_proxy(p: u32, ) -> Weight {
		// Minimum execution time: 31_039 nanoseconds.
		Weight::from_ref_time(31_040_160)
			// Standard Error: 7_291
			.saturating_add(Weight::from_ref_time(48_798).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn remove_proxies(p: u32, ) -> Weight {
		// Minimum execution time: 27_703 nanoseconds.
		Weight::from_ref_time(28_072_511)
			// Standard Error: 10_911
			.saturating_add(Weight::from_ref_time(67_757).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	// Storage: unknown [0x3a65787472696e7369635f696e646578] (r:1 w:0)
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[1, 31]`.
	fn create_pure(_p: u32, ) -> Weight {
		// Minimum execution time: 33_464 nanoseconds.
		Weight::from_ref_time(34_140_480)
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	/// The range of component `p` is `[0, 30]`.
	fn kill_pure(p: u32, ) -> Weight {
		// Minimum execution time: 29_456 nanoseconds.
		Weight::from_ref_time(30_332_887)
			// Standard Error: 47_773
			.saturating_add(Weight::from_ref_time(16_259).saturating_mul(p.into()))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}
}

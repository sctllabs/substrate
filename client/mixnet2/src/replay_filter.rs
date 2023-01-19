// This file is part of Substrate.

// Copyright (C) 2018-2022 Parity Technologies (UK) Ltd.
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

use rand::{rngs::OsRng, RngCore};
use siphasher::sip::SipHasher;
use std::hash::{Hash, Hasher};

// https://hur.st/bloomfilter/?n=7000000&p=&m=67108864&k=8
// The false positive rate is ~1% with 7m messages in the filter. 1% message loss per hop over 5
// hops gives ~5% message loss overall. The key-exchange keys are rotated every session. Polkadot
// sessions are 4 hours. To accumulate 7m messages over a session, we would need to process ~490
// messages per second.
const NUM_BITS: usize = 64 * 1024 * 1024;
const NUM_WORDS: usize = NUM_BITS / 64;
const NUM_HASHES: usize = 8;

pub struct ReplayFilter {
	hash_key: [u8; 16],
	/// Allocated on demand.
	words: Option<Box<[u64]>>,
}

impl ReplayFilter {
	fn new_with_hash_key(hash_key: [u8; 16]) -> Self {
		Self { hash_key, words: None }
	}

	pub fn new() -> Self {
		let mut hash_key = [0; 16];
		OsRng.fill_bytes(&mut hash_key);
		Self::new_with_hash_key(hash_key)
	}

	fn hash<T: Hash>(&self, value: &T) -> (u32, u32) {
		let mut hasher = SipHasher::new_with_key(&self.hash_key);
		value.hash(&mut hasher);
		let h = hasher.finish();
		(h as u32, (h >> 32) as u32)
	}

	pub fn insert<T: Hash>(&mut self, value: &T) {
		let (mut h, inc) = self.hash(value);
		let words = self.words.get_or_insert_with(|| vec![0; NUM_WORDS].into_boxed_slice());
		for _ in 0..NUM_HASHES {
			words[((h as usize) >> 6) % NUM_WORDS] |= 1 << (h & 63);
			h = h.wrapping_add(inc);
		}
	}

	pub fn contains<T: Hash>(&self, value: &T) -> bool {
		match &self.words {
			None => false,
			Some(words) => {
				let (mut h, inc) = self.hash(value);
				for _ in 0..NUM_HASHES {
					if (words[((h as usize) >> 6) % NUM_WORDS] & (1 << (h & 63))) == 0 {
						return false
					}
					h = h.wrapping_add(inc);
				}
				true
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::SeedableRng;

	#[test]
	fn basic_operation() {
		let mut rf = ReplayFilter::new_with_hash_key(Default::default());
		assert!(!rf.contains(&1));
		assert!(!rf.contains(&2));
		rf.insert(&1);
		assert!(rf.contains(&1));
		assert!(!rf.contains(&2));
	}

	#[test]
	fn false_positive_rate() {
		let mut rf = ReplayFilter::new_with_hash_key(Default::default());

		let mut rng = rand_xoshiro::Xoshiro256StarStar::seed_from_u64(0);
		for _ in 0..3_000_000 {
			rf.insert(&rng.next_u64());
		}

		{
			let mut rng = rand_xoshiro::Xoshiro256StarStar::seed_from_u64(0);
			for _ in 0..3_000_000 {
				assert!(rf.contains(&rng.next_u64()));
			}
		}

		// One of these randomly generated integers might actually match one we inserted earlier,
		// but this is much less likely than a false positive...
		let mut false_positives = 0;
		for _ in 0..1_000_000 {
			if rf.contains(&rng.next_u64()) {
				false_positives += 1;
			}
		}

		// The false positive rate should be about 1 in 15,000 with 3m messages in the filter. With
		// the seeds above we get 57 false positives among 1,000,000 random integers that (most
		// likely) aren't actually in the set...
		assert_eq!(false_positives, 57);
	}
}

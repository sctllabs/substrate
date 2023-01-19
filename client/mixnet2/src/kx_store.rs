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

//! Keystore for Sphinx key-exchange keys.
//!
//! A store is split into two parts: `KxPublicStore` and `KxStore`. `KxPublicStore` provides access
//! to the public keys and is intended to be shared among multiple threads. `KxStore` provides
//! access to the secret keys via a key-exchange function and is intended to be used by a single
//! thread.

use crate::replay_filter::ReplayFilter;
use rand::rngs::OsRng;
use sp_mixnet_externalities_ext::MixnetKxPublicStore;
use sp_mixnet_types::{KxPublic, KxPublicForSessionErr};
use sp_session::SessionIndex;
use std::{
	iter::Iterator,
	sync::{Arc, Mutex},
};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

struct SessionPublic {
	index: SessionIndex,
	public: KxPublic,
}

struct PendingSessionSecret {
	index: SessionIndex,
	/// Boxed to avoid leaving copies of the secret key around in memory if `PendingSessionSecret`
	/// is moved.
	secret: Box<StaticSecret>,
}

struct SessionSecret {
	index: SessionIndex,
	secret: Box<StaticSecret>,
	replay_filter: ReplayFilter,
}

impl From<PendingSessionSecret> for SessionSecret {
	fn from(p: PendingSessionSecret) -> Self {
		Self { index: p.index, secret: p.secret, replay_filter: ReplayFilter::new() }
	}
}

pub struct SessionExchange<'p, 's> {
	index: SessionIndex,
	shared_secret: SharedSecret,
	their_public: &'p KxPublic,
	replay_filter: &'s mut ReplayFilter,
}

impl<'p, 's> SessionExchange<'p, 's> {
	pub fn index(&self) -> SessionIndex {
		self.index
	}

	pub fn shared_secret(&self) -> &[u8; 32] {
		self.shared_secret.as_bytes()
	}

	pub fn prevent_replay(&mut self) {
		self.replay_filter.insert(self.their_public);
	}
}

struct KxPublicStoreInner {
	discarded_sessions_before: SessionIndex,
	/// Session public keys.
	session_publics: Vec<SessionPublic>,
	/// Session secret keys not yet added to the main store.
	pending_session_secrets: Vec<PendingSessionSecret>,
}

pub struct KxPublicStore(Mutex<KxPublicStoreInner>);

impl KxPublicStore {
	fn new() -> Self {
		Self(Mutex::new(KxPublicStoreInner {
			discarded_sessions_before: 0,
			session_publics: Vec::new(),
			pending_session_secrets: Vec::new(),
		}))
	}

	fn discard_sessions_before(&self, index: SessionIndex) {
		let mut inner = self.0.lock().unwrap();
		if index > inner.discarded_sessions_before {
			inner.discarded_sessions_before = index;
			inner.session_publics.retain(|s| s.index >= index);
			inner.pending_session_secrets.retain(|p| p.index >= index);
		}
	}

	fn take_pending_session_secrets(&self) -> Vec<PendingSessionSecret> {
		let mut inner = self.0.lock().unwrap();
		std::mem::replace(&mut inner.pending_session_secrets, Vec::new())
	}
}

impl MixnetKxPublicStore for KxPublicStore {
	fn public_for_session(&self, index: SessionIndex) -> Result<KxPublic, KxPublicForSessionErr> {
		let mut inner = self.0.lock().unwrap();

		if index < inner.discarded_sessions_before {
			return Err(KxPublicForSessionErr::Discarded)
		}

		// Search backwards as most likely to be looking up public key for latest session
		for s in (&inner.session_publics).iter().rev() {
			if s.index == index {
				return Ok(s.public)
			}
		}

		// We box the secret to avoid leaving copies of it in memory when wrapper types like
		// `PendingSessionSecret` are moved. Note that we will likely leave some copies on the
		// stack here; I'm not aware of any good way of avoiding this.
		let secret = Box::new(StaticSecret::new(OsRng));
		let public: PublicKey = secret.as_ref().into();
		let public = public.to_bytes();
		inner.session_publics.push(SessionPublic { index, public });
		inner.pending_session_secrets.push(PendingSessionSecret { index, secret });
		Ok(public)
	}
}

pub struct KxStore {
	public: Arc<KxPublicStore>,
	session_secrets: Vec<SessionSecret>,
}

impl KxStore {
	pub fn new() -> Self {
		Self { public: Arc::new(KxPublicStore::new()), session_secrets: Vec::new() }
	}

	pub fn public(&self) -> &Arc<KxPublicStore> {
		&self.public
	}

	/// Forget the keys for sessions before (but not including) `index`.
	pub fn discard_sessions_before(&mut self, index: SessionIndex) {
		self.public.discard_sessions_before(index);
		self.session_secrets.retain(|s| s.index >= index);
	}

	fn add_pending_session_secrets(&mut self) {
		for p in self.public.take_pending_session_secrets() {
			self.session_secrets.push(p.into());
		}
	}

	/// Performs key exchanges using the secret keys for the current, previous, and next sessions,
	/// in that order.
	pub fn session_exchanges<'p, 's>(
		&'s mut self,
		current_index: SessionIndex,
		their_public: &'p KxPublic,
	) -> impl Iterator<Item = SessionExchange<'p, 's>> {
		self.add_pending_session_secrets();

		let mut secrets = [None, None, None];
		for s in &mut self.session_secrets {
			if s.index == current_index {
				secrets[0] = Some(s);
			} else if current_index.saturating_sub(s.index) == 1 {
				secrets[1] = Some(s);
			} else if s.index.saturating_sub(current_index) == 1 {
				secrets[2] = Some(s);
			}
		}

		secrets.into_iter().flatten().filter_map(move |s| {
			if s.replay_filter.contains(their_public) {
				None
			} else {
				Some(SessionExchange {
					index: s.index,
					shared_secret: s.secret.diffie_hellman(&(*their_public).into()),
					their_public,
					replay_filter: &mut s.replay_filter,
				})
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	#[test]
	fn basic_operation() {
		let their_secret = StaticSecret::new(OsRng);
		let their_public: PublicKey = (&their_secret).into();

		let mut store = KxStore::new();

		let mut our_publics: HashMap<SessionIndex, KxPublic> = (0..2)
			.map(|index| (index, store.public().public_for_session(index).unwrap()))
			.collect();

		for mut exchange in store.session_exchanges(1, their_public.as_bytes()) {
			let our_public = our_publics.remove(&exchange.index()).unwrap();
			let shared_secret = their_secret.diffie_hellman(&our_public.into());
			assert_eq!(shared_secret.to_bytes(), *exchange.shared_secret());
			exchange.prevent_replay();
		}
		assert!(our_publics.is_empty());

		// Should not be possible to use same key again due to prevent_replay() calls...
		let mut exchanges = store.session_exchanges(1, their_public.as_bytes());
		assert!(exchanges.next().is_none());
	}

	#[test]
	fn session_discarding() {
		let mut store = KxStore::new();
		let public_0 = store.public().public_for_session(0).unwrap();
		assert_eq!(store.public().public_for_session(0), Ok(public_0));
		store.discard_sessions_before(1);
		assert_eq!(store.public().public_for_session(0), Err(KxPublicForSessionErr::Discarded));
	}
}

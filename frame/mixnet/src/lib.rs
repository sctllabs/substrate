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

#![cfg_attr(not(feature = "std"), no_std)]

use arrayref::array_refs;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
	traits::{EstimateNextSessionRotation, Get, OneSessionHandler, ValidatorSet},
	BoundedVec,
};
use frame_system::offchain::{SendTransactionTypes, SubmitTransaction};
pub use pallet::*;
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_application_crypto::RuntimeAppPublic;
use sp_arithmetic::{per_things::Permill, traits::AtLeast32BitUnsigned};
use sp_core::{
	offchain::{OpaqueMultiaddr, OpaqueNetworkState},
	OpaquePeerId,
};
use sp_io::MultiRemovalResults;
use sp_mixnet_types::{KxPublic, KxPublicForSessionErr, OpaqueMixnode, SessionStatus};
use sp_runtime::{
	offchain::storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
	RuntimeDebug,
};
use sp_session::SessionIndex;
use sp_std::vec::Vec;

mod app {
	use sp_application_crypto::{app_crypto, key_types::MIXNET, sr25519};
	app_crypto!(sr25519, MIXNET);
}

type AuthorityIndex = u32;
pub type AuthorityId = app::Public;
type AuthoritySignature = app::Signature;

#[derive(Clone, Decode, Encode, MaxEncodedLen, PartialEq, TypeInfo, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
/// Identical to `OpaqueMixnode`, but encoded size is bounded.
pub struct BoundedOpaqueMixnode<PeerId, Multiaddrs> {
	/// Key-exchange public key for the mixnode.
	pub kx_public: KxPublic,
	/// libp2p peer ID of the mixnode.
	pub peer_id: PeerId,
	/// libp2p multiaddrs for the mixnode.
	pub external_addresses: Multiaddrs,
}

impl<MaxPeerIdSize, MaxMultiaddrSize, MaxMultiaddrs> Into<OpaqueMixnode>
	for BoundedOpaqueMixnode<
		BoundedVec<u8, MaxPeerIdSize>,
		BoundedVec<BoundedVec<u8, MaxMultiaddrSize>, MaxMultiaddrs>,
	> where
	MaxPeerIdSize: Get<u32>,
	MaxMultiaddrSize: Get<u32>,
	MaxMultiaddrs: Get<u32>,
{
	fn into(self) -> OpaqueMixnode {
		OpaqueMixnode {
			kx_public: self.kx_public,
			network_state: OpaqueNetworkState {
				peer_id: OpaquePeerId(self.peer_id.into_inner()),
				external_addresses: self
					.external_addresses
					.into_iter()
					.map(|multiaddr| OpaqueMultiaddr(multiaddr.into_inner()))
					.collect(),
			},
		}
	}
}

pub type BoundedOpaqueMixnodeFor<T> = BoundedOpaqueMixnode<
	BoundedVec<u8, <T as Config>::MaxPeerIdSize>,
	BoundedVec<
		BoundedVec<u8, <T as Config>::MaxMultiaddrSize>,
		<T as Config>::MaxMultiaddrsPerMixnode,
	>,
>;

#[derive(Clone, Decode, Encode, PartialEq, TypeInfo, RuntimeDebug)]
pub struct Registration<BlockNumber, BoundedOpaqueMixnode> {
	/// Block number at the time of creation. When a registration transaction fails to make it on
	/// to the chain for whatever reason, we send out another one. We want this one to have a
	/// different hash in case the earlier transaction got banned somewhere; including the block
	/// number is a simple way of achieving this.
	pub block_number: BlockNumber,
	/// The session during which this registration should be processed. Note that on success the
	/// mixnode is registered for the _following_ session.
	pub session_index: SessionIndex,
	/// The index in the next session's authority list of the authority registering as a mixnode.
	pub authority_index: AuthorityIndex,
	/// Mixnode information to register for the following session.
	pub mixnode: BoundedOpaqueMixnode,
}

pub type RegistrationFor<T> =
	Registration<<T as frame_system::Config>::BlockNumber, BoundedOpaqueMixnodeFor<T>>;

#[derive(Decode, Encode)]
/// Details of registration attempt, recorded in offchain storage.
struct RegistrationAttempt<BlockNumber> {
	/// The block number at the time we sent the last registration transaction.
	block_number: BlockNumber,
	/// The index of the session during which we sent the last registration transaction.
	session_index: SessionIndex,
	/// The authority index we put in the last registration transaction.
	authority_index: AuthorityIndex,
	/// The authority ID we put in the last registration transaction.
	authority_id: AuthorityId,
}

impl<BlockNumber: AtLeast32BitUnsigned + Copy> RegistrationAttempt<BlockNumber> {
	fn ok_to_replace_with(&self, other: &Self) -> bool {
		if (self.session_index != other.session_index) ||
			(self.authority_index != other.authority_index) ||
			(self.authority_id != other.authority_id)
		{
			// Not equivalent; ok to replace
			return true
		}

		// Equivalent; ok to replace if we have waited long enough
		(self.block_number + 3_u32.into()) < other.block_number
	}
}

enum OffchainErr<BlockNumber> {
	RegistrationsClosed,
	WaitingForSessionProgress,
	NotAnAuthority,
	AlreadyRegistered,
	WaitingForInclusion(BlockNumber),
	LostRace,
	KxPublicForSessionFailed(KxPublicForSessionErr),
	NetworkStateFailed,
	NoMultiaddrs,
	PeerIdTooBig,
	MultiaddrsTooBig,
	SigningFailed,
	SubmitFailed,
}

impl<BlockNumber: sp_std::fmt::Debug> sp_std::fmt::Display for OffchainErr<BlockNumber> {
	fn fmt(&self, fmt: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		match self {
			OffchainErr::RegistrationsClosed =>
				write!(fmt, "Mixnode registrations closed for the next session"),
			OffchainErr::WaitingForSessionProgress => {
				write!(fmt, "Waiting for the session to progress further before registering")
			},
			OffchainErr::NotAnAuthority => write!(fmt, "Not an authority in the next session"),
			OffchainErr::AlreadyRegistered => {
				write!(fmt, "Already registered as a mixnode in the next session")
			},
			OffchainErr::WaitingForInclusion(block_number) =>
				write!(fmt, "Registration already sent at {:?}. Waiting for inclusion", block_number),
			OffchainErr::LostRace => write!(fmt, "Lost a race with another offchain worker"),
			OffchainErr::KxPublicForSessionFailed(err) => {
				write!(fmt, "Failed to get key-exchange public key for session: {}", err)
			},
			OffchainErr::NetworkStateFailed =>
				write!(fmt, "Failed to get peer ID and multiaddrs for the local node"),
			OffchainErr::NoMultiaddrs =>
				write!(fmt, "Don't have any multiaddrs for the local node"),
			OffchainErr::PeerIdTooBig =>
				write!(fmt, "Local node peer ID too big to fit in registration transaction"),
			OffchainErr::MultiaddrsTooBig => write!(
				fmt,
				"All multiaddrs for the local node too big to fit in registration transaction"
			),
			OffchainErr::SigningFailed => write!(fmt, "Failed to sign registration"),
			OffchainErr::SubmitFailed => write!(fmt, "Failed to submit registration transaction"),
		}
	}
}

type OffchainResult<T, R> = Result<R, OffchainErr<<T as frame_system::Config>::BlockNumber>>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config + SendTransactionTypes<Call<Self>> {
		#[pallet::constant]
		/// The maximum number of authorities per session.
		type MaxAuthorities: Get<AuthorityIndex>;

		#[pallet::constant]
		/// The maximum size of a mixnode's libp2p peer ID.
		type MaxPeerIdSize: Get<u32>;

		#[pallet::constant]
		/// The maximum size of one of a mixnode's libp2p multiaddrs.
		type MaxMultiaddrSize: Get<u32>;

		#[pallet::constant]
		/// The maximum number of multiaddrs for a mixnode.
		type MaxMultiaddrsPerMixnode: Get<u32>;

		/// Just for retrieving the current session index.
		type ValidatorSet: ValidatorSet<Self::AccountId>;

		/// Session progress/length estimation. Used to determine when to send registration
		/// transactions (we want these transactions to be roughly evenly spaced out over each
		/// session to avoid load spikes), the longevity of these transactions, and when to close
		/// registrations.
		type NextSessionRotation: EstimateNextSessionRotation<Self::BlockNumber>;

		#[pallet::constant]
		/// How far through a session to close mixnode registrations for the next session.
		type CloseRegistrationsAt: Get<Permill>;

		#[pallet::constant]
		/// Priority of unsigned transactions used to register mixnodes.
		type RegistrationPriority: Get<TransactionPriority>;
	}

	#[pallet::storage]
	/// Authority list for the next session.
	pub(crate) type NextAuthorityIds<T> = StorageMap<_, Identity, AuthorityIndex, AuthorityId>;

	#[pallet::storage]
	/// Are mixnode registrations for the next session closed yet?
	pub(crate) type NextRegistrationsClosed<T> = StorageValue<_, bool, ValueQuery>;

	#[pallet::storage]
	/// Mixnode set. Active during even sessions (0, 2, ...). Built during odd sessions.
	pub(crate) type EvenSessionMixnodes<T> =
		StorageMap<_, Identity, AuthorityIndex, BoundedOpaqueMixnodeFor<T>>;

	#[pallet::storage]
	/// Mixnode set. Active during odd sessions (1, 3, ...). Built during even sessions.
	pub(crate) type OddSessionMixnodes<T> =
		StorageMap<_, Identity, AuthorityIndex, BoundedOpaqueMixnodeFor<T>>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub mixnodes: BoundedVec<(AuthorityIndex, BoundedOpaqueMixnodeFor<T>), T::MaxAuthorities>,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self { mixnodes: Default::default() }
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			assert_eq!(
				T::ValidatorSet::session_index(),
				0,
				"Session index should be 0 in genesis block"
			);
			assert!(
				EvenSessionMixnodes::<T>::iter().next().is_none(),
				"Initial mixnodes already set"
			);
			assert!(
				OddSessionMixnodes::<T>::iter().next().is_none(),
				"Odd session mixnode set should be empty in genesis block"
			);
			for (authority_index, mixnode) in &self.mixnodes {
				EvenSessionMixnodes::<T>::insert(authority_index, mixnode);
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(1)] // TODO
		pub fn register(
			origin: OriginFor<T>,
			registration: RegistrationFor<T>,
			_signature: AuthoritySignature,
		) -> DispatchResult {
			ensure_none(origin)?;

			// Checked by ValidateUnsigned
			debug_assert_eq!(registration.session_index, T::ValidatorSet::session_index());
			debug_assert!(!NextRegistrationsClosed::<T>::get());
			debug_assert!(registration.authority_index < T::MaxAuthorities::get());

			// Note we are registering for the _following_ session, so the if appears to be
			// backwards...
			if (registration.session_index & 1) == 0 {
				OddSessionMixnodes::<T>::insert(registration.authority_index, registration.mixnode);
			} else {
				EvenSessionMixnodes::<T>::insert(
					registration.authority_index,
					registration.mixnode,
				);
			}

			Ok(())
		}
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			if let Self::Call::register { registration, signature } = call {
				// Check session index matches and registrations are still open
				if (registration.session_index != T::ValidatorSet::session_index()) ||
					NextRegistrationsClosed::<T>::get()
				{
					return InvalidTransaction::Stale.into()
				}

				// Check authority index is valid
				if registration.authority_index >= T::MaxAuthorities::get() {
					return InvalidTransaction::BadProof.into()
				}
				let authority_id = match NextAuthorityIds::<T>::get(registration.authority_index) {
					Some(id) => id,
					None => return InvalidTransaction::BadProof.into(),
				};

				// Check the authority hasn't registered yet
				if Self::already_registered(
					registration.session_index,
					registration.authority_index,
				) {
					return InvalidTransaction::Stale.into()
				}

				// Check signature
				let signature_ok = registration.using_encoded(|encoded_registration| {
					authority_id.verify(&encoded_registration, signature)
				});
				if !signature_ok {
					return InvalidTransaction::BadProof.into()
				}

				ValidTransaction::with_tag_prefix("Mixnet")
					.priority(T::RegistrationPriority::get())
					// Include both authority index _and_ ID in tag in case of forks with different
					// authority lists
					.and_provides((
						registration.session_index,
						registration.authority_index,
						authority_id,
					))
					.longevity(
						(T::NextSessionRotation::average_session_length() / 2_u32.into())
							.try_into()
							.unwrap_or(64_u64),
					)
					.build()
			} else {
				InvalidTransaction::Call.into()
			}
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
		fn on_finalize(block_number: T::BlockNumber) {
			let progress = if let (Some(progress), _weight) =
				T::NextSessionRotation::estimate_current_session_progress(block_number)
			{
				progress
			} else {
				// If we can't estimate session progress, registrations will never close early.
				// Things will still work, just possibly not as smoothly.
				return
			};

			if progress >= T::CloseRegistrationsAt::get() {
				NextRegistrationsClosed::<T>::put(true);
			}
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			// If the local node is not running as a validator, never try to register as a
			// mixnode...
			if sp_io::offchain::is_validator() {
				if let Err(err) = Self::maybe_register_local_node(block_number) {
					log::debug!(target: "runtime::mixnet",
						"Mixnet registration at {:?}: {}", block_number, err);
				}
			}
		}
	}
}

fn random_u64() -> u64 {
	let random = sp_io::offchain::random_seed();
	let (random, _) = array_refs![&random, 8, 24];
	u64::from_le_bytes(*random)
}

impl<T: Config> Pallet<T> {
	pub fn session_status() -> SessionStatus {
		SessionStatus {
			current_index: T::ValidatorSet::session_index(),
			next_registrations_closed: NextRegistrationsClosed::<T>::get(),
		}
	}

	fn mixnodes(next: bool) -> Vec<OpaqueMixnode> {
		if (T::ValidatorSet::session_index() & 1) == (next as u32) {
			EvenSessionMixnodes::<T>::iter_values()
		} else {
			OddSessionMixnodes::<T>::iter_values()
		}
		.map(Into::into)
		.collect()
	}

	pub fn current_mixnodes() -> Vec<OpaqueMixnode> {
		Self::mixnodes(false)
	}

	pub fn next_mixnodes() -> Vec<OpaqueMixnode> {
		Self::mixnodes(true)
	}

	/// Is now a good time to register the local node, considering only session progress?
	fn should_register_by_session_progress(block_number: T::BlockNumber) -> bool {
		let progress = if let (Some(progress), _weight) =
			T::NextSessionRotation::estimate_current_session_progress(block_number)
		{
			progress
		} else {
			// Things aren't going to work terribly well in this case as all the authorities will
			// just pile in at the start of each session...
			return true
		};

		// Don't try to register right at the start of a session; any nodes that aren't in the new
		// session yet will reject our registration transaction
		let begin = Permill::from_percent(5) * T::CloseRegistrationsAt::get();
		// Leave some time before registrations close; if we're too close our registration might not
		// make it on to the chain in time
		let end = Permill::from_percent(80) * T::CloseRegistrationsAt::get();

		if progress < begin {
			return false
		}
		if progress >= end {
			return true
		}

		let session_length = T::NextSessionRotation::average_session_length();
		let remaining_blocks = (end - progress).mul_ceil(session_length);
		// Want uniform distribution over the remaining blocks, so pick this block with probability
		// 1/remaining_blocks. This is slightly biased as remaining_blocks most likely won't divide
		// into 2^64, but it doesn't really matter...
		(random_u64() % remaining_blocks.try_into().unwrap_or(u64::MAX)) == 0
	}

	fn next_local_authority() -> Option<(AuthorityIndex, AuthorityId)> {
		// In the case where multiple local IDs are in the next authority set, we just return the
		// first one. There's (currently at least) no point in registering multiple times.
		let mut local_ids = AuthorityId::all();
		local_ids.sort();
		NextAuthorityIds::<T>::iter().find(|(_index, id)| local_ids.binary_search(id).is_ok())
	}

	// session_index must be the index of the current session
	fn already_registered(session_index: SessionIndex, authority_index: AuthorityIndex) -> bool {
		// Note that registration is for the _following_ session, so the if appears to be
		// backwards...
		if (session_index & 1) == 0 {
			OddSessionMixnodes::<T>::contains_key(authority_index)
		} else {
			EvenSessionMixnodes::<T>::contains_key(authority_index)
		}
	}

	/// Record `attempt` in the offchain database, failing if another equivalent registration
	/// attempt was recorded too recently, then call `f`. If `f` fails the recorded attempt is
	/// cleared.
	fn with_recorded_registration_attempt<R>(
		attempt: RegistrationAttempt<T::BlockNumber>,
		f: impl FnOnce() -> OffchainResult<T, R>,
	) -> OffchainResult<T, R> {
		let mut storage = StorageValueRef::persistent(b"parity/mixnet-registration-attempt");

		match storage.mutate(
			|prev_attempt: Result<
				Option<RegistrationAttempt<T::BlockNumber>>,
				StorageRetrievalError,
			>| {
				match prev_attempt {
					Ok(Some(prev_attempt)) if !prev_attempt.ok_to_replace_with(&attempt) =>
						Err(OffchainErr::WaitingForInclusion(prev_attempt.block_number)),
					_ => Ok(attempt),
				}
			},
		) {
			Ok(_) => (),
			Err(MutateStorageError::ConcurrentModification(_)) => return Err(OffchainErr::LostRace),
			Err(MutateStorageError::ValueFunctionFailed(err)) => return Err(err),
		}

		let res = f();
		if res.is_err() {
			storage.clear();
		}
		res
	}

	fn local_mixnode(session_index: SessionIndex) -> OffchainResult<T, BoundedOpaqueMixnodeFor<T>> {
		let kx_public = sp_io::mixnet_kx_public_store::public_for_session(session_index)
			.map_err(OffchainErr::KxPublicForSessionFailed)?;

		let network_state =
			sp_io::offchain::network_state().map_err(|_| OffchainErr::NetworkStateFailed)?;
		let peer_id = network_state.peer_id.0.try_into().map_err(|_| OffchainErr::PeerIdTooBig)?;
		if network_state.external_addresses.is_empty() {
			return Err(OffchainErr::NoMultiaddrs)
		}
		let external_addresses: BoundedVec<_, _> = network_state
			.external_addresses
			.into_iter()
			.flat_map(|multiaddr| multiaddr.0.try_into().ok())
			.take(T::MaxMultiaddrsPerMixnode::get() as usize)
			.collect::<Vec<_>>()
			.try_into()
			.expect("Excess multiaddrs discarded with take()");
		if external_addresses.is_empty() {
			return Err(OffchainErr::MultiaddrsTooBig)
		}

		Ok(BoundedOpaqueMixnode { kx_public, peer_id, external_addresses })
	}

	fn maybe_register_local_node(block_number: T::BlockNumber) -> OffchainResult<T, ()> {
		if NextRegistrationsClosed::<T>::get() {
			return Err(OffchainErr::RegistrationsClosed)
		}
		if !Self::should_register_by_session_progress(block_number) {
			// Don't want to register the local node right now
			return Err(OffchainErr::WaitingForSessionProgress)
		}

		let (authority_index, authority_id) = if let Some(authority) = Self::next_local_authority()
		{
			authority
		} else {
			// Not an authority in the next session
			return Err(OffchainErr::NotAnAuthority)
		};

		let session_index = T::ValidatorSet::session_index();
		if Self::already_registered(session_index, authority_index) {
			// Registration for the local node already on the chain
			return Err(OffchainErr::AlreadyRegistered)
		}

		let attempt = RegistrationAttempt {
			block_number,
			session_index,
			authority_index,
			authority_id: authority_id.clone(),
		};
		Self::with_recorded_registration_attempt(attempt, || {
			let mixnode = Self::local_mixnode(session_index)?;
			let registration =
				Registration { block_number, session_index, authority_index, mixnode };
			let signature =
				authority_id.sign(&registration.encode()).ok_or(OffchainErr::SigningFailed)?;
			let call = Call::register { registration, signature };
			SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
				.map_err(|_| OffchainErr::SubmitFailed)
		})
	}
}

impl<T: Config> sp_runtime::BoundToRuntimeAppPublic for Pallet<T> {
	type Public = AuthorityId;
}

fn check_removed_all(res: MultiRemovalResults) {
	debug_assert!(res.maybe_cursor.is_none());
}

impl<T: Config> OneSessionHandler<T::AccountId> for Pallet<T> {
	type Key = AuthorityId;

	fn on_genesis_session<'a, I: 'a>(validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, Self::Key)>,
	{
		assert!(
			NextAuthorityIds::<T>::iter().next().is_none(),
			"Initial authority IDs already set"
		);
		for (i, (_, authority_id)) in validators.enumerate() {
			NextAuthorityIds::<T>::insert(i as AuthorityIndex, authority_id);
		}
	}

	fn on_new_session<'a, I: 'a>(changed: bool, _validators: I, queued_validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, Self::Key)>,
	{
		// Clear mixnode set for the _following_ session. Note that we do this even if the
		// validator set is not going to change; the key-exchange public keys are still rotated.
		if (T::ValidatorSet::session_index() & 1) == 0 {
			check_removed_all(OddSessionMixnodes::<T>::clear(T::MaxAuthorities::get(), None));
		} else {
			check_removed_all(EvenSessionMixnodes::<T>::clear(T::MaxAuthorities::get(), None));
		}

		// Re-open registrations
		NextRegistrationsClosed::<T>::kill();

		if changed {
			// Save authority set for the next session. Note that we don't care about the authority
			// set for the current session; we just care about the key-exchange public keys that
			// were registered and are stored in Odd/EvenSessionMixnodes.
			check_removed_all(NextAuthorityIds::<T>::clear(T::MaxAuthorities::get(), None));
			for (i, (_, authority_id)) in queued_validators.enumerate() {
				NextAuthorityIds::<T>::insert(i as AuthorityIndex, authority_id);
			}
		}
	}

	fn on_disabled(_i: u32) {
		// For now, to keep things simple, just ignore
	}
}

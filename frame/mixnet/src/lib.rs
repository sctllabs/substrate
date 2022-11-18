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
use codec::{Decode, Encode};
use frame_support::traits::{EstimateNextSessionRotation, Get, OneSessionHandler, ValidatorSet};
use frame_system::offchain::{SendTransactionTypes, SubmitTransaction};
pub use pallet::*;
use scale_info::TypeInfo;
use sp_application_crypto::RuntimeAppPublic;
use sp_arithmetic::{per_things::Permill, traits::AtLeast32BitUnsigned};
use sp_io::MultiRemovalResults;
use sp_mixnet_types::{AuthorityIndex, KxPublic, KxPublicForSessionError, Node};
use sp_runtime::{RuntimeDebug,
    offchain::storage::{MutateStorageError, StorageRetrievalError, StorageValueRef}};
use sp_session::SessionIndex;
use sp_std::vec::Vec;

mod app {
    use sp_application_crypto::{app_crypto, key_types::MIXNET, sr25519};
    app_crypto!(sr25519, MIXNET);
}

pub type AuthorityId = app::Public;
type AuthoritySignature = app::Signature;

#[derive(Clone, Decode, Encode, PartialEq, TypeInfo, RuntimeDebug)]
pub struct Registration<BlockNumber> {
    /// Block number at the time of creation. When a registration transaction fails to make it on
    /// to the chain for whatever reason, we send out another one. We want this one to have a
    /// different hash in case the earlier transaction got banned somewhere; including the block
    /// number is a simple way of achieving this.
    pub block_number: BlockNumber,
    /// The session during which this registration should be processed. Note that on success the
    /// node is registered as part of the mixnet node set for the _following_ session.
    pub session_index: SessionIndex,
    /// The index in the next session's authority list of the authority registering as a mixnet
    /// node.
    pub authority_index: AuthorityIndex,
    /// The key-exchange public key to be used during the following session.
    pub kx_public: KxPublic
}

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
    authority_id: AuthorityId
}

impl<BlockNumber: AtLeast32BitUnsigned + Copy> RegistrationAttempt<BlockNumber> {
    fn ok_to_replace_with(&self, other: &Self) -> bool {
        if (self.session_index != other.session_index) ||
            (self.authority_index != other.authority_index) ||
            (self.authority_id != other.authority_id) {
            // Not equivalent; ok to replace
            return true;
        }

        // Equivalent; ok to replace if we have waited long enough
        (self.block_number + 3_u32.into()) < other.block_number
    }
}

enum OffchainErr<BlockNumber> {
    WaitingForSessionProgress,
    NotAnAuthority,
    AlreadyRegistered,
    WaitingForInclusion(BlockNumber),
    LostRace,
    KxPublicForSessionFailed(KxPublicForSessionError),
    SigningFailed,
    SubmitFailed
}

impl<BlockNumber: sp_std::fmt::Debug> sp_std::fmt::Debug for OffchainErr<BlockNumber> {
    fn fmt(&self, fmt: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        match self {
            OffchainErr::WaitingForSessionProgress =>
                write!(fmt, "Waiting for the session to progress further before registering."),
            OffchainErr::NotAnAuthority => write!(fmt, "Not an authority in the next session."),
            OffchainErr::AlreadyRegistered =>
                write!(fmt, "Already registered as a mixnet node in the next session."),
            OffchainErr::WaitingForInclusion(block_number) =>
                write!(fmt, "Registration already sent at {:?}. Waiting for inclusion.", block_number),
            OffchainErr::LostRace => write!(fmt, "Lost a race with another offchain worker."),
            OffchainErr::KxPublicForSessionFailed(err) =>
                write!(fmt, "Failed to get key-exchange public key for session: {:?}", err),
            OffchainErr::SigningFailed => write!(fmt, "Failed to sign registration."),
            OffchainErr::SubmitFailed => write!(fmt, "Failed to submit registration transaction.")
        }
    }
}

type OffchainResult<T, R> = Result<R, OffchainErr<<T as frame_system::Config>::BlockNumber>>;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use super::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + SendTransactionTypes<Call<Self>> {
		/// The maximum number of authorities per session.
        #[pallet::constant]
		type MaxAuthorities: Get<u32>;

        /// Just for retrieving the current session index.
        type ValidatorSet: ValidatorSet<Self::AccountId>;

        /// Session progress/length estimation. Used to determine when to send registration
        /// transactions (we want these transactions to be roughly evenly spaced out over each
        /// session to avoid load spikes). Also used to determine the longevity of these
        /// transactions.
        type NextSessionRotation: EstimateNextSessionRotation<Self::BlockNumber>;

        /// Priority of unsigned transactions used to register mixnet nodes.
        #[pallet::constant]
        type RegistrationPriority: Get<TransactionPriority>;
    }

    #[pallet::storage]
    /// Authority list for the next session.
    pub(crate) type NextAuthorityIds<T> = StorageMap<_, Identity, AuthorityIndex, AuthorityId>;

    #[pallet::storage]
    /// Mixnet node set. Active during even sessions (0, 2, ...). Built during odd sessions.
    pub(crate) type EvenSessionNodes<T> = StorageMap<_, Identity, AuthorityIndex, KxPublic>;

    #[pallet::storage]
    /// Mixnet node set. Active during odd sessions (1, 3, ...). Built during even sessions.
    pub(crate) type OddSessionNodes<T> = StorageMap<_, Identity, AuthorityIndex, KxPublic>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub nodes: BoundedVec<Node, T::MaxAuthorities>
	}

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            Self { nodes: Default::default() }
        }
    }

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
            assert_eq!(T::ValidatorSet::session_index(), 0,
                "Session index should be 0 in genesis block");
            assert!(EvenSessionNodes::<T>::iter().next().is_none(),
                "Initial mixnet nodes already set");
            assert!(OddSessionNodes::<T>::iter().next().is_none(),
                "Odd session mixnet node set should be empty in genesis block");
            for node in &self.nodes {
                EvenSessionNodes::<T>::insert(node.index, node.kx_public);
            }
		}
	}

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(1)] // TODO
        pub fn register(
            origin: OriginFor<T>,
            registration: Registration<T::BlockNumber>,
            _signature: AuthoritySignature
        ) -> DispatchResult {
            ensure_none(origin)?;

            // Checked by ValidateUnsigned
            debug_assert_eq!(registration.session_index, T::ValidatorSet::session_index());
            debug_assert!(registration.authority_index < T::MaxAuthorities::get());

            // Note we are registering for the _following_ session, so the if appears to be
            // backwards...
            if (registration.session_index & 1) == 0 {
                OddSessionNodes::<T>::insert(registration.authority_index, registration.kx_public);
            } else {
                EvenSessionNodes::<T>::insert(registration.authority_index, registration.kx_public);
            }

            Ok(())
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            if let Self::Call::register { registration, signature } = call {
                // Check session index matches
                if registration.session_index != T::ValidatorSet::session_index() {
                    return InvalidTransaction::Stale.into();
                }

                // Check authority index is valid
                if registration.authority_index >= T::MaxAuthorities::get() {
                    return InvalidTransaction::BadProof.into();
                }
                let authority_id = match NextAuthorityIds::<T>::get(registration.authority_index) {
                    Some(id) => id,
                    None => return InvalidTransaction::BadProof.into()
                };

                // Check the authority hasn't registered yet
                if Self::already_registered(registration.session_index, registration.authority_index) {
                    return InvalidTransaction::Stale.into();
                }

                // Check signature
                let signature_ok = registration.using_encoded(|encoded_registration| {
                    authority_id.verify(&encoded_registration, signature)
                });
                if !signature_ok {
                    return InvalidTransaction::BadProof.into();
                }

                ValidTransaction::with_tag_prefix("Mixnet")
					.priority(T::RegistrationPriority::get())
                    // Include both authority index _and_ ID in tag in case of forks with different
                    // authority lists
					.and_provides((registration.session_index, registration.authority_index, authority_id))
					.longevity((T::NextSessionRotation::average_session_length() / 2_u32.into()).try_into().unwrap_or(64_u64))
					.build()
            } else {
                InvalidTransaction::Call.into()
            }
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<T::BlockNumber> for Pallet<T> {
        fn offchain_worker(block_number: T::BlockNumber) {
            // If this node is not running as a validator, never try to register as a mixnet
            // node...
            if sp_io::offchain::is_validator() {
                if let Err(err) = Self::maybe_register_this_node(block_number) {
                    log::debug!(target: "runtime::mixnet",
                        "Mixnet registration at {:?}: {:?}", block_number, err);
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
    pub fn current_nodes() -> Vec<Node> {
        let iter = if (T::ValidatorSet::session_index() & 1) == 0 {
            EvenSessionNodes::<T>::iter()
        } else {
            OddSessionNodes::<T>::iter()
        };
        iter.map(|(index, kx_public)| Node { index, kx_public }).collect()
    }

    /// Is it ok to register this node now, considering only session progress?
    fn ok_to_register_by_session_progress(block_number: T::BlockNumber) -> bool {
        let progress = if let (Some(progress), _weight) =
            T::NextSessionRotation::estimate_current_session_progress(block_number)
        {
            progress
        } else {
            // Things aren't going to work terribly well in this case as all the authorities will
            // just pile in at the start of each session...
            return true;
        };

        // Don't try to register right at the start of a session; any nodes that aren't in the new
        // session yet will reject our registration transaction
        const BEGIN: Permill = Permill::from_percent(5);
        // Leave some time at the end of the session for registrations to make it on to the chain
        const END: Permill = Permill::from_percent(80);

        if progress < BEGIN {
            return false;
        }
        if progress >= END {
            return true;
        }

        let session_length = T::NextSessionRotation::average_session_length();
        let remaining_blocks = (END - progress).mul_ceil(session_length);
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
            OddSessionNodes::<T>::contains_key(authority_index)
        } else {
            EvenSessionNodes::<T>::contains_key(authority_index)
        }
    }

    /// Record `attempt` in the offchain database, failing if another equivalent registration
    /// attempt was recorded too recently, then call `f`. If `f` fails the recorded attempt is
    /// cleared.
    fn with_recorded_registration_attempt<R>(
        attempt: RegistrationAttempt<T::BlockNumber>,
        f: impl FnOnce() -> OffchainResult<T, R>
    ) -> OffchainResult<T, R> {
        let mut storage = StorageValueRef::persistent(b"parity/mixnet-registration-attempt");

        match storage.mutate(
            |prev_attempt: Result<Option<RegistrationAttempt<T::BlockNumber>>, StorageRetrievalError>| {
                match prev_attempt {
                    Ok(Some(prev_attempt)) if !prev_attempt.ok_to_replace_with(&attempt) =>
                        Err(OffchainErr::WaitingForInclusion(prev_attempt.block_number)),
                    _ => Ok(attempt)
                }
            })
        {
            Ok(_) => (),
            Err(MutateStorageError::ConcurrentModification(_)) => return Err(OffchainErr::LostRace),
            Err(MutateStorageError::ValueFunctionFailed(err)) => return Err(err)
        }

        let res = f();
        if res.is_err() {
            storage.clear();
        }
        res
    }

    fn maybe_register_this_node(block_number: T::BlockNumber) -> OffchainResult<T, ()> {
        if !Self::ok_to_register_by_session_progress(block_number) {
            // Don't want to register this node right now
            return Err(OffchainErr::WaitingForSessionProgress);
        }

        let (authority_index, authority_id) = if let Some(authority) = Self::next_local_authority() {
            authority
        } else {
            // Not an authority in the next session
            return Err(OffchainErr::NotAnAuthority);
        };

        let session_index = T::ValidatorSet::session_index();
        if Self::already_registered(session_index, authority_index) {
            // Registration for this node already on the chain
            return Err(OffchainErr::AlreadyRegistered);
        }

        let attempt = RegistrationAttempt {
            block_number,
            session_index,
            authority_index,
            authority_id: authority_id.clone()
        };
        Self::with_recorded_registration_attempt(attempt, || {
            let kx_public = sp_io::mixnet::kx_public_for_session(session_index)
                .map_err(|err| OffchainErr::KxPublicForSessionFailed(err))?;
            let registration = Registration::<T::BlockNumber> {
                block_number,
                session_index,
                authority_index,
                kx_public
            };
            let signature = authority_id.sign(&registration.encode()).ok_or(OffchainErr::SigningFailed)?;
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
        I: Iterator<Item = (&'a T::AccountId, Self::Key)>
    {
        assert!(NextAuthorityIds::<T>::iter().next().is_none(),
            "Initial authority IDs already set");
        for (i, (_, authority_id)) in validators.enumerate() {
            NextAuthorityIds::<T>::insert(i as AuthorityIndex, authority_id);
        }
    }

	fn on_new_session<'a, I: 'a>(changed: bool, _validators: I, queued_validators: I)
	where
		I: Iterator<Item = (&'a T::AccountId, Self::Key)>
    {
        // Clear node set for the _following_ session. Note that we do this even if the validator
        // set is not going to change; the key-exchange public keys are still rotated.
        if (T::ValidatorSet::session_index() & 1) == 0 {
            check_removed_all(OddSessionNodes::<T>::clear(T::MaxAuthorities::get(), None));
        } else {
            check_removed_all(EvenSessionNodes::<T>::clear(T::MaxAuthorities::get(), None));
        }

        if changed {
            // Save authority set for the next session. Note that we don't care about the authority
            // set for the current session; we just care about the key-exchange public keys that
            // were registered and are stored in Odd/EvenSessionNodes.
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

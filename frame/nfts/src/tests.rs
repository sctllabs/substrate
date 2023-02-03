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

//! Tests for Nfts pallet.

use crate::{mock::*, Event, *};
use enumflags2::BitFlags;
use frame_support::{
	assert_noop, assert_ok,
	dispatch::Dispatchable,
	traits::{
		tokens::nonfungibles_v2::{Destroy, Mutate},
		Currency, Get,
	},
};
use pallet_balances::Error as BalancesError;
use sp_core::{bounded::BoundedVec, Pair};
use sp_runtime::{testing::UintAuthorityId, traits::IdentifyAccount, MultiSignature, MultiSigner};
use sp_std::prelude::*;

type AccountIdOf<Test> = <Test as frame_system::Config>::AccountId;

fn account(id: u8) -> AccountIdOf<Test> {
	[id; 32].into()
}

fn items() -> Vec<(AccountIdOf<Test>, u32, u32)> {
	let mut r: Vec<_> = Account::<Test>::iter().map(|x| x.0).collect();
	r.sort();
	let mut s: Vec<_> = Item::<Test>::iter().map(|x| (x.2.owner, x.0, x.1)).collect();
	s.sort();
	assert_eq!(r, s);
	for collection in Item::<Test>::iter()
		.map(|x| x.0)
		.scan(None, |s, item| {
			if s.map_or(false, |last| last == item) {
				*s = Some(item);
				Some(None)
			} else {
				Some(Some(item))
			}
		})
		.flatten()
	{
		let details = Collection::<Test>::get(collection).unwrap();
		let items = Item::<Test>::iter_prefix(collection).count() as u32;
		assert_eq!(details.items, items);
	}
	r
}

fn collections() -> Vec<(AccountIdOf<Test>, u32)> {
	let mut r: Vec<_> = CollectionAccount::<Test>::iter().map(|x| (x.0, x.1)).collect();
	r.sort();
	let mut s: Vec<_> = Collection::<Test>::iter().map(|x| (x.1.owner, x.0)).collect();
	s.sort();
	assert_eq!(r, s);
	r
}

macro_rules! bvec {
	($( $x:tt )*) => {
		vec![$( $x )*].try_into().unwrap()
	}
}

fn attributes(
	collection: u32,
) -> Vec<(Option<u32>, AttributeNamespace<AccountIdOf<Test>>, Vec<u8>, Vec<u8>)> {
	let mut s: Vec<_> = Attribute::<Test>::iter_prefix((collection,))
		.map(|(k, v)| (k.0, k.1, k.2.into(), v.0.into()))
		.collect();
	s.sort_by_key(|k: &(Option<u32>, AttributeNamespace<AccountIdOf<Test>>, Vec<u8>, Vec<u8>)| k.0);
	s.sort_by_key(|k: &(Option<u32>, AttributeNamespace<AccountIdOf<Test>>, Vec<u8>, Vec<u8>)| {
		k.2.clone()
	});
	s
}

fn approvals(collection_id: u32, item_id: u32) -> Vec<(AccountIdOf<Test>, Option<u64>)> {
	let item = Item::<Test>::get(collection_id, item_id).unwrap();
	let s: Vec<_> = item.approvals.into_iter().collect();
	s
}

fn item_attributes_approvals(collection_id: u32, item_id: u32) -> Vec<AccountIdOf<Test>> {
	let approvals = ItemAttributesApprovalsOf::<Test>::get(collection_id, item_id);
	let s: Vec<_> = approvals.into_iter().collect();
	s
}

fn events() -> Vec<Event<Test>> {
	let result = System::events()
		.into_iter()
		.map(|r| r.event)
		.filter_map(|e| if let mock::RuntimeEvent::Nfts(inner) = e { Some(inner) } else { None })
		.collect::<Vec<_>>();

	System::reset_events();

	result
}

fn collection_config_from_disabled_settings(
	settings: BitFlags<CollectionSetting>,
) -> CollectionConfigFor<Test> {
	CollectionConfig {
		settings: CollectionSettings::from_disabled(settings),
		max_supply: None,
		mint_settings: MintSettings::default(),
	}
}

fn collection_config_with_all_settings_enabled() -> CollectionConfigFor<Test> {
	CollectionConfig {
		settings: CollectionSettings::all_enabled(),
		max_supply: None,
		mint_settings: MintSettings::default(),
	}
}

fn default_collection_config() -> CollectionConfigFor<Test> {
	collection_config_from_disabled_settings(CollectionSetting::DepositRequired.into())
}

fn default_item_config() -> ItemConfig {
	ItemConfig { settings: ItemSettings::all_enabled() }
}

fn item_config_from_disabled_settings(settings: BitFlags<ItemSetting>) -> ItemConfig {
	ItemConfig { settings: ItemSettings::from_disabled(settings) }
}

#[test]
fn pre_signed_mints_should_work() {
	new_test_ext().execute_with(|| {
		let user_1_pair = sp_core::sr25519::Pair::from_string("//Alice", None).unwrap();
		let user_1_signer = MultiSigner::Sr25519(user_1_pair.public());
		let user_1 = user_1_signer.clone().into_account();

		let mint_data = PreSignedMint {
			collection: 0,
			item: 0,
			attributes: vec![(vec![0], vec![1]), (vec![2], vec![3])],
			metadata: vec![0, 1],
			only_account: None,
			deadline: 10000000,
		};
		let message = Encode::encode(&mint_data);
		let signature = MultiSignature::Sr25519(user_1_pair.sign(&message));
		let user_2 = account(2);
		let user_3 = account(3);

		Balances::make_free_balance_be(&user_1, 100);
		Balances::make_free_balance_be(&user_2, 100);
		assert_ok!(Nfts::create(
			RuntimeOrigin::signed(user_1),
			user_1,
			collection_config_with_all_settings_enabled(),
		));

		assert_ok!(Nfts::mint_pre_signed(
			RuntimeOrigin::signed(user_2),
			mint_data.clone(),
			signature.clone(),
			user_1.clone(),
		));
		assert_eq!(items(), vec![(user_2, 0, 0)]);
		let metadata = ItemMetadataOf::<Test>::get(0, 0).unwrap();
		assert_eq!(metadata.deposit, ItemMetadataDeposit { account: Some(user_2), amount: 3 });
		assert_eq!(metadata.data, vec![0, 1]);

		assert_eq!(
			attributes(0),
			vec![
				(Some(0), AttributeNamespace::CollectionOwner, bvec![0], bvec![1]),
				(Some(0), AttributeNamespace::CollectionOwner, bvec![2], bvec![3]),
			]
		);
		let attribute_key: BoundedVec<_, _> = bvec![0];
		let (_, deposit) = Attribute::<Test>::get((
			0,
			Some(0),
			AttributeNamespace::CollectionOwner,
			&attribute_key,
		))
		.unwrap();
		assert_eq!(deposit.account, Some(user_2));
		assert_eq!(deposit.amount, 3);

		assert_eq!(Balances::free_balance(&user_1), 100 - 2); // 2 - collection deposit
		assert_eq!(Balances::free_balance(&user_2), 100 - 1 - 3 - 6); // 1 - item deposit, 3 - metadata, 6 - attributes

		assert_noop!(
			Nfts::mint_pre_signed(
				RuntimeOrigin::signed(user_2),
				mint_data,
				signature.clone(),
				user_1.clone(),
			),
			Error::<Test>::AlreadyExists
		);

		assert_ok!(Nfts::burn(RuntimeOrigin::signed(user_2), 0, 0, Some(user_2)));
		assert_eq!(Balances::free_balance(&user_2), 100 - 6);

		// validate the `only_account` field
		let mint_data = PreSignedMint {
			collection: 0,
			item: 0,
			attributes: vec![],
			metadata: vec![],
			only_account: Some(user_2),
			deadline: 10000000,
		};

		// can't mint with the wrong signature
		assert_noop!(
			Nfts::mint_pre_signed(
				RuntimeOrigin::signed(user_2),
				mint_data.clone(),
				signature.clone(),
				user_1.clone(),
			),
			Error::<Test>::WrongSignature
		);

		let message = Encode::encode(&mint_data);
		let signature = MultiSignature::Sr25519(user_1_pair.sign(&message));

		assert_noop!(
			Nfts::mint_pre_signed(
				RuntimeOrigin::signed(user_3),
				mint_data.clone(),
				signature.clone(),
				user_1.clone(),
			),
			Error::<Test>::WrongOrigin
		);

		// validate signature's expiration
		System::set_block_number(10000001);
		assert_noop!(
			Nfts::mint_pre_signed(
				RuntimeOrigin::signed(user_2),
				mint_data,
				signature,
				user_1.clone(),
			),
			Error::<Test>::DeadlineExpired
		);
		System::set_block_number(1);

		// validate the collection
		let mint_data = PreSignedMintOf::<Test> {
			collection: 1,
			item: 0,
			attributes: vec![],
			metadata: vec![],
			only_account: Some(AccountId::new([2; 32])),
			deadline: 10000000,
		};
		let message = Encode::encode(&mint_data);
		let signature = MultiSignature::Sr25519(user_1_pair.sign(&message));

		assert_noop!(
			Nfts::mint_pre_signed(
				RuntimeOrigin::signed(user_2.clone()),
				mint_data,
				signature,
				user_1.clone(),
			),
			Error::<Test>::UnknownCollection
		);

		// validate max attributes limit
		let mint_data = PreSignedMint {
			collection: 0,
			item: 0,
			attributes: vec![(vec![0], vec![1]), (vec![2], vec![3]), (vec![2], vec![3])],
			metadata: vec![0, 1],
			only_account: None,
			deadline: 10000000,
		};
		let message = Encode::encode(&mint_data);
		let signature = MultiSignature::Sr25519(user_1_pair.sign(&message));
		assert_noop!(
			Nfts::mint_pre_signed(
				RuntimeOrigin::signed(user_2),
				mint_data,
				signature,
				user_1.clone(),
			),
			Error::<Test>::MaxAttributesLimitReached
		);
	})
}

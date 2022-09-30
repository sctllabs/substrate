// This file is part of Substrate.

// Copyright (C) 2022 Parity Technologies (UK) Ltd.
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

#![warn(unused_extern_crates)]

//! Substrate-specific mixnet usage.
//!
//! Topology specific to substrate and utils to link to network.

use mixnet::{
	traits::{
		hash_table::{Configuration as TopoConfigT, Parameters as TopoParams, TopologyHashTable},
		NewRoutingSet, ShouldConnectTo, Topology,
	}, MixnetEvent,
	Error, MixPublicKey, MixnetId, PeerCount, SendOptions,
};

use ambassador::Delegate;
pub use mixnet::{ambassador_impl_Topology, Config, SinkToWorker, StreamFromWorker};
use sp_application_crypto::key_types;
use sp_keystore::SyncCryptoStore;

use codec::{Decode, Encode};
use futures::{
	channel::{mpsc::SendError, oneshot},
	future,
	future::OptionFuture,
	FutureExt, StreamExt,
};
use futures_timer::Delay;
use log::{debug, error, info, trace, warn};
use metrics::{PacketsKind, PacketsResult};
use prometheus_endpoint::Registry as PrometheusRegistry;
use sc_client_api::{BlockchainEvents, FinalityNotification, UsageProvider};
use sc_network::{MixnetCommand, PeerId as NetworkId};
use sc_network_common::service::NetworkPeers;

use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_core::crypto::CryptoTypePublicPair;
pub use sp_finality_grandpa::{AuthorityId, AuthorityList, SetId};
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use sp_session::CurrentSessionKeys;
use std::{
	collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
	pin::Pin,
	sync::Arc,
	time::Duration,
};

const DEFAULT_NUM_HOPS: u32 = 4;

// Buffer size for mixnet command channel.
const COMMAND_BUFFER_SIZE: usize = 25;

/// Number of blocks before seen as synched
/// (do not turn mixnet off every time we are a few block late).
const UNSYNCH_FINALIZED_MARGIN: u32 = 10;

/// Delay in seconds after which if no finalization occurs,
/// we switch back to synching state.
const DELAY_NO_FINALISATION_S: u64 = 60;

/// NetworkProvider provides [`Worker`] with all necessary hooks into the
/// underlying Substrate networking. Using this trait abstraction instead of
/// `sc_network::NetworkService` directly is necessary to unit test [`Worker`].
pub trait NetworkProvider: NetworkPeers {}

impl<T> NetworkProvider for T where T: NetworkPeers {}

struct TopoConfig;

impl TopoConfigT for TopoConfig {
	type Version = ();

	const DISTRIBUTE_ROUTES: bool = false;

	const LOW_MIXNET_THRESHOLD: usize = 5;

	const LOW_MIXNET_PATHS: usize = 2;

	const NUMBER_CONNECTED_FORWARD: usize = 4;

	const NUMBER_CONNECTED_BACKWARD: usize = Self::NUMBER_CONNECTED_FORWARD - 2;

	const EXTERNAL_BANDWIDTH: (usize, usize) = (1, 10);

	const DEFAULT_PARAMETERS: TopoParams =
		TopoParams { max_external: Some(10), number_consumer_connection: Some(1) };
}

/// Mixnet running worker.
pub struct MixnetWorker<B: BlockT, C, N> {
	// current node authority_id if validating.
	authority_id: Option<AuthorityId>,
	worker: mixnet::MixnetWorker<AuthorityTopology>,
	// Finality notification stream, for each new final block
	// we look for an authority set update.
	finality_stream: sc_client_api::FinalityNotifications<B>,
	shared_authority_set:
		sc_finality_grandpa::SharedAuthoritySet<<B as BlockT>::Hash, NumberFor<B>>,
	// last set id form shared authority set.
	session: Option<u64>,
	client: Arc<C>,
	state: State,
	// External command.
	command_stream: futures::channel::mpsc::Receiver<MixnetCommand>,
	authority_discovery_service: Option<sc_authority_discovery::Service>,
	authority_replies: VecDeque<Option<AuthorityRx>>,
	authority_queries: VecDeque<AuthorityInfo>,
	key_store: Arc<dyn SyncCryptoStore>,
	network: Arc<N>,
}

type WorkerChannels = (mixnet::WorkerChannels, futures::channel::mpsc::Receiver<MixnetCommand>);

type AuthorityRx = oneshot::Receiver<Option<HashSet<sc_network::Multiaddr>>>;
#[derive(PartialEq, Eq)]
enum State {
	Synching,
	WaitingMorePeers,
	Running,
}

/// Instantiate channels needed to spawn and communicate with the mixnet worker.
pub fn new_channels(
) -> (WorkerChannels, (SinkToWorker, StreamFromWorker, futures::channel::mpsc::Sender<MixnetCommand>))
{
	let (to_worker_sink, to_worker_stream) = tracing_unbounded("mpsc_mixnet_in");
	let (from_worker_sink, from_worker_stream) = tracing_unbounded("mpsc_mixnet_out");
	let (command_sink, command_stream) = futures::channel::mpsc::channel(COMMAND_BUFFER_SIZE);
	(
		((Box::new(from_worker_sink), Box::new(to_worker_stream)), command_stream),
		(Box::new(to_worker_sink), Box::new(from_worker_stream), command_sink),
	)
}

impl<B, C, N> MixnetWorker<B, C, N>
where
	B: BlockT,
	C: UsageProvider<B> + BlockchainEvents<B> + ProvideRuntimeApi<B>,
	C::Api: CurrentSessionKeys<B>,
	N: NetworkProvider,
{
	/// Instantiate worker. Should be call after imonline and
	/// grandpa as it reads their keystore.
	pub fn new(
		inner_channels: WorkerChannels,
		network_identity: &libp2p::core::identity::Keypair,
		client: Arc<C>,
		network: Arc<N>,
		shared_authority_set: sc_finality_grandpa::SharedAuthoritySet<
			<B as BlockT>::Hash,
			NumberFor<B>,
		>,
		key_store: Arc<dyn SyncCryptoStore>,
		metrics: Option<PrometheusRegistry>,
		authority_discovery_service: Option<sc_authority_discovery::Service>,
	) -> Option<Self> {
		let mut local_public_key = None;
		// get the peer id, could be another one than the one define in session: in this
		// case node will restart.
		for key in SyncCryptoStore::sr25519_public_keys(&*key_store, key_types::IM_ONLINE)
			.into_iter()
			.rev()
		{
			if SyncCryptoStore::has_keys(&*key_store, &[(key.0.into(), key_types::IM_ONLINE)]) {
				// use first with a secret key, on handle new auth, if we are
				// authority this will be updated to the right one, otherwise
				// any key will do.
				local_public_key = Some(key);
				break
			} else {
				log::warn!(target: "mixnet", "No private key for imonline key, may be old key");
			}
		}

		let local_public_key: [u8; 32] = if let Some(key) = local_public_key {
			key.0
		} else {
			log::trace!(target: "mixnet", "Generating new ImOnline key.");
			SyncCryptoStore::sr25519_generate_new(&*key_store, key_types::IM_ONLINE, None)
				.ok()?
				.0
		};

		let mut mixnet_config =
			if let Some((pub_key, priv_key)) = Self::get_mixnet_keys(&*key_store) {
				mixnet::Config::new_with_keys(local_public_key, pub_key, priv_key)
			} else {
				log::error!(target: "mixnet", "Not using grandpa key");
				mixnet::Config::new(local_public_key)
			};

		mixnet_config.num_hops = DEFAULT_NUM_HOPS;

		let finality_stream = client.finality_notification_stream();

		let metrics = if let Some(metrics) = metrics {
			Some(
				metrics::register_metrics(metrics, &mixnet_config.local_id)
					.map_err(|e| {
						log::error!(target: "mixnet", "{}", format!("metrics: {:?}", e));
					})
					.ok()?,
			)
		} else {
			None
		};

		let topology = AuthorityTopology::new(
			mixnet_config.local_id,
			NetworkId::from_public_key(&network_identity.public()),
			mixnet_config.public_key,
			key_store.clone(),
			&mixnet_config,
			metrics,
		);

		let worker = mixnet::MixnetWorker::new(mixnet_config, topology, inner_channels.0);
		let state = State::Synching;
		Some(MixnetWorker {
			authority_id: None,
			worker,
			finality_stream,
			shared_authority_set,
			session: None,
			client,
			state,
			authority_discovery_service,
			command_stream: inner_channels.1,
			key_store,
			authority_queries: VecDeque::new(),
			authority_replies: VecDeque::new(),
			network,
		})
	}

	fn get_mixnet_keys(
		key_store: &dyn SyncCryptoStore,
	) -> Option<(MixPublicKey, mixnet::MixSecretKey)> {
		// get last key, if it is not the right one, node will restart on next
		// handle_new_authority call.
		let mut grandpa_key = None;
		for key in SyncCryptoStore::ed25519_public_keys(key_store, key_types::GRANDPA)
			.into_iter()
			.rev()
		{
			if SyncCryptoStore::has_keys(key_store, &[(key.0.into(), key_types::GRANDPA)]) {
				grandpa_key = Some(key);
				break
			} else {
				log::error!(target: "mixnet", "No private key for grandpa key");
			}
		}

		if let Some(grandpa_key) = grandpa_key {
			let mut p = [0u8; 32];
			p.copy_from_slice(grandpa_key.as_ref());
			let pub_key = mixnet::public_from_ed25519(p);

			let priv_key = SyncCryptoStore::mixnet_secret_from_ed25519(
				key_store,
				key_types::GRANDPA,
				&grandpa_key,
			)
			.ok()?;
			Some((pub_key, priv_key))
		} else {
			None
		}
	}

	pub async fn run(mut self) {
		let info = self.client.usage_info().chain;
		if info.finalized_number == 0u32.into() {
			let authority_set = self.shared_authority_set.current_authority_list();
			let session = self.shared_authority_set.set_id();
			self.handle_new_authority(authority_set, session, info.finalized_number);
		}
		let mut delay_finalized = Delay::new(Duration::from_secs(DELAY_NO_FINALISATION_S));
		let delay_finalized = &mut delay_finalized;
		loop {
			let mut pop_auth_query = false;
			let mut err_auth_query = false;
			let auth_poll = self.authority_replies.get_mut(0).map(Option::as_mut).flatten();
			let auth_poll = OptionFuture2(auth_poll);

			futures::select! {
				// TODO poll more than first??
				auth_address = auth_poll.fuse() => {
					debug!(target: "mixnet", "Received auth reply {:?}.", auth_address);
					match auth_address {
						Ok(Some(addresses)) => {
						let auth_id = self.authority_queries.get(0).unwrap().clone();
						for addr in addresses {
							match sc_network_common::config::parse_addr(addr) {
								Ok((_peer_id, address)) => {
									self.network.dial(address);
								},
								Err(_) => continue,
							};
						}
						pop_auth_query = true; // TODO same for Ok(None)?
					},
					Ok(None) => {
						pop_auth_query = true; // TODO same for Ok(None)?
					},
					Err(e) => {
						// TODO trace
						err_auth_query = true;
					},
					}
				},

					notif = self.finality_stream.next() => {
						// TODO try accessing last of finality stream (possibly skipping some block)
						if let Some(notif) = notif {
							delay_finalized.reset(Duration::from_secs(DELAY_NO_FINALISATION_S));
							self.handle_new_finalize_block(notif);
						} else {
							// This point is reached if the other component did shutdown.
							debug!(target: "mixnet", "Mixnet, shutdown.");
							return;
						}
					},
					command = self.command_stream.next() => {
						if let Some(command) = command {
							self.handle_command(command);
						} else {
							// This point is reached if the other component did shutdown.
							// Shutdown as well.
							debug!(target: "mixnet", "Mixnet, shutdown.");
							return;
						}
					},
				event = future::poll_fn(|cx| self.worker.poll(cx)).fuse() => {
					match event {
						MixnetEvent::Message(message) =>
				match message.kind {
					mixnet::MessageType::FromSurbs(query, recipient) => {
						trace!(target: "mixnet", "Got surb reply for {:?}", query);

						let result = MixnetImportResult::decode(&mut message.message.as_ref());
						// Currently we only log reply for mixnet surb, could be send to
						// some client ws in the future.
						info!(target: "mixnet", "Received from {:?}, surb {:?}", recipient, result);
					},
					kind => {
						trace!(target: "mixnet", "Received query.");
						/* TODO probably useless reply we got it in worker
						let reply = if kind.with_surb() {
							self.mixnet_command_sender.clone()
						} else {
							None
						};*/
						unimplemented!("TODO transaction push ! message is a vec")

					//info!(target: "mixnet", "Inject transaction from mixnet from {:?}) tx: {:?}", sender, message);
					//this.tx_handler_controller.inject_transaction_mixnet(kind, message, reply);
/*						self.events.push_back(BehaviourOut::MixnetMessage(
							message.peer,
							message.message,
							kind,
							reply,
						));
*/
						},
				},
						MixnetEvent::Connected(_, _) => {
						},
						MixnetEvent::Disconnected(disco) => {
							for (net_id, mix_id, try_reco) in disco {
								if try_reco {
									/*
					if let Some(mixnet_id) = mix_id {
						self.try_reco(
							mixnet_id,
							Some(network_id),
							self.mixnet_command_sender.clone(),
						);
					}
*/
								}
							}
						},
						MixnetEvent::TryConnect(try_co) => {
							for (net_id, mix_id) in try_co {
/*						self.try_reco(
							mix_id,
							Some(net_id),
							self.mixnet_command_sender.clone(),
						);
*/
							}
						},
						MixnetEvent::None => (),
						MixnetEvent::Shutdown => {
							debug!(target: "mixnet", "Mixnet, shutdown.");
							return;
						},
					}
				},
					_ = delay_finalized.fuse() => {
						self.state = State::Synching;
						delay_finalized.reset(Duration::from_secs(DELAY_NO_FINALISATION_S));
					},
			}
			if pop_auth_query {
				self.authority_queries.pop_front();
				self.authority_replies.pop_front();
			} else if err_auth_query {
				if let Some(a) = self.authority_queries.pop_front() {
					self.authority_queries.push_back(a);
				}
				if let Some(_) = self.authority_replies.pop_front() {
					self.authority_replies.push_back(None);
				}
			}

			if self.authority_replies.get_mut(0).map(Option::as_mut).flatten().is_none() {
				if let Some(info) = self.authority_queries.get_mut(0) {
					if let Ok(auth_public) = info.authority_discovery_id.1.as_slice().try_into() {
						if let Some(service) = self.authority_discovery_service.as_mut() {
							if let Some(rx) =
								service.get_addresses_by_authority_id_callback(auth_public)
							{
								self.authority_replies[0] = Some(rx);
							} else {
								debug!(target: "mixnet", "Query authority full channel.");
							}
						} else {
							debug!(target: "mixnet", "Non authority node not dialing.");
						}
					}
				}
			}
		}
	}

	/// Can mixnet be use?
	pub fn is_ready(&self) -> bool {
		self.state == State::Running
	}

	fn handle_new_finalize_block(&mut self, notif: FinalityNotification<B>) {
		let info = self.client.usage_info().chain; // these could be part of finality stream info?
		let best_finalized = info.finalized_number;
		let basis = if best_finalized > UNSYNCH_FINALIZED_MARGIN.into() {
			best_finalized - UNSYNCH_FINALIZED_MARGIN.into()
		} else {
			0u32.into()
		};
		if notif.header.number() < &basis {
			debug!(target: "mixnet", "Synching, mixnet suspended {:?}.", (notif.header.number(), &basis));
			self.state = State::Synching;
			return
		} else {
			self.update_state(true);
		}

		let new_session = self.shared_authority_set.set_id();
		if self.session.map(|session| new_session != session).unwrap_or(true) {
			let authority_set = self.shared_authority_set.current_authority_list();
			self.handle_new_authority(authority_set, new_session, *notif.header.number());
		}
	}

	fn handle_command(&mut self, command: MixnetCommand) {
		match command {
			MixnetCommand::TransactionImportResult(surb, result) => {
				debug!(target: "mixnet", "Mixnet, received transaction import result.");
				if let Err(e) = self.worker.mixnet_mut().register_surb(result.encode(), *surb) {
					error!(target: "mixnet", "Could not register surb {:?}", e);
				}
			},
			MixnetCommand::SendTransaction(message, send_options, reply) =>
				if self.is_ready() {
					match self.worker.mixnet_mut().register_message(
						None,
						None,
						message,
						send_options,
					) {
						Ok(()) => {
							let _ = reply.send(Ok(()));
						},
						Err(e) => {
							error!(target: "mixnet", "Could not send transaction in mixnet {:?}", e);
							let _ = reply.send(Err(e));
						},
					}
				} else {
					let _ = reply.send(Err(mixnet::Error::NotReady));
				},
			MixnetCommand::TryReco(mix_id) => {
				// TODO rev index
				let topology = &mut self.worker.mixnet_mut().topology;
				let mut found = None;
				for (grandpa, im_online) in topology.sessions.iter() {
					if im_online.1 == mix_id {
						found = Some(grandpa);
						break
					}
				}
				if let Some(authority_id) = found {
					if let Some(authority_discovery_id) = topology.sessions_disc.get(&authority_id)
					{
						if let Ok(auth_public) = authority_discovery_id.1.as_slice().try_into() {
							if let Ok(grandpa_id) = authority_id.1.as_slice().try_into() {
								self.authority_queries.push_back(AuthorityInfo {
									grandpa_id,
									authority_discovery_id: authority_discovery_id.clone(),
								});

								if let Some(service) = self.authority_discovery_service.as_mut() {
									if let Some(rx) =
										service.get_addresses_by_authority_id_callback(auth_public)
									{
										self.authority_replies.push_back(Some(rx));
									} else {
										debug!(target: "mixnet", "Query authority full channel.");
										self.authority_replies.push_back(None);
									}
								} else {
									debug!(target: "mixnet", "Non authority node not dialing.");
								}
							}
						}
					}
				}
			},
		}
	}

	fn handle_new_authority(&mut self, set: AuthorityList, session: SetId, at: NumberFor<B>) {
		if self.session.as_ref().map(|s| s < &session).unwrap_or(false) {
			error!(target: "mixnet", "Handling outdated authority set.");
			return
		}
		self.session = Some(session);

		self.fetch_new_session_keys(at, session);
		self.update_own_public_key_within_authority_set(&set);
		let current_local_id = *self.worker.mixnet().local_id();
		let current_public_key = *self.worker.mixnet().public_key();
		let topology = &mut self.worker.mixnet_mut().topology;
		debug!(target: "mixnet", "Change authorities {:?}", set);

		let mut routing_set = Vec::with_capacity(set.len());

		let mut restart = None;
		for (auth, _) in set.into_iter() {
			use sp_application_crypto::Public;
			let auth_pub_pair = auth.clone().to_public_crypto_pair();
			if let Some(key) = topology.sessions.get(&auth_pub_pair) {
				let mut peer_id = [0u8; 32];
				peer_id.copy_from_slice(&key.1[..]);
				// derive from grandpa one
				let mut p = [0u8; 32];
				p.copy_from_slice(auth.as_ref());
				let public_key = mixnet::public_from_ed25519(p);

				if self.authority_id.as_ref() == Some(&auth) {
					debug!(target: "mixnet", "Insert self {:?}", peer_id);
					routing_set.push((peer_id, public_key));
					// Use ImOnline for the current session.
					let new_id = (current_local_id != peer_id).then(|| {
						topology.metrics.as_mut().map(|m| {
							if let Err(e) = m.change_id(&peer_id) {
								error!(target: "mixnet", "Error changing local id in metrics {:?}", e);
							}
						});
						peer_id
					});
					let new_key = (current_public_key != public_key)
						.then(|| {
							// TODO recheck again this key logic.
							let new_key = SyncCryptoStore::mixnet_secret_from_ed25519(
								&*self.key_store,
								key_types::GRANDPA,
								&auth.into(),
							)
							.ok()?;

							Some((public_key, new_key))
						})
						.flatten();
					if new_id.is_some() && new_key.is_none() {
						error!(
							"peer id derived from public key, one cannot change without the other"
						);
					}
					if new_id.is_some() || new_key.is_some() {
						restart = Some((new_id, new_key));
					}
				} else {
					debug!(target: "mixnet", "Insert auth {:?}", peer_id);
					routing_set.push((peer_id, public_key));
				}
			} else {
				error!(target: "mixnet", "Missing imonline key for authority {:?}, not adding it to topology.", auth);
			}
		}

		if let Some((id, key)) = restart {
			debug!(target: "mixnet", "Restarting");
			self.worker.restart(id, key);
			unimplemented!(
				"TODO update id and keys in topo too: just add routing set to restart params"
			);
		}

		self.worker.mixnet_mut().new_global_routing_set(&routing_set[..]);
		self.update_state(false);
	}

	fn fetch_new_session_keys(&mut self, mut at: NumberFor<B>, session: SetId) {
		let mut block_id = sp_runtime::generic::BlockId::number(at);
		// find first block with previous session id
		let runtime_api = self.client.runtime_api();
		if session == 0 {
			at = 0u32.into();
			block_id = sp_runtime::generic::BlockId::number(at);
		} else {
			let mut nb = 0;
			let target = match runtime_api.session_index(&block_id) {
				Ok(at) => at - 1,
				Err(e) => {
					error!(target: "mixnet", "Could not fetch session index {:?}, no peer id fetching.", e);
					return
				},
			};
			loop {
				at -= 1u32.into();
				nb += 1;
				block_id = sp_runtime::generic::BlockId::number(at);
				let session_at = match runtime_api.session_index(&block_id) {
					Ok(at) => at,
					Err(e) => {
						error!(target: "mixnet", "Could not fetch session index {:?}, no peer id fetching.", e);
						return
					},
				};
				if session_at == target {
					break
				} else if session_at < target {
					error!(target: "mixnet", "Could not fetch previous session index, no peer id fetching.");
					return
				}
			}

			if nb > 3 {
				warn!(target: "mixnet", "{:?} query to fetch previous session index.", nb);
			}
		}
		let sessions = match runtime_api.queued_keys(&block_id) {
			Ok(at) => at,
			Err(e) => {
				error!(target: "mixnet", "Could not fetch queued session keys {:?}, no peer id fetching.", e);
				return
			},
		};
		debug!(target: "mixnet", "Fetched session keys {:?}, at {:?}", sessions, block_id);
		self.worker.mixnet_mut().topology.sessions = sessions
			.iter()
			.flat_map(|(_, keys)| {
				let mut grandpa = None;
				let mut imonline = None;
				for pair in keys {
					if pair.0 == sp_application_crypto::key_types::GRANDPA {
						grandpa = Some(pair.1.clone());
					} else if pair.0 == sp_application_crypto::key_types::IM_ONLINE {
						imonline = Some(pair.1.clone());
					}
				}
				if let (Some(g), Some(a)) = (grandpa, imonline) {
					Some((g, a))
				} else {
					None
				}
			})
			.collect();
		self.worker.mixnet_mut().topology.sessions_disc = sessions
			.into_iter()
			.flat_map(|(_, keys)| {
				let mut grandpa = None;
				let mut auth_disc = None;
				for pair in keys {
					if pair.0 == sp_application_crypto::key_types::GRANDPA {
						grandpa = Some(pair.1);
					} else if pair.0 == sp_application_crypto::key_types::AUTHORITY_DISCOVERY {
						auth_disc = Some(pair.1);
					}
				}
				if let (Some(g), Some(a)) = (grandpa, auth_disc) {
					Some((g, a))
				} else {
					None
				}
			})
			.collect();
	}

	fn update_own_public_key_within_authority_set(&mut self, set: &AuthorityList) {
		self.authority_id = None;
		let local_pub_keys =
			&SyncCryptoStore::ed25519_public_keys(&*self.key_store, key_types::GRANDPA)
				.into_iter()
				.collect::<HashSet<_>>();

		for authority in set.iter() {
			let auth_id: AuthorityId = authority.0.clone().into();
			if local_pub_keys.contains(&auth_id.clone().into()) {
				debug!("found self in authority set, will route");
				self.authority_id = Some(auth_id);
				return
			}
		}
	}

	fn update_state(&mut self, synched: bool) {
		match &self.state {
			State::Running =>
				if !self.worker.mixnet().topology.topo.has_enough_nodes_to_proxy() {
					self.state = State::WaitingMorePeers;
				},
			State::WaitingMorePeers =>
				if self.worker.mixnet().topology.topo.has_enough_nodes_to_proxy() {
					debug!(target: "mixnet", "Mixnet running.");
					self.state = State::Running;
				},
			State::Synching if synched =>
				if self.worker.mixnet().topology.topo.has_enough_nodes_to_proxy() {
					debug!(target: "mixnet", "Mixnet running.");
					self.state = State::Running;
				} else {
					self.state = State::WaitingMorePeers;
				},
			State::Synching => (),
		}
	}
}

/// Topology for mixnet.
/// This restrict the nodes for routing to authorities with stake.
///
/// Other nodes can join the swarm but will not be routing node.
///
/// When sending a message, the message can only reach nodes
/// that are part of the topology.
#[derive(Delegate)]
#[delegate(Topology, target = "topo")]
pub struct AuthorityTopology {
	network_id: NetworkId,
	key_store: Arc<dyn SyncCryptoStore>,

	topo: TopologyHashTable<TopoConfig>,
	// Current session mapping of Grandpa key to IMonline key.
	sessions: HashMap<CryptoTypePublicPair, CryptoTypePublicPair>,
	// Current session mapping of Grandpa key to Authoritydiscovery keys.
	sessions_disc: HashMap<CryptoTypePublicPair, CryptoTypePublicPair>,

	metrics: Option<metrics::MetricsHandle>,
}

#[derive(Clone)]
pub struct AuthorityInfo {
	pub grandpa_id: AuthorityId,
	pub authority_discovery_id: CryptoTypePublicPair,
}

impl AuthorityTopology {
	/// Instantiate a new topology.
	pub fn new(
		local_id: MixnetId,
		network_id: NetworkId,
		node_public_key: MixPublicKey,
		key_store: Arc<dyn SyncCryptoStore>,
		config: &Config,
		metrics: Option<metrics::MetricsHandle>,
	) -> Self {
		let topo = TopologyHashTable::new(
			// MixnetId is ImOnline key.
			local_id,
			node_public_key,
			config,
			TopoConfig::DEFAULT_PARAMETERS.clone(),
			(),
		);

		AuthorityTopology {
			network_id,
			sessions: HashMap::new(),
			sessions_disc: HashMap::new(),
			topo,
			key_store,
			metrics,
		}
	}

	fn copy_connected_info_to_metrics(&self, stats: &PeerCount) {
		self.metrics.as_ref().map(|m| {
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Total as usize]
				])
				.set(stats.nb_connected as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Forwarding as usize]
				])
				.set(stats.nb_connected_forward_routing as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Receiving as usize]
				])
				.set(stats.nb_connected_receive_routing as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::External as usize]
				])
				.set(stats.nb_connected_external as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Consumer as usize]
				])
				.set(stats.nb_connected_consumer as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Handshakes as usize]
				])
				.set(stats.nb_pending_handshake as u64);
		});
	}
}

impl mixnet::traits::Configuration for AuthorityTopology {
	fn collect_windows_stats(&self) -> bool {
		self.metrics.is_some()
	}

	fn window_stats(&self, stats: &mixnet::WindowStats, peer_stats: &PeerCount) {
		if let Some(metrics) = self.metrics.as_ref() {
			let nb_window = stats.window - stats.last_window;
			if nb_window == 0 {
				return
			}
			metrics.number_of_window.inc();
			for _ in 1..nb_window {
				metrics.number_of_skipped_window.inc();
			}
			let max_paquets = stats.sum_connected.max_peer_paquet_queue_size as u64;
			if metrics.max_packet_queue_for_peer.get() < max_paquets {
				metrics.max_packet_queue_for_peer.set(max_paquets);
			}
			let total_peer_paquets = stats.sum_connected.peer_paquet_queue_size;
			if peer_stats.nb_connected_forward_routing > 0 {
				let peer_paquets =
					total_peer_paquets as f64 / peer_stats.nb_connected_forward_routing as f64;
				let peer_paquets = peer_paquets / nb_window as f64;
				metrics.avg_packet_queue_size_for_peer.set(peer_paquets);
				for _ in 0..nb_window {
					metrics.avg_packet_queue_size_for_peer_histo.observe(peer_paquets);
				}
			} else {
				metrics.avg_packet_queue_size_for_peer.set(0.0);
			}
			let max_paquets = stats.sum_connected.max_peer_paquet_inject_queue_size as u64;
			if metrics.max_packet_inject_queue_for_peer.get() < max_paquets {
				metrics.max_packet_inject_queue_for_peer.set(max_paquets);
			}
			metrics
				.packet_inject_queue_size_for_peer
				.set(stats.sum_connected.peer_paquet_inject_queue_size as u64);

			metrics.set_window_packets(
				stats.number_received_valid,
				nb_window,
				PacketsKind::Received,
				PacketsResult::Success,
			);
			metrics.set_window_packets(
				stats.number_received_invalid,
				nb_window,
				PacketsKind::Received,
				PacketsResult::Failure,
			);
			metrics.set_window_packets(
				stats.number_from_external_received_valid,
				nb_window,
				PacketsKind::ReceivedExternal,
				PacketsResult::Success,
			);
			metrics.set_window_packets(
				stats.number_from_external_received_invalid,
				nb_window,
				PacketsKind::ReceivedExternal,
				PacketsResult::Failure,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_forwarded_success,
				nb_window,
				PacketsKind::Forward,
				PacketsResult::Success,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_forwarded_failed,
				nb_window,
				PacketsKind::Forward,
				PacketsResult::Failure,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_from_external_forwarded_success,
				nb_window,
				PacketsKind::ForwardExternal,
				PacketsResult::Success,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_from_external_forwarded_failed,
				nb_window,
				PacketsKind::ForwardExternal,
				PacketsResult::Failure,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_from_self_send_success,
				nb_window,
				PacketsKind::FromSelf,
				PacketsResult::Success,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_from_self_send_failed,
				nb_window,
				PacketsKind::FromSelf,
				PacketsResult::Failure,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_surbs_reply_success,
				nb_window,
				PacketsKind::SurbsReply,
				PacketsResult::Success,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_surbs_reply_failed,
				nb_window,
				PacketsKind::SurbsReply,
				PacketsResult::Failure,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_cover_send_success,
				nb_window,
				PacketsKind::Cover,
				PacketsResult::Success,
			);
			metrics.set_window_packets(
				stats.sum_connected.number_cover_send_failed,
				nb_window,
				PacketsKind::Cover,
				PacketsResult::Failure,
			);
		}
		self.copy_connected_info_to_metrics(peer_stats);
	}

	fn peer_stats(&self, peer_stats: &PeerCount) {
		self.copy_connected_info_to_metrics(peer_stats);
	}
}

impl mixnet::traits::Handshake for AuthorityTopology {
	fn handshake_size(&self) -> usize {
		32 + 32 + 64
	}

	fn check_handshake(
		&self,
		payload: &[u8],
		_from: &NetworkId,
	) -> Option<(MixnetId, MixPublicKey)> {
		let mut peer_id = [0u8; 32];
		peer_id.copy_from_slice(&payload[0..32]);
		let mut pk = [0u8; 32];
		pk.copy_from_slice(&payload[32..64]);
		let mut signature = [0u8; 64];
		signature.copy_from_slice(&payload[64..]);
		let signature = sp_application_crypto::sr25519::Signature(signature);
		let mut message = self.network_id.to_bytes().to_vec();
		message.extend_from_slice(&pk[..]);
		let key = sp_application_crypto::sr25519::Public(peer_id);
		debug!(target: "mixnet", "check handshake: {:?}, {:?}, {:?} from {:?}", peer_id, message, signature, _from);
		use sp_application_crypto::RuntimePublic;
		if key.verify(&message, &signature) {
			let pk = MixPublicKey::from(pk);
			self.metrics.as_ref().map(|m| m.valid_handshake.inc());
			Some((peer_id, pk))
		} else {
			self.metrics.as_ref().map(|m| m.invalid_handshake.inc());
			None
		}
	}

	fn handshake(&self, with: &NetworkId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		let mut result = self.topo.local_id().to_vec();
		result.extend_from_slice(&public_key.as_bytes()[..]);
		let mut message = with.to_bytes().to_vec();
		message.extend_from_slice(&public_key.as_bytes()[..]);
		match SyncCryptoStore::sign_with(
			&*self.key_store,
			key_types::IM_ONLINE,
			&CryptoTypePublicPair(sp_core::sr25519::CRYPTO_ID, self.topo.local_id().to_vec()),
			&message[..],
		) {
			Ok(Some(signature)) => {
				result.extend_from_slice(&signature[..]);
				trace!(target: "mixnet", "create handshake: {:?}, {:?}, {:?} with {:?}", self.topo.local_id(), message, signature, with);
				return Some(result)
			},
			Err(e) => {
				error!(target: "mixnet", "hanshake signing error: {:?}", e);
			},
			_ => (),
		}
		error!(target: "mixnet", "Missing imonline key for handshake.");
		None
	}
}

mod metrics {
	use log::trace;
	use mixnet::MixnetId;
	use prometheus_endpoint::{
		exponential_buckets, register, Counter, Gauge, GaugeVec, Histogram, HistogramOpts,
		HistogramVec, Opts, PrometheusError, Registry, F64, U64,
	};

	/// Handle to metrics update.
	pub struct MetricsHandle {
		// TODO number of actual message received (from here).
		// TODO something to check packet delayed (here ~70 cover per window, how many packets)
		pub mixnet_info: Gauge<U64>,
		pub current_connected: GaugeVec<U64>,
		pub last_window_packets: GaugeVec<U64>,
		pub last_window_packets_histo: HistogramVec,
		pub valid_handshake: Counter<U64>,
		pub max_packet_queue_for_peer: Gauge<U64>,
		pub avg_packet_queue_size_for_peer: Gauge<F64>,
		pub max_packet_inject_queue_for_peer: Gauge<U64>,
		pub packet_inject_queue_size_for_peer: Gauge<U64>,
		// a bit redundant with gauge, should remove later.
		pub avg_packet_queue_size_for_peer_histo: Histogram,
		pub invalid_handshake: Counter<U64>,
		// only to compare with number of skipped window,
		// otherwhise it is a uptime.
		pub number_of_window: Counter<U64>,
		pub number_of_skipped_window: Counter<U64>,
		registry: Registry,
	}

	pub enum ConnectedNodeStatus {
		Total = 0,
		Forwarding = 1,
		Receiving = 2,
		External = 3,
		Consumer = 4,
		Handshakes = 5,
	}

	pub const LABEL_NODE_STATUS: &[&str] =
		&["total", "forwarding", "receiving", "external", "consumer", "pending_handshakes"];

	#[derive(Clone, Copy)]
	pub enum PacketsKind {
		Received = 0,
		ReceivedExternal = 1,
		Forward = 2,
		ForwardExternal = 3,
		FromSelf = 4,
		SurbsReply = 5,
		Cover = 6,
	}

	const LABEL_PACKET_KINDS: &[&str] = &[
		"received",
		"received from external",
		"forwarded",
		"forwarded from external",
		"send from self",
		"send as surbs reply",
		"send cover message",
	];

	#[derive(Clone, Copy)]
	pub enum PacketsResult {
		Success = 0,
		Failure = 1,
	}

	const LABEL_PACKET_RESULTS: &[&str] = &["success", "failure"];

	/// Register all metrics to endpoint and return handle.
	pub fn register_metrics(
		registry: Registry,
		peer_id: &MixnetId,
	) -> Result<MetricsHandle, PrometheusError> {
		trace!(target: "mixnet", "Registering metrics");
		let mixnet_info = register(
			Gauge::<U64>::with_opts(
				Opts::new("substrate_mixnet_peer_id", "Current mixnet id for a always one value")
					.const_label(
						"id",
						format!("{:?}", sp_core::hexdisplay::HexDisplay::from(peer_id)),
					),
			)?,
			&registry,
		)?;
		mixnet_info.set(1);
		let number_of_window = register(
			Counter::<U64>::new("substrate_mixnet_windows", "Number of windows observed")?,
			&registry,
		)?;
		let number_of_skipped_window = register(
			Counter::<U64>::new("substrate_mixnet_windows_skipped", "Number of windows skipped")?,
			&registry,
		)?;
		let valid_handshake = register(
			Counter::<U64>::new("substrate_mixnet_valid_handshake", "Number of handshake valid")?,
			&registry,
		)?;
		let invalid_handshake = register(
			Counter::<U64>::new(
				"substrate_mixnet_rejected_handshake",
				"Number of handshake invalid",
			)?,
			&registry,
		)?;

		let current_connected = register(
			GaugeVec::new(
				Opts::new("substrate_mixnet_number_connected", "Current number of connected nodes"),
				&["status"],
			)?,
			&registry,
		)?;

		let last_window_packets = register(
			GaugeVec::new(
				Opts::new(
					"substrate_mixnet_last_window_packets",
					"Last observed number of packet send in a window",
				),
				&["kind", "result"],
			)?,
			&registry,
		)?;
		let last_window_packets_histo = register(
			HistogramVec::new(
				HistogramOpts::new(
					"substrate_mixnet_last_window_packets_histo",
					"Histogram of last observed number of packet send in a window",
				)
				.buckets(exponential_buckets(1.0, 2.0, 10).unwrap_or(vec![1.0])),
				&["kind", "result"],
			)?,
			&registry,
		)?;

		for label in LABEL_NODE_STATUS {
			current_connected.with_label_values(&[label]).set(0);
		}
		let max_packet_queue_for_peer = register(
			Gauge::new(
				"substrate_mixnet_max_paquet_queue_for_peer",
				"Bigger queue of packet observed for a connection",
			)?,
			&registry,
		)?;
		let avg_packet_queue_size_for_peer = register(
			Gauge::new(
				"substrate_mixnet_paquet_queue_for_peer",
				"Packet queue size observed for a connection (avg).",
			)?,
			&registry,
		)?;
		let avg_packet_queue_size_for_peer_histo = register(
			Histogram::with_opts(
				HistogramOpts::new(
					"substrate_mixnet_paquet_queue_size_histogram",
					"Histogram of observed packet size at end of windows",
				)
				.buckets(exponential_buckets(1.0, 2.0, 10).unwrap_or(vec![1.0])),
			)?,
			&registry,
		)?;
		let max_packet_inject_queue_for_peer = register(
			Gauge::new(
				"substrate_mixnet_max_paquet_inject_queue_for_peer",
				"Bigger queue of injected packet observed for a connection",
			)?,
			&registry,
		)?;
		let packet_inject_queue_size_for_peer = register(
			Gauge::new(
				"substrate_mixnet_paquet_inject_queue_for_peer",
				"Injected packet queue size observed for all connections.",
			)?,
			&registry,
		)?;

		Ok(MetricsHandle {
			mixnet_info,
			current_connected,
			valid_handshake,
			max_packet_queue_for_peer,
			avg_packet_queue_size_for_peer,
			avg_packet_queue_size_for_peer_histo,
			max_packet_inject_queue_for_peer,
			packet_inject_queue_size_for_peer,
			invalid_handshake,
			last_window_packets,
			last_window_packets_histo,
			number_of_skipped_window,
			number_of_window,
			registry,
		})
	}

	impl MetricsHandle {
		/// Change metrics containing id, this is slown and a misuse of metrics, but does not happen
		/// often.
		pub fn change_id(&mut self, new_peer_id: &MixnetId) -> Result<(), PrometheusError> {
			self.registry.unregister(Box::new(self.mixnet_info.clone()))?;
			self.mixnet_info = register(
				Gauge::<U64>::with_opts(
					Opts::new(
						"substrate_mixnet_peer_id",
						"Current mixnet id for a always one value",
					)
					.const_label(
						"id",
						format!("{:?}", sp_core::hexdisplay::HexDisplay::from(new_peer_id)),
					),
				)?,
				&self.registry,
			)?;
			self.mixnet_info.set(1);
			Ok(())
		}

		/// Add a new number of packet for window.
		pub fn set_window_packets(
			&self,
			nb_packets: usize,
			nb_window: usize,
			kind: PacketsKind,
			result: PacketsResult,
		) {
			let nb_packets = nb_packets / nb_window;
			self.last_window_packets
				.with_label_values(&[
					LABEL_PACKET_KINDS[kind as usize],
					LABEL_PACKET_RESULTS[result as usize],
				])
				.set(nb_packets as u64);
			self.last_window_packets_histo
				.with_label_values(&[
					LABEL_PACKET_KINDS[kind as usize],
					LABEL_PACKET_RESULTS[result as usize],
				])
				.observe(nb_packets as f64);
		}
	}
}

struct OptionFuture2<F>(Option<F>);
// TODO find something doing it
impl<F: futures::Future + Unpin> futures::Future for OptionFuture2<F> {
	type Output = F::Output;

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut futures::task::Context<'_>,
	) -> futures::task::Poll<Self::Output> {
		match self.get_mut().0.as_mut() {
			Some(x) => x.poll_unpin(cx),
			// Do not try to wakeup cx: in a select and handled by a Delay.
			None => futures::task::Poll::Pending,
		}
	}
}

/*
	// TODO type alias for the sender!!!
	fn try_reco(
		&mut self,
		mixnet_id: MixnetId,
		network_id: Option<PeerId>,
		forward: Option<futures::channel::mpsc::Sender<MixnetCommand>>,
	) {
		self.events
			.push_back(BehaviourOut::MixnetTryReco(mixnet_id, network_id, forward));
	}
*/
/*
				Poll::Ready(SwarmEvent::Behaviour(BehaviourOut::MixnetTryReco(
					mixnet_id,
					net_id,
					mut reply,
				))) =>
					if let Some(net_id) = net_id {
						let e = this.network_service.dial(net_id);
						if let Err(DialError::NoAddresses) = e {
							if let Some(Err(e)) = reply
								.as_mut()
								.map(|r| r.start_send(behaviour::MixnetCommand::TryReco(mixnet_id)))
							{
								trace!(target: "mixnet", "Channel issue could not try reco {:?}", e);
							}
						}
					} else {
						if let Some(Err(e)) = reply
							.as_mut()
							.map(|r| r.start_send(behaviour::MixnetCommand::TryReco(mixnet_id)))
						{
							trace!(target: "mixnet", "Channel issue could not try reco {:?}", e);
						}
					},
*/

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

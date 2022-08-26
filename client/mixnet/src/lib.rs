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

use mixnet::{Error, MixPeerId, MixPublicKey, Topology};

pub use mixnet::{Config, SinkToWorker, StreamFromWorker};
use sp_application_crypto::key_types;
use sp_keystore::SyncCryptoStore;

use codec::Encode;
use futures::{future, FutureExt, StreamExt};
use futures_timer::Delay;
use log::{debug, error, trace, warn};
use metrics::{PacketsKind, PacketsResult};
use prometheus_endpoint::Registry as PrometheusRegistry;
use sc_client_api::{BlockchainEvents, FinalityNotification, UsageProvider};
use sc_network::{MixnetCommand, PeerId as NetworkPeerId};
use sc_utils::mpsc::tracing_unbounded;
use sp_api::ProvideRuntimeApi;
use sp_core::crypto::CryptoTypePublicPair;
pub use sp_finality_grandpa::{AuthorityId, AuthorityList, SetId};
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use sp_session::CurrentSessionKeys;
use std::{
	collections::{BTreeMap, BTreeSet, HashMap, HashSet},
	sync::Arc,
	time::Duration,
};

/// Minimal number of node for accepting to add new message.
const LOW_MIXNET_THRESHOLD: usize = 5;

/// Minimal number of paths for sending to recipient.
const LOW_MIXNET_PATHS: usize = 2;

// Buffer size for mixnet command channel.
const COMMAND_BUFFER_SIZE: usize = 25;

/// Number of blocks before seen as synched
/// (do not turn mixnet off every time we are a few block late).
const UNSYNCH_FINALIZED_MARGIN: u32 = 10;

/// Delay in seconds after which if no finalization occurs,
/// we switch back to synching state.
const DELAY_NO_FINALISATION_S: u64 = 60;

/// Maximum number of external node.
const MAX_EXTERNAL: usize = 10;

/// Percent of additional bandwidth allowed for external
/// node message reception.
const EXTERNAL_BANDWIDTH: (usize, usize) = (1, 10);

/// Mixnet running worker.
pub struct MixnetWorker<B: BlockT, C> {
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
	key_store: Arc<dyn SyncCryptoStore>,
}

type WorkerChannels = (mixnet::WorkerChannels, futures::channel::mpsc::Receiver<MixnetCommand>);

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

impl<B, C> MixnetWorker<B, C>
where
	B: BlockT,
	C: UsageProvider<B> + BlockchainEvents<B> + ProvideRuntimeApi<B>,
	C::Api: CurrentSessionKeys<B>,
{
	/// Instantiate worker. Should be call after imonline and
	/// grandpa as it reads their keystore.
	pub fn new(
		inner_channels: WorkerChannels,
		network_identity: &libp2p::core::identity::Keypair,
		client: Arc<C>,
		shared_authority_set: sc_finality_grandpa::SharedAuthoritySet<
			<B as BlockT>::Hash,
			NumberFor<B>,
		>,
		key_store: Arc<dyn SyncCryptoStore>,
		metrics: Option<PrometheusRegistry>,
	) -> Option<Self> {
		let max_external = Some(MAX_EXTERNAL);
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
			mixnet_config.local_id.clone(),
			NetworkPeerId::from_public_key(&network_identity.public()),
			mixnet_config.public_key.clone(),
			key_store.clone(),
			&mixnet_config,
			max_external,
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
			command_stream: inner_channels.1,
			key_store,
		})
	}

	fn get_mixnet_keys(
		key_store: &dyn SyncCryptoStore,
	) -> Option<(MixPublicKey, mixnet::MixSecretKey)> {
		// get last key, if it is not the right one, node will restart on next
		// handle_new_authority call.
		let mut grandpa_key = None;
		for key in SyncCryptoStore::ed25519_public_keys(&*key_store, key_types::GRANDPA)
			.into_iter()
			.rev()
		{
			if SyncCryptoStore::has_keys(&*key_store, &[(key.0.into(), key_types::GRANDPA)]) {
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
				&*key_store,
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
			futures::select! {
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
				success = future::poll_fn(|cx| self.worker.poll(cx)).fuse() => {
					if !success {
						debug!(target: "mixnet", "Mixnet, shutdown.");
						return;
					}
				},
				_ = delay_finalized.fuse() => {
					self.state = State::Synching;
					delay_finalized.reset(Duration::from_secs(DELAY_NO_FINALISATION_S));
				},
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
		let current_local_id = self.worker.local_id().clone();
		let current_public_key = self.worker.public_key().clone();
		let topology = &mut self.worker.mixnet_mut().topology;
		debug!(target: "mixnet", "Change authorities {:?}", set);
		topology.authorities.clear();
		topology.authorities_tables.clear();

		topology.routing = false;

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
					topology.authorities.insert(peer_id, public_key.clone());
					debug!(target: "mixnet", "In new authority set, routing.");
					topology.routing = true;
					// Use ImOnline for the current session.
					let new_id = (current_local_id != peer_id).then(|| {
						topology.metrics.as_mut().map(|m| {
							if let Err(e) = m.change_id(&peer_id) {
								error!(target: "mixnet", "Error changing local id in metrics {:?}", e);
							}
						});
						topology.local_id = peer_id.clone();
						peer_id.clone()
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
							topology.routing_table.public_key = public_key.clone();

							Some((public_key.clone(), new_key))
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
					topology.authorities.insert(peer_id, public_key);
				}
			} else {
				error!(target: "mixnet", "Missing imonline key for authority {:?}, not adding it to topology.", auth);
			}
		}

		for (auth, public_key) in topology.authorities.iter() {
			if auth == &topology.local_id {
				if let Some(table) = AuthorityTopology::refresh_connection_table_to(
					auth,
					public_key,
					Some(&topology.routing_table),
					&topology.authorities,
				) {
					topology.routing_table = table;
					topology.paths.clear();
					topology.paths_depth = 0;
				}
			} else {
				let past = topology.authorities_tables.get(auth);
				if let Some(table) = AuthorityTopology::refresh_connection_table_to(
					auth,
					public_key,
					past,
					&topology.authorities,
				) {
					topology.authorities_tables.insert(auth.clone(), table);
					topology.paths.clear();
					topology.paths_depth = 0;
				}
			}
		}
		for (auth, _public_key) in topology.authorities.iter() {
			if auth == &topology.local_id {
				if let Some(from) = AuthorityTopology::refresh_connection_table_from(
					auth,
					&topology.routing_table.receive_from,
					topology.authorities_tables.iter(),
				) {
					topology.routing_table.receive_from = from;
				}
			} else {
				if let Some(routing_table) = topology.authorities_tables.get(auth) {
					if let Some(from) = AuthorityTopology::refresh_connection_table_from(
						auth,
						&routing_table.receive_from,
						topology
							.authorities_tables
							.iter()
							.chain(std::iter::once((&topology.local_id, &topology.routing_table))),
					) {
						if let Some(routing_table) = topology.authorities_tables.get_mut(auth) {
							routing_table.receive_from = from;
						}
					}
				}
			}
		}

		let connected = std::mem::take(&mut topology.connected_nodes);
		topology.nb_connected_forward_routing = 0;
		topology.nb_connected_receive_routing = 0;
		topology.nb_connected_external = 0;
		topology.copy_connected_info_to_metrics();
		for peer_id in connected.into_iter() {
			topology.add_connected_peer(peer_id.0);
		}

		if let Some((id, key)) = restart {
			debug!(target: "mixnet", "Restarting");
			self.worker.restart(id, key);
		}

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
			.into_iter()
			.flat_map(|(_, keys)| {
				let mut grandpa = None;
				let mut imonline = None;
				for pair in keys {
					if pair.0 == sp_application_crypto::key_types::GRANDPA {
						grandpa = Some(pair.1);
					} else if pair.0 == sp_application_crypto::key_types::IM_ONLINE {
						imonline = Some(pair.1);
					}
				}
				if let (Some(g), Some(a)) = (grandpa, imonline) {
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
				if !self.worker.mixnet().topology.has_enough_nodes_to_proxy() {
					self.state = State::WaitingMorePeers;
				},
			State::WaitingMorePeers =>
				if self.worker.mixnet().topology.has_enough_nodes_to_proxy() {
					debug!(target: "mixnet", "Mixnet running.");
					self.state = State::Running;
				},
			State::Synching if synched =>
				if self.worker.mixnet().topology.has_enough_nodes_to_proxy() {
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
pub struct AuthorityTopology {
	// MixPeerId is ImOnline key.
	local_id: MixPeerId,
	network_id: NetworkPeerId,
	key_store: Arc<dyn SyncCryptoStore>,
	// true when we are in authorities set.
	routing: bool,
	nb_connected_forward_routing: usize,
	nb_connected_receive_routing: usize,
	nb_connected_external: usize,
	// All authorities are considered connected (when building message except first hop).
	authorities: BTreeMap<MixPeerId, MixPublicKey>, // TODO mixpublic key out of routing table??
	// The connected nodes (for first hop use `authorities` joined `connected_nodes`).
	connected_nodes: HashMap<MixPeerId, ConnectedKind>,
	// Current session mapping of Grandpa key to IMonline key.
	sessions: HashMap<CryptoTypePublicPair, CryptoTypePublicPair>,

	target_bytes_per_seconds: usize,

	// limit to external connection
	max_external: Option<usize>,

	metrics: Option<metrics::MetricsHandle>,

	routing_table: AuthorityTable,

	authorities_tables: BTreeMap<MixPeerId, AuthorityTable>,
	// all path of a given size.
	// on every change to auth table this is cleared TODO make change synchronously to
	// avoid full calc every time.
	//
	// This assume topology is balanced, so we can just run random selection at each hop.
	// TODO check topology balancing and balance if needed (keeping only peers with right incoming
	// and outgoing?)
	// TODO find something better
	// TODO could replace HashMap by vec and use indices as ptr
	paths: BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	paths_depth: usize,
}

/// Current published view of an authority routing table.
///
/// Table is currently signed by ImOnline key.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AuthorityTable {
	public_key: MixPublicKey,
	// TODO could put revision but change will be more costy to converge.
	// TODO or put revision in dht key, then on handshake you also pass revision and then crawl
	// over updates -> I kinda like that.
	// Actually would be easier with a `known_latest_revision` field with all known latest revision
	// so peers can easilly resolve dht key and next dht key (if none found, can still query from
	// 0). -> requires outside a Map MixPeerId to latest received revision, so we query other key.
	// Interesting in the sense we have one key on value, but would need to change a bit the dht
	// logic. -> actually may not be proper idea, one key and subsequent update, just need to
	// ensure we are using the latest version which for signed info is easy: ord (sessionid,
	// revision).
	// TODO could replace MixPeerId by index in list of authorities for compactness.
	connected_to: BTreeSet<MixPeerId>,
	receive_from: BTreeSet<MixPeerId>, /* incoming peer needed to check if published information
	                                    * is fresh. */
}

// TODO more but this is ok for testing on a 6 authority network.
// TODO put in config.
const NUMBER_CONNECTED_FORWARD: usize = 4;

const DEFAULT_NUM_HOPS: u32 = 4;

// should statically be NUMBER_CONNECTED_BACKWARD, but applying a small variation margin.
const NUMBER_CONNECTED_BACKWARD: usize = NUMBER_CONNECTED_FORWARD - 2;

impl AuthorityTable {
	fn should_connect_to<D>(
		from: &MixPeerId,
		authorities: &BTreeMap<MixPeerId, D>,
		nb: usize,
	) -> Vec<MixPeerId> {
		// TODO cache common seed when all_auth got init
		let mut common_seed = [0u8; 32];
		for auth in authorities.iter() {
			let hash = sp_core::hashing::blake2_256(auth.0);
			for i in 0..32 {
				common_seed[i] ^= hash[i];
			}
		}
		let mut hash = sp_core::hashing::blake2_256(from);
		for i in 0..32 {
			hash[i] ^= common_seed[i];
		}

		let mut auths: Vec<_> = authorities
			.iter()
			.filter_map(|a| if a.0 != from { Some(a.0) } else { None })
			.collect();
		let mut nb_auth = auths.len();
		let mut result = Vec::with_capacity(std::cmp::min(nb, nb_auth));
		let mut cursor = 0;
		while result.len() < nb && nb_auth > 0 {
			// TODO bit arith
			let mut nb_bytes = match nb_auth {
				nb_auth if nb_auth <= u8::MAX as usize => 1,
				nb_auth if nb_auth <= u16::MAX as usize => 2,
				nb_auth if nb_auth < 1usize << 24 => 3,
				nb_auth if nb_auth < u32::MAX as usize => 4,
				_ => unimplemented!(),
			};
			let mut at = 0usize;
			loop {
				if let Some(next) = hash.get(cursor) {
					nb_bytes -= 1;
					at += (*next as usize) * (1usize << (8 * nb_bytes));
					cursor += 1;
					if nb_bytes == 0 {
						break
					}
				} else {
					cursor = 0;
					hash = sp_core::hashing::blake2_256(&hash);
				}
			}
			at = at % nb_auth;
			result.push(auths.remove(at).clone());
			nb_auth = auths.len();
		}
		result
	}
}

enum ConnectedKind {
	External,
	RoutingForward,
	RoutingReceive,
	RoutingReceiveForward,
}

#[derive(Clone)]
pub struct AuthorityInfo {
	pub grandpa_id: AuthorityId,
	pub authority_discovery_id: CryptoTypePublicPair,
}

impl AuthorityTopology {
	/// Instantiate a new topology.
	pub fn new(
		local_id: MixPeerId,
		network_id: NetworkPeerId,
		node_public_key: MixPublicKey,
		key_store: Arc<dyn SyncCryptoStore>,
		config: &Config,
		max_external: Option<usize>,
		metrics: Option<metrics::MetricsHandle>,
	) -> Self {
		let routing_table = AuthorityTable {
			public_key: node_public_key,
			connected_to: BTreeSet::new(),
			receive_from: BTreeSet::new(),
		};
		AuthorityTopology {
			local_id,
			network_id,
			authorities: BTreeMap::new(),
			connected_nodes: HashMap::new(),
			sessions: HashMap::new(),
			routing: false,
			key_store,
			authorities_tables: BTreeMap::new(),
			routing_table,
			paths: Default::default(),
			paths_depth: 0,
			//disconnected_in_routing: Default::default(),
			nb_connected_forward_routing: 0,
			nb_connected_receive_routing: 0,
			nb_connected_external: 0,
			target_bytes_per_seconds: config.target_bytes_per_second as usize,
			max_external,
			metrics,
		}
	}

	fn has_enough_nodes_to_send(&self) -> bool {
		self.authorities.len() >= LOW_MIXNET_THRESHOLD
	}

	fn has_enough_nodes_to_proxy(&self) -> bool {
		self.authorities.len() >= LOW_MIXNET_THRESHOLD
	}

	fn copy_connected_info_to_metrics(&self) {
		self.metrics.as_ref().map(|m| {
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Total as usize]
				])
				.set(self.connected_nodes.len() as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Forwarding as usize]
				])
				.set(self.nb_connected_forward_routing as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::Receiving as usize]
				])
				.set(self.nb_connected_receive_routing as u64);
			m.current_connected
				.with_label_values(&[
					metrics::LABEL_NODE_STATUS[metrics::ConnectedNodeStatus::External as usize]
				])
				.set(self.nb_connected_external as u64);
		});
	}

	fn add_connected_peer(&mut self, peer_id: MixPeerId) {
		debug!(target: "mixnet", "Connected to mixnet {:?}", peer_id);
		if let Some(_) = self.connected_nodes.get_mut(&peer_id) {
			return
		}
		let kind = if self.is_routing(&peer_id) {
			if !self.routing {
				self.nb_connected_external += 1;
				ConnectedKind::External
			} else if self.routing_to(&self.local_id, &peer_id) {
				self.nb_connected_forward_routing += 1;
				if self.routing_to(&peer_id, &self.local_id) {
					self.nb_connected_receive_routing += 1;
					ConnectedKind::RoutingReceiveForward
				} else {
					ConnectedKind::RoutingForward
				}
			} else if self.routing_to(&peer_id, &self.local_id) {
				self.nb_connected_receive_routing += 1;
				ConnectedKind::RoutingReceive
			} else {
				self.nb_connected_external += 1;
				ConnectedKind::External
			}
		} else {
			self.nb_connected_external += 1;
			ConnectedKind::External
		};
		self.connected_nodes.insert(peer_id, kind);
		self.copy_connected_info_to_metrics();
	}

	fn add_disconnected_peer(&mut self, peer_id: &MixPeerId) {
		debug!(target: "mixnet", "Disconnected from mixnet {:?}", peer_id);
		if let Some(kind) = self.connected_nodes.remove(peer_id) {
			match kind {
				ConnectedKind::External => {
					self.nb_connected_external -= 1;
				},
				ConnectedKind::RoutingReceive => {
					self.nb_connected_receive_routing -= 1;
				},
				ConnectedKind::RoutingForward => {
					self.nb_connected_forward_routing -= 1;
				},
				ConnectedKind::RoutingReceiveForward => {
					self.nb_connected_forward_routing -= 1;
					self.nb_connected_receive_routing -= 1;
				},
			}
			self.copy_connected_info_to_metrics();
		}
	}

	fn refresh_connection_table_to(
		from: &MixPeerId,
		from_key: &MixPublicKey,
		past: Option<&AuthorityTable>,
		authorities: &BTreeMap<MixPeerId, MixPublicKey>,
	) -> Option<AuthorityTable> {
		let tos = AuthorityTable::should_connect_to(from, authorities, NUMBER_CONNECTED_FORWARD);
		let mut routing_table = AuthorityTable {
			public_key: from_key.clone(),
			connected_to: Default::default(),
			receive_from: Default::default(),
		};
		for peer in tos.into_iter() {
			// consider all connected
			routing_table.connected_to.insert(peer);
			if routing_table.connected_to.len() == NUMBER_CONNECTED_FORWARD {
				break
			}
		}

		(past != Some(&routing_table)).then(|| routing_table)
	}

	fn refresh_connection_table_from<'a>(
		from: &MixPeerId,
		past: &BTreeSet<MixPeerId>,
		authorities_tables: impl Iterator<Item = (&'a MixPeerId, &'a AuthorityTable)>,
	) -> Option<BTreeSet<MixPeerId>> {
		let mut receive_from = BTreeSet::default();
		for (peer_id, table) in authorities_tables {
			if table.connected_to.contains(from) {
				receive_from.insert(peer_id.clone());
			}
		}

		(past != &receive_from).then(|| receive_from)
	}
}

impl AuthorityTopology {
	fn random_dest(&self, skip: impl Fn(&MixPeerId) -> bool) -> Option<MixPeerId> {
		use rand::RngCore;
		// Warning this assume that NetworkPeerId is a randomly distributed value.
		let mut ix = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut ix[..]);

		trace!(target: "mixnet", "routing {:?}, ix {:?}", self.authorities_tables, ix);
		for (key, table) in self.authorities_tables.range(ix..) {
			// TODO alert on low receive_from
			if !skip(&key) && !(table.receive_from.len() < NUMBER_CONNECTED_BACKWARD) {
				debug!(target: "mixnet", "Random route node");
				return Some(key.clone())
			} else {
				debug!(target: "mixnet", "Skip {:?}, nb {:?}, {:?}", skip(&key), table.receive_from.len(), NUMBER_CONNECTED_BACKWARD);
			}
		}
		for (key, table) in self.authorities_tables.range(..ix).rev() {
			if !skip(&key) && !(table.receive_from.len() < NUMBER_CONNECTED_BACKWARD) {
				debug!(target: "mixnet", "Random route node");
				return Some(key.clone())
			} else {
				debug!(target: "mixnet", "Skip {:?}, nb {:?}, {:?}", skip(&key), table.receive_from.len(), NUMBER_CONNECTED_BACKWARD);
			}
		}
		None
	}
}

fn random_path(
	paths: &BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	from: &MixPeerId,
	to: &MixPeerId,
	size_path: usize,
) -> Option<Vec<MixPeerId>> {
	trace!(target: "mixnet", "routing from {:?}, to {:?}, path size {:?}", from, to, size_path);
	// TODO some minimal length??
	if size_path < 3 {
		return None
	}
	let mut rng = rand::thread_rng();
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(from.clone());
	exclude.insert(to.clone());
	let mut result = Vec::<MixPeerId>::with_capacity(size_path); // allocate two extra for case where a node is
															 // appended front or/and back.
	result.push(from.clone());
	// TODO consider Vec instead of hashset (small nb elt)
	let mut touched = Vec::<HashSet<MixPeerId>>::with_capacity(size_path - 2);
	touched.push(HashSet::new());
	while at > 2 {
		if let Some(paths) = result.last().and_then(|from| {
			paths.get(&at).and_then(|paths| paths.get(to)).and_then(|paths| paths.get(from))
		}) {
			if let Some(next) = random_path_inner(&mut rng, paths, |p| {
				exclude.contains(p) ||
					touched.last().map(|touched| touched.contains(p)).unwrap_or(false)
			}) {
				result.push(next);
				touched.last_mut().map(|touched| {
					touched.insert(next);
				});
				touched.push(HashSet::new());
				exclude.insert(next);
				at -= 1;
				continue
			}
		}
		// dead end path
		if result.len() == 1 {
			return None
		}
		if let Some(child) = result.pop() {
			exclude.remove(&child);
			touched.pop();
			at += 1;
		}
	}
	result.remove(0); // TODO rewrite to avoid it.
	Some(result)
}

fn count_paths(
	paths: &BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	from: &MixPeerId,
	to: &MixPeerId,
	size_path: usize,
) -> usize {
	let mut total = 0;
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(from.clone());
	exclude.insert(to.clone());
	let mut result = Vec::<(MixPeerId, usize)>::with_capacity(size_path); // allocate two extra for case where a node is
																	  // appended front or/and back.
	result.push((from.clone(), 0));
	let mut touched = Vec::<HashSet<MixPeerId>>::with_capacity(size_path - 2);
	touched.push(HashSet::new());
	loop {
		if let Some((paths, at_ix)) = result.last().and_then(|(from, at_ix)| {
			paths
				.get(&at)
				.and_then(|paths| paths.get(to))
				.and_then(|paths| paths.get(from))
				.map(|p| (p, *at_ix))
		}) {
			if let Some(next) = paths.get(at_ix).cloned() {
				result.last_mut().map(|(_, at_ix)| {
					*at_ix += 1;
				});
				if !exclude.contains(&next) &&
					!touched.last().map(|touched| touched.contains(&next)).unwrap_or(false)
				{
					if at == 3 {
						total += 1;
					} else {
						result.push((next, 0));
						touched.last_mut().map(|touched| {
							touched.insert(next);
						});
						touched.push(HashSet::new());
						exclude.insert(next);
						at -= 1;
					}
					continue
				} else {
					continue
				}
			}
		}
		if result.len() == 1 {
			break
		}
		if let Some((child, _)) = result.pop() {
			exclude.remove(&child);
			touched.pop();
			at += 1;
		}
	}
	total
}

fn random_path_inner(
	rng: &mut rand::rngs::ThreadRng,
	routes: &Vec<MixPeerId>,
	skip: impl Fn(&MixPeerId) -> bool,
) -> Option<MixPeerId> {
	use rand::Rng;
	// Warning this assume that PeerId is a randomly distributed value.
	let ix: usize = match routes.len() {
		l if l <= u8::MAX as usize => rng.gen::<u8>() as usize,
		l if l <= u16::MAX as usize => rng.gen::<u16>() as usize,
		l if l <= u32::MAX as usize => rng.gen::<u32>() as usize,
		_ => rng.gen::<usize>(),
	};
	let ix = ix % routes.len();

	for key in routes[ix..].iter() {
		if !skip(&key) {
			debug!(target: "mixnet", "Random route node");
			return Some(key.clone())
		}
	}
	for key in routes[..ix].iter() {
		if !skip(key) {
			debug!(target: "mixnet", "Random route node");
			return Some(key.clone())
		}
	}
	None
}

impl Topology for AuthorityTopology {
	fn first_hop_nodes_external(
		&self,
		from: &MixPeerId,
		to: &MixPeerId,
	) -> Vec<(MixPeerId, MixPublicKey)> {
		// allow for all
		self.authorities
			.iter()
			.filter(|(id, _key)| from != *id)
			.filter(|(id, _key)| to != *id)
			.filter(|(id, _key)| &self.local_id != *id)
			.filter(|(id, _key)| self.connected_nodes.contains_key(*id))
			.filter_map(|(k, _v)| {
				self.authorities_tables
					.get(k)
					.map(|table| (k.clone(), table.public_key.clone()))
			})
			.collect()
	}

	fn is_first_node(&self, id: &MixPeerId) -> bool {
		// allow for all
		self.is_routing(id)
	}

	// TODO make random_recipient return path directly.
	fn random_recipient(
		&mut self,
		from: &MixPeerId,
		send_options: &mixnet::SendOptions,
	) -> Option<(MixPeerId, MixPublicKey)> {
		if !self.has_enough_nodes_to_send() {
			debug!(target: "mixnet", "Not enough routing nodes for path.");
			return None
		}
		let mut bad = HashSet::new();
		loop {
			debug!(target: "mixnet", "rdest {:?}", (&from, &bad));
			if let Some(peer) = self.random_dest(|p| p == from || bad.contains(p)) {
				debug!(target: "mixnet", "Trying random dest {:?}.", peer);
				let nb_hop = send_options.num_hop.unwrap_or(DEFAULT_NUM_HOPS as usize);
				AuthorityTopology::fill_paths(
					&self.local_id,
					&self.routing_table,
					&mut self.paths,
					&mut self.paths_depth,
					&self.authorities_tables,
					nb_hop,
				);
				let from_count = if !self.is_routing(from) {
					debug!(target: "mixnet", "external {:?}", from);
					// TODO should return path directly rather than random here that could be
					// different that path one -> then the check on count could be part of path
					// building
					let firsts = self.first_hop_nodes_external(from, &peer);
					if firsts.len() == 0 {
						return None
					}
					firsts[0].0.clone()
				} else {
					from.clone()
				};
				// TODO also count surbs??
				let nb_path = count_paths(&self.paths, &from_count, &peer, nb_hop);
				debug!(target: "mixnet", "Number path for dest {:?}.", nb_path);
				debug!(target: "mixnet", "{:?} to {:?}", from_count, peer);
				if nb_path >= LOW_MIXNET_PATHS {
					return self.authorities_tables.get(&peer).map(|keys| (peer, keys.public_key))
				} else {
					bad.insert(peer);
				}
			} else {
				debug!(target: "mixnet", "No random dest.");
				return None
			}
		}
	}

	/// For a given peer return a list of peers it is supposed to be connected to.
	/// Return `None` if peer is unknown to the topology.
	fn neighbors(&self, from: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		if !self.is_routing(from) {
			return None
		}
		// unused, random_paths directly implement.
		Some(
			self.routing_table
				.connected_to
				.iter()
				.filter_map(|k| {
					self.authorities_tables
						.get(k)
						.map(|table| (k.clone(), table.public_key.clone()))
				})
				.collect(),
		)
	}

	fn routing_to(&self, from: &MixPeerId, to: &MixPeerId) -> bool {
		(self.authorities.contains_key(from) || (&self.local_id == from && self.routing)) &&
			(self.authorities.contains_key(to) || (&self.local_id == to && self.routing))
	}

	fn random_path(
		&mut self,
		start_node: (&MixPeerId, Option<&MixPublicKey>),
		recipient_node: (&MixPeerId, Option<&MixPublicKey>),
		nb_chunk: usize,
		num_hops: usize,
		max_hops: usize,
		last_query_if_surb: Option<&Vec<(MixPeerId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		// Diverging from default implementation (random from all possible paths), as `neighbor`
		// return same result for all routing peer building all possible path is not usefull.
		let mut add_start = None;
		let mut add_end = None;
		let start = if self.is_first_node(start_node.0) {
			start_node.0.clone()
		} else {
			trace!(target: "mixnet", "External node");
			if num_hops + 1 > max_hops {
				return Err(Error::TooManyHops)
			}

			let firsts = self.first_hop_nodes_external(start_node.0, recipient_node.0);
			if firsts.len() == 0 {
				return Err(Error::NoPath(Some(recipient_node.0.clone())))
			}
			let mut rng = rand::thread_rng();
			use rand::Rng;
			let n: usize = rng.gen_range(0, firsts.len());
			add_start = Some(firsts[n].clone());
			firsts[n].0.clone()
		};

		let recipient = if self.is_routing(recipient_node.0) {
			recipient_node.0.clone()
		} else {
			trace!(target: "mixnet", "Non routing recipient");
			if num_hops + 1 > max_hops {
				return Err(Error::TooManyHops)
			}

			if let Some(query) = last_query_if_surb {
				// use again a node that was recently connected.
				if let Some(rec) = query.get(0) {
					trace!(target: "mixnet", "Surbs last: {:?}", rec);
					add_end = Some(recipient_node);
					rec.0.clone()
				} else {
					return Err(Error::NoPath(Some(recipient_node.0.clone())))
				}
			} else {
				return Err(Error::NoPath(Some(recipient_node.0.clone())))
			}
		};
		trace!(target: "mixnet", "number hop: {:?}", num_hops);
		AuthorityTopology::fill_paths(
			&self.local_id,
			&self.routing_table,
			&mut self.paths,
			&mut self.paths_depth,
			&self.authorities_tables,
			num_hops,
		);
		let nb_path = count_paths(&self.paths, &start, &recipient, num_hops);
		debug!(target: "mixnet", "Number path for dest {:?}.", nb_path);
		debug!(target: "mixnet", "{:?} to {:?}", start, recipient);
		if nb_path < LOW_MIXNET_PATHS {
			trace!(target: "mixnet", "not enough paths: {:?}", &self.paths);
			// TODO NotEnoughPath error
			return Err(Error::NoPath(Some(recipient)))
		};

		let mut result = Vec::with_capacity(nb_chunk);
		while result.len() < nb_chunk {
			let path_ids =
				if let Some(path) = random_path(&self.paths, &start, &recipient, num_hops) {
					trace!(target: "mixnet", "Got path: {:?}", &path);
					path
				} else {
					return Err(Error::NoPath(Some(recipient)))
				};
			let mut path = Vec::with_capacity(num_hops + 1);
			if let Some((peer, key)) = add_start {
				debug!(target: "mixnet", "Add first, nexts {:?}.", path_ids.len());
				path.push((peer.clone(), key.clone()));
			}

			for peer_id in path_ids.into_iter() {
				if let Some(table) = self.authorities_tables.get(&peer_id) {
					path.push((peer_id, table.public_key.clone()));
				} else {
					error!(target: "mixnet", "node in routing_nodes must also be in connected_nodes");
					unreachable!("node in routing_nodes must also be in connected_nodes");
				}
			}
			if let Some(table) = self.authorities_tables.get(&recipient) {
				path.push((recipient.clone(), table.public_key.clone()));
			} else {
				if self.local_id == recipient {
					// surb reply
					path.push((self.local_id.clone(), self.routing_table.public_key.clone()));
				} else {
					error!(target: "mixnet", "Unknown recipient {:?}", recipient);
					return Err(Error::NotEnoughRoutingPeers)
				}
			}

			if let Some((peer, key)) = add_end {
				if let Some(key) = key {
					path.push((peer.clone(), key.clone()));
				} else {
					return Err(Error::NoPath(Some(recipient_node.0.clone())))
				}
			}
			result.push(path);
		}
		debug!(target: "mixnet", "Path: {:?}", result);
		Ok(result)
	}

	fn is_routing(&self, id: &MixPeerId) -> bool {
		self.authorities.contains_key(id)
	}

	fn connected(&mut self, peer_id: MixPeerId, _key: MixPublicKey) {
		debug!(target: "mixnet", "Connected from internal");
		self.add_connected_peer(peer_id)
	}

	fn disconnect(&mut self, peer_id: &MixPeerId) {
		debug!(target: "mixnet", "Disconnected from internal");
		self.add_disconnected_peer(&peer_id);
	}

	fn bandwidth_external(&self, _id: &MixPeerId) -> Option<(usize, usize)> {
		// TODO can cache this result (Option<Option<(usize, usize))

		// Equal bandwidth amongst connected peers.
		let nb_forward = self.nb_connected_forward_routing;
		let nb_receive = self.nb_connected_receive_routing;
		// TODO add parameter to indicate if for a new peer or an existing one.
		let nb_external = self.nb_connected_external + 1;

		let forward_bandwidth = ((EXTERNAL_BANDWIDTH.0 + EXTERNAL_BANDWIDTH.1) *
			nb_forward * self.target_bytes_per_seconds) /
			EXTERNAL_BANDWIDTH.1;
		let receive_bandwidth = nb_receive * self.target_bytes_per_seconds;

		let available_bandwidth = forward_bandwidth - receive_bandwidth;
		let available_per_external = available_bandwidth / nb_external;

		Some((available_per_external, self.target_bytes_per_seconds))
	}

	fn handshake_size(&self) -> usize {
		32 + 32 + 64
	}

	fn check_handshake(
		&mut self,
		payload: &[u8],
		_from: &NetworkPeerId,
	) -> Option<(MixPeerId, MixPublicKey)> {
		let mut peer_id = [0u8; 32];
		peer_id.copy_from_slice(&payload[0..32]);
		let mut pk = [0u8; 32];
		pk.copy_from_slice(&payload[32..64]);
		let mut signature = [0u8; 64];
		signature.copy_from_slice(&payload[64..]);
		let signature = sp_application_crypto::sr25519::Signature(signature);
		let mut message = self.network_id.to_bytes().to_vec();
		message.extend_from_slice(&pk[..]);
		let key = sp_application_crypto::sr25519::Public(peer_id.clone());
		debug!(target: "mixnet", "check handshake: {:?}, {:?}, {:?} from {:?}", peer_id, message, signature, _from);
		use sp_application_crypto::RuntimePublic;
		if key.verify(&message, &signature) {
			if !self.accept_peer(&self.local_id, &peer_id) {
				self.metrics.as_ref().map(|m| m.invalid_handshake.inc());
				return None
			}
			if self.is_routing(&peer_id) {
				// TODO this should be checking routing table from other peer and see peers
				// connected to multiple others so we wait for their connection or ping them.
				// TODO One could still for big difference in the priority list try to check if
				// online and at some point reject the peer as not being connected enough (globaly
				// with other authorities). Number can be big initially as authority may disable
				// mixnet a lot. TODO in case we are already receiving from more than a threshould
				// we drop others connection.
			}
			let pk = MixPublicKey::from(pk);
			self.metrics.as_ref().map(|m| m.valid_handshake.inc());
			Some((peer_id, pk))
		} else {
			self.metrics.as_ref().map(|m| m.invalid_handshake.inc());
			None
		}
	}

	fn handshake(&mut self, with: &NetworkPeerId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		let mut result = self.local_id.to_vec();
		result.extend_from_slice(&public_key.as_bytes()[..]);
		let mut message = with.to_bytes().to_vec();
		message.extend_from_slice(&public_key.as_bytes()[..]);
		match SyncCryptoStore::sign_with(
			&*self.key_store,
			key_types::IM_ONLINE,
			&CryptoTypePublicPair(sp_core::sr25519::CRYPTO_ID, self.local_id.to_vec()),
			&message[..],
		) {
			Ok(Some(signature)) => {
				result.extend_from_slice(&signature[..]);
				trace!(target: "mixnet", "create handshake: {:?}, {:?}, {:?} with {:?}", self.local_id, message, signature, with);
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

	fn accept_peer(&self, local_id: &MixPeerId, peer_id: &MixPeerId) -> bool {
		let accepted = self.routing_to(local_id, peer_id) ||
			self.routing_to(peer_id, local_id) ||
			(self.nb_connected_external < self.max_external.unwrap_or(usize::MAX) &&
				self.bandwidth_external(peer_id).is_some());
		if !accepted {
			self.metrics.as_ref().map(|m| m.rejected_external.inc());
		}
		accepted
	}

	fn collect_windows_stats(&self) -> bool {
		self.metrics.is_some()
	}

	fn window_stats(&self, stats: &mixnet::WindowStats) {
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
			if self.nb_connected_forward_routing > 0 {
				let peer_paquets =
					total_peer_paquets as f64 / self.nb_connected_forward_routing as f64;
				let peer_paquets = peer_paquets / nb_window as f64;
				metrics.avg_packet_queue_size_for_peer.set(peer_paquets);
				for _ in 0..nb_window {
					metrics.avg_packet_queue_size_for_peer_histo.observe(peer_paquets);
				}
			} else {
				metrics.avg_packet_queue_size_for_peer.set(0.0);
			}
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
	}
}

mod metrics {
	use log::trace;
	use mixnet::MixPeerId;
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
		// a bit redundant with gauge, should remove later.
		pub avg_packet_queue_size_for_peer_histo: Histogram,
		pub invalid_handshake: Counter<U64>,
		// only to compare with number of skipped window,
		// otherwhise it is a uptime.
		pub number_of_window: Counter<U64>,
		pub number_of_skipped_window: Counter<U64>,
		// This may make little sense, just
		// keeping an eye on it, should remove later.
		pub rejected_external: Counter<U64>,
		registry: Registry,
	}

	pub enum ConnectedNodeStatus {
		Total = 0,
		Forwarding = 1,
		Receiving = 2,
		External = 3,
	}

	pub const LABEL_NODE_STATUS: &[&str] = &["total", "forwarding", "receiving", "external"];

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
		peer_id: &MixPeerId,
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
		let rejected_external = register(
			Counter::<U64>::new(
				"substrate_mixnet_rejected_external",
				"Number of external connection refused",
			)?,
			&registry,
		)?;
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

		Ok(MetricsHandle {
			mixnet_info,
			current_connected,
			rejected_external,
			valid_handshake,
			max_packet_queue_for_peer,
			avg_packet_queue_size_for_peer,
			avg_packet_queue_size_for_peer_histo,
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
		pub fn change_id(&mut self, new_peer_id: &MixPeerId) -> Result<(), PrometheusError> {
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

impl AuthorityTopology {
	#[cfg(test)]
	fn paths_mem_size(
		paths: &BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	) -> usize {
		// approximate and slow, just to get idea in test. TODO update when switching paths to use
		// indexes as ptr.
		let mut size = 0;
		for paths in paths.iter() {
			size += 8; // usize
			for paths in paths.1.iter() {
				size += 32;
				for paths in paths.1.iter() {
					size += 32;
					for _ in paths.1.iter() {
						size += 32;
					}
				}
			}
		}
		size
	}

	// TODO Note that building this is rather brutal, could just make some
	// random selection already to reduce size (and refresh after x uses).
	fn fill_paths(
		local_id: &MixPeerId,
		local_routing: &AuthorityTable,
		paths: &mut BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
		paths_depth: &mut usize,
		authorities_tables: &BTreeMap<MixPeerId, AuthorityTable>,
		depth: usize,
	) {
		if &depth <= paths_depth {
			return
		}
		// TODO not strictly needed (all in authorities_tables), convenient to exclude local id..
		//		let mut from_to = HashMap::<MixPeerId, Vec<MixPeerId>>::new();
		// TODO not strictly needed (all in authorities_tables), convenient to exclude local id.
		let mut to_from = HashMap::<MixPeerId, Vec<MixPeerId>>::new();

		for (from, table) in
			authorities_tables.iter().chain(std::iter::once((local_id, local_routing)))
		{
			// TODO change if limitting size of receive_from
			to_from.insert(from.clone(), table.receive_from.iter().cloned().collect());
		}

		Self::fill_paths_inner(to_from, paths, *paths_depth, depth);
		if *paths_depth < depth {
			*paths_depth = depth;
		}
	}

	fn fill_paths_inner(
		to_from: HashMap<MixPeerId, Vec<MixPeerId>>,
		paths: &mut BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
		paths_depth: usize,
		depth: usize,
	) {
		let mut start_depth = std::cmp::max(2, paths_depth);
		while start_depth < depth {
			let depth = start_depth + 1;
			if start_depth == 2 {
				let at = paths.entry(depth).or_default();
				for (to, mid) in to_from.iter() {
					let depth_paths: &mut HashMap<MixPeerId, Vec<MixPeerId>> =
						at.entry(to.clone()).or_default();
					for mid in mid {
						if let Some(parents) = to_from.get(mid) {
							for from in parents.iter() {
								// avoid two identical node locally (paths still contains
								// redundant node in some of its paths but being
								// distributed in a balanced way we will just avoid those
								// on each hop random calculation.
								if from == to {
									continue
								}
								depth_paths.entry(from.clone()).or_default().push(mid.clone());
							}
						}
					}
				}
			} else {
				let at = paths.entry(start_depth).or_default();
				let mut dest_at = HashMap::<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>::new();
				for (to, paths_to) in at.iter() {
					let depth_paths = dest_at.entry(to.clone()).or_default();
					for (mid, _) in paths_to.iter() {
						if let Some(parents) = to_from.get(mid) {
							for from in parents.iter() {
								if from == to {
									continue
								}
								depth_paths.entry(from.clone()).or_default().push(mid.clone());
							}
						}
					}
				}
				paths.insert(depth, dest_at);
			}
			start_depth += 1;
		}
	}
}

#[test]
fn test_fill_paths() {
	/*let nb_peers: u16 = 1000;
	let nb_forward = 10;
	let depth = 5;*/
	let nb_peers: u16 = 5;
	let nb_forward = 3;
	let depth = 4;

	let peers: Vec<[u8; 32]> = (0..nb_peers)
		.map(|i| {
			let mut id = [0u8; 32];
			id[0] = (i % 8) as u8;
			id[1] = (i / 8) as u8;
			id
		})
		.collect();
	let local_id = [255u8; 32];
	let authorities: BTreeMap<_, _> = peers
		.iter()
		.chain(std::iter::once(&local_id))
		.map(|p| (p.clone(), ()))
		.collect();

	/*	let from_to: HashMap<MixPeerId, Vec<MixPeerId>> = vec![
		(peers[0].clone(), vec![peers[1].clone(), peers[2].clone()]),
		(peers[1].clone(), vec![peers[3].clone(), peers[4].clone()]),
		(peers[2].clone(), vec![peers[0].clone(), peers[4].clone()]),
	]
	.into_iter()
	.collect();*/

	let mut from_to: HashMap<MixPeerId, Vec<MixPeerId>> = Default::default();
	for p in peers.iter().chain(std::iter::once(&local_id)) {
		let tos = AuthorityTable::should_connect_to(p, &authorities, nb_forward);
		from_to.insert(p.clone(), tos);
	}
	let mut to_from: HashMap<MixPeerId, Vec<MixPeerId>> = Default::default();
	//	let from_to2: BTreeMap<_, _> = from_to.iter().map(|(k, v)|(k.clone(), v.clone())).collect();
	for (from, tos) in from_to.iter() {
		for to in tos.iter() {
			to_from.entry(to.clone()).or_default().push(from.clone());
		}
	}
	//		let from_to = from_to.clone();
	//		let to_from = to_from.clone();
	let mut paths = BTreeMap::new();
	let paths_depth = 0;
	AuthorityTopology::fill_paths_inner(to_from, &mut paths, paths_depth, depth);
	//	println!("{:?}", paths);
	println!("size {:?}", AuthorityTopology::paths_mem_size(&paths));

	// there is a path but cycle on 0 (depth 4)
	//	assert!(random_path(&paths, &peers[0], &peers[1], depth).is_none());
	let nb_path = count_paths(&paths, &local_id, &peers[1], depth);
	println!("nb_path {:?}", nb_path);
	let path = random_path(&paths, &local_id, &peers[1], depth);
	if path.is_none() {
		assert_eq!(nb_path, 0);
	}
	println!("{:?}", path);
	let mut nb_reachable = 0;
	let mut med_nb_con = 0;
	for i in 1..nb_peers as usize {
		let path = random_path(&paths, &peers[0], &peers[i], depth);
		if path.is_some() {
			nb_reachable += 1;
		}
		let nb_path = count_paths(&paths, &peers[0], &peers[i], depth);
		med_nb_con += nb_path;
	}
	let med_nb_con = med_nb_con as f64 / (nb_peers as f64 - 1.0);
	let reachable = nb_reachable as f64 / (nb_peers as f64 - 1.0);
	println!("Reachable {:?}, Med nb {:?}", reachable, med_nb_con);
	panic!("to print");
}

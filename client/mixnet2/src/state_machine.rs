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

use crate::{config::Config, kx_store::KxStore};
use arrayvec::ArrayVec;
use bitflags::bitflags;
use bytes::Bytes;
use either::Either;
use libp2p::{Multiaddr, PeerId};
use log::{error, warn};
use mixnet_sphinx::{
	kx_public, peel, Action, MixnodeIndex, PeelErr, RawMixnodeIndex, Target, MAX_MIXNODE_INDEX,
	PACKET_SIZE, MAX_HOPS,
};
use rand::Rng;
use sc_offchain::NetworkState;
use sp_api::{ApiError, ApiRef};
use sp_mixnet_externalities_ext::MixnetKxPublicStore;
use sp_mixnet_runtime_api::MixnetApi;
use sp_mixnet_types::{KxPublic, OpaqueMixnode};
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use sp_session::SessionIndex;
use std::{
	cmp::{min, Ordering},
	collections::{BinaryHeap, HashMap, HashSet, VecDeque},
	hash::Hash,
	sync::{Arc, Mutex},
	time::{Duration, Instant},
};

const LOG_TARGET: &str = "mixnet";

struct Mixnode {
	kx_public: KxPublic,
	network_state: Option<NetworkState>,
}

impl From<OpaqueMixnode> for Mixnode {
	fn from(mixnode: OpaqueMixnode) -> Self {
		let network_state: Result<NetworkState, ()> = mixnode.network_state.try_into();
		let network_state = match network_state {
			Ok(mut network_state) => {
				// Filter out addresses which don't match the peer ID
				network_state.external_addresses.retain(|addr| {
					let ok = PeerId::try_from_multiaddr(addr) == Some(network_state.peer_id);
					if !ok {
						error!(
							target: LOG_TARGET,
							"Mixnode address {} does not match mixnode peer ID {}, ignoring",
							addr,
							network_state.peer_id
						);
					}
					ok
				});
				Some(network_state)
			},
			Err(_) => {
				error!(target: LOG_TARGET, "Failed to parse mixnode network state");
				None
			},
		};
		Self { kx_public: mixnode.kx_public, network_state }
	}
}

enum MixnodeIndices {
	Some(Vec<MixnodeIndex>),
	AllExceptLocal,
}

struct Mixnodes {
	vec: Vec<Mixnode>,
	/// Local mixnode index, or `None` if the local node is not one of the mixnodes.
	local_index: Option<MixnodeIndex>,
	/// Indices of the mixnodes to set as reserved peers.
	reserved_peer_indices: MixnodeIndices,
}

impl Mixnodes {
	fn new(
		mut vec: Vec<OpaqueMixnode>,
		local_kx_public: &KxPublic,
		num_gateway_mixnodes: u32,
	) -> Self {
		// Truncate to the maximum number of mixnodes and covert from opaque types
		let max = (MAX_MIXNODE_INDEX + 1) as usize;
		if vec.len() > max {
			warn!(
				target: LOG_TARGET,
				"Too many registered mixnodes ({}, max {}); ignoring excess",
				vec.len(),
				max
			);
			vec.truncate(max);
		}
		let vec: Vec<Mixnode> = vec.into_iter().map(Into::into).collect();

		let local_index =
			vec.iter()
				.position(|mixnode| &mixnode.kx_public == local_kx_public)
				.map(|index| {
					MixnodeIndex::new(index as RawMixnodeIndex)
						.expect("Mixnode set truncated to max size above")
				});

		let reserved_peer_indices = if local_index.is_some() {
			// Local node is a mixnode; want to connect to all other mixnodes
			MixnodeIndices::AllExceptLocal
		} else {
			// Local node is not a mixnode; pick a small number of "gateway" mixnodes to connect to
			MixnodeIndices::Some(
				rand::seq::index::sample(
					&mut rand::thread_rng(),
					vec.len(),
					min(num_gateway_mixnodes as usize, vec.len()),
				)
				.iter()
				.map(|index| {
					MixnodeIndex::new(index as RawMixnodeIndex)
						.expect("Mixnode set truncated to max size above")
				})
				.collect(),
			)
		};

		Self { vec, local_index, reserved_peer_indices }
	}

	fn reserved_peer_addresses(&self) -> impl Iterator<Item = &Multiaddr> {
		let indices = match &self.reserved_peer_indices {
			MixnodeIndices::Some(indices) => Either::Left(indices.iter().map(|index| index.get())),
			MixnodeIndices::AllExceptLocal => Either::Right({
				let num = self.vec.len() as RawMixnodeIndex;
				match self.local_index {
					None => Either::Left(0..num),
					Some(index) => {
						let index = index.get();
						Either::Right((0..index).chain((index + 1)..num))
					},
				}
			}),
		};
		indices.flat_map(|index| {
			self.vec[index as usize]
				.network_state
				.as_ref()
				.map_or(Either::Left(std::iter::empty()), |network_state| {
					Either::Right(network_state.external_addresses.iter())
				})
		})
	}
}

#[derive(Eq)]
struct ForwardPacket {
	/// Where the packet should be sent.
	peer_id: PeerId,
	/// When the packet should be sent.
	deadline: Instant,
	/// The packet contents. The length of this should always be `PACKET_SIZE`.
	packet: Vec<u8>,
}

impl PartialEq for ForwardPacket {
	fn eq(&self, other: &Self) -> bool {
		self.deadline == other.deadline
	}
}

impl PartialOrd for ForwardPacket {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for ForwardPacket {
	fn cmp(&self, other: &Self) -> Ordering {
		// Packets with the earliest deadline considered greatest
		self.deadline.cmp(&other.deadline).reverse()
	}
}

struct ForwardPacketQueue {
	/// Maximum number of packets in the queue. This should match the capacity of `queue`, but we
	/// don't rely on that.
	capacity: usize,
	queue: BinaryHeap<ForwardPacket>,
}

impl ForwardPacketQueue {
	fn new(capacity: usize) -> Self {
		let mut queue = BinaryHeap::new();
		queue.reserve_exact(capacity);
		Self { capacity, queue }
	}

	fn next_deadline(&self) -> Option<Instant> {
		self.queue.peek().map(|packet| packet.deadline)
	}

	/// Push a packet into the queue. Returns true iff the deadline of the item at the head of the
	/// queue changed.
	fn push(&mut self, packet: ForwardPacket) -> bool {
		if self.queue.len() < self.capacity {
			let prev_deadline = self.next_deadline();
			self.queue.push(packet);
			self.next_deadline() != prev_deadline
		} else {
			warn!(target: LOG_TARGET, "Dropped forward packet; forward queue full");
			false
		}
	}

	fn pop(&mut self) -> (Option<ForwardPacket>, bool) {
		let packet = self.queue.pop();
		(packet, !self.queue.is_empty())
	}
}

struct AuthoredPacket {
	/// First hop of the packet.
	peer_id: PeerId,
	/// The packet contents. The length of this should always be `PACKET_SIZE`.
	packet: Vec<u8>,
}

struct AuthoredPacketQueue {
	/// Maximum number of packets in the queue. This should match the capacity of `queue`, but we
	/// don't rely on that.
	capacity: usize,
	queue: VecDeque<AuthoredPacket>,
}

impl AuthoredPacketQueue {
	fn new(capacity: usize) -> Self {
		let mut queue = VecDeque::new();
		queue.reserve_exact(capacity);
		Self { capacity, queue }
	}

	fn pop(&mut self) -> Option<AuthoredPacket> {
		self.queue.pop_front()
	}
}

// Ideally we would use `Rc<RefCell<_>>`, but that would prevent the top-level future from being
// automatically marked `Send`. I believe it would be safe to manually mark it `Send`, but using
// `Arc<Mutex<_>>` is not really a big deal, so I've just done that.
pub struct PeerPacketQueue(Mutex<ArrayVec<Vec<u8>, 2>>);

impl PeerPacketQueue {
	fn new() -> Self {
		Self(Mutex::new(ArrayVec::new()))
	}

	/// Push `packet` onto the queue. Returns true if the queue was previously empty. Fails if the
	/// queue is full.
	fn push(&self, packet: Vec<u8>) -> Result<bool, ()> {
		let mut queue = self.0.lock().unwrap();
		if queue.is_full() {
			Err(())
		} else {
			let was_empty = queue.is_empty();
			queue.push(packet);
			Ok(was_empty)
		}
	}

	/// Drop all packets from the queue.
	pub fn clear(&self) {
		let mut queue = self.0.lock().unwrap();
		queue.clear();
	}

	/// Pop the packet at the head of the queue and return it, or, if the queue is empty, return
	/// `None`. Also returns true if there are more packets in the queue.
	pub fn pop(&self) -> (Option<Vec<u8>>, bool) {
		let mut queue = self.0.lock().unwrap();
		let packet = queue.pop();
		(packet, !queue.is_empty())
	}
}

/// A peer which has packets ready to send but is not currently being serviced.
pub struct ReadyPeer {
	pub id: PeerId,
	/// The peer's packet queue. Not empty.
	pub packet_queue: Arc<PeerPacketQueue>,
}

#[derive(thiserror::Error)]
enum TargetToPeerIdErr {
	#[error("Mixnodes for session {0} not known")]
	MixnodesNotKnown(SessionIndex),
	#[error("Bad mixnode index: {0}")]
	BadMixnodeIndex(MixnodeIndex),
	#[error("Mixnode {0} peer ID not known")]
	MixnodePeerIdNotKnown(MixnodeIndex),
	#[error("Bad peer ID: {0}")]
	BadPeerId(libp2p::identity::error::DecodingError),
}

enum RouteKind {
	/// Route begins at the local node and ends at a random mixnode.
	Regular,
	/// Route begins at a mixnode and ends at the local node.
	Reply,
	/// Route begins and ends at the local node.
	Loop,
}

#[derive(thiserror::Error)]
enum GenRouteErr {
	#[error("Mixnodes for current session not known")]
	MixnodesNotKnown,
	#[error("Too few mixnodes in current session")]
	TooFewMixnodes,
	#[error("The local node has not managed to connect to any mixnodes for the current session")]
	NoConnectedMixnodes,
}

enum CoverKind {
	Loop,
	Drop,
}

bitflags! {
	pub struct Asks: u32 {
		/// Update the reserved peers in the network module.
		const SET_RESERVED_PEERS = 0b001;
		/// Wait for the next forward packet deadline (returned by `next_forward_packet_deadline()`) and
		/// then call `dispatch_next_forward_packet()`.
		const WAIT_THEN_DISPATCH_NEXT_FORWARD_PACKET = 0b010;
		/// If `next_authored_packet_delay()` returns `Some(duration)` then wait for `duration` and then
		/// call `dispatch_next_authored_packet()`.
		const WAIT_THEN_DISPATCH_NEXT_AUTHORED_PACKET = 0b100;
	}
}

pub struct StateMachine<'config> {
	config: &'config Config,
	kx_store: KxStore,

	/// Index of current session.
	current_session_index: SessionIndex,
	/// Mixnodes for prev/current/next sessions. `None` means not known. Note that knowledge of the
	/// next session mixnodes implies knowledge of the current session mixnodes.
	session_mixnodes: [Option<Mixnodes>; 3],

	/// Queue of packets to be forwarded, after some delay.
	forward_packet_queue: ForwardPacketQueue,
	/// Queue of packets authored by us, to be dispatched in place of drop cover traffic.
	authored_packet_queue: AuthoredPacketQueue,
	/// Per-peer packet queues. These are very short and only exist to give packets somewhere to
	/// sit while waiting for notification senders to be ready.
	peer_packet_queues: HashMap<PeerId, Arc<PeerPacketQueue>>,

	/// Flags set to ask the layer above to do things.
	asks: Asks,
}

impl<'config> StateMachine<'config> {
	pub fn new(config: &'config Config, kx_store: KxStore) -> Self {
		Self {
			config,
			kx_store,

			current_session_index: 0,
			session_mixnodes: Default::default(),

			forward_packet_queue: ForwardPacketQueue::new(config.forward_packet_queue_capacity),
			authored_packet_queue: AuthoredPacketQueue::new(config.authored_packet_queue_capacity),
			peer_packet_queues: HashMap::new(),

			asks: Asks::empty(),
		}
	}

	fn kx_public_for_session(&self, session_index: SessionIndex) -> Result<KxPublic, ApiError> {
		self.kx_store.public().public_for_session(session_index).map_err(|err| {
			ApiError::Application(
				format!(
					"Failed to get key-exchange public key for session {}: {}",
					session_index, err
				)
				.into(),
			)
		})
	}

	pub fn handle_finality<Block, Api>(
		&mut self,
		api: ApiRef<Api>,
		block_id: &BlockId<Block>,
	) -> Result<(), ApiError>
	where
		Block: BlockT,
		Api: MixnetApi<Block>,
	{
		let session_status = api.session_status(block_id)?;

		if self.current_session_index != session_status.current_index {
			let advanced_by_one =
				session_status.current_index.saturating_sub(self.current_session_index) == 1;
			if (self.current_session_index != 0) && !advanced_by_one {
				warn!(
					target: LOG_TARGET,
					"Unexpected session index {}; previous session index was {}",
					session_status.current_index,
					self.current_session_index
				);
			}

			self.kx_store
				.discard_sessions_before(session_status.current_index.saturating_sub(1));
			self.current_session_index = session_status.current_index;
			if advanced_by_one {
				self.session_mixnodes.rotate_left(1);
				self.session_mixnodes[2] = None;
			} else {
				self.session_mixnodes = Default::default();
			}
			self.asks |= Asks::SET_RESERVED_PEERS;
		}

		if self.session_mixnodes[1].is_none() {
			self.session_mixnodes[1] = Some(Mixnodes::new(
				api.current_mixnodes(block_id)?,
				&self.kx_public_for_session(self.current_session_index)?,
				self.config.num_gateway_mixnodes,
			));
			// Note that due to the memoryless nature of exponential distributions, always setting
			// WAIT_THEN_DISPATCH_NEXT_AUTHORED_PACKET here is harmless. Doing so is simpler than
			// figuring out exactly when it needs to be set.
			self.asks |= Asks::SET_RESERVED_PEERS | Asks::WAIT_THEN_DISPATCH_NEXT_AUTHORED_PACKET;
		}

		if self.session_mixnodes[2].is_none() && session_status.next_registrations_closed {
			// Discard stuff for the previous session. This is somewhat arbitrary.
			self.kx_store.discard_sessions_before(self.current_session_index);
			self.session_mixnodes[0] = None;

			let next_session_index = self
				.current_session_index
				.checked_add(1)
				.ok_or(ApiError::Application("Session index overflow".into()))?;
			self.session_mixnodes[2] = Some(Mixnodes::new(
				api.next_mixnodes(block_id)?,
				&self.kx_public_for_session(next_session_index)?,
				self.config.num_gateway_mixnodes,
			));

			self.asks |= Asks::SET_RESERVED_PEERS;
		}

		Ok(())
	}

	pub fn reserved_peer_addresses(&self) -> HashSet<Multiaddr> {
		self.session_mixnodes
			.iter()
			.flat_map(|mixnodes| mixnodes.as_ref())
			.flat_map(|mixnodes| mixnodes.reserved_peer_addresses())
			.cloned()
			.collect()
	}

	pub fn handle_stream_opened(&mut self, peer_id: &PeerId) {
		if self
			.peer_packet_queues
			.insert(*peer_id, Arc::new(PeerPacketQueue::new()))
			.is_some()
		{
			error!(target: LOG_TARGET, "Two stream opened notifications for peer ID {}", peer_id);
		}
	}

	pub fn handle_stream_closed(&mut self, peer_id: &PeerId) {
		if self.peer_packet_queues.remove(peer_id).is_none() {
			error!(
				target: LOG_TARGET,
				"Stream closed notification for unknown peer ID {}", peer_id
			);
		}
	}

	fn target_to_peer_id(
		&self,
		target: &Target,
		session_index: SessionIndex,
	) -> Result<PeerId, TargetToPeerIdErr> {
		match target {
			Target::MixnodeIndex(mixnode_index) => {
				let mixnodes = self.session_mixnodes[session_index
					.wrapping_add(1)
					.wrapping_sub(self.current_session_index)
					as usize]
					.as_ref()
					.ok_or(TargetToPeerIdErr::MixnodesNotKnown(session_index))?;
				let mixnode = mixnodes
					.vec
					.get(mixnode_index.get() as usize)
					.ok_or(TargetToPeerIdErr::BadMixnodeIndex(mixnode_index))?;
				let network_state = mixnode
					.network_state
					.as_ref()
					.ok_or(TargetToPeerIdErr::MixnodePeerIdNotKnown(mixnode_index))?;
				Ok(network_state.peer_id)
			},
			Target::PeerId(peer_id) => {
				let public = libp2p::core::identity::ed25519::PublicKey::decode(peer_id)
					.map_err(TargetToPeerIdErr::BadPeerId)?;
				let public = libp2p::core::identity::PublicKey::Ed25519(public);
				Ok(public.into())
			},
		}
	}

	pub fn handle_packet(&mut self, packet: Bytes) {
		let packet = if let Ok(packet) = (*packet).try_into() {
			packet
		} else {
			error!(target: LOG_TARGET, "Received packet with bad size ({} bytes)", packet.len());
			return
		};

		let mut out = Vec::new();
		let res = self
			.kx_store
			// XXX Avoid using next session key before discarded prev, to avoid more than 2 replay filters at same time?
			// XXX Return rel session index?
			.session_exchanges(self.current_session_index, kx_public(packet))
			.find_map(|mut e| {
				// Allocate space for the output if we haven't already
				out.reserve_exact(PACKET_SIZE);
				out.resize(PACKET_SIZE, 0);
				let out = out.as_mut_slice().try_into().expect("Just resized to the required size");

				match peel(out, packet, e.shared_secret()) {
					// Bad MAC possibly means we used the secret from the wrong session; try the
					// secrets from the other sessions (prev/next)
					Err(PeelErr::BadMac) => None,
					// Any other error means the packet is corrupt; just discard it now without
					// trying the secrets from the other sessions
					Err(err) => Some(Err(err)),
					Ok(action) => {
						e.prevent_replay();
						Some(Ok((action, e.index())))
					},
				}
			});

		let (action, session_index) = match res {
			None => {
				error!(
					target: LOG_TARGET,
					"Failed to peel packet; either bad MAC or unknown secret"
				);
				return
			},
			Some(Err(err)) => {
				error!(target: LOG_TARGET, "Failed to peel packet: {}", err);
				return
			},
			Some(Ok(action_and_session_index)) => action_and_session_index,
		};

		match action {
			Action::ForwardTo { target, delay } => {
				match self.target_to_peer_id(&target, session_index) {
					Ok(peer_id) => {
						let deadline =
							Instant::now() + delay.to_duration(self.config.mean_forwarding_delay);
						if self.forward_packet_queue.push(ForwardPacket {
							peer_id,
							deadline,
							packet: out,
						}) {
							self.asks |= Asks::WAIT_THEN_DISPATCH_NEXT_FORWARD_PACKET;
						}
					},
					Err(err) => error!(
						target: LOG_TARGET,
						"Failed to map target {:?} to libp2p peer ID: {}", target, err
					),
				}
			},
			Action::Deliver => {
				// XXX
				// resize vec to size?
				error!(target: LOG_TARGET, "Received message!");
			},
			Action::DeliverReply { surb_id } => {
				// XXX
				// resize vec to size?
				unreachable!();
			},
		}
	}

	/// If the peer is not connected or the peer's packet queue is full, the packet is dropped.
	/// Otherwise the packet is pushed onto the peer's queue, and if the queue was previously empty
	/// a reference to it is returned.
	fn dispatch_packet(&mut self, peer_id: &PeerId, packet: Vec<u8>) -> Option<ReadyPeer> {
		if let Some(queue) = self.peer_packet_queues.get_mut(peer_id) {
			match queue.push(packet) {
				Err(_) => {
					warn!(
						target: LOG_TARGET,
						"Dropped packet to peer ID {}; peer queue full", peer_id
					);
					None
				},
				Ok(was_empty) =>
					was_empty.then(|| ReadyPeer { id: *peer_id, packet_queue: queue.clone() }),
			}
		} else {
			warn!(target: LOG_TARGET, "Dropped packet to peer ID {}; not connected", peer_id);
			None
		}
	}

	pub fn next_forward_packet_deadline(&self) -> Option<Instant> {
		self.forward_packet_queue.next_deadline()
	}

	/// Push the packet at the head of the forward packet queue onto the appropriate peer queue.
	/// Returns a `ReadyPeer` for the peer iff the queue was empty before. Fails if the forward
	/// packet queue is empty.
	pub fn dispatch_next_forward_packet(&mut self) -> Result<Option<ReadyPeer>, ()> {
		let (packet, more_packets) = self.forward_packet_queue.pop();
		let packet = packet.ok_or(())?;
		if more_packets {
			self.asks |= Asks::WAIT_THEN_DISPATCH_NEXT_FORWARD_PACKET;
		}
		Ok(self.dispatch_packet(&packet.peer_id, packet.packet))
	}

	pub fn next_authored_packet_delay(&self) -> Option<Duration> {
		self.session_mixnodes[1].as_ref().map(|mixnodes| {
			let is_mixnode = mixnodes.local_index.is_some();
			let mean = (self.config.mean_authored_packet_period)(is_mixnode);

			let delay: f64 = rand::thread_rng().sample(rand_distr::Exp1);
			// Cap at 10x the mean; this is about the 99.995th percentile. This avoids potential
			// panics in mul_f64() due to overflow.
			mean.mul_f64(delay.min(10.0))
		})
	}

	/// Generate a route through the mixnet. Returns the mixnode index of the first hop.
	fn gen_route(
		&mut self,
		targets: &mut ArrayVec<Target, { MAX_HOPS - 1 }>,
		their_kx_publics: &mut ArrayVec<KxPublic, MAX_HOPS>,
		session_index: SessionIndex, kind: RouteKind,
	) -> Result<MixnodeIndex, GenRouteErr> {
		// XXX make this a function on Session?

		// XXX session_index, add RelSessionIndex?
		let mixnodes = self.session_mixnodes[1].as_ref().ok_or(GenRouteErr::MixnodesNotKnown)?;

		// XXX refuse to send packets if insufficient mixnodes... probably want this check at higher level?
		// maybe this function should never fail, as we shouldn't be sending any packets if we cannot send cover
		// packets
		if mixnodes.vec.len() < (2 *

		let (first_mixnode_index, last_mixnode_index) = if let MixnodeIndices::Some(reserved_peer_indices) = &mixnodes.reserved_peer_indices {
			// We are not a mixnode. We should have attempted to connect to a number of "gateway" mixnodes,
			// but as we compete with other nodes for slots we might not have managed to connect to all of
			// them. Restrict hops to/from the local node to the gateway mixnodes we managed to connect to.
			let connected_indices: ArrayVec<_, 5> = ArrayVec::new();
			reserved_peer_indices.iter().copied()
				.filter(|index| mixnodes.vec[index.get() as usize].network_state.as_ref().map_or(false, |network_state|
					self.peer_packet_queues.contains_key(&network_state.peer_id)))
				.take()
				.collect_into(&mut connected_indices);
			match connected_indices.len() {
				0 => return Err(GenRouteErr::NoConnectedMixnodes),
				1 => {
				}

		} else {
			// We are a mixnode. We should be connected to all other mixnodes. No special handling needed
			// for first/last hop.
			(None, None)
		};


const MAX_SOME_CONNECTED_MIXNODE_INDICES: usize = 5;

enum ConnectedMixnodeIndices {
	Some(ArrayVec<MixnodeIndex, MAX_SOME_CONNECTED_MIXNODE_INDICES>),
	All
}
		let connected_mixnode_indices = match mixnodes.reserved_peer_indices {
			MixnodeIndices::AllExceptLocal => ConnectedMixnodeIndices::All,
			MixnodeIndices::Some(authority_indices) => ConnectedMixnodeIndices::Some(
				authority_indices
					.iter()
					.flat_map(|authority_index| {
						self.peers
							.authority_discovery_id_to_id(&discovery_ids[*authority_index as usize])
							.map(|_id| mixnodes.authority_index_to_index[authority_index])
					})
					.take(MAX_SOME_CONNECTED_MIXNODE_INDICES)
					.collect(),
			),
		};

		//let first_authority_index = None;
		for i in 0..self.config.num_hops {
			// If the local node is not an authority, we only expect to be connected to a small set
			// of mixnodes. If the preceding or following hop is the local node, we must select this
			// hop from the small set of connected mixnodes.
			//
			// first hop must be to one of these, and if
			// hops from and to it must go via one
			// of the
			//if !is_mixnode && (
			//if to_local && (i >= (self.config.num_hops - 2)) {
			//	X
			//} else {
			//}
			unreachable!();
		}
		unreachable!();
	}

	fn gen_cover_packet(&self, kind: CoverKind) -> Option<AuthoredPacket> {
		if !self.config.gen_cover_packets {
			return None
		}

		unreachable!();
	}

	/// Either generate a cover packet or pop the packet at the head of the authored packet queue.
	/// Push this packet onto the appropriate peer queue. Returns a `ReadyPeer` for the peer iff the
	/// queue was empty before.
	pub fn dispatch_next_authored_packet(&mut self) -> Option<ReadyPeer> {
		// Choose randomly between drop and loop cover packet. This function should be called
		// according to a Poisson process. Randomly choosing here is equivalent to there being two
		// independent Poisson processes for generating the two kinds of cover packet; see
		// https://www.randomservices.org/random/poisson/Splitting.html
		// XXX cover packets distinguishable from real packets on switchover as real packets will take
		// longer to switch to new mixnodes. Can fix this for forward packets, but harder for SURBs...
		// send session index with SURB? For some period after switchover, randomly choose
		// between prev&next mixnodes, ideally with a distribution that matches surbs
		let packet = if rand::thread_rng().gen_bool(self.config.loop_cover_proportion) {
			self.gen_cover_packet(CoverKind::Loop)
		} else {
			self.authored_packet_queue
				.pop()
				.or_else(|| self.gen_cover_packet(CoverKind::Drop))
		};
		self.asks |= Asks::WAIT_THEN_DISPATCH_NEXT_AUTHORED_PACKET;
		packet
			.map(|packet| self.dispatch_packet(&packet.peer_id, packet.packet))
			.flatten()
	}

	pub fn pop_asks(&mut self) -> Asks {
		let asks = self.asks;
		self.asks = Asks::empty();
		asks
	}
}

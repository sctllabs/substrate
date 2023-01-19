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

//! Substrate mixnet integration.

mod config;
mod kx_store;
mod replay_filter;
mod state_machine;

pub use config::Config;
use futures::{future::Fuse, stream::FuturesUnordered, FutureExt, StreamExt};
use futures_timer::Delay;
pub use kx_store::{KxPublicStore, KxStore};
use log::error;
use sc_client_api::BlockchainEvents;
use sc_network_common::{
	config::{NonDefaultSetConfig, NonReservedPeerMode, SetConfig},
	protocol::{
		event::Event::{NotificationStreamClosed, NotificationStreamOpened, NotificationsReceived},
		ProtocolName,
	},
	service::{NetworkEventStream, NetworkNotification, NetworkPeers},
};
use sp_api::ProvideRuntimeApi;
use sp_mixnet_runtime_api::MixnetApi;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use state_machine::{Asks, ReadyPeer, StateMachine};
use std::{future::Future, sync::Arc, time::Instant};

const LOG_TARGET: &str = "mixnet";
const PROTOCOL_NAME: ProtocolName = ProtocolName::Static("/mixnet/1");

/// If a future is returned, and if that future returns `Some`, this function should be called
/// again to send the next packet queued for the peer; the `ReadyPeer` is placed in the `Some` to
/// make this straightforward. Otherwise, we have either sent or dropped all packets queued for
/// the peer, and it can be forgotten about for the time being.
fn send_packet_to_ready_peer(
	network: &impl NetworkNotification,
	peer: ReadyPeer,
) -> Option<impl Future<Output = Option<ReadyPeer>>> {
	match network.notification_sender(peer.id, PROTOCOL_NAME) {
		Err(err) => {
			error!(
				target: LOG_TARGET,
				"Failed to get notification sender for peer ID {}: {}", peer.id, err
			);
			peer.packet_queue.clear();
			None
		},
		Ok(sender) => Some(async move {
			match sender.ready().await.and_then(|mut ready| {
				let (packet, more_packets) = peer.packet_queue.pop();
				let packet = packet.expect("Should only be called if there is a packet to send");
				ready.send(packet)?;
				Ok(more_packets)
			}) {
				Err(err) => {
					error!(
						target: LOG_TARGET,
						"Notification sender for peer ID {} failed: {}", peer.id, err
					);
					peer.packet_queue.clear();
					None
				},
				Ok(more_packets) => more_packets.then(|| peer),
			}
		}),
	}
}

pub fn peers_set_config(config: &Config, is_authority: bool) -> NonDefaultSetConfig {
	NonDefaultSetConfig {
		notifications_protocol: PROTOCOL_NAME,
		fallback_names: Vec::new(),
		max_notification_size: mixnet_sphinx::PACKET_SIZE as u64,
		set_config: SetConfig {
			// Mixnodes, which are always authorities, add each other as reserved peers, but should
			// allow connections from nodes outside the mixnode set too, so messages can be
			// submitted to the mixnet. Non-authorities do not need to accept connections.
			in_peers: if is_authority { config.num_gateway_slots } else { 0 },
			// Don't connect to random peers; we are only interested in connecting to mixnodes,
			// which we do by setting them as reserved nodes.
			out_peers: 0,
			reserved_nodes: Vec::new(),
			non_reserved_mode: if is_authority {
				NonReservedPeerMode::Accept
			} else {
				NonReservedPeerMode::Deny
			},
		},
	}
}

pub async fn run<Block, Client, Network>(
	config: Config,
	client: Arc<Client>,
	network: Arc<Network>,
	kx_store: KxStore,
) where
	Block: BlockT,
	Client: BlockchainEvents<Block> + ProvideRuntimeApi<Block>,
	Client::Api: MixnetApi<Block>,
	Network: NetworkEventStream + NetworkNotification + NetworkPeers,
{
	let mut sm = StateMachine::new(&config, kx_store);

	let mut finality_notifications = client.finality_notification_stream();
	let mut network_events = network.event_stream("mixnet").fuse();
	let mut dispatch_next_forward_packet = Fuse::terminated();
	let mut dispatch_next_authored_packet = Fuse::terminated();
	let mut ready_peers = FuturesUnordered::new();

	loop {
		futures::select! {
			notification = finality_notifications.select_next_some() => {
				let api = client.runtime_api();
				let block_id = BlockId::Hash(notification.hash);
				if let Err(err) = sm.handle_finality(api, &block_id) {
					error!(target: LOG_TARGET, "Finality handling failed: {}", err);
				}
			}

			event = network_events.select_next_some() => {
				match event {
					NotificationStreamOpened { remote, protocol, .. }
						if protocol == PROTOCOL_NAME => sm.handle_stream_opened(&remote),
					NotificationStreamClosed { remote, protocol }
						if protocol == PROTOCOL_NAME => sm.handle_stream_closed(&remote),
					NotificationsReceived { remote: _, messages } => {
						for message in messages {
							if message.0 == PROTOCOL_NAME {
								sm.handle_packet(message.1);
							}
						}
					}
					_ => (),
				}
			}

			_ = dispatch_next_forward_packet => {
				if let Some(ready_peer) = sm.dispatch_next_forward_packet()
					.expect("Future only set if there is a packet in the queue")
				{
					if let Some(fut) = send_packet_to_ready_peer(&*network, ready_peer) {
						ready_peers.push(fut);
					}
				}
			}

			_ = dispatch_next_authored_packet => {
				if let Some(ready_peer) = sm.dispatch_next_authored_packet() {
					if let Some(fut) = send_packet_to_ready_peer(&*network, ready_peer) {
						ready_peers.push(fut);
					}
				}
			}

			ready_peer = ready_peers.select_next_some() => {
				if let Some(ready_peer) = ready_peer {
					if let Some(fut) = send_packet_to_ready_peer(&*network, ready_peer) {
						ready_peers.push(fut);
					}
				}
			}
		}

		let asks = sm.pop_asks();
		if !asks.is_empty() {
			if asks.contains(Asks::SET_RESERVED_PEERS) {
				if let Err(err) =
					network.set_reserved_peers(PROTOCOL_NAME, sm.reserved_peer_addresses())
				{
					error!(target: LOG_TARGET, "Setting reserved peers failed: {}", err);
				}
			}
			if asks.contains(Asks::WAIT_THEN_DISPATCH_NEXT_FORWARD_PACKET) {
				let deadline = sm
					.next_forward_packet_deadline()
					.expect("WAIT_THEN_DISPATCH_NEXT_FORWARD_PACKET implies queued packet");
				dispatch_next_forward_packet =
					Delay::new(deadline.saturating_duration_since(Instant::now())).fuse();
			}
			if asks.contains(Asks::WAIT_THEN_DISPATCH_NEXT_AUTHORED_PACKET) {
				if let Some(delay) = sm.next_authored_packet_delay() {
					dispatch_next_authored_packet = Delay::new(delay).fuse();
				}
			}
		}
	}
}

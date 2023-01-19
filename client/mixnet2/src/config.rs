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

use std::time::Duration;

#[derive(Debug)]
pub struct MeanAuthoredPacketPeriod {
	/// Mean period for sessions in which the local node is a mixnode.
	mixnode: Duration,
	/// Mean period for sessions in which the local node is not a mixnode.
	not_mixnode: Duration,
}

#[derive(Debug)]
pub struct Config {
	/// The number of mixnodes to connect to when we are not a mixnode ourselves. When we are a
	/// mixnode, we connect to all other mixnodes.
	pub num_gateway_mixnodes: u32,
	/// Maximum number of incoming connections a mixnode will accept from non-mixnodes.
	pub num_gateway_slots: u32,

	/// Maximum number of packets waiting for their forwarding delay to elapse. When at the limit,
	/// any packets arriving that need forwarding will simply be dropped.
	pub forward_packet_queue_capacity: usize,
	/// Mean forwarding delay at each mixnode.
	pub mean_forwarding_delay: Duration,

	/// Maximum number of packets in the request packet queue. There is just one of these queues.
	pub request_packet_queue_capacity: usize,
	/// Maximum number of packets in each reply packet queue. There is a separate reply packet queue
	/// for each session.
	pub reply_packet_queue_capacity: usize,
	/// XXX
	/// Mean period between dispatch of packets authored by this node. This includes request, reply,
	/// and cover packets; cover packets are sent when there are no suitable request or reply packets
	/// to send, or when we randomly choose to send loop cover packets (see `loop_cover_proportion`).
	/// This parameter, in combination with `loop_cover_proportion`, bounds the maximum rate at which
	/// messages can be sent by this node.
	pub mean_authored_packet_period: MeanAuthoredPacketPeriod,
	/// Proportion of authored packets which should be loop cover packets (as opposed to drop cover
	/// packets or real packets).
	pub loop_cover_proportion: f64,
	/// Generate cover packets? This option is intended for testing purposes only. It essentially
	/// just drops all cover packets instead of sending them.
	pub gen_cover_packets: bool,
	/// Number of hops in authored packets.
	pub num_hops: usize,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			num_gateway_mixnodes: 3,
			num_gateway_slots: 150,

			forward_packet_queue_capacity: 300,
			mean_forwarding_delay: Duration::from_secs(1),

			authored_packet_queue_capacity: 100,
			mean_authored_packet_period: |is_mixnode| {
				if is_mixnode {
					Duration::from_millis(100)
				} else {
					Duration::from_millis(1000)
				}
			},
			loop_cover_proportion: 0.25,
			gen_cover_packets: false, // XXX
			num_hops: mixnet_sphinx::MAX_HOPS,
		}
	}
}

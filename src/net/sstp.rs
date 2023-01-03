//! Stonenet's Secure Transport Protocol (SSTP)
//!
//! Stonenet uses SSTP as a security layer that is meant to be used on top of the
//! OSI link layer, although it could be used on any layer above that, as long
//! as it transmits data in the form of packets/messages.
//!
//! SSTP provides perfect-forward-secrecy and uses ed25519, x25519, hmac-sha256,
//! and chacha20. A new key is renegotiated every window, and every packet is
//! encrypted with a new key that, if breached, won't uncover any previous
//! packets.
//! Basically, this protocol is very similar to the Double-Ratchet Algorithm (DRA)
//! from libsignal, except it doesn't implement the Diffie-Hellman ratchet.
//! This is not really a bad thing, as the DH shared secret is recomputed so
//! often. Actually, a new shared secret is recomputed every ack packet exchange.


use super::socket::{*, UdpSocket};

use crate::{
	common::*,
	identity::{self, *},
};

use std::{
	cmp,
	collections::HashMap,
	fmt,
	net::*,
	io,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc
	},
	time::*
};

use async_std::{
	sync::Mutex,
	task::sleep
};
use chacha20::{
	ChaCha20,
	cipher::{KeyIvInit, StreamCipher}
};
use generic_array::{GenericArray, typenum::*};
use hmac::*;
use log::*;
use tokio::sync::{mpsc, oneshot};
use x25519_dalek as x25519;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio;

const MESSAGE_TYPE_HELLO_REQUEST: u8 = 0;
const MESSAGE_TYPE_HELLO_RESPONSE: u8 = 1;
const MESSAGE_TYPE_DATA: u8 = 2;
const MESSAGE_TYPE_ACK: u8 = 3;
const MESSAGE_TYPE_CLOSE: u8 = 4;

const CRYPTED_PACKET_OUTER_HEADER_SIZE: usize = 5;
const CRYPTED_PACKET_INNER_HEADER_SIZE: usize = 2;
const CRYPTED_PACKET_INNER_FIRST_HEADER_SIZE: usize = 4;

const TIMEOUT: Duration = Duration::from_secs(2);

pub struct Connection<S> where S: LinkSocket {
	socket: SstpSocket<S>,
	target: S::Target,
	their_node_id: IdType,
	their_session_id: u16,
	our_session_id: u16,
	/// The next data packet that is send or received is expected to have this
	/// sequence number.
	next_sequence: u16,
	data_queue: mpsc::UnboundedReceiver<(u16, Vec<u8>)>,
	ack_queue: mpsc::UnboundedReceiver<(u16, Vec<u8>)>,
	session: Arc<Mutex<SessionData>>,
	key_state: KeyState,
	receive_window: WindowInfo,
	send_window: WindowInfo
}

#[derive(Debug)]
pub enum Error {
	/// The connection has already been closed. Either by the Connection or Server.
	ConnectionClosed,
	/// Ack mask has been left empty. Should contain at least one packet.
	EmptyAckMask,
	InvalidChecksum,
	/// The node ID did not match in the hello response. Could be an attempt
	/// at a MitM-attack.
	InsecureConnection,
	/// The public key in the hello exchange didn't match the node ID.
	InvalidPublicKey,
	/// A packet had an invalid message type on it.
	InvalidMessageType(u8),
	/// A different node ID has been responded with than was expected.
	InvalidNodeId,
	InvalidResponseMessageType((u8, u8)),
	InvalidSessionId(u16),
	InvalidSequenceNumber(u16),
	/// A packet had an invalid signature on it.
	InvalidSignature,
	/// The data inside the packet was invalid.
	MalformedPacket,
	/// There is not more room for a new session.
	OutOfSessions,
	/// There were less bytes in the packet than was expected.
	PacketTooSmall,
	/// When the message type of the inner packet was different from what was expected.
	UnexpectedInnerMessageType(u8)
}

struct SessionData {
	client_node_id: IdType, 
	their_session_id: Option<u16>,
	last_message_time: SystemTime,
	hello_oneshot: Option<oneshot::Sender<io::Result<(IdType, u16, x25519::PublicKey)>>>,
	data_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>,
	ack_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>
}

struct Sessions {
	map: HashMap<u16, Arc<Mutex<SessionData>>>,
	next_id: u16
}

pub struct SstpSocket<S> where S: LinkSocket {
	inner: Arc<S>,
	node_id: IdType,
	keypair: identity::Keypair,
	sessions: Arc<Mutex<Sessions>>
}

struct WindowInfo {
	size: u16,
	starting: bool
}

struct KeyState {
	our_dh_key: x25519::StaticSecret,
	their_dh_key: x25519::PublicKey,
	/// The key of the next packet to process.
	/// How far the `current_key` has advanced from the `initial_key`.
	ratchet_position: u16,
	keychain: Vec<GenericArray<u8, U32>>
}

pub struct Server<S, L> where
	S: LinkSocket,
	L: Fn(Connection<S>)
{
	socket: SstpSocket<S>,
	stop_flag: Arc<AtomicBool>,
	on_connect: L,
}


fn calculate_checksum(buffer: &[u8]) -> u16 {
	let mut result = 0u16;
	for i in 2..buffer.len() {
		result = result.wrapping_add(buffer[i] as u16);
	}
	result
}

fn compose_missing_mask<'a, I>(
	max_packet_count: u16,
	completed: u16,
	ooo_sequences: I
) -> Vec<u8> where I: Iterator<Item = &'a u16> {
	let mask_bits = max_packet_count - completed;
	let mut mask = vec![0xFFu8; mask_bits as usize / 8 + ((mask_bits % 8) > 0) as usize];

	// Then reset individual bits back to 0 for those we already have.
	for seq in ooo_sequences {
		let x = seq - completed;
		let byte_index = (x / 8) as usize;
		let bit_index = (x % 8) as usize;
		
		mask[byte_index] ^= 1 << bit_index;
	}

	mask
}

/// Decrypts what has been encrypted by `encrypt_cbc`.
fn decrypt(session_id: u16, sequence: u16, buffer: &mut [u8], key: &GenericArray<u8, U32>) {
	encrypt(session_id, sequence, buffer, key);
}

/// Encrypts the given buffer, assuming that the first block is the IV.
/// Will not decrypt the IV. Also must be the size of 46 blocks.
fn encrypt(session_id: u16, sequence: u16, buffer: &mut [u8], key: &GenericArray<u8, U32>) {
	// Construct nonce out of sequence number
	let mut nonce = GenericArray::<u8, U12>::default();
	nonce[..2].copy_from_slice(&session_id.to_le_bytes());
	nonce[2..4].copy_from_slice(&sequence.to_le_bytes());
	let nonce_part = *array_ref![nonce, 0, 4];
	nonce[4..8].copy_from_slice(&nonce_part);
	nonce[8..12].copy_from_slice(&nonce_part);

	// Encrypt
	let mut cipher = ChaCha20::new(&key, &nonce);
	cipher.apply_keystream(buffer);
}


impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ConnectionClosed => 
				write!(f, "connection has already been closed"),
			Self::EmptyAckMask =>
				write!(f, "ack mask did not contain any missing packet bits"),
			Self::InvalidChecksum => write!(f, "invalid checksum"),
			Self::InsecureConnection => write!(f, "connection not secure"),
			Self::InvalidPublicKey => write!(f, "invalid public key"),
			Self::InvalidMessageType(mt) =>
				write!(f, "invalid message type: {}", mt),
			Self::InvalidNodeId => write!(f, "invalid node ID"),
			Self::InvalidResponseMessageType((mt, ex)) =>
				write!(f, "expected message type {} from response but got {}", ex, mt),
			Self::InvalidSessionId(id) =>
				write!(f, "invalid session ID: {}", id),
			Self::InvalidSequenceNumber(seq) =>
				write!(f, "invalid sequence number {} found", seq),
			Self::InvalidSignature => write!(f, "invalid signature"),
			Self::MalformedPacket => write!(f, "malformed packet"),
			Self::OutOfSessions => write!(f, "there is no more room for any new session"),
			Self::PacketTooSmall => write!(f, "packet was too small"),
			Self::UnexpectedInnerMessageType(mt) => write!(f, "unexpected inner message type: {}", mt)
		}
	}
}

impl Error {
	pub fn to_io(self) -> io::Error {
		self.into()
	}
}

impl std::error::Error for Error {}

impl Into<io::Error> for Error {
	fn into(self) -> io::Error {
		io::Error::new(io::ErrorKind::Other, Box::new(self))
	}
}

impl<S> Connection<S> where S: LinkSocket, S::Target: fmt::Debug {

	pub fn close(self) {}

	fn decrypt_packet(&mut self, sequence: u16, key_sequence: u16, data: &mut [u8]) -> bool {
		debug_assert!(
			key_sequence < self.key_state.keychain.len() as u16,
			"attempting to decrypt a packet out-of-order: {} >= {}",
			sequence,
			self.key_state.keychain.len()
		);
		let key = &self.key_state.keychain[key_sequence as usize];

		decrypt(
			self.our_session_id,
			sequence,
			data,
			key
		);
		
		if !Self::verify_packet(&data) {
			return false;
		}

		true
	}

	pub fn target(&self) -> &S::Target {
		&self.target
	}

	pub fn their_node_id(&self) -> &IdType {
		&self.their_node_id
	}

	fn max_data_packet_length() -> usize {
		SstpSocket::<S>::max_packet_length() - 5 - 2
	}

	pub async fn receive(&mut self) -> io::Result<Vec<u8>> {
		let mut buffer = Vec::new();
		let mut window_size = self.receive_window.size;
		let mut first = true;
		loop {
			self.key_state.our_dh_key = x25519::StaticSecret::new(OsRng);
			let dh_public_key = x25519::PublicKey::from(&self.key_state.our_dh_key);
			let (new_public_key, clean) = self.receive_window(
				&mut buffer,
				window_size,
				first,
				&dh_public_key
			).await?;
			first = false;
			self.key_state.their_dh_key = new_public_key;

			// Adjust window size
			if clean { self.receive_window.increase() }
			else { self.receive_window.decrease() }
			window_size = self.receive_window.size;

			// Update our shared key
			self.key_state.reset_key(window_size);

			debug_assert!(buffer.capacity() > 0, "Message length not set");
			if buffer.len() == buffer.capacity() {
				return Ok(buffer);
			}
		}
	}

	async fn receive_ack(&mut self, window_size: u16, window_start_sequence: u16, timeout: Duration) -> io::Result<Result<x25519::PublicKey, (u16, Vec<u8>)>> {
		let mut sequence = 0u16;
		let mut window_sequence = 0u16;
		let mut packet: Vec<u8> = Vec::new();
		loop {
			(sequence, packet) = self.receive_ack_packet(timeout).await?;
			window_sequence = sequence.wrapping_sub(window_start_sequence);
			if window_sequence as usize >= self.key_state.keychain.len() {
				return Err(Error::InvalidSequenceNumber(sequence).into());
			}

			if self.decrypt_packet(
				sequence,
				window_sequence,
				&mut packet
			) {
				break;
			}
			else {
				warn!("Invalid checksum received for packet, dropping it...");
			}
		}

		// If the other end received our window successfully, we get a new DH
		// public key.
		let error_code = packet[2];
		if error_code != 0 {
			let mask_len = u16::from_le_bytes(*array_ref![packet, 3, 2]) as usize;
			if (5 + mask_len) > packet.len() {
				warn!("Packet contains an unintelligible mask length.");
				return Err(Error::MalformedPacket.into());
			}
			Ok(Err((window_sequence, packet[5..(5+mask_len)].to_vec())))
		}
		else {
			let mut bytes = [0u8; 32];
			bytes.copy_from_slice(&packet[3..35]);
			let new_public_key = x25519::PublicKey::from(bytes);
			Ok(Ok(new_public_key))
		}
	}

	/// Wait for an ack packet, re-sends the last packet a few times if the
	/// other side is unresponsive.
	async fn receive_ack_patiently(&mut self,
		window_size: u16,
		window_start_sequence: u16,
		last_sequence: u16,
		last_key_sequence: u16,
		last_packet: &[u8]
	) -> io::Result<Result<x25519::PublicKey, (u16, Vec<u8>)>> {
		for _ in 0..1 {
			match self.receive_ack(window_size, window_start_sequence, TIMEOUT/2).await {
				Ok(r) => return Ok(r),
				Err(e) => if e.kind() != io::ErrorKind::TimedOut {
					return Err(e)
				}
			}

			// FIXME: The whole transfer goes wrong if this line is uncommented,
			// but it should only re-send a packet.
			self.send_data_packet(last_sequence, last_key_sequence, last_packet, false).await?;
		}
		self.receive_ack(window_size, window_start_sequence, TIMEOUT/2).await
	}

	fn process_packet(&mut self,
		buffer: &mut Vec<u8>,
		packet: &[u8],
		first_window: bool,
		first_packet: bool,
		completed: &mut u16
	) -> io::Result<Option<x25519::PublicKey>> {
		debug_assert!(
			*completed == (self.key_state.keychain.len()-1) as u16,
			"processing received packet out-of-order ({} != ({}-1))",
			*completed,
			self.key_state.keychain.len()
		);
		let mut their_dh_key = None;

		// The first packet of the window always contains the next DH public
		// key. The first packet of the message always contains the message
		// size.
		if first_packet {
			their_dh_key = Some(
				x25519::PublicKey::from(*array_ref![packet, 0, 32])
			);
			if first_window {
				let message_size = u32::from_le_bytes(*array_ref![packet, 32, 4]);
				*buffer = Vec::with_capacity(message_size as _);
				let end = 36 + packet.len();
				if end <= buffer.capacity() {
					buffer.extend(&packet[36..]);
				}
				else {
					buffer.extend(&packet[36..][..buffer.capacity()]);
				}
			}
			else {
				let end = 32 + packet.len();
				if end <= buffer.capacity() {
					buffer.extend(&packet[32..]);
				}
				else {
					buffer.extend(&packet[32..][..buffer.capacity()]);
				}
			}
		}
		else {
			let end = buffer.len() + packet.len();
			if end <= buffer.capacity() {
				buffer.extend(packet);
			}
			else {
				let room_left = buffer.capacity() - buffer.len();
				buffer.extend(&packet[..room_left]);
			}
		}

		//if *completed == 93 {
		//}
		*completed += 1;
		self.next_sequence = self.next_sequence.wrapping_add(1);
		self.key_state.advance_key(&packet);
		Ok(their_dh_key)
	}

	async fn receive_window(&mut self,
		buffer: &mut Vec<u8>,
		window_size: u16,
		first_window: bool,
		new_dh_key: &x25519::PublicKey
	) -> io::Result<(x25519::PublicKey, bool)> {
		let bytes_needed = buffer.capacity() - buffer.len() + 32;
		let mut max_packets_needed = cmp::min(
			window_size as usize,
			bytes_needed / Self::max_data_packet_length() + (bytes_needed % Self::max_data_packet_length() > 0) as usize
		) as u16;
		let mut ooo_cache = HashMap::<u16, Vec<u8>>::new();	// Out-of-order cache
		let mut completed = 0;
		let mut error_free = true;
		let mut last_missing_packet_index = max_packets_needed - 1;
		let mut sent_missing_packet = false;
		let window_start_sequence = self.next_sequence;
		let mut their_dh_key = None;
		let mut ack_not_received_count = 0;
		loop {
			let mut timeout = TIMEOUT;
			loop {
				let (sequence, mut packet) = match self.receive_data_packet(timeout).await {
					Ok(r) => { sent_missing_packet = false; r },
					Err(e) => if e.kind() == io::ErrorKind::TimedOut {
						// If `timeout` is `TIMEOUT/8`, we were just waiting
						// one some possible out-of-order messages to still
						// arive.
						if timeout < TIMEOUT && !sent_missing_packet {
							sent_missing_packet = true;
							break;
						}
						else { return Err(e); }
					}
					else { return Err(e); }
				};
				// Halve timeout after first packet
				if timeout == TIMEOUT {
					timeout /= 2;
				}

				// The actual sequence may not start from 0, but for this window
				// it is usefull to know what sequence comes after what.
				let window_sequence = sequence.wrapping_sub(window_start_sequence);
				if window_sequence > window_size {
					return Err(Error::InvalidSequenceNumber(sequence).into());
				}

				// Fill the buffer, possibly with as much cached data as is
				// available as well.
				if completed == window_sequence {
					if self.decrypt_packet(sequence, window_sequence, &mut packet) {
						match self.process_packet(buffer, &packet[2..], first_window, window_sequence == 0, &mut completed)? {
							None => {},
							Some(key) => their_dh_key = Some(key)
						}
					
						if let Some(max_found_sequence) = ooo_cache.keys()
							.reduce(|a, b| if a > b {a} else {b}).map(|s| *s)
						{
							while completed <= max_found_sequence {
								if let Some(mut more_data) = ooo_cache.remove(&completed) {
									if self.decrypt_packet(sequence, window_sequence, &mut more_data) {
										match self.process_packet(buffer, &more_data[2..], first_window, window_sequence == 0, &mut completed)? {
											None => {},
											Some(key) => their_dh_key = Some(key)
										}
									}
									else {
										warn!("Malformed ooo packet received. (seq={}/{})", sequence, window_sequence);
										break;
									}
								}
								else { break; }
							}
						}

						if buffer.len() == buffer.capacity() {
							self.send_ack_packet(sequence + 1, completed, new_dh_key).await?;
							return Ok((their_dh_key.unwrap(), error_free))
						}
					}
					else {
						warn!("Malformed packet received.");
						// If this last packet was malformed, send back the ack
						// packet immediately, otherwise it'll just slow down
						// the communication exchange.
						// FIXME: Also do this when the last packet is less
						// than the window size.
						if window_sequence == last_missing_packet_index {
							break;
						}
					}
				}
				// If the packet sequence number is too high, remember it.
				else if completed < window_sequence {
					ooo_cache.insert(window_sequence, packet);
				}

				// If we have received the last packet, try to wait for a small
				// moment to see if more packets are coming through. Then, we
				// send our ack packet back.
				if window_sequence == last_missing_packet_index {
					timeout = TIMEOUT / 8;
				}

				if completed == max_packets_needed {
					self.send_ack_packet(sequence + 1, completed, new_dh_key).await?;
					return Ok((their_dh_key.unwrap(), error_free));
				}
			}

			error_free = false;
			// Adjust what the last packet is that we need to wait for
			let missing_mask = compose_missing_mask(
				max_packets_needed,
				completed,
				ooo_cache.keys()
			);
			self.send_missing_mask_packet(
				window_start_sequence.wrapping_add(completed),
				completed,
				missing_mask
			).await?;
			
			// Reduce the last_packet_index to the highest index still needed
			while ooo_cache.contains_key(&last_missing_packet_index) {
				debug_assert!(last_missing_packet_index >= completed, "last_packet_index should not still be 0");
				last_missing_packet_index -= 1;
			}
		}
	}

	async fn receive_ack_packet(&mut self, timeout: Duration) -> io::Result<(u16, Vec<u8>)> {
		tokio::select! {
			result = self.ack_queue.recv() => {
				if result.is_none() {
					return Err(Error::ConnectionClosed.into())
				}
				Ok(result.unwrap())
			},
			_ = sleep(timeout) => {
				Err(io::ErrorKind::TimedOut.into())
			}
		}
	}

	async fn receive_data_packet(&mut self, timeout: Duration) -> io::Result<(u16, Vec<u8>)> {
		tokio::select! {
			result = self.data_queue.recv() => {
				if result.is_none() {
					return Err(Error::ConnectionClosed.into())
				}
				Ok(result.unwrap())
			},
			_ = sleep(timeout) => {
				Err(io::ErrorKind::TimedOut.into())
			}
		}
	}

	pub async fn send(&mut self, message: &[u8]) -> io::Result<()> {
		let mut send = 0usize;
		let mut window_size =  self.send_window.size;
		let mut buffer = vec![0u8; 4 + message.len()];
		
		// The actual buffer to send contains a 4-byte message size as its header
		assert!(message.len() <= u32::MAX as usize, "buffer too big");
		buffer[..4].copy_from_slice(&u32::to_le_bytes(message.len() as _));
		buffer[4..].copy_from_slice(message);

		loop {
			self.key_state.our_dh_key = x25519::StaticSecret::new(OsRng);
			let (s, clean, their_dh_key) = self.send_window(
				&buffer[send..],
				window_size,
				&x25519::PublicKey::from(&self.key_state.our_dh_key)
			).await?;
			send += s;
			self.key_state.their_dh_key = their_dh_key;
			debug_assert!(send <= buffer.len(), "More data send out than exists! {} <= {}", send, buffer.len());

			// Adjust window size
			if clean { self.send_window.increase() }
			else { self.send_window.decrease() }
			window_size = self.send_window.size;

			// Apply new ephemeral DH secret.
			self.key_state.reset_key(window_size);
			
			if send == buffer.len() { break; }
		}
		Ok(())
	}

	async fn send_ack_packet(&mut self, sequence: u16, key_sequence: u16, dh_key: &x25519::PublicKey) -> io::Result<()> {
		let mut buffer = vec![0u8; 33];
		buffer[0] = 0;	// Success
		buffer[1..33].copy_from_slice(dh_key.as_bytes());
		self.send_crypted_packet_filled(MESSAGE_TYPE_ACK, sequence, key_sequence, &buffer).await
	}

	/// Tries to send as much as of the buffer as made possible by the window
	/// size, and waits untill all of it has been received
	async fn send_window(&mut self,
		buffer: &[u8],
		window_size: u16,
		public_key: &x25519::PublicKey
	) -> io::Result<(usize, bool, x25519::PublicKey)> {
		debug_assert!(buffer.len() > 0, "buffer is empty");
		let packet_length = Self::max_data_packet_length();
		let first_packet_length = packet_length - 32;
		let actual_buffer_size = buffer.len() + 32;
		let packet_count = cmp::min(
			actual_buffer_size / packet_length + ((actual_buffer_size % packet_length) > 0) as usize,
			window_size as usize
		);
		let mut real_buffer = vec![0u8; packet_count * packet_length];
		if actual_buffer_size < real_buffer.len() {
			OsRng.fill_bytes(&mut real_buffer[actual_buffer_size..]);
		}
		real_buffer[..32].copy_from_slice(public_key.as_bytes());
		let mut last_packet: &[u8] = &real_buffer;
		let window_start_sequence = self.next_sequence;
		let mut window_sequence = 0u16;
		
		// Send all data in different packets
		let mut send = 0;
		for i in 0..window_size {
			// The first packet of the window always contains the next DH pubkey
			// to use.
			let mut end = send + if i == 0 {first_packet_length} else {packet_length};
			if i == 0 {
				if buffer.len() < first_packet_length {
					real_buffer[32..][..buffer.len()].copy_from_slice(buffer);
				}
				else {
					real_buffer[32..][..first_packet_length].copy_from_slice(&buffer[..first_packet_length]);
				}
			}
			else {
				let length = if buffer[send..].len() >= packet_length {packet_length} else {buffer[send..].len()};
				real_buffer[(i as usize * packet_length)..][..length].copy_from_slice(&buffer[send..][..length]);
			}
			last_packet = &real_buffer[(i as usize * packet_length)..][..packet_length];
			
			self.send_data_packet(
				self.next_sequence,
				window_sequence,
				&last_packet,
				true
			).await?;
			self.next_sequence = self.next_sequence.wrapping_add(1);
			window_sequence = window_sequence.wrapping_add(1);

			send = end;
			if end >= buffer.len() {
				send = buffer.len();
				break;
			}
		}

		// Wait until ack packet, and resent missing packets, until nothing is
		// missing.
		let mut error_free = true;
		loop {
			let mut last_needed_packet = last_packet;
			let mut last_needed_packet_index = window_sequence.wrapping_sub(1);
			let mut last_needed_packet_sequence = self.next_sequence.wrapping_sub(1);
			let (completed, received_mask) = match self.receive_ack_patiently(
				window_size,
				window_start_sequence,
				last_needed_packet_sequence,
				last_needed_packet_index,
				&last_needed_packet
			).await? {
				Err(mask) => {
					error_free = false;
					mask
				},
				Ok(public_key) => {
					return Ok((send, error_free, public_key));
				}
			};
			let mut errors = 0;
			for i in 0..(received_mask.len()) {
				let byte = received_mask[i];
				let j_end: usize = if (i+1) < received_mask.len() { 8 }
					else { (packet_count - completed as usize) % 8 };
				for j in 0..j_end {
					if (byte & (1<<j)) != 0 {
						errors += 1;
						let packet_index = completed as usize + i*8 + j;
						let buffer_start = packet_index * packet_length;
						
						last_needed_packet = &real_buffer[buffer_start..][..packet_length];
						last_needed_packet_sequence = window_start_sequence.wrapping_add(packet_index as _);
						last_needed_packet_index = packet_index as _;
						self.send_data_packet(
							last_needed_packet_sequence,
							last_needed_packet_index,
							last_needed_packet,
							false
						).await?;
					}
				}
			}
			if errors == 0 {
				return Err(Error::EmptyAckMask.into())
			}
		}
	}

	async fn send_crypted_packet(&self,
		message_type: u8,
		sequence: u16,
		key_sequence: u16,
		packet: &[u8],
	) -> io::Result<()> {
		debug_assert!(
			packet.len() <= Self::max_data_packet_length(),
			"packet size too big: {} > {}",
			packet.len(),
			Self::max_data_packet_length() + 1
		);
		let outer_size = 5 + 2 + packet.len();
		let mut buffer = vec![0u8; 7 + Self::max_data_packet_length()];
		buffer[0] = message_type;
		buffer[1..3].copy_from_slice(&self.their_session_id.to_le_bytes());
		buffer[3..5].copy_from_slice(&sequence.to_le_bytes());
		buffer[7..][..(packet.len())].copy_from_slice(&packet);
		let checksum = calculate_checksum(&buffer[7..]);
		buffer[5..7].copy_from_slice(&checksum.to_le_bytes());

		// Encrypt the message
		let key = &self.key_state.keychain[key_sequence as usize];
		//if key_sequence == 94 {
			//println!("Encrypt with {} {} {} {:?}", self.their_session_id, sequence, key_sequence, key);
		//}
		encrypt(self.their_session_id, sequence, &mut buffer[5..], key);

		self.socket.send(&self.target, &buffer).await
	}

	async fn send_crypted_packet_filled(&mut self,
		message_type: u8,
		sequence: u16,
		key_sequence: u16,
		packet: &[u8]
	) -> io::Result<()> {
		let mut buffer = Vec::new();
		let slice = if packet.len() == Self::max_data_packet_length() {
			packet
		}
		else {
			buffer = vec![0u8; Self::max_data_packet_length()];
			let end = packet.len();
			buffer[..end].copy_from_slice(packet);
			OsRng.fill_bytes(&mut buffer[end..]);
			&buffer
		};

		self.send_crypted_packet(message_type, sequence, key_sequence, slice).await
	}

	async fn send_data_packet(&mut self,
		sequence: u16,
		key_sequence: u16,
		packet: &[u8],
		advance_key: bool
	) -> io::Result<()> {
		debug_assert!(
			packet.len() <= Self::max_data_packet_length(),
			"Cannot send a SSTP packet of more than {} bytes! {}", Self::max_data_packet_length(), packet.len()
		);

		if advance_key {
			//if key_sequence == 93 {
				//println!("advance_key send {:?}", &packet);
			//}
			self.key_state.advance_key(&packet);
		}

		self.send_crypted_packet(
			MESSAGE_TYPE_DATA,
			sequence,
			key_sequence,
			&packet
		).await
	}

	async fn send_missing_mask_packet(&mut self,
		sequence: u16,
		completed: u16,
		mask: Vec<u8>
	) -> io::Result<()> {
		let data_packet_length = Self::max_data_packet_length();
		let mut buffer = if (3 + mask.len()) <= data_packet_length {
			vec![0u8; 3 + mask.len()]
		}
		else {
			vec![0u8; data_packet_length]
		};
		buffer[0] = 1;
		buffer[1..3].copy_from_slice(&(mask.len() as u16).to_le_bytes());
		if mask.len() <= buffer[3..].len() {
			buffer[3..].copy_from_slice(&mask);
		}
		else {
			buffer[3..].copy_from_slice(&mask[..(data_packet_length-3)]);
		}

		self.send_crypted_packet_filled(MESSAGE_TYPE_ACK, sequence, completed, &buffer).await
	}

	fn verify_packet(buffer: &[u8]) -> bool {
		let given_checksum = u16::from_le_bytes(
			*array_ref![buffer, 0, 2]
		);
		let calculated_checksum = calculate_checksum(&buffer[2..]);

		given_checksum == calculated_checksum
	}
}

impl<S> Drop for Connection<S> where S: LinkSocket {
	fn drop(&mut self) {
		// TODO: Close the connection: self.send_close_packet();
	}
}

impl KeyState {

	pub fn new(
		our_dh_key: x25519::StaticSecret,
		their_dh_key: x25519::PublicKey,
		window_size: u16
	) -> Self {
		let shared_secret = our_dh_key.diffie_hellman(&their_dh_key);
		let mut hasher = Sha256::new();
		hasher.update(shared_secret.as_bytes());
		let initial_key = hasher.finalize();
		let mut keychain = Vec::with_capacity(window_size as usize);
		keychain.push(initial_key);

		Self {
			our_dh_key,
			their_dh_key,
			ratchet_position: 0,
			keychain
		}
	}

	/// Calculates a new key based on the current DH keys.
	pub fn reset_key(&mut self, window_size: u16) {
		let shared_secret = self.our_dh_key.diffie_hellman(&self.their_dh_key);
		let mut hasher = Sha256::new();
		hasher.update(shared_secret.as_bytes());
		let initial_key = hasher.finalize();
		self.ratchet_position = 0;
		if self.keychain.capacity() < (window_size+1) as usize {
			self.keychain = Vec::with_capacity(window_size as usize);
		}
		else {
			self.keychain.clear();
		}
		self.keychain.push(initial_key);
		let our_public = x25519::PublicKey::from(&self.our_dh_key);
	}

	/// Generates a new key
	pub fn advance_key(&mut self, data: &[u8]) {
		let last_key = self.keychain.last().unwrap();
		let mut mac = Hmac::<Sha256>::new_from_slice(last_key).unwrap();
		mac.update(data);
		let new_key = mac.finalize().into_bytes();
		self.keychain.push(new_key);
		self.ratchet_position += 1;
	}
}

impl SessionData {

	pub fn new(
		node_id: IdType,
		hello_oneshot: oneshot::Sender<io::Result<(IdType, u16, x25519::PublicKey)>>,
		data_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>,
		ack_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>,
	) -> Self {
		Self {
			client_node_id: node_id,
			their_session_id: None,
			hello_oneshot: Some(hello_oneshot),
			data_queue,
			ack_queue,
			last_message_time: SystemTime::now(),

		}
	}

	pub fn new_with_their_session(
		their_session_id: u16,
		node_id: IdType,
		data_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>,
		ack_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>,
	) -> Self {
		let (dummy_tx, _) = oneshot::channel();
		Self {
			client_node_id: node_id,
			their_session_id: Some(their_session_id),
			hello_oneshot: Some(dummy_tx),
			data_queue,
			ack_queue,
			last_message_time: SystemTime::now()
		}
	}
}

impl Sessions {
	pub fn new() -> Self {
		Self {
			map: HashMap::new(),
			next_id: 0
		}
	}

	/// Returns a new unused session ID, or None if all session ID's are taken.
	pub fn next_id(&mut self) -> Option<u16> {
		let mut i = 0u16;
		while let Some(_) = self.map.get(&self.next_id) {
			self.next_id += 1;
			i += 1;

			if i == 0xFFFF {
				return None;
			}
		}
		let next_id = self.next_id;
		self.next_id += 1;
		Some(next_id)
	}
}

impl<S> SstpSocket<S> where S: LinkSocket, S::Target: fmt::Debug {

	pub async fn bind(addr: &S::Target, keypair: identity::Keypair) -> io::Result<Self> {
		Ok(Self {
			inner: Arc::new(S::bind(&addr).await?),
			sessions: Arc::new(Mutex::new(Sessions::new())),
			node_id: keypair.public().generate_address(),
			keypair
		})
	}

	fn max_packet_length() -> usize {
		S::max_packet_length()
	}

	async fn receive(&self) -> io::Result<(S::Target, Vec<u8>)> {
		self.inner.receive().await
	}

	async fn send(&self, target: &S::Target, message: &[u8]) -> io::Result<()> {
		self.inner.send(target, message).await
	}

	pub async fn connect(&self,
		target: S::Target,
		node_id: Option<&IdType>
	) -> io::Result<Connection<S>> {
		let secret_key = x25519::StaticSecret::new(OsRng);
		let (
			our_session_id,
			session,
			hello_oneshot,
			data_queue,
			ack_queue
		) = self.new_outgoing_session(self.node_id.clone()).await
			.ok_or::<io::Error>(Error::OutOfSessions.into())?;

		self.send_hello(&target, &secret_key, our_session_id).await?;
		// Wait for the hello response to arrive
		tokio::select! {
			result = hello_oneshot => {
				let (their_node_id, their_session_id, their_public_key) = result.expect("oneshot didn't work")?;

				// If a specific node ID is expected, test it
				match node_id {
					None => {},
					Some(id) => {
						if &their_node_id != id {
							return Err(Error::InvalidNodeId.into());
						}
					}
				}
				
				Ok(Connection {
					socket: self.clone(),
					target,
					their_node_id,
					their_session_id,
					our_session_id,
					next_sequence: 0,
					data_queue,
					ack_queue,
					session,
					key_state: KeyState::new(secret_key, their_public_key, 1),
					receive_window: WindowInfo::default(),
					send_window: WindowInfo::default(),
				})
			},
			_ = sleep(TIMEOUT) => {
				Err(io::ErrorKind::TimedOut.into())
			}
		}
	}

	pub fn listen<L>(&self,
		stop_flag: Arc<AtomicBool>,
		on_connect: L
	) -> Server<S, L>  where L: Fn(Connection<S>) {
		Server {
			socket: self.clone(),
			stop_flag,
			on_connect
		}
	}

	async fn new_incomming_session(&self,
		their_node_id: IdType,
		their_session_id: u16,
		data_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>,
		ack_queue: mpsc::UnboundedSender<(u16, Vec<u8>)>,
	) -> Option<(u16, Arc<Mutex<SessionData>>)> {
		let mut sessions = self.sessions.lock().await;
		let session_id = match sessions.next_id() {
			None => return None,
			Some(id) => id
		};
		let session_data = Arc::new(Mutex::new(
			SessionData::new_with_their_session(
				their_session_id,
				their_node_id,
				data_queue,
				ack_queue
			)
		));
		sessions.map.insert(session_id, session_data.clone());
		return Some((session_id, session_data));
	}

	async fn new_outgoing_session(&self, client_node_id: IdType) -> Option<(u16,
		Arc<Mutex<SessionData>>,
		oneshot::Receiver<io::Result<(IdType, u16, x25519::PublicKey)>>,
		mpsc::UnboundedReceiver<(u16, Vec<u8>)>,
		mpsc::UnboundedReceiver<(u16, Vec<u8>)>)>
	{
		let mut sessions = self.sessions.lock().await;
		let session_id = match sessions.next_id() {
			None => return None,
			Some(id) => id
		};
		let (hello_tx, hello_rx) = oneshot::channel();
		let (data_tx, data_rx) = mpsc::unbounded_channel();
		let (ack_tx, ack_rx) = mpsc::unbounded_channel();
		let session_data = Arc::new(Mutex::new(SessionData::new(
			client_node_id,
			hello_tx,
			data_tx,
			ack_tx
		)));
		sessions.map.insert(session_id, session_data.clone());
		return Some((session_id, session_data, hello_rx, data_rx, ack_rx));
	}

	async fn send_hello(&self,
		target: &S::Target,
		private_key: &x25519::StaticSecret,
		my_session_id: u16
	) -> io::Result<()> {
		let mut buffer = vec![0u8; 163];
		buffer[0] = MESSAGE_TYPE_HELLO_REQUEST;
		buffer[1..33].clone_from_slice(self.node_id.as_bytes());
		buffer[33..65].clone_from_slice(self.keypair.public().as_bytes());
		let public_key = x25519::PublicKey::from(private_key);
		buffer[129..161].clone_from_slice(public_key.as_bytes());
		buffer[161..163].clone_from_slice(&u16::to_le_bytes(my_session_id));

		// Sign request
		let signature = self.keypair.sign(&buffer[129..]);
		buffer[65..129].clone_from_slice(signature.as_bytes());

		self.inner.send(target, &buffer).await
	}
}

impl<S> Clone for SstpSocket<S> where S: LinkSocket {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
			node_id: self.node_id.clone(),
			keypair: self.keypair.clone(),
			sessions: self.sessions.clone()
		}
	}
}

impl<S, L> Server<S, L> where
	S: LinkSocket,
	S::Target: Clone + fmt::Debug,
	L: Fn(Connection<S>)
{
	async fn process_ack(&self,
		packet: &[u8]
	) -> io::Result<()> {
		let our_session_id = u16::from_le_bytes(*array_ref![packet, 0, 2]);
		let sequence = u16::from_le_bytes(*array_ref![packet, 2, 2]);
		let data = packet[4..].to_vec();

		let sessions = self.socket.sessions.lock().await;
		if let Some(s) = sessions.map.get(&our_session_id) {
			let mut session = s.lock().await;
			session.last_message_time = SystemTime::now();
			if session.ack_queue.send((sequence, data)).is_err() {
				return Err(Error::ConnectionClosed.into());
			}
			Ok(())
		}
		else {
			Err(Error::InvalidSessionId(our_session_id).into())
		}
	}

	async fn process_data(&self, packet: &[u8]) -> io::Result<()> {
		if packet.len() != (S::max_packet_length() - 1) {
			return Err(Error::MalformedPacket.into());
		}
		let session_id = u16::from_le_bytes(*array_ref![packet, 0, 2]);
		let sequence_number = u16::from_le_bytes(*array_ref![packet, 2, 2]);

		let session_mutex = {
			let sessions = self.socket.sessions.lock().await;
			match sessions.map.get(&session_id) {
				Some(s) => s.clone(),
				None => return Err(Error::InvalidSessionId(session_id).into())
			}
		};
		let session = session_mutex.lock().await;
		match session.data_queue.send((sequence_number, packet[4..].to_vec())) {
			Ok(()) => Ok(()),
			Err(_) => Err(Error::ConnectionClosed.into())
		}
	}

	async fn process_hello_request(&self, sender: &S::Target, packet: &[u8]) -> io::Result<()> {
		if packet.len() < 162 {
			return Err(Error::MalformedPacket.into());
		}
		let node_id = IdType::from_slice(&packet[..32]).unwrap();
		let identity_pubkey = match identity::PublicKey::from_bytes(
			*array_ref![packet, 32, 32]
		) {
			Some(k) => k,
			None => return Err(Error::InvalidPublicKey.into())
		};
		// Verify that the node ID is valid
		let node_id2 = identity_pubkey.generate_address();
		if node_id != node_id2 {
			return Err(Error::InvalidPublicKey.into());
		}
		
		// Verify that the signature is correct
		let signature = Signature::from_bytes(*array_ref![packet, 64, 64]);
		if !identity_pubkey.verify(&packet[128..162], &signature) {
			return Err(Error::InvalidSignature.into());
		}
		let dh_pubkey_bytes: [u8; 32] = packet[128..160].try_into().unwrap();
		
		let their_public_key = x25519::PublicKey::from(dh_pubkey_bytes);
		let own_secret_key = x25519::StaticSecret::new(OsRng);
		let own_public_key = x25519::PublicKey::from(&own_secret_key);
		let their_session_id = u16::from_le_bytes(*array_ref![packet, 160, 2]);

		let (data_tx, data_rx) = mpsc::unbounded_channel();
		let (ack_tx, ack_rx) = mpsc::unbounded_channel();
		let (our_session_id, session) = self.socket.new_incomming_session(
			node_id.clone(),
			their_session_id,
			data_tx,
			ack_tx
		).await.ok_or::<io::Error>(Error::OutOfSessions.into())?;
		
		let mut response = vec![0u8; 165];
		response[0] = MESSAGE_TYPE_HELLO_RESPONSE;
		// Send back the sender's node ID to verify that both nodes share the
		// same secret.
		response[1..33].clone_from_slice(node_id.as_bytes());
		response[33..65].clone_from_slice(self.socket.keypair.public().as_bytes());
		response[129..161].clone_from_slice(own_public_key.as_bytes());
		response[161..163].clone_from_slice(&their_session_id.to_le_bytes());
		response[163..165].clone_from_slice(&our_session_id.to_le_bytes());

		// Sign DH public key, and write it to the response buffer
		let signature = self.socket.keypair.sign(&response[129..]);
		response[65..129].clone_from_slice(signature.as_bytes());

		let connection = Connection {
			socket: self.socket.clone(),
			target: sender.clone(),
			their_node_id: node_id,
			their_session_id,
			our_session_id,
			session,
			data_queue: data_rx,
			ack_queue: ack_rx,
			key_state: KeyState::new(own_secret_key, their_public_key, 1),
			next_sequence: 0,
			receive_window: WindowInfo::default(),
			send_window: WindowInfo::default(),
		};
		(self.on_connect)(connection);
		
		self.socket.send(sender, &response).await
	}

	async fn process_hello_response(&self, packet: &[u8]) -> io::Result<()> {
		if packet.len() != 164 {
			return Err(Error::MalformedPacket.into());
		}

		// Verify that the node ID is the same as ours. If it isn't, the
		// recipient of our request didn't receive the correct node ID.
		// An attacker could try to change this, even though it wouldn't be
		// able to perform a MitM-attack because the attacker would have to
		// sign the DH key as well.
		let my_node_id = IdType::from_slice(&packet[..32]).unwrap();
		if my_node_id != self.socket.node_id {
			return Err(Error::InsecureConnection.into())
		}

		let identity_pubkey = match identity::PublicKey::from_bytes(
			*array_ref![packet, 32, 32]
		) {
			Some(k) => k,
			None => return Err(Error::InvalidPublicKey.into())
		};
		
		// Verify that the signature is correct
		let signature = Signature::from_bytes(*array_ref![packet, 64, 64]);
		if !identity_pubkey.verify(&packet[128..], &signature) {
			return Err(Error::InvalidSignature.into());
		}

		// Once we have verified the signature, take note of our session ID.
		let our_session_id = u16::from_le_bytes(*array_ref![packet, 160, 2]);
		let session_lock = match self.socket.sessions.lock().await.map.get(&our_session_id) {
			None => return Err(Error::InvalidSessionId(our_session_id).into()),
			Some(s) => s.clone()
		};
		let mut session = session_lock.lock().await;

		// Remember their session ID
		let their_session_id = u16::from_le_bytes(*array_ref![packet, 162, 2]);
		session.their_session_id = Some(their_session_id);

		// Notify the connection's thread of the successful response
		let their_node_id = identity_pubkey.generate_address();
		let their_dh_key = x25519::PublicKey::from(*array_ref![packet, 128, 32]);
		if session.hello_oneshot.take().unwrap()
			.send(Ok((their_node_id, their_session_id, their_dh_key))).is_err()
		{
			debug!("Session {} already closed before it was initiated.", our_session_id);
		}
		Ok(())
	}

	async fn process_packet(&self,
		sender: &S::Target,
		packet: &[u8]
	) -> io::Result<()> {
		let message_type = packet[0];
		match message_type {
			MESSAGE_TYPE_HELLO_REQUEST => self.process_hello_request(sender, &packet[1..]).await,
			MESSAGE_TYPE_HELLO_RESPONSE => self.process_hello_response(&packet[1..]).await,
			MESSAGE_TYPE_DATA => self.process_data(&packet[1..]).await,
			MESSAGE_TYPE_ACK => self.process_ack(&packet[1..]).await,
			other => Err::<(), io::Error>(Error::InvalidMessageType(other).into())
		}
	}

	pub async fn serve(&self, x: &str) {
		while !self.stop_flag.load(Ordering::Relaxed) {
			match self.socket.receive().await {
				Err(e) => warn!("[{}] Sstp io error on receiving packet: {}", x, e),
				Ok((address, packet)) => {
					match self.process_packet(&address, &packet).await {
						Ok(()) => {},
						Err(e) => println!("[{}] Sstp io error while processing packet: {}", x, e)
					}
				}
			}
		}
	}
}

impl WindowInfo {
	pub fn decrease(&mut self) {
		self.starting = false;
		if self.size > 1 {
			self.size >>= 1;
		}
	}

	pub fn increase(&mut self) {
		if self.starting {
			if self.size < 0x8000 {
				self.size <<= 1;
			}
			else {
				self.size = 0xFFFF;
			}
		}
		else {
			if self.size != 0xFFFF {
				self.size += 1;
			}
		}
	}
}

impl Default for WindowInfo {
	fn default() -> Self {
		Self {
			starting: true,
			size: 1
		}
	}
}


#[test]
fn test_encryption() {
	let mut key = GenericArray::<u8, U32>::default();
	let mut original = [0u8; 46*32];
	OsRng.fill_bytes(key.as_mut());
	OsRng.fill_bytes(&mut original);
	
	let mut buffer = original.clone();
	encrypt(321, 123, &mut buffer, &key);
	assert!(buffer != original);
	decrypt(321, 123, &mut buffer, &key);
	assert!(buffer == original);
}

#[tokio::test]
async fn test_connection() {
	env_logger::init();
	let ip = Ipv4Addr::new(0, 0, 0, 0);
	let master_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10000));
	let slave_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10001));
	let master = SstpSocket::<UdpSocket>::bind(
		&master_addr,
		Keypair::generate()
	).await.expect("unable to bind master");
	let slave = SstpSocket::<UdpSocket>::bind(
		&slave_addr,
		Keypair::generate()
	).await.expect("unable to bind slave");
	let stop_flag = Arc::new(AtomicBool::new(false));

	let stop_flag_slave = stop_flag.clone();
	let slave2 = slave.clone();
	tokio::spawn(async move {
		slave2.listen(stop_flag_slave, |_| {}).serve("CLIENT").await;
	});

	let mut small_message = vec![0u8; 1000];
	OsRng.fill_bytes(&mut small_message);
	let mut big_message = vec![0u8; 1000000]; // One MB of data
	OsRng.fill_bytes(&mut big_message);

	let small_message2 = small_message.clone();
	let big_message2 = big_message.clone();
	let stop_flag2 = stop_flag.clone();
	let join_handle = tokio::spawn(async move {
		master.listen(stop_flag2, move |mut connection| {
			let small = small_message2.clone();
			let big = big_message2.clone();
			tokio::spawn(async move {
				let received_message = connection.receive().await.expect("master unable to receive small message ");
				debug!("Received small message");
				assert!(received_message == small, "small message got corrupted");

				connection.send(&big).await.expect("master unable to send big message");
				debug!("Send big message");
			});
		}).serve("SERVER").await;
	});

	let mut connection = slave.connect(master_addr, None).await
		.expect("unable to connect to master");

	connection.send(&small_message).await.expect("slave unable to send small message");
	debug!("Send small message");
	let received_message = connection.receive().await.expect("slave unable to receive big message");
	debug!("Received big message");
	assert!(received_message == big_message, "big message got corrupted {} {}", received_message.len(), big_message.len());

	stop_flag.store(true, Ordering::Relaxed);
	join_handle.await;
}
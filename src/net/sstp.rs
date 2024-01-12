//! Stonenet's Secure Transport Protocol (SSTP)
//!
//! Stonenet uses SSTP as a security layer that is meant to be used on top of
//! the OSI link layer, although it could be used on any layer above that, as
//! long as it transmits data in the form of packets/messages.
//!
//! SSTP provides perfect-forward-secrecy and uses ed25519, x25519, hmac-sha256,
//! and chacha20. A new key is renegotiated every window, and every packet is
//! encrypted with a new key that, if breached, won't uncover any previous
//! packets.
//! Basically, this protocol is very similar to the Double-Ratchet Algorithm
//! (DRA) from libsignal, except it doesn't implement the Diffie-Hellman
//! ratchet. This is not really a bad thing, as the DH shared secret is
//! recomputed so extremely often. Actually, a new shared secret is established
//! after every window.
//!
//! If any part of this protocol is ever discovered to be insecure, it is easy
//! to just 'fix' it, or replace any of the 'outdated' ciphers. Because this
//! protocol isn't currently tied to any specification document.

// FIXME: Remove when going stable:
#![allow(dead_code)]


use std::{
	cmp::{self, min},
	collections::HashMap,
	fmt, io,
	result::Result as StdResult,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc, Mutex as StdMutex,
	},
	time::*,
};

use chacha20::{
	cipher::{KeyIvInit, StreamCipher},
	ChaCha20,
};
use futures::{channel::oneshot, join};
use generic_array::{typenum::*, GenericArray};
use hmac::*;
use log::*;
use once_cell::sync::OnceCell;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::{
	self, spawn,
	sync::{
		mpsc::{self, error::*},
		watch, Mutex,
	},
	task::JoinHandle,
	time::sleep,
};
use x25519_dalek as x25519;

use super::{
	bincode,
	socket::{
		ConnectionBasedLinkServer, ConnectionLessLinkServer, LinkServer, LinkSocket,
		LinkSocketReceiver, LinkSocketSender, TcpServer, UdpServer,
	},
};
use crate::{
	common::*,
	config::Config,
	identity::{self, *},
	net::*,
};

const KEEP_ALIVE_IDLE_TIME: Duration = Duration::from_secs(120);
const MESSAGE_TYPE_HELLO_REQUEST: u8 = 0;
const MESSAGE_TYPE_HELLO_RESPONSE: u8 = 1;
const MESSAGE_TYPE_DATA: u8 = 2;
const MESSAGE_TYPE_ACK: u8 = 3;
const MESSAGE_TYPE_CLOSE: u8 = 4;
const MESSAGE_TYPE_PUNCH_HOLE: u8 = 5;
/// If nothing was received on a TCP connection for 2 minutes, assume the
/// connection is broken.
const TCP_CONNECTION_TIMEOUT: u64 = 120;

pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// The minimum timeout time that will be waited on a crucial packet before
/// retrying.
pub const MAXIMUM_RETRY_TIMEOUT: Duration = Duration::from_millis(500);

pub struct Connection {
	server: Arc<Server>,
	keep_alive_flag: AtomicBool,
	/// A flag that indicates that a close packet has already been received from
	/// the other side, and that the connection unusable after the last data
	/// packet has been received.
	is_closing: AtomicBool,
	sender: Arc<dyn LinkSocketSender>,
	receiver_handle: Option<JoinHandle<()>>,
	peer_address: SocketAddr,
	their_node_info: NodeContactInfo,
	their_session_id: u16,
	our_session_id: u16,
	node_id: IdType,
	peer_node_id: IdType,
	private_key: identity::PrivateKey,
	/// The next data packet that is send or received is expected to have this
	/// sequence number.
	queues: QueueReceivers,
	//session: Arc<Mutex<SessionData>>,
	pub key_state: KeyState,
	previous_keystate: KeyState,
	previous_window_ack_sequence: u16,
	receive_window: WindowInfo,
	send_window: WindowInfo,

	last_activity: Arc<StdMutex<SystemTime>>,
	unprocessed_close_packets: Vec<(u16, u16, Vec<u8>)>,

	#[cfg(debug_assertions)]
	pub should_be_closed: AtomicBool,

	timeout: Duration,
	keep_alive_timeout: Duration,
}

#[derive(Clone, Debug)]
pub enum Error {
	IoError(Arc<io::Error>),

	/// The connection has already been closed. Either by the Connection or
	/// Server.
	ConnectionClosed,
	/// Ack mask has been left empty. Should contain at least one packet.
	EmptyAckMask,
	/// The node ID did not match in the hello response. Could be an attempt
	/// at a MitM-attack.
	InsecureConnection,
	/// The data that got inspected during a pipe failed a check.
	InvalidData,
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
	// The message itself was not understood
	MalformedMessage(Option<Arc<bincode::Error>>),
	/// Unable to connect because there were no matching options
	NoConnectionOptions,
	/// There is not more room for a new session.
	OutOfSessions,
	/// There were less bytes in the packet than was expected.
	PacketTooSmall,
	Timeout,
	DummyError,
	SenderDropped,
}

type HelloWatchReceiver = watch::Receiver<HelloWatchResult>;
type HelloWatchResult = Result<(
	IdType,
	ContactInfo,
	u16,
	x25519::PublicKey,
	Arc<StdMutex<SystemTime>>,
)>;
type HelloWatchSender = watch::Sender<HelloWatchResult>;

#[derive(Clone)]
pub struct KeyState {
	pub sequence: u16,
	our_dh_key: x25519::StaticSecret,
	their_dh_key: x25519::PublicKey,
	/// The key of the next packet to process.
	/// How far the `current_key` has advanced from the `initial_key`.
	ratchet_position: u16,
	keychain: Vec<GenericArray<u8, U32>>,
}

pub type OnPacket =
	Arc<dyn Fn(Arc<dyn LinkSocketSender>, &SocketAddr, &[u8]) + Send + Sync + 'static>;

type PingReceiver = Mutex<mpsc::Receiver<SystemTime>>;
type PingSender = mpsc::Sender<SystemTime>;

pub type Result<T> = StdResult<T, Error>;

struct SessionData {
	their_node_id: IdType,
	their_session_id: Option<u16>,
	last_activity: Arc<StdMutex<SystemTime>>,
	hello_watch: Option<HelloWatchSender>,
	queues: QueueSenders,
	keep_alive_timeout: Duration,
}

struct Sessions {
	map: HashMap<u16, Arc<Mutex<SessionData>>>,
	next_id: u16,
}

#[derive(Debug)]
pub enum SocketBindError {
	Io(io::Error),
	InvalidAddress(String, AddrParseError),
}

struct SocketCollection {
	ipv4: Option<SstpSocketServers<SocketAddrV4>>,
	ipv6: Option<SstpSocketServers<SocketAddrV6>>,
}

struct SstpSocketServers<V>
where
	V: Into<SocketAddr> + Send + Clone + 'static,
{
	udp: Option<Arc<SstpSocketServer<UdpServer<V>>>>,
	tcp: Option<Arc<SstpSocketServer<TcpServer<V>>>>,
}

struct SstpSocketServer<S>
where
	S: LinkServer,
{
	inner: S,
	openness: Openness,
}

struct WindowInfo {
	size: u16,
	starting: bool,
}

/// The role of the SSTP server is to receive packets on any available
/// communication method, most notably UDP and TCP over IPv4 or IPv6, and then
/// forward them to the corresponding connection to be handled.
pub struct Server {
	stop_flag: Arc<AtomicBool>,
	sockets: SocketCollection,
	our_contact_info: StdMutex<ContactInfo>,
	sessions: Mutex<Sessions>,
	node_id: IdType,
	private_key: identity::PrivateKey,
	on_connect: OnceCell<Box<dyn Fn(Box<Connection>) + Send + Sync>>,
	default_timeout: Duration,
}

struct Queues;

type QueueReceiver = mpsc::UnboundedReceiver<(u16, u16, Vec<u8>)>;
type QueueSender = mpsc::UnboundedSender<(u16, u16, Vec<u8>)>;

pub struct QueueReceivers {
	data: QueueReceiver,
	ack: QueueReceiver,
	close: QueueReceiver,
}

pub struct QueueSenders {
	data: QueueSender,
	ack: QueueSender,
	close: QueueSender,
	session_id: u16,
}


fn calculate_checksum(buffer: &[u8]) -> u16 {
	let mut result = 0u16;
	for i in 0..buffer.len() {
		result = result.wrapping_add(buffer[i] as u16);
	}
	result
}

/// Decrypts what has been encrypted by `encrypt_cbc`.
fn decrypt(
	session_id: u16, keystate_sequence: u16, key_sequence: u16, buffer: &mut [u8],
	key: &GenericArray<u8, U32>,
) {
	encrypt(session_id, keystate_sequence, key_sequence, buffer, key);
}

/// Encrypts the given buffer, assuming that the first block is the IV.
/// Will not decrypt the IV. Also must be the size of 46 blocks.
/// The sessions_id and sequence are important to be different for each packet,
/// and act as a sort of salt.
fn encrypt(
	session_id: u16, keystate_sequence: u16, key_sequence: u16, buffer: &mut [u8],
	key: &GenericArray<u8, U32>,
) {
	// Construct nonce out of session_id & sequence number.
	let mut nonce = GenericArray::<u8, U12>::default();
	nonce[..2].copy_from_slice(&session_id.to_le_bytes());
	nonce[2..4].copy_from_slice(&keystate_sequence.to_le_bytes());
	nonce[4..6].copy_from_slice(&key_sequence.to_le_bytes());
	let nonce_part = *array_ref![nonce, 0, 6];
	nonce[6..12].copy_from_slice(&nonce_part);

	// Encrypt
	let mut cipher = ChaCha20::new(&key, &nonce);
	cipher.apply_keystream(buffer);
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::IoError(e) => write!(f, "I/O error: {}", e),
			Self::ConnectionClosed => write!(f, "connection has already been closed"),
			Self::SenderDropped => write!(f, "sender dropped"),
			Self::DummyError => write!(f, "dummy error"),
			Self::EmptyAckMask => write!(f, "ack mask did not contain any missing packet bits"),
			Self::InsecureConnection => write!(f, "connection not secure"),
			Self::InvalidData => write!(f, "invalid data"),
			Self::InvalidPublicKey => write!(f, "invalid public key"),
			Self::InvalidMessageType(mt) => write!(f, "invalid message type: {}", mt),
			Self::InvalidNodeId => write!(f, "invalid node ID"),
			Self::InvalidResponseMessageType((mt, ex)) => write!(
				f,
				"expected message type {} from response but got {}",
				ex, mt
			),
			Self::InvalidSessionId(id) => write!(f, "invalid session ID (ours): {}", id),
			Self::InvalidSequenceNumber(seq) => write!(f, "invalid sequence number {} found", seq),
			Self::InvalidSignature => write!(f, "invalid signature"),
			Self::MalformedPacket => write!(f, "malformed packet"),
			Self::MalformedMessage(oe) => match oe {
				Some(e) => write!(f, "malformed message: {}", e),
				None => write!(f, "malformed message"),
			},
			Self::NoConnectionOptions => write!(f, "no connection options"),
			Self::OutOfSessions => write!(f, "there is no more room for any new session"),
			Self::PacketTooSmall => write!(f, "packet was too small"),
			Self::Timeout => write!(f, "timeout exceeded"),
		}
	}
}

impl Error {
	/// Returns false if the error is a mistake by the other endpoint that
	/// shouldn't happen, and could result in a kick/ban.
	pub fn forgivable(&self) -> bool {
		match self {
			// The io::Error usually comes from an issue local to our endpoint
			Self::IoError(_) => true,
			// This error is given if the sending node closes the connection, which may happen for
			// good reasons.
			Self::ConnectionClosed => true,
			Self::OutOfSessions => true,
			_ => false,
		}
	}

	pub fn to_io(self) -> io::Error { self.into() }
}

impl std::error::Error for Error {}

impl Into<io::Error> for Error {
	fn into(self) -> io::Error { io::Error::new(io::ErrorKind::Other, Box::new(self)) }
}

impl Connection {
	/// This size includes the 4 byte message header, so to know the amount of
	/// bytes you're able to sent in the first window, subtract 4 bytes.
	fn calculate_window_data_length(&self, window_size: u16) -> usize {
		window_size as usize * self.max_data_packet_length() - 32
	}

	pub async fn close(&mut self) -> Result<()> {
		#[cfg(debug_assertions)]
		self.should_be_closed.store(false, Ordering::Relaxed);
		self.is_closing.store(true, Ordering::Relaxed);
		self.send_close_packet().await?;
		self.sender.close().await?;
		match &mut self.receiver_handle {
			None => {}
			Some(h) => h.await.expect("join error"),
		}
		Ok(())
	}

	/// Like close, but closes the connection somewhere in the future and you
	/// don't need to wait on it.
	pub fn close_async(mut self: Box<Self>) {
		#[cfg(debug_assertions)]
		self.should_be_closed.store(false, Ordering::Relaxed);
		spawn(async move {
			if let Err(e) = self.close().await {
				debug!("Unable to close connection: {}", e);
			}
		});
	}

	fn compose_missing_mask(
		&self, mut max_packet_count: u16, completed: u16, ooo_sequences: &[&u16],
	) -> Vec<u8> {
		debug_assert!(
			max_packet_count as u16 >= completed,
			"max_packet_count is incorrect: {} >= {}",
			max_packet_count,
			completed
		);
		// If the message size hasn't been determined yet (because the first packet
		// didn't arrive), assume there has at least be one packet
		if max_packet_count == 0 {
			max_packet_count = ooo_sequences.iter().fold(0u16, |a, b| a.max(**b)) as u16 + 1;
		}
		let mask_bits = (max_packet_count - completed) as usize;
		let mask_size = min(
			mask_bits as usize / 8 + ((mask_bits % 8) > 0) as usize,
			self.max_data_packet_length(),
		);
		let mut mask = vec![0u8; mask_size];

		// Then reset individual bits back to 1 for those we still need.
		for i in completed..(max_packet_count as u16) {
			if !ooo_sequences.contains(&&(i as u16)) {
				let x = i - completed;
				let byte_index = (x / 8) as usize;
				if byte_index > mask.len() {
					break;
				}
				let bit_index = (x % 8) as usize;
				mask[byte_index] ^= 1 << bit_index;
			}
		}

		mask
	}

	pub fn contact_option(&self) -> ContactOption {
		ContactOption {
			target: self.peer_address.clone(),
			use_tcp: self.sender.is_tcp(),
		}
	}

	/// Decrypts a packet that is expected to have a specific key sequence set
	/// on its packet.
	fn decrypt_packet(&self, keystate: &KeyState, key_sequence: u16, data: &mut [u8]) -> bool {
		debug_assert!(
			key_sequence < self.key_state.keychain.len() as u16,
			"attempting to decrypt a packet out-of-order: {} >= {}",
			key_sequence,
			self.key_state.keychain.len()
		);
		let key = &keystate.keychain[key_sequence as usize];
		decrypt(
			self.our_session_id,
			keystate.sequence,
			key_sequence,
			data,
			key,
		);

		if !Self::verify_packet(&data) {
			return false;
		}

		true
	}

	pub fn our_session_id(&self) -> u16 { self.our_session_id }

	fn max_data_packet_length(&self) -> usize { self.sender.max_packet_length() - 5 - 2 - 2 }

	pub fn network_level(&self) -> NetworkLevel { NetworkLevel::from_ip(&self.peer_address.ip()) }

	pub fn peer_address(&self) -> &SocketAddr { &self.peer_address }

	/// Listen on the other connection and send all data on this connection.
	pub async fn pipe(
		&mut self, other: &mut Connection, verify_data: impl FnMut(&[u8]) -> bool + Send,
	) -> Result<usize> {
		let (len_tx, len_rx) = oneshot::channel();
		let (tx, rx) = mpsc::unbounded_channel();

		// Spawn a task that listens on the other connection and forwards the data on
		// the mpsc channel.
		let (_, result) = join!(
			other.pipe_receive(len_tx, tx, verify_data),
			self.pipe_send(len_rx, rx),
		);
		result
	}

	pub async fn pipe_mutex(
		&mut self, other: Arc<Mutex<Box<Connection>>>, close_other: bool,
		verify_data: impl FnMut(&[u8]) -> bool + Send + 'static,
	) -> Result<usize> {
		let (len_tx, len_rx) = oneshot::channel();
		let (tx, rx) = mpsc::unbounded_channel();

		// Spawn a task that listens on the other connection and forwards the data on
		// the mpsc channel.
		spawn(async move {
			let mut connection = other.lock().await;
			connection.pipe_receive(len_tx, tx, verify_data).await;
			if close_other {
				if let Err(e) = connection.close().await {
					error!("Unable to close piped connection: {}", e);
				}
			}
		});

		self.pipe_send(len_rx, rx).await
	}

	async fn pipe_receive(
		&mut self, len_tx: oneshot::Sender<usize>, tx: mpsc::UnboundedSender<Result<Vec<u8>>>,
		mut verify_data: impl FnMut(&[u8]) -> bool + Send,
	) {
		let mut buffer = Vec::new();
		let mut received;

		let timeout: Duration = self.timeout;
		match self.receive_chunk(&mut buffer, true, timeout).await {
			Err(e) => {
				let _ = tx.send(Err(e));
				if let Err(_) = len_tx.send(0) {
					return;
				}
				return;
			}
			Ok(done) => {
				received = buffer.len();
				if verify_data(&buffer) {
					// After receiving the first chunk, we can send back the message length
					if let Err(_) = len_tx.send(buffer.capacity()) {
						return;
					}
					if let Err(_) = tx.send(Ok(buffer.clone())) {
						return;
					}
					if done {
						return;
					}
				} else {
					let _ = tx.send(Err(Error::InvalidData));
					return;
				}
			}
		}
		loop {
			let timeout = self.timeout;
			match self.receive_chunk(&mut buffer, false, timeout).await {
				Err(e) => {
					let _ = tx.send(Err(e));
					return;
				}
				Ok(done) =>
					if verify_data(&buffer) {
						if let Err(_) = tx.send(Ok(buffer[received..].to_vec())) {
							return;
						}
						if done {
							return;
						}
						received = buffer.len();
					} else {
						let _ = tx.send(Err(Error::InvalidData));
						return;
					},
			}
		}
	}

	async fn pipe_send(
		&mut self, len_rx: oneshot::Receiver<usize>,
		mut rx: mpsc::UnboundedReceiver<Result<Vec<u8>>>,
	) -> Result<usize> {
		let message_size = if let Ok(m) = len_rx.await {
			m
		} else {
			if let Ok(result) = rx.try_recv() {
				// When the len queue is closed, an error might still have been sent on the
				// normal queue, if the first window was never received correctly.
				debug_assert!(
					result.is_err(),
					"received data from queue without first receiving a message length"
				);
				return Err(result.unwrap_err());
			} else {
				return Err(Error::ConnectionClosed);
			}
		};
		let mut buffer = Vec::with_capacity(4 + message_size);
		buffer.extend((message_size as u32).to_le_bytes());
		let mut already_sent = 0;
		while let Some(result) = rx.recv().await {
			let chunk = result?;
			buffer.extend(chunk);

			let mut available = buffer.len() - already_sent;
			while available >= self.calculate_window_data_length(self.send_window.size)
				|| (available > 0 && buffer.len() == buffer.capacity())
			// when something is still left to be sent out and we've already received the whole of
			// the buffer
			{
				let sent = self.send_chunk(&mut buffer[already_sent..]).await?;
				already_sent += sent;
				available = buffer.len() - already_sent;
			}

			debug_assert!(
				already_sent <= buffer.capacity(),
				"sent more bytes than message: send={}, size={}",
				already_sent,
				buffer.capacity()
			);
			if already_sent == buffer.capacity() {
				return Ok(already_sent);
			}
		}
		panic!(
			"less bytes sent ({}) than message ({})",
			already_sent,
			buffer.capacity()
		);
	}

	/// Processes all the stored close packets that are left to be processed
	async fn process_unprocessed_close_packets(&mut self) {
		if self.unprocessed_close_packets.len() == 0 {
			return;
		}

		let mut i = 0;
		while i < self.unprocessed_close_packets.len() {
			let item = &self.unprocessed_close_packets[i];
			if item.0 <= self.key_state.sequence {
				let item = self.unprocessed_close_packets.remove(i);
				self.process_close_packet(item);
			} else {
				i += 1;
			}
		}
	}

	pub async fn receive(&mut self) -> Result<Vec<u8>> {
		self.receive_with_timeout(self.timeout).await
	}

	async fn receive_chunk(
		&mut self, buffer: &mut Vec<u8>, is_first_window: bool, timeout: Duration,
	) -> Result<bool> {
		self.key_state.our_dh_key = x25519::StaticSecret::random_from_rng(OsRng);
		let dh_public_key = x25519::PublicKey::from(&self.key_state.our_dh_key);
		let current_timeout = if is_first_window {
			timeout
		} else {
			self.timeout
		};

		let (next_window_size, new_public_key) = self
			.receive_window(
				current_timeout,
				buffer,
				self.receive_window.size,
				is_first_window,
				&dh_public_key,
			)
			.await?;

		// Adjust window size
		self.receive_window.size = next_window_size;

		// Update our shared key
		self.previous_keystate = self.key_state.clone();
		self.key_state.their_dh_key = new_public_key;
		self.key_state.reset_key(self.receive_window.size);
		self.process_unprocessed_close_packets().await;

		debug_assert!(buffer.capacity() > 0, "message length not set");
		debug_assert!(buffer.len() > 0, "nothing was received");
		Ok(buffer.len() == buffer.capacity())
	}

	/// Like `receive`, but waits a different amount of time for the first
	/// packet, and proceeds to receive the remainder at the connection's
	/// configured timeout.
	pub async fn receive_with_timeout(&mut self, first_timeout: Duration) -> Result<Vec<u8>> {
		if self.is_closing.load(Ordering::Relaxed) {
			return Err(Error::ConnectionClosed);
		}

		let mut buffer = Vec::new();
		let mut first = true;
		let mut timeout = first_timeout;
		loop {
			if self.receive_chunk(&mut buffer, first, timeout).await? {
				return Ok(buffer);
			}
			first = false;
			timeout = self.timeout;
		}
	}

	async fn receive_ack(
		&mut self, timeout: Duration,
	) -> Result<StdResult<(u16, x25519::PublicKey), (u16, Vec<u8>)>> {
		let mut packet_sequence;
		let mut packet: Vec<u8>;
		loop {
			let keystate_sequence;
			(keystate_sequence, packet_sequence, packet) = self.receive_ack_packet(timeout).await?;
			// Drop ack packets for another window
			if keystate_sequence != self.key_state.sequence {
				continue;
			}
			if packet_sequence as usize >= self.key_state.keychain.len() {
				return Err(Error::InvalidSequenceNumber(packet_sequence).into());
			}

			if self.decrypt_packet(&self.key_state, packet_sequence, &mut packet) {
				break;
			} else {
				warn!("Invalid checksum received for packet, dropping it...");
			}
		}

		// First two bytes are the checksum
		let data = &packet[2..];


		// If the other end received our window successfully, we get a new DH
		// public key.
		let error_code = data[0];
		if error_code != 0 {
			if data.len() > 1 {
				Ok(Err((packet_sequence, data[1..].to_vec())))
			} else {
				Err(Error::EmptyAckMask)
			}
		} else {
			let next_window_size = u16::from_le_bytes(*array_ref![data, 1, 2]);
			let mut bytes = [0u8; 32];
			bytes.copy_from_slice(&data[3..35]);
			let new_public_key = x25519::PublicKey::from(bytes);
			Ok(Ok((next_window_size, new_public_key)))
		}
	}

	fn process_packet(
		&mut self, buffer: &mut Vec<u8>, packet: &[u8], first_window: bool, first_packet: bool,
		completed: &mut u16,
	) -> Result<Option<(u16, x25519::PublicKey)>> {
		debug_assert!(
			*completed <= (self.key_state.keychain.len() - 1) as u16,
			"processing received packet out-of-order ({} > ({}-1))",
			*completed,
			self.key_state.keychain.len()
		);
		let mut their_window_size = 0u16;
		let mut their_dh_key = None;
		// The first packet of the window always contains the next DH public
		// key. The first packet of the message always contains the message
		// size.
		if first_packet {
			their_window_size = u16::from_le_bytes(*array_ref![packet, 0, 2]);
			their_dh_key = Some(x25519::PublicKey::from(*array_ref![packet, 2, 32]));
			if first_window {
				let message_size = u32::from_le_bytes(*array_ref![packet, 34, 4]);
				*buffer = Vec::with_capacity(message_size as _);
				let end = buffer.len() + packet.len() - 38;
				if end <= buffer.capacity() {
					buffer.extend(&packet[38..]);
				} else {
					let room_left = buffer.capacity() - buffer.len();
					buffer.extend(&packet[38..][..room_left]);
				}
			} else {
				let end = buffer.len() + packet.len() - 34;
				if end <= buffer.capacity() {
					buffer.extend(&packet[34..]);
				} else {
					let room_left = buffer.capacity() - buffer.len();
					buffer.extend(&packet[34..][..room_left]);
				}
			}
		} else {
			let end = buffer.len() + packet.len();
			if end <= buffer.capacity() {
				buffer.extend(packet);
			} else {
				let room_left = buffer.capacity() - buffer.len();
				buffer.extend(&packet[..room_left]);
			}
		}

		*completed += 1;
		self.key_state.advance_key(&packet);
		Ok(their_dh_key.map(|pk| (their_window_size, pk)))
	}

	async fn receive_window(
		&mut self, first_timeout: Duration, buffer: &mut Vec<u8>, window_size: u16,
		first_window: bool, new_dh_key: &x25519::PublicKey,
	) -> Result<(u16, x25519::PublicKey)> {
		// The buffer should be either not yet allocated, or allocated to accomodate for
		// the amount of bytes that this window will provide.
		debug_assert!(
			buffer.capacity() == 0 || buffer.len() != buffer.capacity(),
			"nothing left to receive: {}/{}",
			buffer.len(),
			buffer.capacity()
		);
		let mut last_missing_packet_index = 0u16;
		let mut max_packets_needed = 0u16;
		let mut their_new_window_size = 0u16;
		let mut ooo_cache = HashMap::<u16, Vec<u8>>::new(); // Out-of-order cache
		let mut packets_collected = 0u16;
		let mut error_free = true;
		let mut their_dh_key = None;
		let packet_len = self.max_data_packet_length();
		let mut sent_first_ack_packet: Option<SystemTime> = None;
		let mut sent_previous_ack_packet: Option<SystemTime> = None;
		let mut timeout = first_timeout;
		let mut timeouts = 0;

		fn calculate_packet_count(window_size: u16, packet_len: usize, bytes_needed: usize) -> u16 {
			cmp::min(
				window_size,
				// Keep in mind that we've already processed one packet.
				(bytes_needed / packet_len) as u16 + (bytes_needed % packet_len > 0) as u16,
			)
		}
		if max_packets_needed == 0 && buffer.capacity() > 0 {
			max_packets_needed = calculate_packet_count(
				window_size,
				packet_len,
				buffer.capacity() - buffer.len() + 34,
			);
			last_missing_packet_index = max_packets_needed - 1;
		}

		loop {
			loop {
				let (keystate_sequence, mut sequence, mut packet) =
					match self.receive_data_packet(timeout).await {
						Ok(r) => {
							// We've received a data packet (again), so we shouldn't loop to retry
							// sending ack packets (anymore).
							sent_first_ack_packet = None;
							r
						}
						Err(e) => {
							match e {
								Error::Timeout => {
									// Break out of the loop after a timeout, so that we resend our
									// missing ack packet. But after 8 retries, we give up.
									timeouts += 1;
									if timeouts == 8 {
										return Err(Error::Timeout);
									} else {
										break;
									}
								}
								_ => return Err(e),
							}
						}
					};

				// If a packet of the previous keystate has been found, resend an ack packet of
				// the previous window.
				if keystate_sequence != self.key_state.sequence {
					if keystate_sequence == (self.key_state.sequence - 1) {
						// Rate limitting for sending back previous ack packets
						if let Some(time) = sent_previous_ack_packet {
							if SystemTime::now() < (time + MAXIMUM_RETRY_TIMEOUT) {
								continue;
							}
						}
						self.send_previous_ack_packet().await?;
						sent_previous_ack_packet = Some(SystemTime::now());
					} /*else {
						debug!(
							"Dropping packet with invalid keystate sequence (normal): {}",
							keystate_sequence,
						);
					}*/
					continue;
				}

				// Sequence sanity check
				if sequence > window_size {
					return Err(Error::InvalidSequenceNumber(sequence).into());
				}

				// If the packet has already been processed, drop it
				if sequence < packets_collected {
					continue;
				}

				// If the received packet is the next packet we're processing
				let new = if packets_collected == sequence {
					if self.decrypt_packet(&self.key_state, sequence, &mut packet) {
						match self.process_packet(
							buffer,
							&packet[2..],
							first_window,
							sequence == 0,
							&mut packets_collected,
						)? {
							None => {}
							Some((ws, key)) => {
								their_new_window_size = ws;
								their_dh_key = Some(key);
							}
						}
						if first_window && sequence == 0 {
							max_packets_needed = calculate_packet_count(
								window_size,
								packet_len,
								buffer.capacity() + 38,
							); // The first window has 38 less bytes of space because 4 bytes are used for the message size, and 34 for the window header
							last_missing_packet_index = max_packets_needed - 1;
						}

						if let Some(max_found_sequence) = ooo_cache
							.keys()
							.reduce(|a, b| if a > b { a } else { b })
							.map(|s| *s)
						{
							while packets_collected <= max_found_sequence {
								if let Some(mut more_data) = ooo_cache.remove(&packets_collected) {
									sequence = packets_collected;
									if self.decrypt_packet(
										&self.key_state,
										sequence,
										&mut more_data,
									) {
										match self.process_packet(
											buffer,
											&more_data[2..],
											first_window,
											sequence == 0,
											&mut packets_collected,
										)? {
											None => {}
											Some((ws, key)) => {
												their_new_window_size = ws;
												their_dh_key = Some(key);
											}
										}
									} else {
										debug!(
											"Malformed ooo packet received. (seq={}/{})",
											sequence, window_size
										);
										break;
									}
								} else {
									break;
								}
							}
						}
						true
					} else {
						false
					}
				}
				// If this packet has a higher sequence than the one we're waiting on, just cache it
				// for now.
				else if packets_collected < sequence {
					ooo_cache.insert(sequence, packet).is_none()
				} else {
					false
				};

				// Use regular timeout after the first packet has been received. The timeout
				// might still be set to either first_timeout, or a lower timeout for retrying
				// ack packets.
				if new {
					timeout = self.timeout / 8;
					timeouts = 0;
				// If the packet has already been received or could not be
				// decrypted, ignore it
				} else {
					continue;
				}

				// If as many packets have been collected as were needed, we're done
				if max_packets_needed > 0 && packets_collected == max_packets_needed as u16 {
					self.previous_window_ack_sequence = sequence + 1;
					let our_new_window_size = if error_free && packets_collected == window_size {
						self.receive_window.increase_window_size()
					} else {
						self.receive_window.decrease_window_size()
					};
					let next_window_size = min(our_new_window_size, their_new_window_size);
					self.send_ack_packet(
						self.previous_window_ack_sequence,
						next_window_size,
						new_dh_key,
					)
					.await?;
					return Ok((next_window_size, their_dh_key.unwrap()));
				}

				// If we've just received the last packet but are still missing some other
				// packets, send back a missing ack packet. This is quicker than waiting 1/8th
				// of the timeout, even though an out-of-order packet might still arrive a
				// milisecond later. At the cost of receiving an extra packet or two, the packet
				// exchange goes faster.
				if max_packets_needed > 0 && sequence == last_missing_packet_index {
					break;
				}
			}

			// At this point we've received all the packet we think we're getting from the
			// other side, but are still missing some packets because the function hasn't
			// returned yet.
			if let Some(time) = sent_first_ack_packet {
				// Check to see if we've sent enough ack packets already
				if time >= (SystemTime::now() + self.timeout) {
					return Err(Error::Timeout);
				}
			}
			error_free = false;
			let missing_sequences: Vec<&u16> = ooo_cache.keys().collect();
			let missing_mask = self.compose_missing_mask(
				max_packets_needed,
				packets_collected,
				&missing_sequences,
			);
			self.send_missing_mask_packet(packets_collected, missing_mask)
				.await?;
			sent_first_ack_packet = Some(SystemTime::now());
			// Reduce the last_packet_index to the highest index still needed
			while ooo_cache.contains_key(&last_missing_packet_index) {
				debug_assert!(
					last_missing_packet_index >= packets_collected,
					"last_packet_index should not still be 0"
				);
				last_missing_packet_index -= 1;
			}

			timeout = min(self.timeout / 4, MAXIMUM_RETRY_TIMEOUT);
		}
	}

	async fn receive_packet(
		&mut self, timeout: Duration, queue: &mut QueueReceiver,
	) -> Result<(u16, u16, Vec<u8>)> {
		loop {
			tokio::select! {
				result = queue.recv() => {
					if result.is_none() {
						if self.is_closing.load(Ordering::Relaxed) {
							return Err(Error::ConnectionClosed.into());
						} else {
							return Err(Error::Timeout);
						}
					}
					return Ok(result.unwrap())
				},
				result = self.queues.close.recv() => {
					if let Some(packet) = result {
						let _ = self.process_close_packet(packet);
					}
				},
				_ = sleep(timeout) => {
					if self.is_closing.load(Ordering::Relaxed) {
						return Err(Error::ConnectionClosed.into());
					} else {
						return Err(Error::Timeout);
					}
				}
			}
		}
	}

	async fn receive_ack_packet(&mut self, timeout: Duration) -> Result<(u16, u16, Vec<u8>)> {
		loop {
			tokio::select! {
				result = self.queues.ack.recv() => {
					if result.is_none() {
						if self.is_closing.load(Ordering::Relaxed) {
							return Err(Error::ConnectionClosed.into());
						} else {
							return Err(Error::Timeout);
						}
					}
					return Ok(result.unwrap())
				},
				result = self.queues.close.recv() => {
					if let Some(packet) = result {
						let _ = self.process_close_packet(packet);
					}
				},
				_ = sleep(timeout) => {
					if self.is_closing.load(Ordering::Relaxed) {
						return Err(Error::ConnectionClosed.into());
					} else {
						return Err(Error::Timeout);
					}
				}
			}
		}
	}

	fn process_close_packet(&mut self, item: (u16, u16, Vec<u8>)) -> bool {
		let (keystate_sequence, sequence, mut buffer) = item;
		let key_state_opt = if keystate_sequence == self.key_state.sequence {
			Some(&self.key_state)
		} else if keystate_sequence == (self.key_state.sequence - 1) {
			Some(&self.previous_keystate)
		} else if keystate_sequence > self.key_state.sequence {
			self.unprocessed_close_packets
				.push((keystate_sequence, sequence, buffer.clone()));
			None
		} else {
			warn!("Received invalid close packet: keystate sequence is too old");
			None
		};

		if let Some(key_state) = key_state_opt {
			if !self.decrypt_packet(key_state, sequence, &mut buffer) {
				warn!(
					"Received malformed close packet: checksum didn't match {} {} [{}]",
					keystate_sequence, self.key_state.sequence, sequence
				);
			} else if buffer.len() < 34 {
				warn!("Received malformed close packet: packet too small");
			} else if &buffer[2..34] != self.peer_node_id.as_bytes() {
				warn!("Received malformed close packet: node ID didn't match.");
			} else {
				self.is_closing.store(true, Ordering::Relaxed);
				// Close the other queues so that an end of the connection is signified on the
				// task that may be waiting for those
				self.queues.ack.close();
				self.queues.data.close();
				return true;
			}
		}
		false
	}

	async fn receive_data_packet(&mut self, timeout: Duration) -> Result<(u16, u16, Vec<u8>)> {
		loop {
			tokio::select! {
				result = self.queues.data.recv() => {
					if result.is_none() {
						if self.is_closing.load(Ordering::Relaxed) {
							return Err(Error::ConnectionClosed.into());
						} else {
							return Err(Error::Timeout);
						}
					}
					return Ok(result.unwrap())
				},
				result = self.queues.close.recv() => {
					if let Some(packet) = result {
						let _ = self.process_close_packet(packet);
					}
				},
				_ = sleep(timeout) => {
					if self.is_closing.load(Ordering::Relaxed) {
						return Err(Error::ConnectionClosed.into());
					} else {
						return Err(Error::Timeout);
					}
				}
			}
		}
	}

	pub async fn send(&mut self, message: &[u8]) -> Result<()> {
		// The actual buffer to send contains a 4-byte message size as its header
		assert!(message.len() > 0, "buffer is empty");
		assert!(message.len() <= u32::MAX as usize, "buffer too big");
		let mut buffer = vec![0u8; 4 + message.len()];
		buffer[..4].copy_from_slice(&u32::to_le_bytes(message.len() as _));
		buffer[4..].copy_from_slice(message);

		self.send_data(&buffer).await
	}

	async fn send_close_packet(&mut self) -> Result<()> {
		self.send_crypted_packet(
			MESSAGE_TYPE_CLOSE,
			&self.key_state,
			(self.key_state.keychain.len() - 1) as _,
			self.node_id.as_bytes(),
		)
		.await
	}

	async fn send_chunk(&mut self, buffer: &[u8]) -> Result<usize> {
		debug_assert!(buffer.len() > 0, "buffer is empty");
		// The sending side has to sent their idea for the window size in the window
		// data itself, and there is no way to determine if it will go error free, so
		// always sent an optimistic window size.
		let our_new_window_size = self.send_window.increase_window_size();
		self.key_state.our_dh_key = x25519::StaticSecret::random_from_rng(OsRng);
		let result = self
			.send_window(
				&buffer,
				self.send_window.size,
				&x25519::PublicKey::from(&self.key_state.our_dh_key),
				our_new_window_size,
			)
			.await;
		let (send, their_new_window_size, their_dh_key) = result?;
		debug_assert!(
			send <= buffer.len(),
			"More data send out than exists! {} <= {}",
			send,
			buffer.len()
		);

		// Adjust window size
		//self.previous_window_size = self.send_window.size;
		self.send_window.size = min(our_new_window_size, their_new_window_size);

		// Apply new ephemeral DH secret.
		self.previous_keystate = self.key_state.clone();
		self.key_state.their_dh_key = their_dh_key;
		self.key_state.reset_key(self.send_window.size);
		return Ok(send);
	}

	async fn send_data(&mut self, buffer: &[u8]) -> Result<()> {
		let mut send = 0usize;
		loop {
			send += self.send_chunk(&buffer[send..]).await?;
			debug_assert!(send <= buffer.len(), "send too many bytes");
			if send == buffer.len() {
				return Ok(());
			}
		}
	}

	async fn send_ack_packet(
		&self, key_sequence: u16, new_window_size: u16, dh_key: &x25519::PublicKey,
	) -> Result<()> {
		let mut buffer = vec![0u8; 35];
		buffer[0] = 0; // Success
		buffer[1..3].copy_from_slice(&new_window_size.to_le_bytes());
		buffer[3..35].copy_from_slice(dh_key.as_bytes());
		self.send_crypted_packet(MESSAGE_TYPE_ACK, &self.key_state, key_sequence, &buffer)
			.await
	}

	/// Tries to send as much as of the buffer as made possible by the window
	/// size, and waits untill all of it has been received
	async fn send_window(
		&mut self, buffer: &[u8], window_size: u16, public_key: &x25519::PublicKey,
		requested_window_size: u16,
	) -> Result<(usize, u16, x25519::PublicKey)> {
		debug_assert!(buffer.len() > 0, "buffer is empty");

		let packet_length = self.max_data_packet_length();
		let first_packet_length = packet_length - 34;
		let actual_buffer_size = buffer.len() + 34;
		let packet_count = cmp::min(
			(actual_buffer_size / packet_length
				+ ((actual_buffer_size % packet_length) > 0) as usize) as u16,
			window_size,
		);
		let mut sequence = 0u16;

		let mut real_buffer = vec![0u8; packet_count as usize * packet_length];
		if actual_buffer_size < real_buffer.len() {
			OsRng.fill_bytes(&mut real_buffer[actual_buffer_size..]);
		}
		real_buffer[..2].copy_from_slice(&requested_window_size.to_le_bytes());
		real_buffer[2..34].copy_from_slice(public_key.as_bytes());

		// Send all data in different packets
		let mut send = 0;
		for i in 0..(window_size as usize) {
			// The first packet of the window always contains the next DH pubkey
			// to use.
			let end = send
				+ if i == 0 {
					first_packet_length
				} else {
					packet_length
				};
			if i == 0 {
				if buffer.len() < first_packet_length {
					real_buffer[34..][..buffer.len()].copy_from_slice(buffer);
				} else {
					real_buffer[34..][..first_packet_length]
						.copy_from_slice(&buffer[..first_packet_length]);
				}
			} else {
				let length = if buffer[send..].len() >= packet_length {
					packet_length
				} else {
					buffer[send..].len()
				};
				real_buffer[(i * packet_length)..][..length]
					.copy_from_slice(&buffer[send..][..length]);
			}
			let packet = &real_buffer[(i * packet_length)..][..packet_length];
			self.send_data_packet(sequence, packet, true).await?;
			sequence = sequence.wrapping_add(1);

			send = end;
			if end >= buffer.len() {
				send = buffer.len();
				break;
			}
		}

		// Wait until ack packet, and resent missing packets, until nothing is
		// missing.
		loop {
			let (completed, received_mask) = match self.receive_ack(self.timeout).await? {
				Err(mask) => mask,
				Ok((ws, public_key)) => {
					return Ok((send, ws, public_key));
				}
			};
			let mut errors = 0;
			for i in 0..(received_mask.len() as u16) {
				let byte = received_mask[i as usize];
				for j in 0..8 {
					if (byte & (1 << j)) != 0 {
						errors += 1;
						let packet_index = completed + i * 8 + j;
						let buffer_start = packet_index as usize * packet_length;

						if buffer_start < real_buffer.len() {
							self.send_data_packet(
								packet_index,
								&real_buffer[buffer_start..][..packet_length],
								false,
							)
							.await?;
						}
					}
				}
			}
			// This shouldn't happen:
			debug_assert!(errors > 0, "no errors were resolved");
		}
	}

	async fn send_crypted_packet(
		&self, message_type: u8, keystate: &KeyState, key_sequence: u16, packet: &[u8],
	) -> Result<()> {
		debug_assert!(
			packet.len() <= self.max_data_packet_length(),
			"packet size too big: {} > {}",
			packet.len(),
			self.max_data_packet_length()
		);
		//let outer_size = 5 + 2 + 2 + packet.len();
		let mut buffer = vec![0u8; 9 + packet.len()];
		buffer[0] = message_type;
		buffer[1..3].copy_from_slice(&self.their_session_id.to_le_bytes());
		buffer[3..5].copy_from_slice(&keystate.sequence.to_le_bytes());
		buffer[5..7].copy_from_slice(&key_sequence.to_le_bytes());
		let checksum = calculate_checksum(&packet);
		buffer[7..9].copy_from_slice(&checksum.to_le_bytes());
		buffer[9..][..(packet.len())].copy_from_slice(&packet);

		// Encrypt the message
		let key = &keystate.keychain[key_sequence as usize];
		encrypt(
			self.their_session_id,
			keystate.sequence,
			key_sequence,
			&mut buffer[7..],
			key,
		);

		*self.last_activity.lock().unwrap() = SystemTime::now();
		self.sender.send(&buffer, self.timeout).await?;
		Ok(())
	}

	async fn send_crypted_packet_filled(
		&self, message_type: u8, keystate: &KeyState, key_sequence: u16, packet: &[u8],
	) -> Result<()> {
		let max_len = self.max_data_packet_length();
		let mut buffer;
		let slice = if packet.len() == max_len {
			packet
		} else {
			buffer = vec![0u8; max_len];
			let end = packet.len();
			buffer[..end].copy_from_slice(packet);
			OsRng.fill_bytes(&mut buffer[end..]);
			&buffer
		};

		self.send_crypted_packet(message_type, keystate, key_sequence, slice)
			.await
	}

	async fn send_data_packet(
		&mut self, key_sequence: u16, mut packet: &[u8], advance_key: bool,
	) -> Result<()> {
		let max_len = self.max_data_packet_length();
		if packet.len() > max_len {
			packet = &packet[..max_len];
		}

		if advance_key {
			self.key_state.advance_key(&packet);
		}

		self.send_crypted_packet(MESSAGE_TYPE_DATA, &self.key_state, key_sequence, &packet)
			.await
	}

	async fn send_missing_mask_packet(&self, packet_sequence: u16, mask: Vec<u8>) -> Result<()> {
		debug_assert!(mask.len() > 0, "mask is empty");
		let max_len = self.max_data_packet_length();
		let data_packet_length = max_len;
		let mut buffer = if (1 + mask.len()) <= data_packet_length {
			vec![0u8; 1 + mask.len()]
		} else {
			vec![0u8; data_packet_length]
		};
		buffer[0] = 1;
		if mask.len() <= buffer.len() - 1 {
			buffer[1..].copy_from_slice(&mask);
		} else {
			buffer[1..].copy_from_slice(&mask[..(data_packet_length - 1)]);
		}

		self.send_crypted_packet(MESSAGE_TYPE_ACK, &self.key_state, packet_sequence, &buffer)
			.await
	}

	async fn send_previous_ack_packet(&mut self) -> Result<()> {
		let our_pubkey = x25519::PublicKey::from(&self.previous_keystate.our_dh_key);
		let mut buffer = vec![0u8; 35];
		buffer[0] = 0; // Success
		buffer[1..3].copy_from_slice(&self.receive_window.size.to_le_bytes());
		buffer[3..35].copy_from_slice(our_pubkey.as_bytes());
		self.send_crypted_packet(
			MESSAGE_TYPE_ACK,
			&self.previous_keystate,
			self.previous_window_ack_sequence,
			&buffer,
		)
		.await
	}

	/// Updates the cleanup timeout of the connection.
	pub async fn set_keep_alive_timeout(&mut self, timeout: Duration) -> bool {
		self.keep_alive_timeout = timeout;
		let sessions = self.server.sessions.lock().await;
		if let Some(session_mutex) = sessions.map.get(&self.our_session_id) {
			let session_mutex2 = session_mutex.clone();
			drop(sessions);
			let mut session = session_mutex2.lock().await;
			session.keep_alive_timeout = timeout;
			true
		} else {
			false
		}
	}

	pub fn their_node_info(&self) -> &NodeContactInfo { &self.their_node_info }

	pub fn their_node_id(&self) -> &IdType { &self.their_node_info.node_id }

	pub fn their_session_id(&self) -> u16 { self.their_session_id }

	pub fn update_their_node_info(&mut self, node_info: NodeContactInfo) {
		self.their_node_info = node_info;
	}

	fn verify_packet(buffer: &[u8]) -> bool {
		let given_checksum = u16::from_le_bytes(*array_ref![buffer, 0, 2]);
		let calculated_checksum = calculate_checksum(&buffer[2..]);

		given_checksum == calculated_checksum
	}
}

#[cfg(debug_assertions)]
impl Drop for Connection {
	fn drop(&mut self) {
		if self.should_be_closed.load(Ordering::Relaxed) {
			panic!("Connection {} not closed before drop", self.our_session_id);
		}
	}
}

impl From<PublicKeyError> for Error {
	fn from(_other: PublicKeyError) -> Self { Self::InvalidPublicKey }
}

impl From<io::Error> for Error {
	fn from(other: io::Error) -> Self { Self::IoError(Arc::new(other)) }
}

impl From<bincode::Error> for Error {
	fn from(other: bincode::Error) -> Self { Self::MalformedMessage(Some(Arc::new(other))) }
}


impl KeyState {
	pub fn new(
		our_dh_key: x25519::StaticSecret, their_dh_key: x25519::PublicKey, window_size: u16,
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
			keychain,
			sequence: 0,
		}
	}

	/// Calculates a new key based on the current DH keys.
	pub fn reset_key(&mut self, window_size: u16) {
		let shared_secret = self.our_dh_key.diffie_hellman(&self.their_dh_key);
		let mut hasher = Sha256::new();
		hasher.update(shared_secret.as_bytes());
		let initial_key = hasher.finalize();
		self.ratchet_position = 0;
		if self.keychain.capacity() < (window_size + 1) as usize {
			self.keychain = Vec::with_capacity((window_size + 1) as usize);
		} else {
			self.keychain.clear();
		}
		self.keychain.push(initial_key);
		self.sequence = self.sequence.wrapping_add(1);
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
		node_id: IdType, hello_watch: HelloWatchSender, queues: QueueSenders, timeout: Duration,
	) -> Self {
		Self {
			their_node_id: node_id,
			their_session_id: None,
			hello_watch: Some(hello_watch),
			queues,
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
			keep_alive_timeout: timeout,
		}
	}

	pub fn new_with_their_session(
		their_session_id: u16, node_id: IdType, queues: QueueSenders, timeout: Duration,
	) -> Self {
		let (dummy_tx, _) = watch::channel(Err(Error::DummyError));
		Self {
			their_node_id: node_id,
			their_session_id: Some(their_session_id),
			hello_watch: Some(dummy_tx),
			queues,
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
			keep_alive_timeout: timeout,
		}
	}
}

impl Sessions {
	pub async fn find_their_session(
		&self, their_node_id: &IdType, their_session_id: u16,
	) -> Option<(u16, Arc<Mutex<SessionData>>)> {
		for (our_session_id, session_data_mutex) in self.map.iter() {
			let session_data = session_data_mutex.lock().await;
			if session_data.their_session_id.is_some()
				&& session_data.their_session_id.unwrap() == their_session_id
				&& &session_data.their_node_id == their_node_id
			{
				return Some((*our_session_id, session_data_mutex.clone()));
			}
		}
		None
	}

	pub fn new() -> Self {
		Self {
			map: HashMap::new(),
			next_id: 0,
		}
	}

	/// Returns a new unused session ID, or None if all session ID's are taken.
	pub fn next_id(&mut self) -> Option<u16> {
		let mut i = 0u16;
		while self.map.contains_key(&self.next_id) {
			self.next_id += 1;
			i += 1;

			if i == 0xFFFF {
				return None;
			}
		}
		let new_id = self.next_id;
		self.next_id += 1;
		Some(new_id)
	}
}

impl fmt::Display for SocketBindError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(e) => write!(f, "I/O error: {}", e),
			Self::InvalidAddress(s, e) => write!(f, "invalid address syntax for \"{}\": {}", s, e),
		}
	}
}

impl From<io::Error> for SocketBindError {
	fn from(other: io::Error) -> Self { Self::Io(other) }
}

impl SocketCollection {
	/// Binds all internal sockets to the given addresses and ports.
	pub async fn bind(config: &Config) -> StdResult<Self, SocketBindError> {
		let mut this = Self::default();

		// Parse IPv4 configuration
		if let Some(addr_string) = &config.ipv4_address {
			let addr = Ipv4Addr::from_str(&addr_string)
				.map_err(|e| SocketBindError::InvalidAddress(addr_string.clone(), e))?;
			let mut servers = SstpSocketServers::default();

			// Parse UDPv4 configuration
			if let Some(port) = config.ipv4_udp_port {
				servers.udp = Some(Arc::new(SstpSocketServer {
					inner: UdpServer::bind(SocketAddrV4::new(addr, port)).await?,
					openness: config
						.ipv4_udp_openness
						.as_ref()
						.map(|s| match Openness::from_str(s) {
							Ok(o) => o,
							Err(_) => {
								error!(
									"Unable to parse UDPv4 openness \"{}\" from config file. \
									 Assuming unidirectional.",
									s
								);
								Openness::Unidirectional
							}
						})
						.unwrap_or(Openness::Unidirectional),
				}));
			}

			// Parse TCPv4 configuration
			if let Some(port) = config.ipv4_tcp_port {
				servers.tcp = Some(Arc::new(SstpSocketServer {
					inner: TcpServer::bind(SocketAddrV4::new(addr, port)).await?,
					openness: config
						.ipv4_tcp_openness
						.as_ref()
						.map(|s| match Openness::from_str(s) {
							Ok(o) => o,
							Err(_) => {
								error!(
									"Unable to parse TCPv4 openness \"{}\" from config file. \
									 Assuming unidirectional.",
									s
								);
								Openness::Unidirectional
							}
						})
						.unwrap_or(Openness::Unidirectional),
				}));
			}

			this.ipv4 = Some(servers);
		}

		// Parse IPv6 configuration
		if let Some(addr_string) = &config.ipv6_address {
			let addr = Ipv6Addr::from_str(&addr_string)
				.map_err(|e| SocketBindError::InvalidAddress(addr_string.clone(), e))?;
			let mut servers = SstpSocketServers::default();

			// Parse UDPv6 configuration
			if let Some(port) = config.ipv6_udp_port {
				servers.udp = Some(Arc::new(SstpSocketServer {
					inner: UdpServer::bind(SocketAddrV6::new(addr, port, 0, 0)).await?,
					openness: config
						.ipv6_udp_openness
						.as_ref()
						.map(|s| match Openness::from_str(&s) {
							Ok(o) => o,
							Err(_) => {
								error!(
									"Unable to parse UDPv6 openness \"{}\" from config file. \
									 Assuming unidirectional.",
									s
								);
								Openness::Unidirectional
							}
						})
						.unwrap_or(Openness::Unidirectional),
				}));
			}

			// Parse TCPv6 configuration
			if let Some(port) = config.ipv6_tcp_port {
				servers.tcp = Some(Arc::new(SstpSocketServer {
					inner: TcpServer::bind(SocketAddrV6::new(addr, port, 0, 0)).await?,
					openness: config
						.ipv6_tcp_openness
						.as_ref()
						.map(|s| match Openness::from_str(&s) {
							Ok(o) => o,
							Err(_) => {
								error!(
									"Unable to parse TCPv6 openness \"{}\" from config file. \
									 Assuming unidirectional.",
									s
								);
								Openness::Unidirectional
							}
						})
						.unwrap_or(Openness::Unidirectional),
				}));
			}

			this.ipv6 = Some(servers);
		}

		Ok(this)
	}

	/// This spawns all the loops that wait for incomming packets and
	/// connections.
	fn spawn_servers(
		&self, stop_flag: Arc<AtomicBool>,
		on_packet: impl Fn(Arc<dyn LinkSocketSender>, &SocketAddr, &[u8]) + Send + Sync + 'static,
	) {
		let on_packet2 = Arc::new(on_packet);
		match &self.ipv4 {
			None => {}
			Some(socket_servers) => {
				match &socket_servers.udp {
					None => {}
					Some(socket_server) => socket_server
						.clone()
						.spawn_connection_less(stop_flag.clone(), on_packet2.clone()),
				}
				match &socket_servers.tcp {
					None => {}
					Some(socket_server) => socket_server
						.clone()
						.spawn_connection_based(stop_flag.clone(), on_packet2.clone()),
				}
			}
		}
		match &self.ipv6 {
			None => {}
			Some(socket_servers) => {
				match &socket_servers.udp {
					None => {}
					Some(socket_server) => socket_server
						.clone()
						.spawn_connection_less(stop_flag.clone(), on_packet2.clone()),
				}
				match &socket_servers.tcp {
					None => {}
					Some(socket_server) => socket_server
						.clone()
						.spawn_connection_based(stop_flag, on_packet2),
				}
			}
		}
	}
}

impl Default for SocketCollection {
	fn default() -> Self {
		Self {
			ipv4: None,
			ipv6: None,
		}
	}
}

impl Server {
	/// Sets up all necessary sockets internally.
	/// default_timeout: The timeout that incomming connection will be
	/// configured for
	pub async fn bind(
		stop_flag: Arc<AtomicBool>, config: &Config, node_id: IdType, private_key: PrivateKey,
		default_timeout: Duration,
	) -> StdResult<Arc<Self>, SocketBindError> {
		let contact_info = ContactInfo::from_config(config);
		Ok(Arc::new(Self {
			stop_flag,
			sockets: SocketCollection::bind(config).await?,
			our_contact_info: StdMutex::new(contact_info),
			sessions: Mutex::new(Sessions::new()),
			node_id,
			private_key,
			on_connect: OnceCell::new(),
			default_timeout,
		}))
	}

	pub fn listen(&self, on_connect: impl Fn(Box<Connection>) + Send + Sync + 'static) {
		if let Err(_) = self.on_connect.set(Box::new(on_connect)) {
			panic!("Unwrapping on_connect failed.");
		}
	}

	pub fn pick_contact_option(&self, target: &ContactInfo) -> Option<(ContactOption, Openness)> {
		self.sockets.pick_contact_option(target)
	}

	pub async fn connect(
		self: &Arc<Self>, target: &ContactOption, node_id: Option<&IdType>,
	) -> Result<Box<Connection>> {
		let stop_flag = Arc::new(AtomicBool::new(false));
		self.connect_with_timeout(stop_flag, target, node_id, DEFAULT_TIMEOUT)
			.await
	}

	pub async fn connect_with_timeout(
		self: &Arc<Self>, stop_flag: Arc<AtomicBool>, target: &ContactOption,
		node_id: Option<&IdType>, timeout: Duration,
	) -> Result<Box<Connection>> {
		let (sender, receiver) = match self.sockets.connect(target, timeout).await? {
			None => return Err(Error::NoConnectionOptions),
			Some(s) => s,
		};

		// Handle the new connection if socket is connection based.
		let mut handle = None;
		if target.use_tcp {
			let this = self.clone();
			let sender2 = sender.clone();
			let target2 = target.target.clone();
			let stop_flag = self.stop_flag.clone();
			handle = Some(spawn(async move {
				Self::serve_connection_based_socket(
					stop_flag,
					sender2.clone(),
					receiver,
					target2,
					Arc::new(move |_link_socket, address, packet| {
						let this2 = this.clone();
						let sender3 = sender2.clone();
						let address2 = address.clone();
						// FIXME: Make sure packet is received in an arc, so that cloning it is
						// effecient
						let packet2 = packet.to_vec();
						spawn(async move {
							match this2.process_packet(sender3, &address2, &packet2).await {
								Ok(()) => {}
								Err(e) => warn!("Sstp io error: {}", e),
							}
						});
					}),
				)
				.await;
			}));
		}

		let secret_key = x25519::StaticSecret::random_from_rng(OsRng);
		let (our_session_id, _session, mut hello_watch, queues) = self
			.new_outgoing_session(self.node_id.clone(), timeout)
			.await
			.ok_or(Error::OutOfSessions)?;

		// Wait for the hello response to arrive
		let started = SystemTime::now();
		let sleep_time = min(timeout / 4, MAXIMUM_RETRY_TIMEOUT);
		while !stop_flag.load(Ordering::Relaxed)
			&& SystemTime::now().duration_since(started).unwrap() < timeout
		{
			self.send_hello(
				&*sender,
				&secret_key,
				our_session_id,
				&self.our_contact_info(),
				timeout / 2,
			)
			.await?;

			tokio::select! {
				result = hello_watch.changed() => {
					result.expect("hello watch didn't work");
					let (their_node_id, their_contact_info, their_session_id, their_public_key, last_activity) = (*hello_watch.borrow()).clone()?;

					// If a specific node ID is expected, test it
					match node_id {
						None => {},
						Some(id) => {
							if &their_node_id != id {
								return Err(Error::InvalidNodeId.into());
							}
						}
					}

					return Ok(Box::new(Connection {
						server: self.clone(),
						keep_alive_flag: AtomicBool::new(false),
						is_closing: AtomicBool::new(false),
						sender,
						receiver_handle: handle,
						peer_address: target.target.clone(),
						their_session_id,
						our_session_id,
						their_node_info: NodeContactInfo {
							node_id: their_node_id.clone(),
							contact_info: their_contact_info,
						},
						node_id: self.node_id.clone(),
						peer_node_id: their_node_id,
						private_key: self.private_key.clone(),
						queues,
						//session,
						key_state: KeyState::new(secret_key.clone(), their_public_key.clone(), 1),
						previous_keystate: KeyState::new(secret_key, their_public_key, 0),
						previous_window_ack_sequence: 0,
						receive_window: WindowInfo::default(),
						send_window: WindowInfo::default(),
						last_activity,
						#[cfg(debug_assertions)]
						should_be_closed: AtomicBool::new(true),
						unprocessed_close_packets: Vec::new(),
						timeout,
						keep_alive_timeout: timeout
					}))
				},
				_ = sleep(sleep_time) => {}
			}
		}

		// If the connecting task was stopped from an outside force, don't give a
		// timeout error
		if stop_flag.load(Ordering::Relaxed) {
			Err(Error::ConnectionClosed)
		} else {
			Err(Error::Timeout)
		}
	}

	async fn new_incomming_session(
		&self, their_node_id: IdType, their_session_id: u16, queues: QueueSenders,
		timeout: Duration,
	) -> Result<(u16, bool)> {
		let mut sessions = self.sessions.lock().await;
		// Check if session doesn't already exists
		match sessions
			.find_their_session(&their_node_id, their_session_id)
			.await
		{
			None => {}
			// If it exists, return None
			Some((our_session_id, _)) => return Ok((our_session_id, false)),
		}
		let session_id = match sessions.next_id() {
			None => return Err(Error::OutOfSessions),
			Some(id) => id,
		};
		let session_data = Arc::new(Mutex::new(SessionData::new_with_their_session(
			their_session_id,
			their_node_id,
			queues,
			timeout,
		)));
		sessions.map.insert(session_id, session_data);
		return Ok((session_id, true));
	}

	async fn new_outgoing_session(
		&self, client_node_id: IdType, timeout: Duration,
	) -> Option<(
		u16,
		Arc<Mutex<SessionData>>,
		HelloWatchReceiver,
		QueueReceivers,
	)> {
		let mut sessions = self.sessions.lock().await;
		let session_id = match sessions.next_id() {
			None => return None,
			Some(id) => id,
		};
		let (hello_tx, hello_rx) = watch::channel(Err(Error::DummyError));
		let (tx_queues, rx_queues) = Queues::channel(session_id);
		let session_data = Arc::new(Mutex::new(SessionData::new(
			client_node_id,
			hello_tx,
			tx_queues,
			timeout,
		)));
		sessions.map.insert(session_id, session_data.clone());
		return Some((session_id, session_data, hello_rx, rx_queues));
	}

	pub fn our_contact_info(&self) -> ContactInfo { self.our_contact_info.lock().unwrap().clone() }

	pub async fn send_punch_hole_packet(&self, contact: &ContactOption) -> Result<bool> {
		if let Some((tx, _rx)) = self.sockets.connect(contact, self.default_timeout).await? {
			let buffer = vec![MESSAGE_TYPE_PUNCH_HOLE; 1];
			tx.send(&buffer, self.default_timeout).await?;
			return Ok(true);
		}
		Ok(false)
	}

	async fn send_hello(
		&self, socket: &dyn LinkSocketSender, private_key: &x25519::StaticSecret,
		my_session_id: u16, my_contact_info: &ContactInfo, timeout: Duration,
	) -> Result<()> {
		let my_contact_info_len = bincode::serialized_size(&my_contact_info).unwrap();
		let mut buffer = vec![0u8; 163 + my_contact_info_len];
		buffer[0] = MESSAGE_TYPE_HELLO_REQUEST;
		buffer[1..33].copy_from_slice(self.node_id.as_bytes());
		buffer[33..65].copy_from_slice(self.private_key.public().as_bytes());
		let public_key = x25519::PublicKey::from(private_key);
		buffer[129..161].copy_from_slice(public_key.as_bytes());
		buffer[161..163].copy_from_slice(&u16::to_le_bytes(my_session_id));
		buffer[163..].copy_from_slice(&bincode::serialize(&my_contact_info).unwrap());

		// Sign request
		let signature = self.private_key.sign(&buffer[129..]);
		buffer[65..129].copy_from_slice(&signature.to_bytes());

		socket.send(&buffer, timeout).await?;
		Ok(())
	}

	pub fn set_contact_info(&self, contact_info: ContactInfo) {
		*self.our_contact_info.lock().unwrap() = contact_info;
	}
}

impl SocketCollection {
	pub fn bidirectional_contact_option(&self, target: &ContactInfo) -> Option<ContactOption> {
		self.pick_contact_option_at_openness(target, Openness::Bidirectional)
	}

	fn pick_contact_option_at_openness(
		&self, target: &ContactInfo, openness: Openness,
	) -> Option<ContactOption> {
		match self.ipv6.as_ref() {
			None => {}
			Some(socket_servers) => match target.ipv6.as_ref() {
				None => {}
				Some(contact_option) => {
					match socket_servers.udp.as_ref() {
						None => {}
						Some(_) => match contact_option.availability.udp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV6::new(
									contact_option.addr.clone(),
									transport_option.port,
									0,
									0,
								);
								if transport_option.openness == openness {
									return Some(ContactOption {
										target: SocketAddr::V6(addr),
										use_tcp: false,
									});
								}
							}
						},
					}
					match socket_servers.tcp.as_ref() {
						None => {}
						Some(_) => match contact_option.availability.tcp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV6::new(
									contact_option.addr.clone(),
									transport_option.port,
									0,
									0,
								);
								if transport_option.openness == openness {
									return Some(ContactOption {
										target: SocketAddr::V6(addr),
										use_tcp: true,
									});
								}
							}
						},
					}
				}
			},
		}
		match self.ipv4.as_ref() {
			None => {}
			Some(socket_servers) => match target.ipv4.as_ref() {
				None => {}
				Some(contact_option) => {
					match socket_servers.udp.as_ref() {
						None => {}
						Some(_) => match contact_option.availability.udp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV4::new(
									contact_option.addr.clone(),
									transport_option.port,
								);
								if transport_option.openness == openness {
									return Some(ContactOption {
										target: SocketAddr::V4(addr),
										use_tcp: false,
									});
								}
							}
						},
					}
					match socket_servers.tcp.as_ref() {
						None => {}
						Some(_) => match contact_option.availability.tcp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV4::new(
									contact_option.addr.clone(),
									transport_option.port,
								);
								if transport_option.openness == openness {
									return Some(ContactOption {
										target: SocketAddr::V4(addr),
										use_tcp: true,
									});
								}
							}
						},
					}
				}
			},
		}
		None
	}

	async fn pick_socket(
		&self, target: &ContactInfo, openness: Openness, timeout: Duration,
	) -> io::Result<
		Option<(
			Arc<dyn LinkSocketSender>,
			Box<dyn LinkSocketReceiver>,
			SocketAddr,
			bool,
		)>,
	> {
		match self.ipv6.as_ref() {
			None => {}
			Some(socket_servers) => match target.ipv6.as_ref() {
				None => {}
				Some(contact_option) => {
					match socket_servers.udp.as_ref() {
						None => {}
						Some(socket_server) => match contact_option.availability.udp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV6::new(
									contact_option.addr.clone(),
									transport_option.port,
									0,
									0,
								);
								if transport_option.openness == openness {
									let (tx, rx) =
										socket_server.inner.connect(addr.clone())?.split();
									return Ok(Some((
										Arc::new(tx),
										Box::new(rx),
										SocketAddr::V6(addr),
										false,
									)));
								}
							}
						},
					}
					match socket_servers.tcp.as_ref() {
						None => {}
						Some(socket_server) => match contact_option.availability.tcp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV6::new(
									contact_option.addr.clone(),
									transport_option.port,
									0,
									0,
								);
								if transport_option.openness == openness {
									let (tx, rx) = socket_server
										.inner
										.connect(addr.clone(), timeout)
										.await?
										.split();
									return Ok(Some((
										Arc::new(tx),
										Box::new(rx),
										SocketAddr::V6(addr),
										true,
									)));
								}
							}
						},
					}
				}
			},
		}
		match self.ipv4.as_ref() {
			None => {}
			Some(socket_servers) => match target.ipv4.as_ref() {
				None => {}
				Some(contact_option) => {
					match socket_servers.udp.as_ref() {
						None => {}
						Some(socket_server) => match contact_option.availability.udp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV4::new(
									contact_option.addr.clone(),
									transport_option.port,
								);
								if transport_option.openness == openness {
									let (tx, rx) =
										socket_server.inner.connect(addr.clone())?.split();
									return Ok(Some((
										Arc::new(tx),
										Box::new(rx),
										SocketAddr::V4(addr),
										false,
									)));
								}
							}
						},
					}
					match socket_servers.tcp.as_ref() {
						None => {}
						Some(socket_server) => match contact_option.availability.tcp.as_ref() {
							None => {}
							Some(transport_option) => {
								let addr = SocketAddrV4::new(
									contact_option.addr.clone(),
									transport_option.port,
								);
								if transport_option.openness == openness {
									let (tx, rx) = socket_server
										.inner
										.connect(addr.clone(), timeout)
										.await?
										.split();
									return Ok(Some((
										Arc::new(tx),
										Box::new(rx),
										SocketAddr::V4(addr),
										true,
									)));
								}
							}
						},
					}
				}
			},
		}
		Ok(None)
	}

	/// Connects to the best available IP version and transport option. Only
	/// tries one option. If no matching options were found, returns None.
	pub async fn connect(
		&self, contact: &ContactOption, timeout: Duration,
	) -> io::Result<Option<(Arc<dyn LinkSocketSender>, Box<dyn LinkSocketReceiver>)>> {
		match &contact.target {
			SocketAddr::V4(a) => match &self.ipv4 {
				None => Ok(None),
				Some(servers) =>
					if !contact.use_tcp {
						match &servers.udp {
							None => Ok(None),
							Some(server) => {
								let (tx, rx) = server.inner.connect(a.clone())?.split();
								Ok(Some((Arc::new(tx), Box::new(rx))))
							}
						}
					} else {
						match &servers.tcp {
							None => Ok(None),
							Some(server) => {
								let (tx, rx) =
									server.inner.connect(a.clone(), timeout).await?.split();
								Ok(Some((Arc::new(tx), Box::new(rx))))
							}
						}
					},
			},
			SocketAddr::V6(a) => match &self.ipv6 {
				None => Ok(None),
				Some(servers) =>
					if !contact.use_tcp {
						match &servers.udp {
							None => Ok(None),
							Some(server) => {
								let (tx, rx) = server.inner.connect(a.clone())?.split();
								Ok(Some((Arc::new(tx), Box::new(rx))))
							}
						}
					} else {
						match &servers.tcp {
							None => Ok(None),
							Some(server) => {
								let (tx, rx) =
									server.inner.connect(a.clone(), timeout).await?.split();
								Ok(Some((Arc::new(tx), Box::new(rx))))
							}
						}
					},
			},
		}
	}

	/// Picks the contact option that it would as if it would connect to the
	/// targeted contact.
	pub fn pick_contact_option(&self, target: &ContactInfo) -> Option<(ContactOption, Openness)> {
		if let Some(option) = self.pick_contact_option_at_openness(target, Openness::Bidirectional)
		{
			return Some((option, Openness::Bidirectional));
		}
		if let Some(option) = self.pick_contact_option_at_openness(target, Openness::Punchable) {
			return Some((option, Openness::Punchable));
		}
		if let Some(option) = self.pick_contact_option_at_openness(target, Openness::Unidirectional)
		{
			return Some((option, Openness::Unidirectional));
		}
		None
	}
}

impl Server {
	async fn serve_connection_based_socket(
		stop_flag: Arc<AtomicBool>, sender: Arc<dyn LinkSocketSender>,
		receiver: Box<dyn LinkSocketReceiver>, addr: SocketAddr, on_packet: OnPacket,
	) {
		while !stop_flag.load(Ordering::Relaxed) {
			match receiver
				.receive(Duration::from_secs(TCP_CONNECTION_TIMEOUT))
				.await
			{
				Err(e) => {
					match e.kind() {
						io::ErrorKind::UnexpectedEof => {
							// TODO: Close the sender if not already closed.
							debug!("TCP connection closed {}.", &addr);
						}
						_ => warn!("TCP io error: {}", e),
					}
					return;
				}
				Ok(packet) => on_packet(sender.clone(), &addr, &packet),
			}
		}
	}
}

impl<S> SstpSocketServer<S>
where
	S: ConnectionLessLinkServer + 'static,
{
	fn spawn_connection_less(self: Arc<Self>, stop_flag: Arc<AtomicBool>, on_packet: OnPacket) {
		let this = self.clone();
		spawn(async move {
			while !stop_flag.load(Ordering::Relaxed) {
				match this.inner.listen().await {
					Err(e) => match e.kind() {
						io::ErrorKind::TimedOut => {}
						_ => warn!("Sstp io error on receiving packet: {}", e),
					},
					Ok((packet, addr)) => {
						let addr2: SocketAddr = addr.clone().into();
						let (sender, _) = this
							.inner
							.connect(addr.try_into().unwrap())
							.expect("no error expected")
							.split();
						on_packet(Arc::new(sender), &addr2, &packet);
					}
				}
			}
		});
	}
}

impl<S> SstpSocketServer<S>
where
	S: ConnectionBasedLinkServer + 'static,
{
	fn spawn_connection_based(self: Arc<Self>, stop_flag: Arc<AtomicBool>, on_packet: OnPacket) {
		// Spawn the loop that accepts connections
		let this = self.clone();
		spawn(async move {
			while !stop_flag.load(Ordering::Relaxed) {
				match this.inner.accept(Duration::from_secs(1)).await {
					Err(e) => match e.kind() {
						io::ErrorKind::TimedOut => {}
						_ => warn!("Sstp io error on receiving connection: {}", e),
					},
					Ok(result) => match result {
						None => return,
						Some((socket, addr)) => {
							let stop_flag2 = stop_flag.clone();
							let (sender, receiver) = socket.split();
							let on_packet2 = on_packet.clone();
							spawn(async move {
								Server::serve_connection_based_socket(
									stop_flag2,
									Arc::new(sender),
									Box::new(receiver),
									addr.into(),
									on_packet2,
								)
								.await;
							});
						}
					},
				}
			}
		});
	}
}

impl<V> Default for SstpSocketServers<V>
where
	V: Into<SocketAddr> + Send + Clone,
{
	fn default() -> Self {
		Self {
			udp: None,
			tcp: None,
		}
	}
}

impl Server {
	pub async fn clean_sessions(self: &Arc<Self>) {
		let mut sessions = self.sessions.lock().await;
		let mut done_ids = Vec::with_capacity(0);
		for (session_id, session_mutex) in sessions.map.iter() {
			let session = session_mutex.lock().await;
			if SystemTime::now()
				.duration_since(*session.last_activity.lock().unwrap())
				.unwrap() >= session.keep_alive_timeout
			{
				drop(session);
				done_ids.push(*session_id);
			}
		}

		for done_id in done_ids {
			sessions.map.remove(&done_id).unwrap();
		}
	}

	async fn process_sequenced_packet(
		&self, packet: &[u8],
		handle_queue: impl FnOnce(
			&mut SessionData,
			u16,
			u16,
			Vec<u8>,
		) -> StdResult<(), SendError<(u16, u16, Vec<u8>)>>,
	) -> Result<()> {
		let our_session_id = u16::from_le_bytes(*array_ref![packet, 0, 2]);
		let keystate_sequence = u16::from_le_bytes(*array_ref![packet, 2, 2]);
		let key_sequence = u16::from_le_bytes(*array_ref![packet, 4, 2]);
		let data = packet[6..].to_vec();

		let mut sessions = self.sessions.lock().await;
		let mut should_close = false;
		if let Some(s) = sessions.map.get(&our_session_id) {
			let mut session = s.lock().await;
			*session.last_activity.lock().unwrap() = SystemTime::now();
			let result = handle_queue(&mut session, keystate_sequence, key_sequence, data);
			// If the result is an error, the receiving end of the queue has been closed.
			// This happens all the time because connections get closed and then dropped
			// before the other side may be able to send a close packet.
			if result.is_err() {
				should_close = true;
			}
		} else {
			//debug!("Invalid session ID: {}", our_session_id);
		}

		if should_close {
			sessions.map.remove(&our_session_id);
			return Err(Error::ConnectionClosed.into());
		}
		Ok(())
	}

	async fn process_ack(&self, packet: &[u8]) -> Result<()> {
		self.process_sequenced_packet(packet, |session, ks_seq, seq, data| {
			session.queues.ack.send((ks_seq, seq, data))
		})
		.await
	}

	async fn process_close(&self, packet: &[u8]) -> Result<()> {
		self.process_sequenced_packet(packet, |session, ks_seq, seq, data| {
			session.queues.close.send((ks_seq, seq, data))
		})
		.await
	}

	async fn process_data(&self, packet: &[u8]) -> Result<()> {
		self.process_sequenced_packet(packet, |session, ks_seq, seq, data| {
			session.queues.data.send((ks_seq, seq, data))
		})
		.await
	}

	async fn process_hello_request(
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, addr: &SocketAddr, packet: &[u8],
	) -> Result<()> {
		if packet.len() < 162 {
			return Err(Error::MalformedPacket.into());
		}

		let node_id = IdType::from_slice(&packet[..32]).unwrap();
		let identity_pubkey = match identity::PublicKey::from_bytes(*array_ref![packet, 32, 32]) {
			Ok(k) => k,
			Err(_) => return Err(Error::InvalidPublicKey.into()),
		};
		// Verify that the node ID is valid
		let node_id2 = identity_pubkey.generate_address();
		if node_id != node_id2 {
			return Err(Error::InvalidPublicKey.into());
		}

		// Verify that the signature is correct
		let signature = Signature::from_bytes(*array_ref![packet, 64, 64]);
		if !identity_pubkey.verify(&packet[128..], &signature) {
			return Err(Error::InvalidSignature.into());
		}
		let dh_pubkey_bytes: [u8; 32] = packet[128..160].try_into().unwrap();

		let their_public_key = x25519::PublicKey::from(dh_pubkey_bytes);
		let own_secret_key = x25519::StaticSecret::random_from_rng(OsRng);
		let own_public_key = x25519::PublicKey::from(&own_secret_key);
		let their_session_id = u16::from_le_bytes(*array_ref![packet, 160, 2]);
		let mut their_contact_info: ContactInfo = bincode::deserialize(&packet[162..])?;
		their_contact_info.update(addr, sender.is_tcp());

		let (tx_queues, rx_queues) = Queues::channel(their_session_id);
		let (our_session_id, is_new) = self
			.new_incomming_session(
				node_id.clone(),
				their_session_id,
				tx_queues,
				self.default_timeout,
			)
			.await?;

		let addr_len = match addr {
			SocketAddr::V4(_) => 4,
			SocketAddr::V6(_) => 16,
		};
		let contact_info = self.our_contact_info();
		let contact_info_len = bincode::serialized_size(&contact_info).unwrap();
		let mut response = vec![0u8; 165 + addr_len + contact_info_len + 2];
		response[0] = MESSAGE_TYPE_HELLO_RESPONSE;
		// Send back the sender's node ID to verify that both nodes share the
		// same secret.
		response[1..33].copy_from_slice(node_id.as_bytes());
		response[33..65].copy_from_slice(self.private_key.public().as_bytes());
		response[129..161].copy_from_slice(own_public_key.as_bytes());
		response[161..163].copy_from_slice(&their_session_id.to_le_bytes());
		response[163..165].copy_from_slice(&our_session_id.to_le_bytes());
		let i = 165 + contact_info_len;
		response[165..i].copy_from_slice(&bincode::serialize(&contact_info).unwrap());
		match addr {
			SocketAddr::V4(a) => {
				response[i..(i + 4)].copy_from_slice(&bincode::serialize(a.ip()).unwrap());
				response[(i + 4)..(i + 6)].copy_from_slice(&a.port().to_le_bytes());
			}
			SocketAddr::V6(a) => {
				response[i..(i + 16)].copy_from_slice(&bincode::serialize(a.ip()).unwrap());
				response[(i + 16)..(i + 18)].copy_from_slice(&a.port().to_le_bytes());
			}
		}

		// Sign DH public key, and write it to the response buffer
		let signature = self.private_key.sign(&response[129..]);
		response[65..129].clone_from_slice(&signature.to_bytes());

		// If the connection was already created before, just return the response again.
		// The other side might not have received the hello response packet
		if !is_new {
			sender.send(&response, self.default_timeout).await?;
			return Ok(());
		}

		let connection = Box::new(Connection {
			server: self.clone(),
			keep_alive_flag: AtomicBool::new(false),
			is_closing: AtomicBool::new(false),
			sender: sender.clone(),
			receiver_handle: None,
			peer_address: addr.clone(),
			their_session_id,
			our_session_id,
			their_node_info: NodeContactInfo {
				node_id: node_id.clone(),
				contact_info: their_contact_info,
			},
			node_id: self.node_id.clone(),
			peer_node_id: node_id,
			private_key: self.private_key.clone(),
			//session,
			queues: rx_queues,
			key_state: KeyState::new(own_secret_key.clone(), their_public_key.clone(), 1),
			previous_keystate: KeyState::new(own_secret_key, their_public_key, 0),
			previous_window_ack_sequence: 0,
			receive_window: WindowInfo::default(),
			send_window: WindowInfo::default(),
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
			#[cfg(debug_assertions)]
			should_be_closed: AtomicBool::new(false),
			unprocessed_close_packets: Vec::new(),
			timeout: self.default_timeout,
			keep_alive_timeout: self.default_timeout,
		});
		match self.on_connect.get() {
			None => {}
			Some(closure) => {
				closure(connection);
				sender.send(&response, self.default_timeout).await?;
			}
		}

		Ok(())
	}

	async fn process_hello_response(
		&self, sender: &SocketAddr, is_tcp: bool, packet: &[u8],
	) -> Result<()> {
		let addr_len = match sender {
			SocketAddr::V4(_) => 4,
			SocketAddr::V6(_) => 16,
		};
		if packet.len() < (164 + addr_len) {
			return Err(Error::MalformedPacket.into());
		}

		// Verify that the node ID is the same as ours. If it isn't, the
		// recipient of our request didn't receive the correct node ID.
		// An attacker could try to change this, even though it wouldn't be
		// able to perform a MitM-attack because the attacker would have to
		// sign the DH key as well.
		let my_node_id = IdType::from_slice(&packet[..32]).unwrap();
		if my_node_id != self.node_id {
			return Err(Error::InsecureConnection.into());
		}

		let identity_pubkey = identity::PublicKey::from_bytes(*array_ref![packet, 32, 32])
			.map_err(|e| Into::<Error>::into(e))?;

		// Verify that the signature is correct
		let signature = Signature::from_bytes(*array_ref![packet, 64, 64]);
		if !identity_pubkey.verify(&packet[128..], &signature) {
			return Err(Error::InvalidSignature.into());
		}

		// Once we have verified the signature, take note of our session ID.
		let our_session_id = u16::from_le_bytes(*array_ref![packet, 160, 2]);
		let session_lock = match self.sessions.lock().await.map.get(&our_session_id) {
			None => {
				return Err(Error::InvalidSessionId(our_session_id).into());
			}
			Some(s) => s.clone(),
		};
		let mut session = session_lock.lock().await;
		// If the hello_watch is already gone, we've processed this response before
		if session.hello_watch.is_none() {
			return Ok(());
		}

		// Remember their session ID
		let their_session_id = u16::from_le_bytes(*array_ref![packet, 162, 2]);
		session.their_session_id = Some(their_session_id);

		let mut their_contact_info: ContactInfo =
			bincode::deserialize_with_trailing(&packet[164..])?;
		let i = 164 + bincode::serialized_size(&their_contact_info).unwrap();
		their_contact_info.update(sender, is_tcp);

		// Update our own external IP address with what is given by the other side
		match sender {
			SocketAddr::V4(_) => {
				let ip: Ipv4Addr = bincode::deserialize(&packet[i..(i + 4)])?;
				let port = u16::from_le_bytes(*array_ref![packet, i + 4, 2]);
				self.our_contact_info
					.lock()
					.unwrap()
					.update_v4(&ip, port, is_tcp);
			}
			SocketAddr::V6(_) => {
				let ip: Ipv6Addr = bincode::deserialize(&packet[i..(i + 16)])?;
				let port = u16::from_le_bytes(*array_ref![packet, i + 16, 2]);
				self.our_contact_info
					.lock()
					.unwrap()
					.update_v6(&ip, port, is_tcp);
			}
		}

		// Notify the connection's thread of the successful response
		let their_node_id = identity_pubkey.generate_address();
		let their_dh_key = x25519::PublicKey::from(*array_ref![packet, 128, 32]);

		// Send the hello response data back to the connecting task if not send already
		let sender = session.hello_watch.take().unwrap();
		if sender
			.send(Ok((
				their_node_id,
				their_contact_info,
				their_session_id,
				their_dh_key,
				session.last_activity.clone(),
			)))
			.is_err()
		{
			debug!(
				"Unable to send connection data back to connecting task. ({})",
				our_session_id
			);
		}

		Ok(())
	}

	async fn process_packet(
		self: &Arc<Self>, link_socket: Arc<dyn LinkSocketSender>, sender: &SocketAddr,
		packet: &[u8],
	) -> Result<()> {
		let message_type = packet[0];
		let result = match message_type {
			MESSAGE_TYPE_HELLO_REQUEST =>
				self.process_hello_request(link_socket, sender, &packet[1..])
					.await,
			MESSAGE_TYPE_HELLO_RESPONSE =>
				self.process_hello_response(sender, link_socket.is_tcp(), &packet[1..])
					.await,
			MESSAGE_TYPE_DATA => self.process_data(&packet[1..]).await,
			MESSAGE_TYPE_ACK => self.process_ack(&packet[1..]).await,
			MESSAGE_TYPE_CLOSE => self.process_close(&packet[1..]).await,
			// Hole punching packets don't need to be responded to. They don't have any data other
			// than the message type anyway.
			MESSAGE_TYPE_PUNCH_HOLE => Ok(()),
			other => Err(Error::InvalidMessageType(other)),
		};

		match result {
			// Ignore invalid session id exceptions, as they happen regularely due to the fact that
			// the sender might resend some of their packets if they are still waiting on a
			// response.
			Err(e) => match e {
				Error::InvalidSessionId(session_id) => {
					// Close packets may be received after we've already closed the connection
					// ourselves, at which point we've forgotten about the session ID already. So
					// ignore this error for close packets.
					if message_type == MESSAGE_TYPE_CLOSE {
						Ok(())
					} else {
						Err(Error::InvalidSessionId(session_id))
					}
				}
				other => Err(other),
			},
			Ok(()) => Ok(()),
		}
	}

	pub fn spawn(self: &Arc<Self>) {
		self.clone().spawn_garbage_collector();

		let this = self.clone();
		self.sockets
			.spawn_servers(self.stop_flag.clone(), move |sender, address, packet| {
				let this2 = this.clone();
				let sender2 = sender.clone();
				let address2 = address.clone();
				let packet2 = packet.to_vec();
				spawn(async move {
					match this2.process_packet(sender2, &address2, &packet2).await {
						Ok(()) => {}
						Err(e) => match e {
							// A connection is opened without sending anything all the time
							Error::ConnectionClosed => {}
							_ => warn!("Sstp io error: {}", e),
						},
					}
				});
			});
	}

	/// Starts garbage collecting the unresponded requests.
	pub fn spawn_garbage_collector(self: Arc<Self>) {
		tokio::task::spawn(async move {
			let this = self.clone();
			while !self.stop_flag.load(Ordering::Relaxed) {
				sleep(Duration::from_secs(1)).await;
				this.clean_sessions().await;
			}
		});
	}

	fn verify_close_packet(buffer: &[u8], node_id: &IdType) -> bool { buffer == node_id.as_bytes() }
}

impl WindowInfo {
	pub fn decrease_window_size(&mut self) -> u16 {
		self.starting = false;
		if self.size > 1 { self.size >> 1 } else { 1 }
	}

	pub fn increase_window_size(&self) -> u16 {
		if self.starting {
			if self.size < 0x8000 {
				self.size << 1
			} else {
				0xFFFF
			}
		} else {
			if self.size != 0xFFFF {
				self.size + 1
			} else {
				0xFFFF
			}
		}
	}
}

impl Default for WindowInfo {
	fn default() -> Self {
		Self {
			starting: true,
			size: 1,
		}
	}
}

impl Queues {
	fn channel(sending_session_id: u16) -> (QueueSenders, QueueReceivers) {
		let (data_tx, data_rx) = mpsc::unbounded_channel();
		let (ack_tx, ack_rx) = mpsc::unbounded_channel();
		let (close_tx, close_rx) = mpsc::unbounded_channel();

		(
			QueueSenders {
				data: data_tx,
				ack: ack_tx,
				close: close_tx,
				session_id: sending_session_id,
			},
			QueueReceivers {
				data: data_rx,
				ack: ack_rx,
				close: close_rx,
			},
		)
	}
}

#[cfg(test)]
mod tests {
	use std::net::*;

	use super::*;
	use crate::test;

	#[test]
	fn test_encryption() {
		let mut rng = test::initialize_rng();
		let mut key = GenericArray::<u8, U32>::default();
		let mut original = [0u8; 46 * 32];
		rng.fill_bytes(key.as_mut());
		rng.fill_bytes(&mut original);

		let mut buffer = original.clone();
		encrypt(777, 321, 123, &mut buffer, &key);
		assert!(buffer != original);
		decrypt(777, 321, 123, &mut buffer, &key);
		assert!(buffer == original);
	}

	#[tokio::test]
	/// Sent and receive a bunch of messages.
	async fn test_connection() {
		let mut rng = test::initialize_rng();
		//env_logger::init();
		let ip = Ipv4Addr::new(127, 0, 0, 1);
		let master_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10000));
		let slave_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10001));
		let mut master_config = Config::default();
		master_config.ipv4_address = Some("127.0.0.1".to_string());
		master_config.ipv4_udp_port = Some(10000);
		let mut slave_config = master_config.clone();
		slave_config.ipv4_udp_port = Some(10001);
		let master_contact_info: ContactInfo = (&master_addr).into();
		let slave_contact_info: ContactInfo = (&slave_addr).into();
		let stop_flag = Arc::new(AtomicBool::new(false));
		let master_private_key = PrivateKey::generate();
		let master_node_id = master_private_key.public().generate_address();
		let master = sstp::Server::bind(
			stop_flag.clone(),
			&master_config,
			master_node_id,
			master_private_key,
			DEFAULT_TIMEOUT,
		)
		.await
		.expect("unable to bind master");
		let slave_private_key = PrivateKey::generate();
		let slave_node_id = slave_private_key.public().generate_address();
		let slave = Arc::new(
			sstp::Server::bind(
				stop_flag.clone(),
				&slave_config,
				slave_node_id,
				slave_private_key,
				DEFAULT_TIMEOUT,
			)
			.await
			.expect("unable to bind slave"),
		);

		let mut small_message = vec![0u8; 1000];
		rng.fill_bytes(&mut small_message);
		let mut small_message2 = vec![0u8; 1000];
		rng.fill_bytes(&mut small_message2);
		let mut big_message = vec![0u8; 1000000]; // One MB of data
		rng.fill_bytes(&mut big_message);
		let mut small_message3 = vec![0u8; 1000];
		rng.fill_bytes(&mut small_message3);

		let small_message_clone = small_message.clone();
		let small_message_clone2 = small_message2.clone();
		let big_message2 = big_message.clone();
		let small_message_clone3 = small_message3.clone();
		master.listen(move |mut connection| {
			let small = small_message_clone.clone();
			let small2 = small_message_clone2.clone();
			let big = big_message2.clone();
			let small3 = small_message_clone3.clone();
			spawn(async move {
				let received_message = connection
					.receive()
					.await
					.expect("master unable to receive small message");
				debug!("Received small message");
				assert!(received_message == small, "small message got corrupted");

				let received_message2 = connection
					.receive()
					.await
					.expect("master unable to receive second small message");
				debug!("Received second small message");
				assert!(
					received_message2 == small2,
					"second small message got corrupted"
				);

				connection
					.send(&big)
					.await
					.expect("master unable to send big message");
				debug!("Sent big message");

				connection
					.send(&small3)
					.await
					.expect("master unable to send third small message");
				debug!("Sent third small message");
			});
		});
		master.spawn();
		let slave2 = slave.clone();
		slave2.spawn();

		let mut connection = slave
			.clone()
			.connect(&ContactOption::use_udp(master_addr), None)
			.await
			.expect("unable to connect to master");

		connection
			.send(&small_message)
			.await
			.expect("slave unable to send small message");
		debug!("Sent small message");
		connection
			.send(&small_message2)
			.await
			.expect("slave unable to send second small message");
		debug!("Sent second small message");
		let received_message = connection
			.receive()
			.await
			.expect("slave unable to receive big message");
		debug!("Received big message");
		assert!(
			received_message == big_message,
			"big message got corrupted {} {}",
			received_message.len(),
			big_message.len()
		);
		let received_message2 = connection
			.receive()
			.await
			.expect("slave unable to receive third small message");
		debug!("Received third small message");
		assert!(
			received_message2 == small_message3,
			"third small message got corrupted {} {}",
			received_message.len(),
			small_message3.len()
		);
		connection
			.close()
			.await
			.expect("unable to close connection");

		stop_flag.store(true, Ordering::Relaxed);
	}

	#[tokio::test]
	/// Sent and receive a message through a relay
	async fn test_connection_piping() {
		let mut rng = test::initialize_rng();
		let mut relay_config = Config::default();
		relay_config.ipv4_address = Some("127.0.0.1".to_string());
		relay_config.ipv4_udp_port = Some(10002);
		let mut node1_config = relay_config.clone();
		node1_config.ipv4_udp_port = Some(10003);
		let mut node2_config = relay_config.clone();
		node2_config.ipv4_udp_port = Some(10004);
		let ip = Ipv4Addr::new(127, 0, 0, 1);
		let relay_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10002));
		let node2_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10004));
		let stop_flag = Arc::new(AtomicBool::new(false));
		let relay_private_key = PrivateKey::generate();
		let relay_node_id = relay_private_key.public().generate_address();
		let relay = sstp::Server::bind(
			stop_flag.clone(),
			&relay_config,
			relay_node_id.clone(),
			relay_private_key,
			DEFAULT_TIMEOUT,
		)
		.await
		.expect("unable to bind relay");
		let node1_private_key = PrivateKey::generate();
		let node1_node_id = node1_private_key.public().generate_address();
		let node1 = sstp::Server::bind(
			stop_flag.clone(),
			&node1_config,
			node1_node_id,
			node1_private_key,
			DEFAULT_TIMEOUT,
		)
		.await
		.expect("unable to bind node 1");
		let node2_private_key = PrivateKey::generate();
		let node2_node_id = node2_private_key.public().generate_address();
		let node2 = Arc::new(
			sstp::Server::bind(
				stop_flag.clone(),
				&node2_config,
				node2_node_id.clone(),
				node2_private_key,
				DEFAULT_TIMEOUT,
			)
			.await
			.expect("unable to bind node 2"),
		);

		let mut message = vec![0u8; 100000];
		rng.fill_bytes(&mut message);

		// Set up the relay node
		let relay2 = relay.clone();
		let node2_node_id2 = node2_node_id.clone();
		let message_len = message.len();
		relay.listen(move |mut connection1| {
			let relay3 = relay2.clone();
			let node2_node_id3 = node2_node_id2.clone();
			spawn(async move {
				let mut connection2 = relay3
					.connect(&ContactOption::use_udp(node2_addr), Some(&node2_node_id3))
					.await
					.expect("unable to connect to node 2");
				let sent = connection1
					.pipe(&mut connection2, |_| true)
					.await
					.expect("unable to pipe data");
				connection2.close().await.expect("unable to close");
				connection1.close().await.expect("unable to close");
				assert_eq!(sent, message_len);
			});
		});

		// Set up the node that has the message
		let message2 = message.clone();
		node2.listen(move |mut connection| {
			let message3 = message2.clone();
			spawn(async move {
				connection
					.send(&message3)
					.await
					.expect("unable to send message from node 2");
				connection.close().await.expect("unable to close");
			});
		});

		relay.spawn();
		node1.spawn();
		node2.spawn();

		// Receive relayed message
		let mut connection = node1
			.connect(&ContactOption::use_udp(relay_addr), Some(&relay_node_id))
			.await
			.expect("unable to connect to relay node");
		let received_message = connection
			.receive()
			.await
			.expect("unable to receive message");
		connection.close().await.expect("unable to close");
		assert_eq!(received_message, message, "relayed message got corrupted");
	}
}

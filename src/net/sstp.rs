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
	cmp,
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
use generic_array::{typenum::*, GenericArray};
use hmac::*;
use log::*;
use once_cell::sync::OnceCell;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::{
	self, select, spawn,
	sync::{
		mpsc::{self, error::*},
		watch, Mutex,
	},
	task::JoinHandle,
	time::sleep,
};
use x25519_dalek as x25519;

// FIXME: Why can't I use super::socket::* here?
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

const KEEP_ALIVE_IDLE_TIME: Duration = Duration::from_secs(10);
const MESSAGE_TYPE_HELLO_REQUEST: u8 = 0;
const MESSAGE_TYPE_HELLO_RESPONSE: u8 = 1;
const MESSAGE_TYPE_DATA: u8 = 2;
const MESSAGE_TYPE_ACK: u8 = 3;
const MESSAGE_TYPE_CLOSE: u8 = 4;
const MESSAGE_TYPE_PING: u8 = 5;
const MESSAGE_TYPE_PONG: u8 = 6;
/// If nothing was received on a TCP connection for 2 minutes, assume the
/// connection is broken.
const TCP_CONNECTION_TIMEOUT: u64 = 120;

pub(super) const TIMEOUT: Duration = Duration::from_secs(2);

pub struct Connection {
	keep_alive_flag: AtomicBool,
	/// A flag that signifies that a timeout has actually occurred.
	keep_alive_timeout: AtomicBool,
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
	private_key: identity::PrivateKey,
	/// The next data packet that is send or received is expected to have this
	/// sequence number.
	next_sequence: u16,
	queues: QueueReceivers,
	//session: Arc<Mutex<SessionData>>,
	key_state: KeyState,
	previous_keystate: KeyState,
	current_keystate_sequence: u16,
	receive_window: WindowInfo,
	send_window: WindowInfo,

	last_activity: Arc<StdMutex<SystemTime>>,

	#[cfg(debug_assertions)]
	pub should_be_closed: AtomicBool,
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
	/// The public key in the hello exchange didn't match the node ID.
	InvalidPublicKey,
	/// A packet had an invalid message type on it.
	InvalidMessageType(u8),
	/// A different node ID has been responded with than was expected.
	InvalidNodeId,
	InvalidResponseMessageType((u8, u8)),
	InvalidSessionIdOurs(u16),
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
struct KeyState {
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
}

struct Sessions {
	map: HashMap<u16, Arc<Mutex<SessionData>>>,
	next_id: u16,
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
	our_contact_info: Mutex<ContactInfo>,
	sessions: Mutex<Sessions>,
	node_id: IdType,
	private_key: identity::PrivateKey,
	on_connect: OnceCell<Box<dyn Fn(Box<Connection>) + Send + Sync>>,
}

struct Queues;

type QueueReceiver = mpsc::UnboundedReceiver<(u16, u16, Vec<u8>)>;
type QueueSender = mpsc::UnboundedSender<(u16, u16, Vec<u8>)>;

pub struct QueueReceivers {
	data: QueueReceiver,
	ack: QueueReceiver,
	ping: PingReceiver,
	close: QueueReceiver,
}

pub struct QueueSenders {
	data: QueueSender,
	ack: QueueSender,
	ping: PingSender,
	close: QueueSender,
	session_id: u16,
}


fn calculate_checksum(buffer: &[u8]) -> u16 {
	let mut result = 0u16;
	for i in 2..buffer.len() {
		result = result.wrapping_add(buffer[i] as u16);
	}
	result
}

fn compose_missing_mask<'a, I>(max_packet_count: usize, completed: u16, ooo_sequences: I) -> Vec<u8>
where
	I: Iterator<Item = &'a u16>,
{
	let mask_bits = max_packet_count - completed as usize;
	let mut mask = vec![0xFFu8; mask_bits / 8 + ((mask_bits % 8) > 0) as usize];

	// Then reset individual bits back to 0 for those we already have.
	for seq in ooo_sequences {
		let x = seq - completed;
		let byte_index = (x / 8) as usize;
		let bit_index = (x % 8) as usize;

		mask[byte_index] ^= 1 << bit_index;
	}

	mask
}

/// Parses the contact info ready for initiating a `SstpSocket` from the config
/// file
pub fn contact_info_from_config(config: &Config) -> ContactInfo {
	let mut contact_info = ContactInfo::default();

	fn parse_openness(string: &str) -> Openness {
		match string {
			"bidirectional" => Openness::Bidirectional,
			"unidirectional" => Openness::Unidirectional,
			other => {
				warn!(
					"Openness setting {} not recognized, defaulting to \"unidirectional\"",
					other
				);
				Openness::Unidirectional
			}
		}
	}

	// IPv4
	match &config.ipv4_address {
		None => {}
		Some(address) => {
			contact_info.ipv4 = Some(ContactInfoEntry {
				addr: address.parse().expect("invalid IPv4 address configured"),
				availability: IpAvailability {
					udp: config
						.ipv4_udp_openness
						.as_ref()
						.map(|o| TransportAvailabilityEntry {
							port: config.ipv4_udp_port,
							openness: parse_openness(o),
						}),
					tcp: config.ipv4_tcp_openness.as_ref().map(|_o| {
						TransportAvailabilityEntry {
							port: config.ipv4_tcp_port,
							openness: Openness::Unidirectional, /* FIXME: TCP hole punching is
							                                     * not working yet at the moment. */
						}
					}),
				},
			})
		}
	}

	// IPv6
	match &config.ipv6_address {
		None => {}
		Some(address) => {
			contact_info.ipv6 = Some(ContactInfoEntry {
				addr: address.parse().expect("invalid IPv6 address configured"),
				availability: IpAvailability {
					udp: config
						.ipv6_udp_openness
						.as_ref()
						.map(|o| TransportAvailabilityEntry {
							port: config.ipv6_udp_port,
							openness: parse_openness(o),
						}),
					tcp: config.ipv6_tcp_openness.as_ref().map(|_| {
						TransportAvailabilityEntry {
							port: config.ipv6_tcp_port,
							openness: Openness::Unidirectional, /* FIXME: TCP hole punching is
							                                     * not working yet at the moment. */
						}
					}),
				},
			})
		}
	}

	contact_info
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
			Self::IoError(e) => write!(f, "I/O error: {}", e),
			Self::ConnectionClosed => write!(f, "connection has already been closed"),
			Self::EmptyAckMask => write!(f, "ack mask did not contain any missing packet bits"),
			Self::InsecureConnection => write!(f, "connection not secure"),
			Self::InvalidPublicKey => write!(f, "invalid public key"),
			Self::InvalidMessageType(mt) => write!(f, "invalid message type: {}", mt),
			Self::InvalidNodeId => write!(f, "invalid node ID"),
			Self::InvalidResponseMessageType((mt, ex)) => write!(
				f,
				"expected message type {} from response but got {}",
				ex, mt
			),
			Self::InvalidSessionIdOurs(id) => write!(f, "invalid session ID (ours): {}", id),
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
		spawn(async move {
			if let Err(e) = self.close().await {
				debug!("Unable to close connection: {}", e);
			}
		});
	}

	async fn send_close_packet(&mut self) -> Result<()> {
		self.send_crypted_packet(
			MESSAGE_TYPE_CLOSE,
			self.next_sequence,
			0,
			self.node_id.as_bytes(),
		)
		.await
	}

	/// Decrypts a packet that is expected to have a specific key sequence set on its packet.
	fn decrypt_packet(&self, key_state: &KeyState, sequence: u16, key_sequence: u16, data: &mut [u8]) -> bool {
		debug_assert!(
			key_sequence < self.key_state.keychain.len() as u16,
			"attempting to decrypt a packet out-of-order: {} >= {}",
			sequence,
			self.key_state.keychain.len()
		);
		let key = &key_state.keychain[key_sequence as usize];

		decrypt(self.our_session_id, sequence, data, key);

		if !Self::verify_packet(&data) {
			return false;
		}

		true
	}

	pub async fn keep_alive(
		this: &Arc<Mutex<Box<Self>>>,
		on_timeout: impl FnOnce(Arc<Mutex<Box<Self>>>) + Send + 'static,
	) {
		let lock = this.lock().await;

		if lock.keep_alive_flag.load(Ordering::Relaxed) == false {
			let this2 = this.clone();
			spawn(async move {
				let lock = this2.lock().await;
				// Keep sending pings over the connection if there was no activity for too long
				while !lock.keep_alive_timeout.load(Ordering::Relaxed)
					&& lock.keep_alive_flag.load(Ordering::Relaxed)
				{
					let wait = {
						let g = lock.last_activity.lock().unwrap();
						let now = SystemTime::now();
						if let Ok(elapsed) = now.duration_since(*g) {
							if elapsed
								>= KEEP_ALIVE_IDLE_TIME
									.checked_sub(Duration::from_millis(10))
									.unwrap()
							{
								None
							} else {
								Some(KEEP_ALIVE_IDLE_TIME.checked_sub(elapsed).unwrap())
							}
						} else {
							Some(KEEP_ALIVE_IDLE_TIME)
						}
					};

					if let Some(wait_time) = wait {
						sleep(wait_time).await;
					} else {
						if let Err(_e) = lock.ping().await {
							// Disconnect the close queue in order to signify that the connection is
							// closed.
							lock.keep_alive_timeout.store(true, Ordering::Relaxed);
							break;
						}
					}
				}

				if lock.keep_alive_timeout.load(Ordering::Relaxed) {
					on_timeout(this2.clone());
				}
			});
		}
		lock.keep_alive_flag.store(true, Ordering::Relaxed);
	}

	pub fn peer_contact_option(&self) -> ContactOption {
		ContactOption {
			target: self.peer_address.clone(),
			use_tcp: self.sender.is_tcp(),
		}
	}

	pub fn peer_address(&self) -> &SocketAddr { &self.peer_address }

	pub async fn ping(&self) -> Result<()> {
		self.send_ping_packet().await?;
		self.receive_pong_packet().await
	}

	pub async fn pipe(&mut self, other: &mut Connection) -> Result<()> {
		// FIXME: Don't wait on the send_data function. It introduces unnecessary
		// lock-ups
		let (chunk, ml_opt) = self.receive_chunk(true).await?;
		let message_length = ml_opt.unwrap() as u32;

		let mut first_chunk = vec![0u8; 4 + chunk.len()];
		first_chunk.copy_from_slice(&message_length.to_le_bytes());
		first_chunk.copy_from_slice(&chunk);
		other.send_data(&first_chunk).await?;

		let forwarded = chunk.len();
		while forwarded < message_length as usize {
			let (chunk, _) = self.receive_chunk(false).await?;
			other.send_data(&chunk).await?;
		}
		Ok(())
	}

	pub fn their_node_info(&self) -> &NodeContactInfo { &self.their_node_info }

	pub fn their_node_id(&self) -> &IdType { &self.their_node_info.node_id }

	pub fn our_session_id(&self) -> u16 { self.our_session_id }

	fn max_data_packet_length(&self) -> usize { self.sender.max_packet_length() - 5 - 2 }

	pub async fn receive(&mut self) -> Result<Vec<u8>> {
		if self.is_closing.load(Ordering::Relaxed) {
			return Err(Error::ConnectionClosed);
		}

		let mut buffer = Vec::new();
		let mut window_size = self.receive_window.size;
		let mut first = true;
		loop {
			self.key_state.our_dh_key = x25519::StaticSecret::random_from_rng(OsRng);
			let dh_public_key = x25519::PublicKey::from(&self.key_state.our_dh_key);
			let (new_public_key, clean, window_full) = self
				.receive_window(&mut buffer, window_size, first, &dh_public_key)
				.await?;
			first = false;

			// Adjust window size
			if clean && window_full {
				self.receive_window.increase()
			} else {
				self.receive_window.decrease()
			}
			window_size = self.receive_window.size;

			// Update our shared key
			self.key_state.their_dh_key = new_public_key;
			self.previous_keystate = self.key_state.clone();
			self.key_state.reset_key(window_size);
			let _ = self.current_keystate_sequence.wrapping_add(1);

			debug_assert!(buffer.capacity() > 0, "Message length not set");
			if buffer.len() == buffer.capacity() {
				return Ok(buffer);
			}
		}
	}

	async fn receive_chunk(&mut self, is_first: bool) -> Result<(Vec<u8>, Option<usize>)> {
		let mut window_size = self.receive_window.size;
		let mut buffer = Vec::with_capacity(if is_first {
			0
		} else {
			window_size as usize * self.max_data_packet_length()
		});

		self.key_state.our_dh_key = x25519::StaticSecret::random_from_rng(OsRng);
		let dh_public_key = x25519::PublicKey::from(&self.key_state.our_dh_key);
		let (new_public_key, clean, window_full) = self
			.receive_window(&mut buffer, window_size, is_first, &dh_public_key)
			.await?;
		self.key_state.their_dh_key = new_public_key;

		// Adjust window size
		if clean && window_full {
			self.receive_window.increase()
		} else {
			self.receive_window.decrease()
		}

		// Update our shared key
		window_size = self.receive_window.size;
		self.key_state.reset_key(window_size);

		// Return the complete message length if this was the first chunk
		if is_first {
			let message_length = buffer.capacity();
			buffer.shrink_to_fit();
			Ok((buffer, Some(message_length)))
		} else {
			Ok((buffer, None))
		}
	}

	async fn receive_ack(
		&mut self, window_start_sequence: u16, timeout: Duration,
	) -> Result<StdResult<x25519::PublicKey, (u16, Vec<u8>)>> {
		let mut sequence;
		let mut window_sequence;
		let mut packet: Vec<u8>;
		loop {
			(_, sequence, packet) = self.receive_ack_packet(timeout).await?;
			window_sequence = sequence.wrapping_sub(window_start_sequence);
			if window_sequence as usize >= self.key_state.keychain.len() {
				return Err(Error::InvalidSequenceNumber(sequence).into());
			}

			if self.decrypt_packet(&self.key_state, sequence, window_sequence, &mut packet) {
				break;
			} else {
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
			Ok(Err((window_sequence, packet[5..(5 + mask_len)].to_vec())))
		} else {
			let mut bytes = [0u8; 32];
			bytes.copy_from_slice(&packet[3..35]);
			let new_public_key = x25519::PublicKey::from(bytes);
			Ok(Ok(new_public_key))
		}
	}

	/// Wait for an ack packet, re-sends the last packet a few times if the
	/// other side is unresponsive.
	async fn receive_ack_patiently(
		&mut self, window_start_sequence: u16, last_sequence: u16, last_key_sequence: u16,
		last_packet: &[u8],
	) -> Result<StdResult<x25519::PublicKey, (u16, Vec<u8>)>> {
		for _ in 0..1 {
			match self.receive_ack(window_start_sequence, TIMEOUT / 2).await {
				Ok(r) => return Ok(r),
				Err(e) => match e {
					Error::Timeout => {}
					other => return Err(other),
				},
			}

			self.send_data_packet(last_sequence, last_key_sequence, last_packet, false)
				.await?;
		}
		self.receive_ack(window_start_sequence, TIMEOUT / 2).await
	}

	async fn receive_pong_packet(&self) -> Result<()> {
		let mut queue = self.queues.ping.lock().await;

		// This loop throws all pongs away that where queued too early in order to
		// prevent a DoS attack.
		loop {
			match queue.try_recv() {
				Err(e) => match e {
					TryRecvError::Empty => {
						select! {
							_ = queue.recv() => return Ok(()),
							_ = sleep(TIMEOUT) => return Err(Error::Timeout)
						}
					}
					TryRecvError::Disconnected => return Err(Error::ConnectionClosed),
				},
				Ok(time) =>
					if SystemTime::now().duration_since(time).unwrap() < TIMEOUT {
						return Ok(());
					},
			}
		}
	}

	fn process_packet(
		&mut self, buffer: &mut Vec<u8>, packet: &[u8], first_window: bool, first_packet: bool,
		completed: &mut u16,
	) -> Result<Option<x25519::PublicKey>> {
		debug_assert!(
			*completed == (self.key_state.keychain.len() - 1) as u16,
			"processing received packet out-of-order ({} != ({}-1))",
			*completed,
			self.key_state.keychain.len()
		);
		let mut their_dh_key = None;
		// The first packet of the window always contains the next DH public
		// key. The first packet of the message always contains the message
		// size.
		if first_packet {
			their_dh_key = Some(x25519::PublicKey::from(*array_ref![packet, 0, 32]));
			if first_window {
				let message_size = u32::from_le_bytes(*array_ref![packet, 32, 4]);
				*buffer = Vec::with_capacity(message_size as _);
				let end = buffer.len() + packet.len() - 36;
				if end <= buffer.capacity() {
					buffer.extend(&packet[36..]);
				} else {
					let room_left = buffer.capacity() - buffer.len();
					buffer.extend(&packet[36..][..room_left]);
				}
			} else {
				let end = buffer.len() + packet.len() - 32;
				if end <= buffer.capacity() {
					buffer.extend(&packet[32..]);
				} else {
					let room_left = buffer.capacity() - buffer.len();
					buffer.extend(&packet[32..][..room_left]);
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
		self.next_sequence = self.next_sequence.wrapping_add(1);
		self.key_state.advance_key(&packet);
		Ok(their_dh_key)
	}

	async fn receive_window(
		&mut self, buffer: &mut Vec<u8>, window_size: u16, first_window: bool,
		new_dh_key: &x25519::PublicKey,
	) -> Result<(x25519::PublicKey, bool, bool)> {
		// The buffer should be either not yet allocated, or allocated to accomodate for
		// the amount of bytes that this window will provide.
		debug_assert!(
			buffer.capacity() == 0 || buffer.len() != buffer.capacity(),
			"nothing left to receive: {}",
			buffer.capacity()
		);
		let mut max_packets_needed: usize = 0;
		let mut last_missing_packet_index: u16 = 0;
		let mut ooo_cache = HashMap::<u16, Vec<u8>>::new(); // Out-of-order cache
		let mut packets_collected = 0;
		let mut error_free = true;
		let mut sent_missing_packet = false;
		let window_start_sequence = self.next_sequence;
		let mut their_dh_key = None;
		let packet_len = self.max_data_packet_length();
		if buffer.capacity() > 0 {
			let bytes_needed = buffer.capacity() - buffer.len() + 32;
			max_packets_needed = cmp::min(
				window_size as usize,
				// Keep in mind that we've already processed one packet.
				bytes_needed / packet_len + (bytes_needed % packet_len > 0) as usize,
			);
			last_missing_packet_index = (max_packets_needed - 1) as u16;
		}

		loop {
			let mut timeout = TIMEOUT;
			loop {
				let (_keystate_sequence, mut sequence, mut packet) = match self.receive_data_packet(timeout).await {
					Ok(r) => {
						sent_missing_packet = false;
						r
					}
					Err(e) => {
						match e {
							Error::Timeout => {
								// If `timeout` is less than `TIMEOUT`, we are just waiting
								// one some possible out-of-order messages to still
								// arive.
								if timeout != TIMEOUT && !sent_missing_packet {
									break;
								} else {
									return Err(e);
								}
							}
							_ => return Err(e),
						}
					}
				};
				// Halve timeout after first packet
				if timeout == TIMEOUT {
					timeout /= 2;
				}

				// The actual sequence may not start from 0, but for this window
				// it is usefull to know what sequence comes after what.
				let mut window_sequence = sequence.wrapping_sub(window_start_sequence);
				if window_sequence > window_size {
					return Err(Error::InvalidSequenceNumber(sequence).into());
				}

				// Fill the buffer, possibly with as much cached data as is
				// available as well.
				if packets_collected == window_sequence {
					if self.decrypt_packet(&self.key_state, sequence, window_sequence, &mut packet) {
						match self.process_packet(
							buffer,
							&packet[2..],
							first_window,
							window_sequence == 0,
							&mut packets_collected,
						)? {
							None => {}
							Some(key) => their_dh_key = Some(key),
						}

						// After having processed the first packet, the buffer has been allocated as
						// much bytes as needed. In other words, buffer.capacity() is the message
						// size.
						if first_window && window_sequence == 0 {
							let bytes_needed = buffer.capacity() - buffer.len() + 32;
							max_packets_needed = cmp::min(
								window_size as usize,
								// Keep in mind that we've already processed one packet.
								1 + bytes_needed / packet_len
									+ (bytes_needed % packet_len > 0) as usize,
							);
							last_missing_packet_index = (max_packets_needed - 1) as u16;
						}
						debug_assert!(
							max_packets_needed > 0,
							"max_packets_needed should be set by now {} {}",
							first_window,
							window_sequence
						);

						if let Some(max_found_sequence) = ooo_cache
							.keys()
							.reduce(|a, b| if a > b { a } else { b })
							.map(|s| *s)
						{
							while packets_collected <= max_found_sequence {
								if let Some(mut more_data) = ooo_cache.remove(&packets_collected) {
									sequence = sequence.wrapping_add(1);
									window_sequence = window_sequence.wrapping_add(1);
									if self.decrypt_packet(
										&self.key_state,
										sequence,
										window_sequence,
										&mut more_data,
									) {
										match self.process_packet(
											buffer,
											&more_data[2..],
											first_window,
											window_sequence == 0,
											&mut packets_collected,
										)? {
											None => {}
											Some(key) => their_dh_key = Some(key),
										}
									} else {
										debug!(
											"Malformed ooo packet received. (seq={}/{})",
											sequence, window_sequence
										);
										break;
									}
								} else {
									break;
								}
							}
						}

						if buffer.len() == buffer.capacity() {
							self.send_ack_packet(sequence + 1, packets_collected, new_dh_key)
								.await?;
							return Ok((
								their_dh_key.unwrap(),
								error_free,
								packets_collected == window_size,
							));
						}
					} else {
						warn!("Malformed packet received.");
						// If this last packet was malformed, send back the ack
						// packet immediately, otherwise it'll just slow down
						// the communication exchange.
						if window_sequence == last_missing_packet_index {
							break;
						}
					}
				}
				// If the packet sequence number is too high, remember it.
				else if packets_collected < window_sequence {
					ooo_cache.insert(window_sequence, packet);
				}

				// If we have received the last packet, try to wait for a small
				// moment to see if more packets are coming through. Then, we
				// send our ack packet back.
				if !sent_missing_packet && window_sequence == last_missing_packet_index {
					timeout = TIMEOUT / 8;
				}

				if packets_collected == max_packets_needed as u16 {
					self.send_ack_packet(sequence + 1, packets_collected, new_dh_key)
						.await?;
					return Ok((
						their_dh_key.unwrap(),
						error_free,
						packets_collected == window_size,
					));
				}
			}

			error_free = false;
			// Adjust what the last packet is that we need to wait for
			let missing_mask =
				compose_missing_mask(max_packets_needed, packets_collected, ooo_cache.keys());
			self.send_missing_mask_packet(
				window_start_sequence.wrapping_add(packets_collected),
				packets_collected,
				missing_mask,
			)
			.await?;
			sent_missing_packet = true;

			// Reduce the last_packet_index to the highest index still needed
			while ooo_cache.contains_key(&last_missing_packet_index) {
				debug_assert!(
					last_missing_packet_index >= packets_collected,
					"last_packet_index should not still be 0"
				);
				last_missing_packet_index -= 1;
			}
		}
	}

	async fn receive_packet(
		&mut self, timeout: Duration, queue: &mut QueueReceiver,
	) -> Result<(u16, u16, Vec<u8>)> {
		loop {
			tokio::select! {
				result = queue.recv() => {
					if result.is_none() {
						return Err(Error::ConnectionClosed.into())
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
						return Err(Error::ConnectionClosed.into())
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
		let mut result = self.keep_alive_timeout.load(Ordering::Relaxed);

		if !result {
			let (keystate_sequence, sequence, mut buffer) = item;
			let key_state_opt = if keystate_sequence == self.current_keystate_sequence {
				Some(&self.key_state)
			} else if keystate_sequence == (self.current_keystate_sequence - 1) {
				Some(&self.previous_keystate)
			} else {
				warn!("Received malformed close packet: keystate sequence is too old or too new");
				None
			};

			if let Some(key_state) = key_state_opt {
				if !self.decrypt_packet(key_state, sequence, sequence, &mut buffer) {
					warn!("Received malformed close packet: checksum didn't match");
					result = false;
				} else if buffer.len() < 34 {
					warn!("Received malformed close packet: packet too small");
					result = false;
				} else if &buffer[2..34] != self.their_node_id().as_bytes() {
					warn!("Received malformed close packet: node ID didn't match.");
					result = false;
				} else {
					result = true;
				}
			} else {
				result = false;
			}
		}

		if result {
			self.is_closing.store(true, Ordering::Relaxed);
			// Close the other queues so that an end of the connection is signified on the
			// task that may be waiting for those
			self.queues.ack.close();
			self.queues.data.close();
		}
		result
	}

	async fn receive_data_packet(&mut self, timeout: Duration) -> Result<(u16, u16, Vec<u8>)> {
		loop {
			tokio::select! {
				result = self.queues.data.recv() => {
					if result.is_none() {
						return Err(Error::ConnectionClosed.into())
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

	async fn send_data(&mut self, buffer: &[u8]) -> Result<()> {
		let mut send = 0usize;
		let mut window_size = self.send_window.size;

		loop {
			self.key_state.our_dh_key = x25519::StaticSecret::random_from_rng(OsRng);
			let (s, clean, their_dh_key, window_full) = self
				.send_window(
					&buffer[send..],
					window_size,
					&x25519::PublicKey::from(&self.key_state.our_dh_key),
				)
				.await?;
			send += s;
			debug_assert!(
				send <= buffer.len(),
				"More data send out than exists! {} <= {}",
				send,
				buffer.len()
			);

			// Adjust window size
			if clean && window_full {
				self.send_window.increase()
			} else {
				self.send_window.decrease()
			}
			window_size = self.send_window.size;

			// Apply new ephemeral DH secret.
			self.key_state.their_dh_key = their_dh_key;
			self.previous_keystate = self.key_state.clone();
			self.key_state.reset_key(window_size);
			let _ = self.current_keystate_sequence.wrapping_add(1);

			if send == buffer.len() {
				break;
			}
		}
		Ok(())
	}

	async fn send_ack_packet(
		&mut self, sequence: u16, key_sequence: u16, dh_key: &x25519::PublicKey,
	) -> Result<()> {
		let mut buffer = vec![0u8; 33];
		buffer[0] = 0; // Success
		buffer[1..33].copy_from_slice(dh_key.as_bytes());
		self.send_crypted_packet_filled(MESSAGE_TYPE_ACK, sequence, key_sequence, &buffer)
			.await
	}

	async fn send_ping_packet(&self) -> Result<()> {
		let mut buffer = vec![0u8; 3];
		buffer[0] = MESSAGE_TYPE_PING;
		buffer[1..3].copy_from_slice(&self.their_session_id.to_le_bytes());
		self.sender.send(&[MESSAGE_TYPE_PING], TIMEOUT).await?;
		Ok(())
	}

	/// Tries to send as much as of the buffer as made possible by the window
	/// size, and waits untill all of it has been received
	async fn send_window(
		&mut self, buffer: &[u8], window_size: u16, public_key: &x25519::PublicKey,
	) -> Result<(usize, bool, x25519::PublicKey, bool)> {
		debug_assert!(buffer.len() > 0, "buffer is empty");
		let packet_length = self.max_data_packet_length();
		let first_packet_length = packet_length - 32;
		let actual_buffer_size = buffer.len() + 32;
		let packet_count = cmp::min(
			actual_buffer_size / packet_length
				+ ((actual_buffer_size % packet_length) > 0) as usize,
			window_size as usize,
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
			let end = send
				+ if i == 0 {
					first_packet_length
				} else {
					packet_length
				};
			if i == 0 {
				if buffer.len() < first_packet_length {
					real_buffer[32..][..buffer.len()].copy_from_slice(buffer);
				} else {
					real_buffer[32..][..first_packet_length]
						.copy_from_slice(&buffer[..first_packet_length]);
				}
			} else {
				let length = if buffer[send..].len() >= packet_length {
					packet_length
				} else {
					buffer[send..].len()
				};
				real_buffer[(i as usize * packet_length)..][..length]
					.copy_from_slice(&buffer[send..][..length]);
			}
			last_packet = &real_buffer[(i as usize * packet_length)..][..packet_length];

			self.send_data_packet(self.next_sequence, window_sequence, &last_packet, true)
				.await?;
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
			let (completed, received_mask) = match self
				.receive_ack_patiently(
					window_start_sequence,
					last_needed_packet_sequence,
					last_needed_packet_index,
					&last_needed_packet,
				)
				.await?
			{
				Err(mask) => {
					error_free = false;
					mask
				}
				Ok(public_key) => {
					return Ok((
						send,
						error_free,
						public_key,
						(last_needed_packet_index + 1) == window_size,
					));
				}
			};
			let mut errors = 0;
			for i in 0..(received_mask.len()) {
				let byte = received_mask[i];
				let j_end: usize = if (i + 1) < received_mask.len() {
					8
				} else {
					(packet_count - completed as usize) % 8
				};
				for j in 0..j_end {
					if (byte & (1 << j)) != 0 {
						errors += 1;
						let packet_index = completed as usize + i * 8 + j;
						let buffer_start = packet_index * packet_length;

						last_needed_packet = &real_buffer[buffer_start..][..packet_length];
						last_needed_packet_sequence =
							window_start_sequence.wrapping_add(packet_index as _);
						last_needed_packet_index = packet_index as _;
						self.send_data_packet(
							last_needed_packet_sequence,
							last_needed_packet_index,
							last_needed_packet,
							false,
						)
						.await?;
					}
				}
			}
			if errors == 0 {
				return Err(Error::EmptyAckMask.into());
			}
		}
	}

	async fn send_crypted_packet(
		&self, message_type: u8, sequence: u16, key_sequence: u16, packet: &[u8],
	) -> Result<()> {
		let max_len = self.max_data_packet_length();
		debug_assert!(
			packet.len() <= max_len,
			"packet size too big: {} > {}",
			packet.len(),
			max_len + 1
		);
		//let outer_size = 5 + 2 + 2 + packet.len();
		let mut buffer = vec![0u8; 9 + max_len];
		buffer[0] = message_type;
		buffer[1..3].copy_from_slice(&self.their_session_id.to_le_bytes());
		buffer[3..5].copy_from_slice(&self.current_keystate_sequence.to_le_bytes());
		buffer[5..7].copy_from_slice(&sequence.to_le_bytes());
		let checksum = calculate_checksum(&packet);
		buffer[7..9].copy_from_slice(&checksum.to_le_bytes());
		buffer[9..][..(packet.len())].copy_from_slice(&packet);

		// Encrypt the message
		let key = &self.key_state.keychain[key_sequence as usize];
		encrypt(self.their_session_id, sequence, &mut buffer[7..], key);

		self.sender.send(&buffer, TIMEOUT).await?;
		Ok(())
	}

	async fn send_crypted_packet_filled(
		&mut self, message_type: u8, sequence: u16, key_sequence: u16, packet: &[u8],
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

		self.send_crypted_packet(message_type, sequence, key_sequence, slice)
			.await
	}

	async fn send_data_packet(
		&mut self, sequence: u16, key_sequence: u16, packet: &[u8], advance_key: bool,
	) -> Result<()> {
		let max_len = self.max_data_packet_length();
		debug_assert!(
			packet.len() <= max_len,
			"Cannot send a SSTP packet of more than {} bytes! {}",
			max_len,
			packet.len()
		);

		if advance_key {
			self.key_state.advance_key(&packet);
		}

		self.send_crypted_packet(MESSAGE_TYPE_DATA, sequence, key_sequence, &packet)
			.await
	}

	async fn send_missing_mask_packet(
		&mut self, sequence: u16, completed: u16, mask: Vec<u8>,
	) -> Result<()> {
		let max_len = self.max_data_packet_length();
		let data_packet_length = max_len;
		let mut buffer = if (3 + mask.len()) <= data_packet_length {
			vec![0u8; 3 + mask.len()]
		} else {
			vec![0u8; data_packet_length]
		};
		buffer[0] = 1;
		buffer[1..3].copy_from_slice(&(mask.len() as u16).to_le_bytes());
		if mask.len() <= buffer[3..].len() {
			buffer[3..].copy_from_slice(&mask);
		} else {
			buffer[3..].copy_from_slice(&mask[..(data_packet_length - 3)]);
		}

		self.send_crypted_packet_filled(MESSAGE_TYPE_ACK, sequence, completed, &buffer)
			.await
	}

	pub fn their_session_id(&self) -> u16 { self.their_session_id }

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
			panic!("connection {} not closed before drop", self.our_session_id);
		}
	}
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
			self.keychain = Vec::with_capacity(window_size as usize);
		} else {
			self.keychain.clear();
		}
		self.keychain.push(initial_key);
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
	pub fn new(node_id: IdType, hello_watch: HelloWatchSender, queues: QueueSenders) -> Self {
		Self {
			their_node_id: node_id,
			their_session_id: None,
			hello_watch: Some(hello_watch),
			queues,
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
		}
	}

	pub fn new_with_their_session(
		their_session_id: u16, node_id: IdType, queues: QueueSenders,
	) -> Self {
		let (dummy_tx, _) = watch::channel(Err(Error::ConnectionClosed));
		Self {
			their_node_id: node_id,
			their_session_id: Some(their_session_id),
			hello_watch: Some(dummy_tx),
			queues,
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
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
		let next_id = self.next_id;
		self.next_id += 1;
		Some(next_id)
	}
}

impl SocketCollection {
	/// Binds all internal sockets to the given addresses and ports.
	pub async fn bind(contact_info: &ContactInfo) -> io::Result<Self> {
		let mut this = Self::default();

		if let Some(ci_entry) = contact_info.ipv4.as_ref() {
			let mut servers = SstpSocketServers::default();
			if let Some(trans_entry) = &ci_entry.availability.udp {
				servers.udp = Some(Arc::new(SstpSocketServer {
					inner: UdpServer::bind(SocketAddrV4::new(
						ci_entry.addr.clone(),
						trans_entry.port,
					))
					.await?,
					openness: trans_entry.openness.clone(),
				}));
			}
			if let Some(trans_entry) = &ci_entry.availability.tcp {
				servers.tcp = Some(Arc::new(SstpSocketServer {
					inner: TcpServer::bind(SocketAddrV4::new(
						ci_entry.addr.clone(),
						trans_entry.port,
					))
					.await?,
					openness: trans_entry.openness.clone(),
				}));
			}
			this.ipv4 = Some(servers);
		}

		if let Some(ci_entry) = contact_info.ipv6.as_ref() {
			let mut servers = SstpSocketServers::default();
			if let Some(trans_entry) = &ci_entry.availability.udp {
				servers.udp = Some(Arc::new(SstpSocketServer {
					inner: UdpServer::bind(SocketAddrV6::new(
						ci_entry.addr.clone(),
						trans_entry.port,
						0,
						0,
					))
					.await?,
					openness: trans_entry.openness.clone(),
				}));
			}
			if let Some(trans_entry) = &ci_entry.availability.tcp {
				servers.tcp = Some(Arc::new(SstpSocketServer {
					inner: TcpServer::bind(SocketAddrV6::new(
						ci_entry.addr.clone(),
						trans_entry.port,
						0,
						0,
					))
					.await?,
					openness: trans_entry.openness.clone(),
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
	pub fn bidirectional_contact_option(&self, target: &ContactInfo) -> Option<ContactOption> {
		self.sockets.pick_contact_option_at_openness(target, Openness::Bidirectional)
	}

	pub async fn bind(
		stop_flag: Arc<AtomicBool>, node_id: IdType, contact_info: ContactInfo,
		private_key: PrivateKey,
	) -> Result<Arc<Self>> {
		Ok(Arc::new(Self {
			stop_flag,
			sockets: SocketCollection::bind(&contact_info).await?,
			our_contact_info: Mutex::new(contact_info),
			sessions: Mutex::new(Sessions::new()),
			node_id,
			private_key,
			on_connect: OnceCell::new(),
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
		let (sender, receiver) = match self.sockets.connect(target).await? {
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
			.new_outgoing_session(self.node_id.clone())
			.await
			.ok_or(Error::OutOfSessions)?;

		// Wait for the hello response to arrive
		let mut timeouts = 0;
		while timeouts < 2 {
			self.send_hello(
				&*sender,
				&secret_key,
				our_session_id,
				&self.our_contact_info().await,
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
						keep_alive_flag: AtomicBool::new(false),
						keep_alive_timeout: AtomicBool::new(false),
						is_closing: AtomicBool::new(false),
						sender,
						receiver_handle: handle,
						peer_address: target.target.clone(),
						their_session_id,
						our_session_id,
						their_node_info: NodeContactInfo {
							node_id: their_node_id,
							contact_info: their_contact_info,
						},
						node_id: self.node_id.clone(),
						private_key: self.private_key.clone(),
						next_sequence: 0,
						queues,
						//session,
						key_state: KeyState::new(secret_key.clone(), their_public_key.clone(), 1),
						previous_keystate: KeyState::new(secret_key, their_public_key, 0),
						current_keystate_sequence: 0,
						receive_window: WindowInfo::default(),
						send_window: WindowInfo::default(),
						last_activity,
						should_be_closed: AtomicBool::new(true),
					}))
				},
				_ = sleep(TIMEOUT/2) => {
					timeouts += 1;
				}
			}
		}

		Err(Error::Timeout)
	}

	async fn new_incomming_session(
		&self, their_node_id: IdType, their_session_id: u16, queues: QueueSenders,
	) -> Result<Option<(u16, Arc<Mutex<SessionData>>)>> {
		let mut sessions = self.sessions.lock().await;
		// Check if session doesn't already exists
		match sessions
			.find_their_session(&their_node_id, their_session_id)
			.await
		{
			None => {}
			// If it exists, return None
			Some(_) => return Ok(None),
		}
		let session_id = match sessions.next_id() {
			None => return Err(Error::OutOfSessions),
			Some(id) => id,
		};
		let session_data = Arc::new(Mutex::new(SessionData::new_with_their_session(
			their_session_id,
			their_node_id,
			queues,
		)));
		sessions.map.insert(session_id, session_data.clone());
		return Ok(Some((session_id, session_data)));
	}

	async fn new_outgoing_session(
		&self, client_node_id: IdType,
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
		let (hello_tx, hello_rx) = watch::channel(Err(Error::ConnectionClosed));
		let (tx_queues, rx_queues) = Queues::channel(session_id);
		let session_data = Arc::new(Mutex::new(SessionData::new(
			client_node_id,
			hello_tx,
			tx_queues,
		)));
		sessions.map.insert(session_id, session_data.clone());
		return Some((session_id, session_data, hello_rx, rx_queues));
	}

	pub async fn our_contact_info(&self) -> ContactInfo {
		self.our_contact_info.lock().await.clone()
	}

	async fn send_hello(
		&self, socket: &dyn LinkSocketSender, private_key: &x25519::StaticSecret,
		my_session_id: u16, my_contact_info: &ContactInfo,
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

		socket.send(&buffer, TIMEOUT).await?;
		Ok(())
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
		&self, target: &ContactInfo, openness: Openness,
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
										.connect(addr.clone(), TIMEOUT)
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
										.connect(addr.clone(), TIMEOUT)
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
		&self, contact: &ContactOption,
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
									server.inner.connect(a.clone(), TIMEOUT).await?.split();
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
									server.inner.connect(a.clone(), TIMEOUT).await?.split();
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
			if SystemTime::now()
				.duration_since(*session_mutex.lock().await.last_activity.lock().unwrap())
				.unwrap() >= Duration::from_secs(2)
			{
				done_ids.push(*session_id)
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
		let sequence = u16::from_le_bytes(*array_ref![packet, 4, 2]);
		let data = packet[6..].to_vec();

		let mut sessions = self.sessions.lock().await;
		let mut should_close = false;
		if let Some(s) = sessions.map.get(&our_session_id) {
			let mut session = s.lock().await;
			*session.last_activity.lock().unwrap() = SystemTime::now();
			let result = handle_queue(&mut session, keystate_sequence, sequence, data);
			// Should only give an error when the mpsc queues have been closed, meaning the
			// session is not being used anymore.
			if result.is_err() {
				warn!(
					"Error while handling queue: {}",
					result.as_ref().unwrap_err()
				);
				should_close = true;
			}
		} else {
			return Err(Error::InvalidSessionIdOurs(our_session_id).into());
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
		&self, sender: Arc<dyn LinkSocketSender>, addr: &SocketAddr, packet: &[u8],
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
		let (our_session_id, _session) = match self
			.new_incomming_session(node_id.clone(), their_session_id, tx_queues)
			.await?
		{
			None => return Ok(()),
			Some(r) => r,
		};

		let addr_len = match addr {
			SocketAddr::V4(_) => 4,
			SocketAddr::V6(_) => 16,
		};
		let contact_info = self.our_contact_info().await;
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

		let connection = Box::new(Connection {
			keep_alive_flag: AtomicBool::new(false),
			keep_alive_timeout: AtomicBool::new(false),
			is_closing: AtomicBool::new(false),
			sender: sender.clone(),
			receiver_handle: None,
			peer_address: addr.clone(),
			their_session_id,
			our_session_id,
			their_node_info: NodeContactInfo {
				node_id,
				contact_info: their_contact_info,
			},
			node_id: self.node_id.clone(),
			private_key: self.private_key.clone(),
			//session,
			queues: rx_queues,
			key_state: KeyState::new(own_secret_key.clone(), their_public_key.clone(), 1),
			previous_keystate: KeyState::new(own_secret_key, their_public_key, 0),
			current_keystate_sequence: 0,
			next_sequence: 0,
			receive_window: WindowInfo::default(),
			send_window: WindowInfo::default(),
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
			should_be_closed: AtomicBool::new(false),
		});
		match self.on_connect.get() {
			None => {}
			Some(closure) => {
				closure(connection);
				sender.send(&response, TIMEOUT).await?;
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
				return Err(Error::InvalidSessionIdOurs(our_session_id).into());
			}
			Some(s) => s.clone(),
		};
		let mut session = session_lock.lock().await;

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
					.await
					.update_v4(&ip, port, is_tcp);
			}
			SocketAddr::V6(_) => {
				let ip: Ipv6Addr = bincode::deserialize(&packet[i..(i + 16)])?;
				let port = u16::from_le_bytes(*array_ref![packet, i + 16, 2]);
				self.our_contact_info
					.lock()
					.await
					.update_v6(&ip, port, is_tcp);
			}
		}

		// Notify the connection's thread of the successful response
		let their_node_id = identity_pubkey.generate_address();
		let their_dh_key = x25519::PublicKey::from(*array_ref![packet, 128, 32]);

		// Send the hello response data back to the connecting task if not send already
		match session.hello_watch.take() {
			None => {}
			Some(sender) => {
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
						"Session {} already closed before it was initiated.",
						our_session_id
					);
				}
			}
		}

		Ok(())
	}

	async fn process_packet(
		&self, link_socket: Arc<dyn LinkSocketSender>, sender: &SocketAddr, packet: &[u8],
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
			MESSAGE_TYPE_PING => self.process_ping(link_socket, &packet[1..]).await,
			MESSAGE_TYPE_PONG => self.process_pong(&packet[1..]).await,
			other => Err(Error::InvalidMessageType(other)),
		};

		match result {
			// Ignore invalid session id exceptions, as they happen regularely due to the fact that
			// the sender might resend some of their packets if they are still waiting on a
			// response.
			Err(e) => match e {
				Error::InvalidSessionIdOurs(_) => Ok(()),
				other => Err(other),
			},
			Ok(()) => Ok(()),
		}
	}

	async fn process_ping(&self, socket: Arc<dyn LinkSocketSender>, packet: &[u8]) -> Result<()> {
		if packet.len() != 2 {
			return Err(Error::MalformedPacket);
		}

		let our_session_id = u16::from_le_bytes(*array_ref![packet, 0, 2]);
		let sessions = self.sessions.lock().await;
		let session = sessions.map.get(&our_session_id);
		match session {
			None => Err(Error::InvalidSessionIdOurs(our_session_id)),
			Some(s) => {
				let their_session_id = s.lock().await.their_session_id.expect("missing session id");

				// Send pong
				let mut buffer = vec![0u8; 3];
				buffer[0] = MESSAGE_TYPE_PONG;
				buffer[1..3].copy_from_slice(&u16::to_le_bytes(their_session_id));
				socket.send(&buffer, TIMEOUT).await?;
				Ok(())
			}
		}
	}

	async fn process_pong(&self, packet: &[u8]) -> Result<()> {
		if packet.len() != 2 {
			return Err(Error::MalformedPacket);
		}

		let session_id = u16::from_le_bytes(*array_ref![packet, 0, 2]);

		let sessions = self.sessions.lock().await;
		if let Some(session) = sessions.map.get(&session_id) {
			let s = session.clone();
			drop(sessions);

			let tx = &s.lock().await.queues.ping;
			match tx.try_send(SystemTime::now()) {
				Ok(()) => Ok(()),
				Err(e) => match e {
					TrySendError::Full(_) => {
						warn!("Pong queue is full, probably a DoS attack!");
						Ok(())
					}
					TrySendError::Closed(_) => Err(Error::ConnectionClosed),
				},
			}
		} else {
			Err(Error::InvalidSessionIdOurs(session_id))
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
			} else {
				self.size = 0xFFFF;
			}
		} else {
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
			size: 1,
		}
	}
}

impl Queues {
	fn channel(session_id: u16) -> (QueueSenders, QueueReceivers) {
		let (data_tx, data_rx) = mpsc::unbounded_channel();
		let (ack_tx, ack_rx) = mpsc::unbounded_channel();
		let (close_tx, close_rx) = mpsc::unbounded_channel();
		let (ping_tx, ping_rx) = mpsc::channel(1000);

		(
			QueueSenders {
				data: data_tx,
				ack: ack_tx,
				ping: ping_tx,
				close: close_tx,
				session_id,
			},
			QueueReceivers {
				data: data_rx,
				ack: ack_rx,
				ping: Mutex::new(ping_rx),
				close: close_rx,
			},
		)
	}
}

#[cfg(test)]
mod tests {
	use std::net::*;

	use super::*;

	#[test]
	fn test_encryption() {
		let mut key = GenericArray::<u8, U32>::default();
		let mut original = [0u8; 46 * 32];
		OsRng.fill_bytes(key.as_mut());
		OsRng.fill_bytes(&mut original);

		let mut buffer = original.clone();
		encrypt(321, 123, &mut buffer, &key);
		assert!(buffer != original);
		decrypt(321, 123, &mut buffer, &key);
		assert!(buffer == original);
	}

	#[tokio::test]
	/// Sent and receive a bunch of messages.
	async fn test_connection() {
		env_logger::init();
		let ip = Ipv4Addr::new(127, 0, 0, 1);
		let master_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10000));
		let slave_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10001));
		let master_contact_info: ContactInfo = (&master_addr).into();
		let slave_contact_info: ContactInfo = (&slave_addr).into();
		let stop_flag = Arc::new(AtomicBool::new(false));
		let master_private_key = PrivateKey::generate();
		let master_node_id = master_private_key.public().generate_address();
		let master = sstp::Server::bind(
			stop_flag.clone(),
			master_node_id,
			master_contact_info.clone(),
			master_private_key,
		)
		.await
		.expect("unable to bind master");
		let slave_private_key = PrivateKey::generate();
		let slave_node_id = slave_private_key.public().generate_address();
		let slave = Arc::new(
			sstp::Server::bind(
				stop_flag.clone(),
				slave_node_id,
				slave_contact_info.clone(),
				slave_private_key,
			)
			.await
			.expect("unable to bind slave"),
		);

		let mut small_message = vec![0u8; 1000];
		OsRng.fill_bytes(&mut small_message);
		let mut small_message2 = vec![0u8; 1000];
		OsRng.fill_bytes(&mut small_message2);
		let mut big_message = vec![0u8; 1000000]; // One MB of data
		OsRng.fill_bytes(&mut big_message);
		let mut small_message3 = vec![0u8; 1000];
		OsRng.fill_bytes(&mut small_message3);

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

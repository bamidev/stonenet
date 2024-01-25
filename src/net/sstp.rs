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
//! ratchet in the exact same way. This is not really a bad thing, as the DH
//! exchange happens so frequently. Actually, a new shared secret is established
//! after every window.


mod server;
mod transporter;


use std::{
	cmp::{self, min},
	collections::HashMap,
	fmt, io,
	result::Result as StdResult,
	sync::{atomic::Ordering, Arc},
	time::*,
};

use async_trait::async_trait;
use chacha20::{
	cipher::{KeyIvInit, StreamCipher},
	ChaCha20,
};
use futures::StreamExt;
use generic_array::{typenum::*, GenericArray};
use hmac::*;
use log::*;
use once_cell::sync::OnceCell;
use rand::{rngs::OsRng, RngCore};
pub use server::{MessageProcessorResult, Server, SocketBindError};
use sha2::{Digest, Sha256};
use tokio::{self, spawn, time::sleep};
use transporter::*;
use x25519_dalek as x25519;

use super::{
	binserde,
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
	trace::{self, Traceable, Traced},
};


/// If nothing was received on a TCP connection for 2 minutes, assume the
/// connection is broken.
const TCP_CONNECTION_TIMEOUT: u64 = 120;
const MAX_PACKET_FILL_BLOCK_SIZE: usize = 10000;

pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// The minimum timeout time that will be waited on a crucial packet before
/// retrying.
pub const MAXIMUM_RETRY_TIMEOUT: Duration = Duration::from_millis(500);

pub struct Connection {
	transporter: TransporterHandle,
	server: Arc<Server>,

	keep_alive_timeout: Duration,
	peer_address: SocketAddr,
	peer_node_info: NodeContactInfo,
	dest_session_id: u16,
	encrypt_session_id: u16,
	local_session_id: u16, // our session ID
}

struct CryptedPacket {
	ks_seq: u16,
	seq: u16,
	data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum Error {
	IoError(Arc<io::Error>),

	BothSending,
	BothReceiving,
	DummyError,
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
	InvalidSessionId(u16),
	/// A packet had an invalid signature on it.
	InvalidSignature,
	/// The data inside the packet was invalid.
	MalformedPacket,
	// The message itself was not understood
	MalformedMessage(Option<Arc<binserde::Error>>),
	/// Unable to connect because there were no matching options
	NoConnectionOptions,
	/// There is not more room for a new session.
	OutOfSessions,
	/// There were less bytes in the packet than was expected.
	PacketTooSmall,
	SessionForRelaying(u16),
	SessionNotForRelaying(u16),
	/// No packets have been received in the given amount of time
	Timeout(Duration),
}

#[async_trait]
pub trait MessageWorkToDo: Send + Sync {
	/// Should return whether or not it will take ownership of the
	/// `connection_mutex` after the function returns.
	async fn run(&mut self, connection: Box<Connection>) -> Option<Box<Connection>>;
}

pub type OnPacket =
	Arc<dyn Fn(Arc<dyn LinkSocketSender>, &SocketAddr, &[u8]) + Send + Sync + 'static>;

pub type Result<T> = trace::Result<T, Error>;


/// Decrypts what has been encrypted by `encrypt_cbc`.
fn decrypt(session_id: u16, ks_seq: u16, seq: u16, buffer: &mut [u8], key: &GenericArray<u8, U32>) {
	encrypt(session_id, ks_seq, seq, buffer, key);
}

/// Encrypts the given buffer, assuming that the first block is the IV.
/// Will not decrypt the IV. Also must be the size of 46 blocks.
/// The sessions_id and sequence are important to be different for each packet,
/// and act as a sort of salt.
fn encrypt(session_id: u16, ks_seq: u16, seq: u16, buffer: &mut [u8], key: &GenericArray<u8, U32>) {
	// Construct nonce out of session_id & sequence numbers.
	let mut nonce = GenericArray::<u8, U12>::default();
	nonce[..2].copy_from_slice(&session_id.to_le_bytes());
	nonce[2..4].copy_from_slice(&ks_seq.to_le_bytes());
	nonce[4..6].copy_from_slice(&seq.to_le_bytes());
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
			Self::DummyError => write!(f, "dummy error"),
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
			Self::InvalidSessionId(id) =>
				write!(f, "invalid session ID for incomming packet: {}", id),
			Self::InvalidSignature => write!(f, "invalid signature"),
			Self::MalformedPacket => write!(f, "malformed packet"),
			Self::MalformedMessage(oe) => match oe {
				Some(e) => write!(f, "malformed message: {}", e),
				None => write!(f, "malformed message"),
			},
			Self::NoConnectionOptions => write!(f, "no connection options"),
			Self::OutOfSessions => write!(f, "there is no more room for any new session"),
			Self::PacketTooSmall => write!(f, "packet was too small"),
			Self::Timeout(timeout) => write!(f, "timeout of {:?} exceeded", timeout),
			Self::BothReceiving => write!(f, "both sides are in receiving mode"),
			Self::BothSending => write!(f, "both sides are in sending mode"),
			Self::SessionForRelaying(session_id) =>
				write!(f, "session ID {} is not for relaying", session_id),
			Self::SessionNotForRelaying(session_id) =>
				write!(f, "session ID {} is not for relaying", session_id),
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
}

impl std::error::Error for Error {}

impl Into<io::Error> for Error {
	fn into(self) -> io::Error { io::Error::new(io::ErrorKind::Other, Box::new(self)) }
}

impl Connection {
	pub fn alive_flag(&self) -> Arc<AtomicBool> { self.transporter.alive_flag() }

	pub async fn close(&mut self) -> Result<()> { self.transporter.close().await.unwrap_or(Ok(())) }

	pub fn contact_option(&self) -> ContactOption {
		ContactOption {
			target: self.peer_address.clone(),
			use_tcp: self.transporter.is_connection_based(),
		}
	}

	//pub fn network_level(&self) -> NetworkLevel {
	// NetworkLevel::from_ip(&self.peer_address.ip()) }

	pub fn our_session_id(&self) -> u16 { self.local_session_id }

	pub fn peer_address(&self) -> &SocketAddr { &self.peer_address }

	pub async fn receive(&mut self) -> Result<Vec<u8>> {
		if let Some((message_size_result, mut stream)) = self.transporter.receive().await {
			let message_size = if let Some(m) = message_size_result {
				m
			} else {
				return trace::err(Error::ConnectionClosed);
			};

			let mut buffer = Vec::with_capacity(message_size as usize);
			while let Some(result) = stream.next().await {
				buffer.extend(result?);
			}
			Ok(buffer)
		} else {
			trace::err(Error::ConnectionClosed)
		}
	}

	pub async fn send(&mut self, message: Vec<u8>) -> Result<()> {
		self.transporter
			.send(message)
			.await
			.unwrap_or(trace::err(Error::ConnectionClosed))?;
		Ok(())
	}

	pub fn send_async(&mut self, message: Vec<u8>) -> Result<()> {
		match self.transporter.send_async(message) {
			None => trace::err(Error::ConnectionClosed),
			Some(()) => Ok(()),
		}
	}

	pub async fn wait_for(&mut self, wait_time: Duration) -> Result<Vec<u8>> {
		if let Some((message_size_result, mut stream)) = self.transporter.wait_for(wait_time).await
		{
			let message_size = if let Some(m) = message_size_result {
				m
			} else {
				return trace::err(Error::ConnectionClosed);
			};

			let mut buffer = Vec::with_capacity(message_size as usize);
			while let Some(result) = stream.next().await {
				buffer.extend(result?);
			}
			Ok(buffer)
		} else {
			trace::err(Error::ConnectionClosed)
		}
	}

	/// Updates the cleanup timeout of the connection.
	pub async fn set_keep_alive_timeout(&mut self, timeout: Duration) -> bool {
		self.keep_alive_timeout = timeout;
		let sessions = self.server.sessions.lock().await;
		if let Some(session_mutex) = sessions.map.get(&self.local_session_id) {
			let session_mutex2 = session_mutex.clone();
			drop(sessions);
			let mut session = session_mutex2.lock().await;
			session.keep_alive_timeout = timeout;
			true
		} else {
			false
		}
	}

	pub fn their_node_info(&self) -> &NodeContactInfo { &self.peer_node_info }

	pub fn their_node_id(&self) -> &IdType { &self.peer_node_info.node_id }

	pub fn their_session_id(&self) -> u16 { self.dest_session_id }

	pub fn update_their_node_info(&mut self, node_info: NodeContactInfo) {
		self.peer_node_info = node_info;
	}
}

impl From<PublicKeyError> for Error {
	fn from(_other: PublicKeyError) -> Self { Self::InvalidPublicKey }
}

impl From<PublicKeyError> for Traced<Error> {
	fn from(other: PublicKeyError) -> Self { Into::<Error>::into(other).trace() }
}

impl From<io::Error> for Error {
	fn from(other: io::Error) -> Self { Self::IoError(Arc::new(other)) }
}

impl From<io::Error> for Traced<Error> {
	fn from(other: io::Error) -> Self { Into::<Error>::into(other).trace() }
}

impl From<binserde::Error> for Error {
	fn from(other: binserde::Error) -> Self { Self::MalformedMessage(Some(Arc::new(other))) }
}

impl From<binserde::Error> for Traced<Error> {
	fn from(other: binserde::Error) -> Self { Into::<Error>::into(other).trace() }
}


#[cfg(test)]
mod tests {


	#[ctor::ctor]
	fn initialize() { env_logger::init(); }

	/*#[tokio::test]
	async fn test_connection_with_tcp() { test_connection(false).await; }

	#[tokio::test]
	async fn test_connection_with_udp() { test_connection(true).await; }

	/// Sent and receive a bunch of messages.
	async fn test_connection(use_udp: bool) {
		let mut rng = test::initialize_rng();
		let ip = Ipv4Addr::new(127, 0, 0, 1);
		let master_addr = SocketAddr::V4(SocketAddrV4::new(ip, 10000));
		let mut master_config = Config::default();
		master_config.ipv4_address = Some("127.0.0.1".to_string());
		if use_udp {
			master_config.ipv4_udp_port = Some(10000);
		} else {
			master_config.ipv4_tcp_port = Some(10000);
		}
		let mut slave_config = master_config.clone();
		if use_udp {
			slave_config.ipv4_udp_port = Some(10001);
		} else {
			slave_config.ipv4_tcp_port = Some(10001);
		}
		let stop_flag = Arc::new(AtomicBool::new(false));
		let master_private_key = PrivateKey::generate_with_rng(&mut rng);
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
		let slave_private_key = PrivateKey::generate_with_rng(&mut rng);
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
		let mut big_message = vec![0u8; 1000000]; // One MiB of data
		rng.fill_bytes(&mut big_message);
		let mut small_message3 = vec![0u8; 1000];
		rng.fill_bytes(&mut small_message3);

		let (small1, small2, small3, big) = (small_message.clone(), small_message2.clone(), small_message3.clone(), big_message.clone());
		master.listen(move |request, _, _| {
			let small_message_clone = small1.clone();
			let small_message_clone2 = small2.clone();
			let small_message_clone3 = small3.clone();
			let big_message_clone = big.clone();

			Box::pin(async move {
				let small = small_message_clone;
				let small2 = small_message_clone2;
				let small3 = small_message_clone3;
				let big = big_message_clone;

				if request == small {
					Some((small2, None))
				} else if request == big {
					Some((small3, None))
				} else {
					panic!("unknown message");
				}
			})
		});
		master.spawn();
		let slave2 = slave.clone();
		slave2.spawn();

		let (mut connection, _) = slave
			.clone()
			.connect(&ContactOption::new(master_addr, !use_udp), None, None)
			.await
			.unwrap();
		debug!("Sent small message");
		let message = connection.receive().await.unwrap();
		assert_eq!(&message, &small_message2);
		debug!("Received small message");

		connection.send(big_message).await.unwrap();
		debug!("Sent big message");
		let message = connection.receive().await.unwrap();
		assert_eq!(&message, &small_message3);
		debug!("Received small message");

		connection.close().await.unwrap();
		stop_flag.store(true, Ordering::Relaxed);
	}*/

	//#[tokio::test]
	// Sent and receive a message through a relay
	/*async fn test_connection_piping() {
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
					.send(message3)
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
	}*/
}

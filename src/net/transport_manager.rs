//! Stonenet uses its own transport protocol on top of UDP. This is because for
//! most people their access to the internet is limited to using either UDP or
//! TCP, and only UDP generally allows for P2P communcations behind firewalls.
//! That being said, a proper transport protocol is still needed to transfer 
//! large portions of data.
//! Stonenet also uses peer-to-peer (as opposed to end-to-end)
//! encryption. This is merged into the transport protocol, for effeciency
//! purposes. The initial packets to start the connection with, already include
//! Diffie-Hellman public keys, in order to 

use rand_core::OsRng;
use tokio::sync::{mpsc, Mutex};
use x25519_dalek::{EphemeralSecret, PublicKey};


/// The size of the blocks that are sent per-packet. Set to 32KiB.
const MAX_PACKET_SIZE: usize = 1500;
const MESSAGE_ID_HELLO: u8 = 0;
const MESSAGE_ID_ENCRYPTED: u8 = 1;

struct AckData {
	window_size: u8,
	success_mask: Vec<u8>
}

pub struct TransportManager {
	recv: Mutex<TransportRecvManager>,
	send: Mutex<TransportSendManager>
}

struct TransportRecvManager {
	sessions: HashMap<u16, TransportReceiveSession>,
	next_session_id: u16
}

struct TransportSendManager {
	sessions: HashMap<u16, TransportSendSession>,
	next_session_id: u16
}

struct TransportReceiveSession {
	buffer: Vec<u8>,
	window_size: usize,
	received_mask: [u8; 32],
	success_mask: [u8, 32],
	highest_block_id_seen: Option<u8>
}

struct TransportSendSession {
	mpsc: mpsc::Receiver<Vec<u8>>
}

pub struct TransportSocket {
	base: UdpSocket,
	max_packet_size: usize
}


impl TransportManager {
	pub fn process_message(&mut self, address: SocketAddr, buffer: &[u8]) {
		// Parse the packet
		if buffer.len() < 3 {
			debug!("Transport packet too small for header: {} bytes", buffer.len());
			return;
		}
		let session_id = u16::from_le_bytes([buffer[0], buffer[1]]);
		let block_id = buffer[2];
		let block = &buffer[2..];

		// Copy the block onto the session buffer
		let block_index = block_id * BLOCK_SIZE;
		if let Some(session) = self.sessions.get(session_id) {
			if (block.len() < BLOCK_SIZE && block_id != (self.received.len()-1)) {
				debug!("Transport packet block is too small: {} bytes", block.len());
				session.mark_block_error(block_id);
			}
			else {
				session.mark_block_received(block_id);
				session.buffer[block_index..].clone_from_slice(block);

				if block_id > self.highest_block_id {
					self.highest_block_id = block_id;
					if block_id == (self.window_size-1) {
						self.send_ack(session_id)
					}
				}
				// TODO: Also send ack after a 1 second timeout, in case the last packet got lost.
			}
			
		}
		else {
			warn!("Transport packet with invalid session ID: {}", session_id);
		}
	}

	pub async fn process_ack(&mut self, address: SocketAddr, buffer: &[u8]) {
		let session_id = u16::from_le_bytes([buffer[0], buffer[1]]);

		if let Some(session) = self.send_sessions.get(session_id) {
			let (received, success) = parse_bitmask(*buffer[2..]);

			// Increase window size if successful
			if success {
				if !session.initiating { session.window_size += 1; }
				else { session.window_size <<= 1 }
			}
			// Devide by half if unsuccessful
			else {
				session.window_size >>= 1;
				session.initiating = false;
			}

			
		}
		else {
			warn!("Ack packet with unknown session ID received: {}", session_id);
		}
	}

	pub async fn transmit(&mut self,
		target: SocketAddr,
		socket: &UdpSocket,
		buffer: &[u8]
	) -> io::Result<()> {
		let mut initiating = true;
		let mut window_size = 1usize;
		let mut block_id = 0u32;
		let mut block_index = 0usize;
		let block_total: u16 = buffer.len() / BLOCK_SIZE +
			(buffer.len() % BLOCK_SIZE != 0) as usize;
		let last_block_id = block_total - 1;

		// Start sending session
		let (session_id, rx) = self.start_send_session(buffer.len() as _).await
			.ok_or(io::ErrorKind::OutOfMemory.into())?;

		loop {
			// Send as many packets as our window allows
			for i in 0..window_size {
				let next_block_index = block_index + BLOCK_SIZE;
				if block_id < last_block_id {
					socket.send_to(&buffer[block_index..next_block_index], target).await?;
				}
				else {
					socket.send_to(&buffer[block_index..], target).await?;
					break;
				}
				block_index = next_block_index;
			}

			// Wait for the acknowledgement packet
			if let Some(()) = rx.await {

			}
		}
	}

	/// Starts a new session to allow data packets to be received.
	/// Returns None in the event that all sessions IDs are taken.
	pub fn start_recv_session(&mut self, size: u32) -> Option<u16> {
		let recv = self.recv.lock().await;
		let mut next_session_id = recv.next_session_id;

		// Pick a session ID that has not been taken yet
		let mut i = 0u16;
		while let Some(_) = recv.sessions.get(next_session_id) {
			if i == 0xFFFF {
				return None;
			}
			next_session_id += 1;
			i += 1;
		}
		
		// Create the session
		recv.sessions.insert(next_session_id, TransportRecvSession::new(size));
		let result = Some(next_session_id);
		recv.next_session_id += 1;
		result
	}

	async fn start_send_session(&self,
		size: u32
	) -> Option<(u16, mpsc::Receiver<Vec<u8>>)> {
		let send = self.send.lock().await;
		let mut next_session_id = send.next_session_id;

		// Pick a session ID that has not been taken yet
		let mut i = 0u16;
		while let Some(_) = send.sessions.get(next_session_id) {
			if i == 0xFFFF {
				return None;
			}
			next_session_id += 1;
			i += 1;
		}
		
		// Create the session
		let (tx, rx) = mpsc::channel();
		send.insert(next_session_id, TransportSendSession::new(size, tx));
		let session_id = send.next_session_id;
		send.next_session_id += 1;
		Some(session_id, rx)
	}
}

impl TransportSocket {
	pub async fn bind<A: ToSocketAddrs>(addrs: A, max_packet_size: usize) -> io::Result<Self> {
		Ok(Self {
			base: UdpSocket::bind(addrs).await?,
			max_packet_size
		)
	}

	pub async fn connect(&self) -> TransportSession {
		let private_key = EphemeralSecret::new(OsRng);
		let public_key = 
	}

	pub async fn receive(&self) -> io::Result<Vec<u8>, SocketAddr> {
		
	}

	pub async fn send(&self, target: &SocketAddr, buffer: &[u8]) -> io::Result<usize> {

	}
}

impl TransportReceiveSession {
	fn new(size: u32) -> Self {
		let x = (size % BLOCK_SIZE > 0) as usize;
		Self {
			buffer: vec![0u8; size as usize],
		}
	}
}

impl TransportSendSession {
	fn new(size: u32) -> Self {
		let x = (size % BLOCK_SIZE > 0) as usize;
		Self {
			buffer: vec![0u8; size as usize],
		}
	}
}

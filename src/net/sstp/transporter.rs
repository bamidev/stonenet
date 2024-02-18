use std::backtrace::Backtrace;

use futures::Stream;
use tokio::{
	select,
	sync::{mpsc::*, oneshot},
};
use tokio_stream::wrappers::UnboundedReceiverStream;

use super::{server::PACKET_TYPE_CRYPTED, *};
use crate::trace::{Traceable, Traced};


const CRYPTED_PACKET_TYPE_DATA: u8 = 0;
const CRYPTED_PACKET_TYPE_ACK: u8 = 1;
const CRYPTED_PACKET_TYPE_ACK_WAIT: u8 = 2;
const CRYPTED_PACKET_TYPE_CLOSE: u8 = 3;
const CRYPTED_PACKET_TYPE_CLOSE_ACK: u8 = 4;
const FIRST_WINDOW_HEADER_SIZE: usize = WINDOW_HEADER_SIZE + MESSAGE_HEADER_SIZE;
const INITIAL_WINDOW_SIZE: u16 = 16;
const MESSAGE_HEADER_SIZE: usize = 4;
const WINDOW_HEADER_SIZE: usize = 34;


#[derive(Clone)]
pub struct KeyState {
	pub sequence: u16,
	private_key: x25519::StaticSecret,
	public_key: x25519::PublicKey,
	keychain: Vec<GenericArray<u8, U32>>,
}

struct KeyStateManager {
	use_first: bool,
	keystate1: KeyState,
	keystate2: KeyState,
}

#[derive(Clone, Copy)]
struct KeyStateDuo<'a> {
	current: &'a KeyState,
	previous: &'a KeyState,
}

struct KeyStateDuoMut<'a> {
	current: &'a mut KeyState,
	previous: &'a KeyState,
}

/// The `Transporter` is a task that runs in the background to transport
/// messages for a connection.
pub struct Transporter {
	pub(super) inner: TransporterInner,
	pub alive_flag: Arc<AtomicBool>,
	key_state_manager: KeyStateManager,
	pub(super) keep_alive: bool,
}

pub(super) struct TransporterInner {
	current_backtrace: Option<Backtrace>,
	socket_sender: Arc<dyn LinkSocketSender>,
	packet_receiver: UnboundedReceiver<CryptedPacket>,

	// Non-temporary vars
	encrypt_session_id: u16,
	node_id: IdType,
	local_session_id: u16,
	peer_node_id: IdType,
	timeout: Duration,
	dest_session_id: u16,

	// All temporary vars that change on every message
	message_bytes_received: u32,

	// All temporary vars that change on every window
	receive_window: WindowInfo,
	send_window: WindowInfo,
	close_received: bool,
	previous_window_size: u16,
	first_window: bool,
	max_packets_expected: u16,
	message_size: u32,
	next_private_key: x25519::StaticSecret,
	next_public_key: x25519::PublicKey,
	next_sequence: u16,
	requested_window_size: u16,
	window_bytes_received: u32,
	window_error_free: bool,
	current_ks_unprocessed_packets: HashMap<u16, Vec<u8>>,
	current_ks_unprocessed_first_packet: Option<Vec<u8>>,
	next_ks_unprocessed_packets: Vec<(u16, Vec<u8>)>, // TODO: Make this a linked list
}

#[derive(Clone)]
pub struct TransporterHandle {
	sender: UnboundedSender<Traced<TransporterTask>>,
	pub(super) alive_flag: Arc<AtomicBool>,
	is_connection_based: bool,
	pub(super) socket_sender: Arc<dyn LinkSocketSender>,
}

/// The instruction that is sent to the transporter task to make it do what we
/// want
enum TransporterTask {
	Receive(
		oneshot::Sender<u32>,
		UnboundedSender<Result<Vec<u8>>>,
		Option<Duration>,
	),
	Send(Vec<u8>, oneshot::Sender<Result<()>>),
	SendAsync(Vec<u8>),
	Close(oneshot::Sender<Result<()>>),
	CloseAsync,
	KeepAlive,
}

struct WindowInfo {
	size: u16,
	starting: bool,
}


fn calculate_checksum(buffer: &[u8]) -> u16 {
	let mut result = 0u16;
	for i in 0..buffer.len() {
		result = result.wrapping_add(buffer[i] as u16);
	}
	result
}


impl KeyState {
	pub fn calculate_initial_key(
		private_key: &x25519::StaticSecret, public_key: &x25519::PublicKey,
	) -> GenericArray<u8, U32> {
		let shared_secret = private_key.diffie_hellman(&public_key);
		let mut hasher = Sha256::new();
		hasher.update(shared_secret.as_bytes());
		hasher.finalize()
	}

	pub fn new(
		private_key: x25519::StaticSecret, public_key: x25519::PublicKey, window_size: u16,
	) -> Self {
		let initial_key = Self::calculate_initial_key(&private_key, &public_key);
		let mut keychain = Vec::with_capacity(window_size as usize);
		keychain.push(initial_key);

		Self {
			private_key,
			public_key,
			keychain,
			sequence: 0,
		}
	}

	/// Calculates a new key based on the current DH keys.
	pub fn reset_key(&mut self, window_size: u16) {
		let shared_secret = self.private_key.diffie_hellman(&self.public_key);
		let mut hasher = Sha256::new();
		hasher.update(shared_secret.as_bytes());
		let initial_key = hasher.finalize();
		if self.keychain.capacity() < (window_size + 1) as usize {
			self.keychain = Vec::with_capacity((window_size + 1) as usize);
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
	}
}

impl<'a> From<KeyStateDuoMut<'a>> for KeyStateDuo<'a> {
	fn from(other: KeyStateDuoMut<'a>) -> Self {
		Self {
			current: other.current,
			previous: other.previous,
		}
	}
}

impl<'a> KeyStateDuoMut<'a> {
	fn get_const(&'a self) -> KeyStateDuo<'a> {
		KeyStateDuo {
			current: self.current,
			previous: self.previous,
		}
	}
}

impl KeyStateManager {
	pub fn new(
		our_dh_key: x25519::StaticSecret, their_dh_key: x25519::PublicKey, window_size: u16,
	) -> Self {
		Self {
			use_first: true,
			keystate1: KeyState::new(our_dh_key.clone(), their_dh_key.clone(), window_size),
			keystate2: KeyState::new(our_dh_key, their_dh_key, 0),
		}
	}

	pub fn current_key_state(&self) -> &KeyState {
		if self.use_first {
			&self.keystate1
		} else {
			&self.keystate2
		}
	}

	pub fn get_duo(&self) -> KeyStateDuo {
		if self.use_first {
			KeyStateDuo {
				current: &self.keystate1,
				previous: &self.keystate2,
			}
		} else {
			KeyStateDuo {
				current: &self.keystate2,
				previous: &self.keystate1,
			}
		}
	}

	pub fn get_duo_mut(&mut self) -> KeyStateDuoMut {
		if self.use_first {
			KeyStateDuoMut {
				current: &mut self.keystate1,
				previous: &self.keystate2,
			}
		} else {
			KeyStateDuoMut {
				current: &mut self.keystate2,
				previous: &self.keystate1,
			}
		}
	}

	pub fn setup_next_keystate(
		&mut self, private_key: x25519::StaticSecret, public_key: x25519::PublicKey,
		new_window_size: u16,
	) {
		if self.use_first {
			self.keystate2.sequence = self.keystate1.sequence + 1;
			self.keystate2.public_key = public_key;
			self.keystate2.private_key = private_key;
			self.keystate2.reset_key(new_window_size);
			self.use_first = false;
		} else {
			self.keystate1.sequence = self.keystate2.sequence + 1;
			self.keystate1.public_key = public_key;
			self.keystate1.private_key = private_key;
			self.keystate1.reset_key(new_window_size);
			self.use_first = true;
		}
	}
}

impl Transporter {
	pub(super) fn new_with_receiver(
		encrypt_session_id: u16, our_session_id: u16, their_session_id: u16,
		socket_sender: Arc<dyn LinkSocketSender>, node_id: IdType, peer_node_id: IdType,
		timeout: Duration, private_key: x25519::StaticSecret, public_key: x25519::PublicKey,
		receiver: UnboundedReceiver<CryptedPacket>,
	) -> Self {
		Self {
			inner: TransporterInner::new(
				encrypt_session_id,
				our_session_id,
				their_session_id,
				socket_sender,
				receiver,
				node_id,
				peer_node_id,
				timeout,
			),
			alive_flag: Arc::new(AtomicBool::new(false)),
			key_state_manager: KeyStateManager::new(private_key, public_key, INITIAL_WINDOW_SIZE),
			keep_alive: false,
		}
	}

	pub async fn receive(
		&mut self, size_sender: oneshot::Sender<u32>,
		packet_sender: UnboundedSender<Result<Vec<u8>>>, wait_time: Duration,
	) -> bool {
		self.inner.first_window = true;
		self.inner.message_bytes_received = 0;
		self.inner.message_size = 0;

		let mut size_sender2 = Some(size_sender);
		while !self.inner.close_received {
			let ks = self.key_state_manager.get_duo_mut();
			let window_wait_time = if self.inner.message_bytes_received == 0 {
				wait_time
			} else {
				self.inner.timeout
			};
			if !self
				.inner
				.receive_window(&mut size_sender2, &packet_sender, ks, window_wait_time)
				.await
			{
				return false;
			}
			self.inner.first_window = false;

			// We don't need the cache of unprocessed packets for this ks_seq anymore.
			self.inner.current_ks_unprocessed_first_packet = None;
			self.inner.current_ks_unprocessed_packets.clear();

			// Update the key state manager
			self.key_state_manager.setup_next_keystate(
				self.inner.next_private_key.clone(),
				self.inner.next_public_key.clone(),
				self.inner.previous_window_size,
			);
			self.inner.receive_window.size = self.inner.previous_window_size;
			if !self.inner.window_error_free {
				self.inner.receive_window.starting = false;
			}
			self.inner.reset_receive_window_state();

			debug_assert!(self.inner.message_bytes_received <= self.inner.message_size);
			if self.inner.message_bytes_received == self.inner.message_size {
				return true;
			}

			if let Err(e) = self
				.inner
				.process_next_ks_unprocessed_packets(self.key_state_manager.current_key_state())
				.await
			{
				let _ = packet_sender.send(Err(e));
				return false;
			}
		}
		true
	}

	async fn run(mut self, mut receiver: UnboundedReceiver<Traced<TransporterTask>>) {
		// Keep executing tasks until either a close packet has been received, or the
		// task channel has been closed, in which case we should close the connection
		// ourselves.
		self.alive_flag.store(true, Ordering::Relaxed);
		let mut close_sender = None;
		while !self.inner.close_received {
			select! {
				result = receiver.recv() => {
					if let Some(traced_task) = result {
						let task;
						(task, self.inner.current_backtrace) = traced_task.unwrap();
						trace!("Running task {} for {} (session [{} -> {}])", &task, self.inner.node_id, self.inner.local_session_id, self.inner.dest_session_id);
						let success = match task {
							TransporterTask::Receive(size_sender, packet_sender, wait_time) => self.receive(size_sender, packet_sender, wait_time.unwrap_or(self.inner.timeout)).await,
							TransporterTask::Send(message, result_sender) => self.send(message, Some(result_sender)).await,
							TransporterTask::SendAsync(message) => self.send(message, None).await,
							TransporterTask::Close(tx) => { close_sender = Some(tx); break; }
							TransporterTask::CloseAsync => break,
							TransporterTask::KeepAlive => {
								self.keep_alive = true;
								true
							}
						};
						// If there was an error that caused the task to be stopped prematurely, stop everything without trying to close it cleanly.
						if !success {
							return;
						}
					// If the task channel has closed down, proceed with the closing sequence
					} else {
						break;
					}
				},
				// While not sending or receiving, a close packet, or an ack-wait packet may still be received, and they need to be handled.
				result = self.inner.packet_receiver.recv() => {
					let ks = self.key_state_manager.get_duo();
					if let Some(packet) = result {
						if let Err(e) = self.inner.process_stray_packet(ks, packet).await {
							warn!("Error while processing stray packet: {}", e);
						}
					} else {
						trace!("Packet channel with transporter has been disconnected. {} {}", self.inner.local_session_id, self.inner.dest_session_id);
						return;
					}
				},
				// Generally speaking, the transporter should be busy processing a task most of the time.
				// Whenever a task hasn't been given (yet), that might be because of the work that
				// is done in between the calls to `send` or `receive` in the corresponding
				// connection instance.
				_ = sleep(Duration::from_secs(10)) => {
					#[cfg(debug_assertions)]
					if !self.keep_alive {
						warn!("Transporter has been sleeping for ten seconds.");
						if let Some(backtrace) = &self.inner.current_backtrace {
							warn!("Last task: {:?}", backtrace);
						}
					}
				}
			}
		}

		// The closing sequence
		let ks = self.key_state_manager.get_duo();
		let result = if self.inner.close_received {
			self.inner.acknowledge_close(ks).await
		} else {
			self.inner.close(ks).await
		};
		if let Some(tx) = close_sender {
			let r = match result {
				Ok(ok) => {
					if !ok {
						warn!(
							"Transporter close channel got disconnected during the closing \
							 sequence."
						);
					}
					tx.send(Ok(()))
				}
				Err(e) => tx.send(Err(e)),
			};
			if let Err(_) = r {
				warn!("Transporter handle has been closed before the closing sequence finished.");
			}
		}

		// Once we're done, we can let the garbage collector clean up our session ID.
		self.alive_flag.store(false, Ordering::Relaxed);
	}

	async fn send(
		&mut self, message: Vec<u8>, result_sender: Option<oneshot::Sender<Result<()>>>,
	) -> bool {
		debug_assert!(message.len() > 0, "empty message");
		let message_len = message.len();
		let mut buffer = Vec::with_capacity(MESSAGE_HEADER_SIZE + message.len());
		buffer.extend((message_len as u32).to_le_bytes()); // The message header
		buffer.extend(message);
		self.inner.first_window = true;

		let mut sent = 0;
		let mut error = None;
		while !self.inner.close_received {
			let mut their_next_window_size = 0;
			let mut next_public_key = x25519::PublicKey::from([0u8; 32]);
			let next_private_key = x25519::StaticSecret::random_from_rng(OsRng);
			let our_next_public_key = x25519::PublicKey::from(&next_private_key);
			let ks = self.key_state_manager.get_duo_mut();
			let our_next_window_size = self.inner.send_window.increase_window_size();

			match self
				.inner
				.send_window(
					ks,
					&buffer[sent..],
					our_next_window_size,
					our_next_public_key,
				)
				.await
			{
				Ok((s, ack_data)) => {
					sent += s as usize;
					if let Some((a, b)) = ack_data {
						their_next_window_size = a;
						next_public_key = b;
					}
				}
				Err(e) => {
					error = Some(e);
					break;
				}
			}
			self.inner.first_window = false;

			// Update the key state manager
			self.inner.current_ks_unprocessed_first_packet = None;
			self.inner.current_ks_unprocessed_packets.clear();
			let next_window_size = min(our_next_window_size, their_next_window_size);
			self.key_state_manager.setup_next_keystate(
				next_private_key,
				next_public_key,
				next_window_size,
			);
			self.inner.send_window.size = next_window_size;
			if !self.inner.window_error_free {
				self.inner.send_window.starting = false;
			}
			self.inner.reset_send_window_state();

			debug_assert!(
				sent <= buffer.len(),
				"sent more bytes than are in the send buffer: {} > {}",
				sent,
				buffer.len()
			);
			if sent == buffer.len() {
				break;
			}
			self.inner.first_window = false;

			if let Err(e) = self
				.inner
				.process_next_ks_unprocessed_packets(self.key_state_manager.current_key_state())
				.await
			{
				if let Some(tx) = result_sender {
					let _ = tx.send(Err(e));
				}
				return false;
			}
		}

		let ok = error.is_none();
		if let Some(tx) = result_sender {
			let r = if let Some(e) = error {
				tx.send(Err(e))
			} else {
				debug_assert!(sent - MESSAGE_HEADER_SIZE == message_len);
				tx.send(Ok(()))
			};
			if let Err(_) = r {
				warn!("Transporter send result oneshot disconnected.");
			}
		}
		ok
	}

	/// Runs the transporter in the background.
	pub fn spawn(self) -> TransporterHandle {
		// Packets will be queued by the underlying socket implementation, so no reason
		// to have an unbounded (or large) channel buffer.
		// The task channel is unbounded, because otherwise if the run loop has exitted
		// the loop that processes tasks, sending on this channel would block during the
		// closing sequence.
		let (tx, rx) = unbounded_channel();
		let handle = TransporterHandle {
			sender: tx,
			alive_flag: Arc::new(AtomicBool::new(false)),
			is_connection_based: self.inner.socket_sender.is_connection_based(),
			socket_sender: self.inner.socket_sender.clone(),
		};
		spawn(self.run(rx));
		handle
	}
}

impl TransporterInner {
	/// Respond in the closing sequence when the other side already closed the
	/// connection.
	async fn acknowledge_close(&mut self, ks: KeyStateDuo<'_>) -> Result<bool> {
		self.send_close_ack_packet(ks.current).await?;

		let mut timeouts = 0;
		loop {
			select! {
				result = self.packet_receiver.recv() => {
					if let Some(packet) = result {
						if self.process_closing_sequence_packet(ks, packet).await? {
							return Ok(true);
						}
					} else {
						return Ok(false);
					}
				},
				_ = sleep(self.timeout / 8) => {
					if timeouts < 7 {
						self.send_close_ack_packet(ks.current).await?;
					} else {
						return trace::err(Error::Timeout(self.timeout));
					}
					timeouts += 1;
				}
			}
		}
	}

	/// Initiate the closing sequence
	async fn close(&mut self, ks: KeyStateDuo<'_>) -> Result<bool> {
		let mut timeouts = 0;
		let mut acks_received = 0;
		loop {
			select! {
				result = self.packet_receiver.recv() => {
					if let Some(packet) = result {
						// FIXME: If we receive a normal close packet, the other side will also reply to close-ack packets, which creates a (limited) loop.
						// We could fix this by leaving this function and switching into `acknowledge_close`.
						if self.process_closing_sequence_packet(ks, packet).await? {
							// Only reply to 8 close ack packets.
							if acks_received < 8 {
								self.send_close_ack_packet(ks.current).await?;
								timeouts = 0;
								acks_received += 1;
							}
						}
					} else {
						return Ok(false);
					}
				},
				_ = sleep(self.timeout / 8) => {
					// If we have already replied the close-ack packet with a close-ack packet, we don't have to sent normal close packets anymore, we only need to replay close-ack packets to any further close-ack packets.
					if acks_received == 0 {
						if timeouts < 8 {
							self.send_close_packet(ks.current).await?;
						} else {
							return trace::err(Error::Timeout(self.timeout));
						}
					} else if timeouts == 8 {
						return Ok(true);
					}
					timeouts += 1;
				}
			}
		}
	}

	fn decrypt_packet(&self, ks: &KeyState, seq: u16, data: &mut [u8]) -> bool {
		debug_assert!(
			seq < ks.keychain.len() as u16,
			"attempting to decrypt a packet out-of-order: {} >= {}",
			seq,
			ks.keychain.len()
		);
		let key = &ks.keychain[seq as usize];
		decrypt(self.local_session_id, ks.sequence, seq, data, key);

		Self::verify_packet(&data)
	}

	fn fill_packet<'a>(&self, packet: &'a [u8], buffer: &'a mut Vec<u8>) -> &'a [u8] {
		let max_len = if packet.len() != self.max_data_packet_length()
			&& self.max_data_packet_length() > MAX_PACKET_FILL_BLOCK_SIZE
		{
			(packet.len() / MAX_PACKET_FILL_BLOCK_SIZE
				+ (packet.len() % MAX_PACKET_FILL_BLOCK_SIZE > 0) as usize)
				* MAX_PACKET_FILL_BLOCK_SIZE
		} else {
			self.max_data_packet_length()
		};

		debug_assert!(
			packet.len() <= max_len,
			"packet.len()={}, max_len={}",
			packet.len(),
			max_len
		);
		if packet.len() == max_len {
			packet
		} else {
			buffer.resize(max_len, 0u8);
			let end = packet.len();
			buffer[..end].copy_from_slice(packet);
			OsRng.fill_bytes(&mut buffer[end..]);
			buffer
		}
	}

	async fn handle_window_sender_packets(
		&mut self, ks: KeyStateDuoMut<'_>, packets: &[&[u8]],
	) -> Result<Option<(u16, x25519::PublicKey)>> {
		let mut timeouts = 0;
		loop {
			select! {
				result = self.packet_receiver.recv() => {
					if let Some(packet) = result {
						let seq = packet.seq;
						if let Some(ack) = self.process_packet_while_sending(ks.get_const(), packet).await? {
							match ack {
								Ok(ack_data) => return Ok(Some(ack_data)),
								Err(missing_mask) => {
									self.window_error_free = false;
									self.send_missing_packets(ks.current, seq, &missing_mask, packets).await?;
								}
							}
						}
					} else {
						return Ok(None);
					}
				},
				_ = sleep(self.timeout / 8) => {
					if timeouts < 8 {
						self.send_ack_wait_packet(ks.current).await?;
					} else {
						return trace::err(Error::Timeout(self.timeout));
					}
					timeouts += 1;
				}
			}
		}
	}

	// The max amount of byte that can be sent in one data packet
	fn max_data_packet_length(&self) -> usize {
		// 10 bytes are used for the header
		self.socket_sender.max_packet_length() - 10
	}

	pub fn new(
		encrypt_session_id: u16, our_session_id: u16, their_session_id: u16,
		socket_sender: Arc<dyn LinkSocketSender>,
		packet_receiver: UnboundedReceiver<CryptedPacket>, node_id: IdType, peer_node_id: IdType,
		timeout: Duration,
	) -> Self {
		Self {
			close_received: false,
			current_backtrace: None,
			current_ks_unprocessed_first_packet: None,
			current_ks_unprocessed_packets: HashMap::new(),
			encrypt_session_id,
			first_window: true,
			max_packets_expected: 0,
			message_bytes_received: 0,
			message_size: 0,
			next_ks_unprocessed_packets: Vec::new(),
			next_private_key: x25519::StaticSecret::from([0u8; 32]),
			next_public_key: x25519::PublicKey::from([0u8; 32]),
			next_sequence: 0,
			node_id,
			local_session_id: our_session_id,
			peer_node_id,
			previous_window_size: 0,
			packet_receiver,
			receive_window: WindowInfo::default(),
			requested_window_size: 0,
			send_window: WindowInfo::default(),
			socket_sender,
			dest_session_id: their_session_id,
			timeout,
			window_bytes_received: 0,
			window_error_free: false,
		}
	}

	fn next_receiving_window_size(&mut self) -> u16 {
		let our_next_window_size =
			if self.max_packets_expected == self.receive_window.size && self.window_error_free {
				self.receive_window.increase_window_size()
			} else {
				self.receive_window.decrease_window_size()
			};

		// Take the lowest of the two requested window sizes
		min(our_next_window_size, self.requested_window_size)
	}

	fn prepare_missing_mask(&self) -> Vec<u8> {
		debug_assert!(
			self.max_packets_expected as u16 >= self.next_sequence,
			"max_packet_count is incorrect: {} >= {}",
			self.max_packets_expected,
			self.next_sequence
		);
		let completed = self.next_sequence;
		let ooo_sequences_iter = self
			.current_ks_unprocessed_first_packet
			.iter()
			.map(|_| &0u16)
			.chain(self.current_ks_unprocessed_packets.keys());
		let ooo_sequences: Vec<u16> = ooo_sequences_iter.clone().map(|s| *s).collect();

		// If the message size hasn't been determined yet (because the first packet
		// didn't arrive), base the number of packets to be expected on the highest
		// sequence we've received before.
		let max_packets_expected = if self.max_packets_expected == 0 {
			min(
				ooo_sequences_iter.fold(0u16, |a, b| a.max(*b)) as u16 + 1,
				self.receive_window.size, // But limit it to our current window size of course
			)
		} else {
			self.max_packets_expected
		};

		let mask_bits = (max_packets_expected - completed) as usize;
		let mask_size = min(
			mask_bits as usize / 8 + ((mask_bits % 8) > 0) as usize,
			self.max_data_packet_length(),
		);
		let mut mask = vec![0u8; mask_size];
		// Then reset individual bits back to 1 for those we still need.
		for i in completed..(max_packets_expected as u16) {
			if !ooo_sequences.contains(&i) {
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

	fn process_ack_packet(
		&self, mut data: Vec<u8>,
	) -> Result<StdResult<(u16, x25519::PublicKey), Vec<u8>>> {
		let error_code = data.remove(0);
		if error_code != 0 {
			if data.len() > 0 {
				Ok(Err(data))
			} else {
				trace::err(Error::EmptyAckMask)
			}
		} else {
			if data.len() < WINDOW_HEADER_SIZE {
				return trace::err(Error::PacketTooSmall);
			}

			let next_window_size = u16::from_le_bytes(*array_ref![data, 0, 2]);
			data.drain(0..2);
			let pub_bytes: [u8; 32] = data.try_into().unwrap();
			let new_public_key = x25519::PublicKey::from(pub_bytes);
			Ok(Ok((next_window_size, new_public_key)))
		}
	}

	async fn process_current_ack_wait_packet(&self, ks: &KeyState, packet: Vec<u8>) -> Result<()> {
		if self.verify_peer_node_id(&packet) {
			// Send either a success or missing ack packet depending on the state
			self.send_missing_ack_packet(ks).await?;
		}
		Ok(())
	}

	async fn process_packet_while_receiving_ks_current(
		&mut self, size_sender: &mut Option<oneshot::Sender<u32>>,
		sender: &UnboundedSender<Result<Vec<u8>>>, ks: &mut KeyState, seq: u16, packet: Vec<u8>,
	) -> Result<Option<bool>> {
		// If already processed before, drop it
		if packet.len() == 0 {
			trace!("Dropping empty packet.");
			return trace::err(Error::PacketTooSmall);
		}

		if seq < self.next_sequence {
			self.process_stray_packet_for_ks_current(ks, seq, packet, true, false)
				.await?;
			return Ok(None);
		} else if seq == self.next_sequence {
			if let Some(ok) = self
				.process_next_sequence_in_line_while_receiving(size_sender, sender, ks, seq, packet)
				.await?
			{
				return Ok(Some(ok));
			}
		} else if seq > self.next_sequence {
			self.current_ks_unprocessed_packets.insert(seq, packet);
			return Ok(None);
		}

		// Process any remaining unprocessed packets
		if seq == 0 {
			if let Some(decrypted_packet) = self.current_ks_unprocessed_first_packet.take() {
				if let Some(ok) =
					self.process_next_data_packet(size_sender, sender, ks, true, decrypted_packet)?
				{
					return Ok(Some(ok));
				}
			}
		}

		while let Some(packet) = self
			.current_ks_unprocessed_packets
			.remove(&self.next_sequence)
		{
			if let Some(ok) = self
				.process_next_sequence_in_line_while_receiving(
					size_sender,
					sender,
					ks,
					self.next_sequence,
					packet,
				)
				.await?
			{
				return Ok(Some(ok));
			}
		}
		Ok(None)
	}

	async fn process_packet_while_sending_ks_current(
		&mut self, ks: &KeyState, seq: u16, mut data: Vec<u8>,
	) -> Result<Option<StdResult<(u16, x25519::PublicKey), Vec<u8>>>> {
		if !self.decrypt_packet(ks, seq, &mut data) {
			warn!(
				"Dropping malformed packet (ks_seq={}, seq={}, session_id={})",
				ks.sequence, seq, self.local_session_id
			);
		}

		let packet_type = data.drain(0..3).last().unwrap();
		match packet_type {
			CRYPTED_PACKET_TYPE_ACK => return Ok(Some(self.process_ack_packet(data)?)),
			CRYPTED_PACKET_TYPE_ACK_WAIT => return trace::err(Error::BothSending),
			CRYPTED_PACKET_TYPE_CLOSE => self.process_close_packet(data)?,
			_ => self.process_unexpected_packet(ks.sequence, seq, packet_type),
		}
		Ok(None)
	}

	/*async fn process_packet_while_sending_ks_previous(&mut self, ks: KeyStateDuo<'_>, seq: u16, mut data: Vec<u8>) -> Result<()> {
		if !self.decrypt_packet(ks, seq, &mut data) {
			debug!("Dropping malformed packet (ks_seq={}, seq={}", ks.previous.sequence, seq);
		}

		let packet_type = data.remove(0);
		data.drain(0..2);	// Drain checksum
		match packet_type {
			CRYPTED_PACKET_TYPE_ACK_WAIT => self.process_previous_ack_wait_packet(ks, data).await?,
			_ => self.process_unexpected_packet(ks.previous.sequence, seq, packet_type)
		}
		Ok(())
	}*/

	async fn process_packet_while_receiving(
		&mut self, size_sender: &mut Option<oneshot::Sender<u32>>,
		sender: &UnboundedSender<Result<Vec<u8>>>, ks: &mut KeyStateDuoMut<'_>,
		packet: CryptedPacket,
	) -> Result<Option<bool>> {
		if packet.ks_seq == ks.current.sequence {
			return self
				.process_packet_while_receiving_ks_current(
					size_sender,
					sender,
					ks.current,
					packet.seq,
					packet.data,
				)
				.await;
		} else if packet.ks_seq == ks.previous.sequence {
			return Ok(self
				.process_packet_while_receiving_ks_previous(
					sender,
					ks.get_const(),
					packet.seq,
					packet.data,
				)
				.await);
		} else if packet.ks_seq == ks.current.sequence.wrapping_add(1) {
			self.next_ks_unprocessed_packets
				.push((packet.seq, packet.data));
		} else {
			warn!(
				"Dropping packet with invalid ks_seq={} (current={}, session_id={})2 {} {}",
				packet.ks_seq,
				ks.current.sequence,
				self.local_session_id,
				self.node_id,
				self.peer_node_id
			);
		}
		Ok(None)
	}

	async fn process_packet_while_sending(
		&mut self, ks: KeyStateDuo<'_>, packet: CryptedPacket,
	) -> Result<Option<StdResult<(u16, x25519::PublicKey), Vec<u8>>>> {
		if packet.ks_seq == ks.current.sequence {
			//trace!("process_packet_while_sender current {} (session={}->{})",
			// packet.ks_seq, self.local_session_id, self.dest_session_id);
			return self
				.process_packet_while_sending_ks_current(ks.current, packet.seq, packet.data)
				.await;
		} else if packet.ks_seq == ks.previous.sequence {
			//trace!("process_packet_while_sender prev {} (session={}->{})", packet.ks_seq,
			// self.local_session_id, self.dest_session_id);
			self.process_stray_packet_for_ks_previous(ks, packet.seq, packet.data)
				.await?;
		} else if packet.ks_seq == ks.current.sequence.wrapping_add(1) {
			//trace!("process_packet_while_sender next {} (session={}->{})", packet.ks_seq,
			// self.local_session_id, self.dest_session_id);
			self.next_ks_unprocessed_packets
				.push((packet.seq, packet.data));
		} else {
			//trace!("process_packet_while_sender else {} (session={}->{})", packet.ks_seq,
			// self.local_session_id, self.dest_session_id);
			warn!(
				"Dropping packet with invalid ks_seq={} (session_id={})3",
				packet.ks_seq, self.local_session_id
			);
		}
		Ok(None)
	}

	fn process_close_ack_packet(&self, packet: Vec<u8>) -> bool {
		self.verify_peer_node_id(&packet)
	}

	fn process_close_packet(&mut self, packet: Vec<u8>) -> Result<()> {
		if self.verify_peer_node_id(&packet) {
			self.close_received = true;
			return trace::err::<(), _>(Error::ConnectionClosed);
		}
		Ok(())
	}

	async fn process_closing_sequence_packet(
		&mut self, ks: KeyStateDuo<'_>, packet: CryptedPacket,
	) -> Result<bool> {
		if packet.ks_seq == ks.current.sequence {
			self.process_closing_sequence_packet_for_ks(ks.current, packet.seq, packet.data)
				.await
		} else if packet.ks_seq == ks.previous.sequence {
			self.process_closing_sequence_packet_for_ks(ks.previous, packet.seq, packet.data)
				.await
		} else if packet.ks_seq == ks.current.sequence.wrapping_add(1) {
			trace!("Dropping packet after closing sequence.");
			Ok(false)
		} else {
			warn!(
				"Dropping packet with invalid ks_seq={} (session_id={})4",
				packet.ks_seq, self.local_session_id
			);
			Ok(false)
		}
	}

	async fn process_closing_sequence_packet_for_ks(
		&mut self, ks: &KeyState, seq: u16, mut data: Vec<u8>,
	) -> Result<bool> {
		if !self.decrypt_packet(ks, seq, &mut data) {
			warn!(
				"Dropping malformed packet (ks_seq={}, seq={}, session_id={})",
				ks.sequence, seq, self.local_session_id
			);
		}

		let packet_type = data.drain(0..3).last().unwrap();
		match packet_type {
			CRYPTED_PACKET_TYPE_ACK => {}
			// FIXME: Handle CRYPTED_PACKET_TYPE_ACK_WAIT so that the sending end can finish.
			CRYPTED_PACKET_TYPE_CLOSE =>
				if self.process_close_packet(data).is_err() {
					self.send_close_ack_packet(ks).await?;
				},
			CRYPTED_PACKET_TYPE_CLOSE_ACK => return Ok(self.process_close_ack_packet(data)),
			_ => self.process_unexpected_packet(ks.sequence, seq, packet_type),
		}
		Ok(false)
	}

	/// Processes the data packet. Returns true if the last packet was found.
	fn process_next_data_packet(
		&mut self, size_sender: &mut Option<oneshot::Sender<u32>>,
		sender: &UnboundedSender<Result<Vec<u8>>>, ks: &mut KeyState, is_first: bool,
		mut packet: Vec<u8>,
	) -> Result<Option<bool>> {
		let packet_bytes = packet.len() as u32;
		if is_first {
			if let Some(last_found) =
				self.process_window_first_data_packet(size_sender, &mut packet)?
			{
				return Ok(Some(last_found));
			}
		}

		// Remove the filler
		let bytes_left = (self.message_size - self.message_bytes_received) as usize;
		if packet.len() > bytes_left {
			packet.resize(bytes_left, 0u8);
		}

		// Advance key with all data found
		ks.advance_key(&packet);

		self.next_sequence += 1;
		debug_assert!(self.next_sequence <= (ks.keychain.len() - 1) as u16);
		let packet_len = packet.len() as u32;
		if sender.send(Ok(packet)).is_err() {
			error!("Channel to send received data on has closed.");
			return Ok(Some(false));
		}

		self.message_bytes_received += packet_len;
		self.window_bytes_received += packet_bytes;
		if self.next_sequence == self.max_packets_expected {
			Ok(Some(true))
		} else {
			Ok(None)
		}
	}

	async fn process_next_ks_unprocessed_packets(&mut self, ks: &KeyState) -> Result<()> {
		let packets: Vec<(u16, Vec<u8>)> = self.next_ks_unprocessed_packets.drain(..).collect();
		for (seq, packet) in packets {
			self.process_stray_packet_for_ks_current(ks, seq, packet, false, false)
				.await?;
		}
		Ok(())
	}

	/// If something is returned, the current task should be stopped.
	/// The bool indicates whether it ended succesfully.
	async fn process_next_packet_while_receiving(
		&mut self, size_sender: &mut Option<oneshot::Sender<u32>>,
		sender: &UnboundedSender<Result<Vec<u8>>>, ks: &mut KeyState, seq: u16, mut data: Vec<u8>,
	) -> Result<Option<bool>> {
		let packet_type = data.drain(0..3).last().unwrap();
		match packet_type {
			CRYPTED_PACKET_TYPE_ACK => trace!(
				"Ignoring ack packet while in receiving mode. (Is the other end in receiving mode \
				 as well?)"
			),
			other => {
				let result = match other {
					CRYPTED_PACKET_TYPE_DATA => {
						return self.process_next_data_packet(
							size_sender,
							sender,
							ks,
							seq == 0,
							data,
						);
					}
					CRYPTED_PACKET_TYPE_ACK_WAIT =>
						self.process_current_ack_wait_packet(ks, data).await,
					CRYPTED_PACKET_TYPE_CLOSE => self.process_close_packet(data),
					_ => {
						self.process_unexpected_packet(ks.sequence, seq, packet_type);
						Ok(())
					}
				};
				if let Err(e) = result {
					if let Err(_) = sender.send(Err(e)) {
						debug!("Unable to send error through receiving channel.");
					}
				}
			}
		}
		Ok(None)
	}

	/// If something is returned, the current task should be stopped.
	/// The bool indicates whether it ended succesfully.
	async fn process_next_sequence_in_line_while_receiving(
		&mut self, size_sender: &mut Option<oneshot::Sender<u32>>,
		sender: &UnboundedSender<Result<Vec<u8>>>, ks: &mut KeyState, seq: u16,
		mut packet: Vec<u8>,
	) -> Result<Option<bool>> {
		// Decrypt the packet
		if !self.decrypt_packet(ks, seq, &mut packet) {
			warn!(
				"Malformed packet received for current window, dropping it. (ks_seq={}, seq={})",
				ks.sequence, seq
			);
			return Ok(None);
		}

		self.process_next_packet_while_receiving(size_sender, sender, ks, seq, packet)
			.await
	}

	async fn process_previous_ack_wait_packet(
		&self, ks: KeyStateDuo<'_>, packet: Vec<u8>,
	) -> Result<()> {
		if self.previous_window_size > 0 {
			if self.verify_peer_node_id(&packet) {
				let our_public_key = x25519::PublicKey::from(&ks.current.private_key);
				self.send_success_ack_packet(
					ks.previous,
					(ks.previous.keychain.len() - 1) as u16,
					self.previous_window_size,
					&our_public_key,
				)
				.await?;
			}
		}
		Ok(())
	}

	/// Returns either None if nothing special happened to exit the current
	/// task, or Some(false) if it has. The return type is chosen to match the
	/// caller's return type.
	async fn process_packet_while_receiving_ks_previous(
		&mut self, sender: &UnboundedSender<Result<Vec<u8>>>, ks: KeyStateDuo<'_>, seq: u16,
		mut packet: Vec<u8>,
	) -> Option<bool> {
		if seq as usize >= ks.previous.keychain.len() {
			warn!("Received packet with higher sequence than possible for previous keystate");
			return None;
		}

		if !self.decrypt_packet(ks.previous, seq, &mut packet) {
			warn!(
				"Malformed packet received for current window, dropping it. (ks_seq={}, seq={})",
				ks.previous.sequence, seq
			);
			return None;
		}

		let packet_type = packet.drain(0..3).last().unwrap();
		let result = match packet_type {
			CRYPTED_PACKET_TYPE_ACK_WAIT => self.process_previous_ack_wait_packet(ks, packet).await,
			CRYPTED_PACKET_TYPE_CLOSE => self.process_close_packet(packet),
			_ => {
				self.process_unexpected_packet(ks.previous.sequence, seq, packet_type);
				Ok(())
			}
		};
		if let Err(e) = result {
			let _ = sender.send(Err(e));
			return Some(false);
		}
		None
	}

	/// Process any packet that is received for the current key-state, before we
	/// know what the next task is going to be.
	async fn process_stray_packet_for_ks_current(
		&mut self, ks: &KeyState, seq: u16, mut data: Vec<u8>, is_receiving: bool, is_sending: bool,
	) -> Result<()> {
		// Cache the packets that we can't decrypt yet.
		if seq as usize >= ks.keychain.len() {
			self.current_ks_unprocessed_packets.insert(seq, data);
			return Ok(());
		}

		if !self.decrypt_packet(ks, seq, &mut data) {
			warn!("Malformed stray packet found, dropping it...");
			return Ok(());
		}

		let packet_type = data.drain(0..3).last().unwrap();
		match packet_type {
			CRYPTED_PACKET_TYPE_DATA => {
				debug_assert!(
					seq == 0,
					"higher sequences should have already been cached."
				);
				self.current_ks_unprocessed_first_packet = Some(data);
			}
			// Stray ack packets can happen if our side has send out an ack-wait packet just before
			// receiving the successful ack packet, then the other side will still respond to our
			// ack-wait packet but we've already ended the sending task.
			CRYPTED_PACKET_TYPE_ACK =>
				if is_receiving {
					return trace::err(Error::BothReceiving);
				},
			CRYPTED_PACKET_TYPE_CLOSE => {
				let _ = self.process_close_packet(data);
			}
			CRYPTED_PACKET_TYPE_ACK_WAIT =>
				if is_sending {
					return trace::err(Error::BothSending);
				// At this state, we don't know what task is going to be served
				// to the transporter yet, so we can't really give an
				// intelligent response at this point.
				} else {
					if self.current_ks_unprocessed_first_packet.is_none() {
						return self.process_current_ack_wait_packet(ks, data).await;
					} else {
						trace!(
							"Dropping stray ack-wait packet because we don't have a task for the \
							 current stray packets yet. ({})",
							ks.sequence
						);
					}
				},
			_ => self.process_unexpected_packet(ks.sequence, seq, packet_type),
		}
		Ok(())
	}

	async fn process_stray_packet_for_ks_previous(
		&mut self, ks: KeyStateDuo<'_>, seq: u16, mut packet: Vec<u8>,
	) -> Result<()> {
		if seq as usize >= ks.previous.keychain.len() {
			warn!("Dropping packet with higher sequence than possible for the previous keystate");
			return Ok(());
		}

		if !self.decrypt_packet(ks.previous, seq, &mut packet) {
			warn!("Malformed stray packet found, dropping it...");
			return Ok(());
		}

		let packet_type = packet.drain(0..3).last().unwrap();
		match packet_type {
			CRYPTED_PACKET_TYPE_CLOSE => {
				let _ = self.process_close_packet(packet);
			}
			CRYPTED_PACKET_TYPE_ACK_WAIT =>
				return self.process_previous_ack_wait_packet(ks, packet).await,
			_ => self.process_unexpected_packet(ks.previous.sequence, seq, packet_type),
		}
		Ok(())
	}

	async fn process_stray_packet(
		&mut self, ks: KeyStateDuo<'_>, packet: CryptedPacket,
	) -> Result<()> {
		if packet.ks_seq == ks.current.sequence {
			self.process_stray_packet_for_ks_current(
				ks.current,
				packet.seq,
				packet.data,
				false,
				false,
			)
			.await?;
		} else if packet.ks_seq == ks.previous.sequence {
			self.process_stray_packet_for_ks_previous(ks, packet.seq, packet.data)
				.await?;
		} else if packet.ks_seq == ks.current.sequence.wrapping_add(1) {
			self.next_ks_unprocessed_packets
				.push((packet.seq, packet.data));
		} else {
			warn!(
				"Dropping packet with invalid ks_seq={} (session_id={})1",
				packet.ks_seq, self.local_session_id
			);
		}
		Ok(())
	}

	fn process_unexpected_packet(&self, ks_seq: u16, seq: u16, packet_type: u8) {
		if packet_type <= CRYPTED_PACKET_TYPE_CLOSE_ACK {
			warn!(
				"Dropping unexpected packet type {} (ks_seq={}, seq={}, session_id={})",
				packet_type, ks_seq, seq, self.local_session_id
			);
		} else {
			warn!(
				"Dropping unknown packet type {} (ks_seq={}, seq={}, session_id={})",
				packet_type, ks_seq, seq, self.local_session_id
			);
		}
	}

	/// Extracts info from the window header, and the message header if
	/// applicable The headers will be removed from the packet buffer.
	fn process_window_first_data_packet(
		&mut self, size_sender: &mut Option<oneshot::Sender<u32>>, packet: &mut Vec<u8>,
	) -> Result<Option<bool>> {
		if packet.len() <= WINDOW_HEADER_SIZE {
			return trace::err(Error::PacketTooSmall);
		}
		let packet_len = self.max_data_packet_length() as u32;
		self.requested_window_size = u16::from_le_bytes(*array_ref![packet, 0, 2]);
		self.next_public_key = x25519::PublicKey::from(*array_ref![packet, 2, 32]);

		// Calculate the number of bytes that are needed within the crypted packet
		// parts, including the window header
		let total_bytes = if self.first_window {
			if packet.len() <= FIRST_WINDOW_HEADER_SIZE {
				return trace::err(Error::PacketTooSmall);
			}
			self.message_size = u32::from_le_bytes(*array_ref![packet, WINDOW_HEADER_SIZE, 4]);
			if let Some(tx) = size_sender.take() {
				if let Err(_) = tx.send(self.message_size) {
					return Ok(Some(false));
				}
			}

			packet.drain(0..FIRST_WINDOW_HEADER_SIZE);
			self.message_size - self.message_bytes_received + FIRST_WINDOW_HEADER_SIZE as u32
		} else {
			packet.drain(0..WINDOW_HEADER_SIZE);
			self.message_size - self.message_bytes_received + WINDOW_HEADER_SIZE as u32
		};

		let left_to_receive = total_bytes - self.window_bytes_received;
		self.max_packets_expected = cmp::min(
			self.receive_window.size as u32,
			// Keep in mind that we've already processed one packet.
			(left_to_receive / packet_len) + (left_to_receive % packet_len > 0) as u32,
		) as u16;
		Ok(None)
	}

	/// Returns whether it completed successfully or not.
	/// If false, either an error occurred which has been sent on the
	/// `packet_sender`, or the `size_sender` - or `packet_sender` channel has
	/// closed prematurely.
	async fn receive_window(
		&mut self, size_sender: &mut Option<oneshot::Sender<u32>>,
		packet_sender: &UnboundedSender<Result<Vec<u8>>>, mut ks: KeyStateDuoMut<'_>,
		initial_wait_time: Duration,
	) -> bool {
		if self.close_received {
			let _ = packet_sender.send(trace::err(Error::ConnectionClosed));
			return false;
		}

		// Process any packets which may have already been collected but not yet
		// processed.
		let mut already_done = false;
		if let Some(decrypted_packet) = self.current_ks_unprocessed_first_packet.take() {
			match self.process_next_data_packet(
				size_sender,
				packet_sender,
				ks.current,
				true,
				decrypted_packet,
			) {
				Err(e) => {
					let _ = packet_sender.send(Err(e));
				}
				Ok(result) => match result {
					None => {}
					Some(completed) => already_done = completed,
				},
			}
		}
		while let Some(data) = self
			.current_ks_unprocessed_packets
			.remove(&self.next_sequence)
		{
			match self
				.process_next_sequence_in_line_while_receiving(
					size_sender,
					&packet_sender,
					ks.current,
					self.next_sequence,
					data,
				)
				.await
			{
				Err(e) => {
					let _ = packet_sender.send(Err(e));
					return false;
				}
				Ok(result) =>
					if let Some(completed) = result {
						already_done = completed;
						break;
					},
			}
		}

		// Receive and process packets until the last data packet has been found
		self.next_private_key = x25519::StaticSecret::random_from_rng(OsRng);
		if !already_done {
			let mut i = 0;
			let start_time = SystemTime::now();
			let mut interval = initial_wait_time;
			let initial_end_time = start_time + initial_wait_time;
			let mut waiting = true;
			while !self.close_received {
				select! {
					result = self.packet_receiver.recv() => {
						if let Some(packet) = result {
							match self.process_packet_while_receiving(size_sender, &packet_sender, &mut ks, packet).await {
								Err(e) => {
									let _ = packet_sender.send(Err(e));
									return false;
								}
								Ok(result) => if let Some(done) = result {
									if done { break; }
									else { return false; }
								} else if waiting {
									// If we've been able to process at least one packet, stop waiting & adjust interval
									if self.next_sequence > 0 {
										interval = self.timeout / 8;
										waiting = false;
									// If we have not been able to process at least the first packet, but we've received other packets, we haven't had the chance to verify them yet. But we should at least start sending ack-wait packets just to be sure they are valid.
									} else if self.current_ks_unprocessed_packets.len() > 0 {
										if initial_end_time > SystemTime::now() {
											interval = self.timeout / 8;
										}
									}
								}
							}
						} else { return false; }
						i = 0;
					},
					_ = sleep(interval) => {
						if i < 8 || waiting {
							self.window_error_free = false;
							if let Err(e) = self.send_missing_ack_packet(ks.current).await {
								let _ = packet_sender.send(Err(e));
								return false;
							}
							if !waiting { i += 1; }
						} else {
							let _ = packet_sender.send(trace::err(Error::Timeout(self.timeout)));
							return false;
						}
					}
				}
			}
		}

		// Send the ack packet
		self.previous_window_size = self.next_receiving_window_size();
		let our_next_public_key = x25519::PublicKey::from(&self.next_private_key);
		if let Err(e) = self
			.send_success_ack_packet(
				ks.current,
				self.next_sequence,
				self.previous_window_size,
				&our_next_public_key,
			)
			.await
		{
			let _ = packet_sender.send(Err(e));
			return false;
		}

		true
	}

	/// Reset state after each window
	fn reset_receive_window_state(&mut self) {
		self.next_sequence = 0;
		self.max_packets_expected = 0;
		self.requested_window_size = 0;
		self.window_bytes_received = 0;
		self.window_error_free = true;
	}

	/// Reset state after each window
	fn reset_send_window_state(&mut self) {
		self.next_sequence = 0;
		self.window_error_free = true;
	}

	async fn send_ack_packet(&self, ks: &KeyState, seq: u16, mask: Vec<u8>) -> Result<()> {
		let max_len = self.max_data_packet_length();
		let data_packet_length = max_len;
		let mut buffer = if (1 + mask.len()) <= data_packet_length {
			vec![0u8; 1 + mask.len()]
		} else {
			vec![0u8; data_packet_length]
		};
		buffer[0] = (mask.len() > 0) as u8;
		if mask.len() <= buffer.len() - 1 {
			buffer[1..].copy_from_slice(&mask);
		} else {
			buffer[1..].copy_from_slice(&mask[..(data_packet_length - 1)]);
		}

		self.send_crypted_packet(ks, CRYPTED_PACKET_TYPE_ACK, seq, &buffer)
			.await
	}

	async fn send_ack_wait_packet(&self, ks: &KeyState) -> Result<()> {
		self.send_crypted_packet(
			&ks,
			CRYPTED_PACKET_TYPE_ACK_WAIT,
			0, /* Send with seq 0 because we don't know what packets the other side received,
			    * however, we should keep track of what the other side already received as
			    * mentioned in their last ack packet. */
			self.node_id.as_bytes(),
		)
		.await
	}

	async fn send_close_ack_packet(&self, key_state: &KeyState) -> Result<()> {
		self.send_crypted_packet(
			key_state,
			CRYPTED_PACKET_TYPE_CLOSE_ACK,
			0,
			self.node_id.as_bytes(),
		)
		.await
	}

	async fn send_close_packet(&self, key_state: &KeyState) -> Result<()> {
		self.send_crypted_packet(
			key_state,
			CRYPTED_PACKET_TYPE_CLOSE,
			0,
			self.node_id.as_bytes(),
		)
		.await
	}

	fn prepare_crypted_packet(
		&self, ks: &KeyState, message_type: u8, seq: u16, packet: &[u8],
	) -> Vec<u8> {
		debug_assert!(
			packet.len() <= self.max_data_packet_length(),
			"packet size too big: {} > {}",
			packet.len(),
			self.max_data_packet_length()
		);

		let mut buffer = vec![0u8; 10 + packet.len()];
		buffer[0] = PACKET_TYPE_CRYPTED;
		buffer[1..3].copy_from_slice(&self.dest_session_id.to_le_bytes());
		buffer[3..5].copy_from_slice(&ks.sequence.to_le_bytes());
		buffer[5..7].copy_from_slice(&seq.to_le_bytes());
		buffer[9] = message_type;
		buffer[10..][..(packet.len())].copy_from_slice(&packet);
		let checksum = calculate_checksum(&buffer[9..]);
		buffer[7..9].copy_from_slice(&checksum.to_le_bytes());

		// Encrypt the message
		let key = &ks.keychain[seq as usize];
		encrypt(
			self.encrypt_session_id,
			ks.sequence,
			seq,
			&mut buffer[7..],
			key,
		);
		buffer
	}

	async fn send_crypted_packet(
		&self, ks: &KeyState, message_type: u8, seq: u16, packet: &[u8],
	) -> Result<()> {
		#[cfg(feature = "trace-packets")]
		trace!(
			"Send crypted packet (message_type={}, ks_seq={}, seq={}, session={}->{})",
			message_type,
			ks.sequence,
			seq,
			self.local_session_id,
			self.dest_session_id
		);

		let buffer = self.prepare_crypted_packet(ks, message_type, seq, packet);
		self.socket_sender
			.send(&buffer)
			.await
			.map_err(|_| Error::ConnectionClosed.trace())?;
		Ok(())
	}

	async fn send_data_packet(&mut self, ks: &mut KeyState, seq: u16, packet: &[u8]) -> Result<()> {
		// If we have to add additional bytes to achieve the max packet length, use a
		// different buffer for it
		let mut buffer = Vec::new();
		let used_buffer = self.fill_packet(packet, &mut buffer);
		self.send_crypted_packet(ks, CRYPTED_PACKET_TYPE_DATA, seq, used_buffer)
			.await
	}

	/// Function optimized for sending ack packets that notify the other end
	/// we're still missing packets. But if no packets are missing it just sents
	/// a successful ack packet.
	async fn send_missing_ack_packet(&self, ks: &KeyState) -> Result<()> {
		let missing_mask = self.prepare_missing_mask();
		self.send_ack_packet(ks, self.next_sequence, missing_mask)
			.await
	}

	async fn send_missing_packets(
		&mut self, ks: &mut KeyState, start_seq: u16, missing_mask: &[u8], packets: &[&[u8]],
	) -> Result<()> {
		let mut errors = 0;
		for i in 0..missing_mask.len() {
			let byte = missing_mask[i];
			for j in 0..8 {
				if (byte & (1 << j)) != 0 {
					errors += 1;
					let packet_index = start_seq as usize + i * 8 + j;
					let packet = packets[packet_index];

					if packet_index < packets.len() {
						self.send_data_packet(ks, packet_index as u16, packet)
							.await?;
					}
				}
			}
		}
		debug_assert!(
			missing_mask.len() == 0 || errors > 0,
			"no packets sent for missing-mask: {:?}, start_seq={}, errors={}",
			&missing_mask,
			start_seq,
			errors,
		);
		Ok(())
	}

	async fn send_success_ack_packet(
		&self, ks: &KeyState, seq: u16, new_window_size: u16, public_key: &x25519::PublicKey,
	) -> Result<()> {
		let mut buffer = vec![0u8; 35];
		buffer[0] = 0; // Success
		buffer[1..3].copy_from_slice(&new_window_size.to_le_bytes());
		buffer[3..35].copy_from_slice(public_key.as_bytes());
		self.send_crypted_packet(ks, CRYPTED_PACKET_TYPE_ACK, seq, &buffer)
			.await
	}

	async fn send_window(
		&mut self, ks: KeyStateDuoMut<'_>, buffer: &[u8], request_window_size: u16,
		our_next_public_key: x25519::PublicKey,
	) -> Result<(u32, Option<(u16, x25519::PublicKey)>)> {
		if self.first_window {
			debug_assert!(buffer.len() > MESSAGE_HEADER_SIZE);
		} else {
			debug_assert!(buffer.len() > 0);
		}
		debug_assert!(buffer.len() > 0);

		// Calculate number of data bytes in the first packet, and the number of packets
		// for this window
		let max_packet_len = self.max_data_packet_length();
		let first_packet_max_data_len = max_packet_len - WINDOW_HEADER_SIZE;
		let packet_count = if buffer.len() <= first_packet_max_data_len {
			1
		} else {
			let remainder = buffer.len() - first_packet_max_data_len;
			remainder / max_packet_len + (remainder % max_packet_len > 0) as usize
		};
		let mut packets = Vec::with_capacity(packet_count);

		// Send first packet, and include the window header in it
		let buffer_first_packet_limit = if buffer.len() < first_packet_max_data_len {
			buffer.len()
		} else {
			first_packet_max_data_len
		};
		let actual_first_packet_len = WINDOW_HEADER_SIZE + buffer_first_packet_limit;
		let mut first_packet = vec![0u8; actual_first_packet_len];
		first_packet[..2].copy_from_slice(&request_window_size.to_le_bytes());
		first_packet[2..WINDOW_HEADER_SIZE].copy_from_slice(our_next_public_key.as_bytes());
		first_packet[WINDOW_HEADER_SIZE..].copy_from_slice(&buffer[..buffer_first_packet_limit]);
		// Only advance key for actual data, not including any of the headers.
		if self.first_window {
			ks.current
				.advance_key(&buffer[MESSAGE_HEADER_SIZE..buffer_first_packet_limit]);
		} else {
			ks.current.advance_key(&buffer[..buffer_first_packet_limit]);
		}
		self.send_data_packet(ks.current, 0, &first_packet).await?;
		self.next_sequence = 1;
		packets.push(&first_packet[..]);

		// Send additional packets
		let mut sent = buffer_first_packet_limit;
		while !self.close_received
			&& self.next_sequence < self.send_window.size
			&& sent < buffer.len()
		{
			let packet = if (buffer.len() - sent) > max_packet_len {
				&buffer[sent..][..max_packet_len]
			} else {
				&buffer[sent..]
			};
			ks.current.advance_key(packet);
			self.send_data_packet(ks.current, self.next_sequence, packet)
				.await?;
			self.next_sequence += 1;
			debug_assert!(self.next_sequence <= (ks.current.keychain.len() - 1) as u16);
			sent += packet.len();
			packets.push(packet);
		}

		// Handle incomming ack packets
		let ack_result = self.handle_window_sender_packets(ks, &packets).await?;
		Ok((sent as u32, ack_result))
	}

	fn verify_packet(buffer: &[u8]) -> bool {
		let given_checksum = u16::from_le_bytes(*array_ref![buffer, 0, 2]);
		let calculated_checksum = calculate_checksum(&buffer[2..]);

		given_checksum == calculated_checksum
	}

	fn verify_peer_node_id(&self, buffer: &[u8]) -> bool {
		if buffer.len() < 32 {
			warn!("Malformed close packet: too small.");
			return false;
		}

		let node_id = IdType::from_bytes(array_ref![buffer, 0, 32]);
		if node_id != self.peer_node_id {
			warn!("Malformed close packet: invalid node ID");
			return false;
		}

		true
	}
}

impl TransporterHandle {
	/// Initiate the closing sequence on the connection
	#[allow(dead_code)]
	pub async fn close(&mut self) -> Option<Result<()>> {
		let (tx, rx) = oneshot::channel();
		self.sender.send(TransporterTask::Close(tx).trace()).ok()?;
		rx.await.ok()
	}

	#[allow(dead_code)]
	pub fn close_async(self) -> bool {
		self.sender
			.send(TransporterTask::CloseAsync.trace())
			.is_ok()
	}

	/*#[cfg(test)]
	pub(super) fn dummy() -> Self {
		let (tx, _) = unbounded_channel();
		Self {
			sender: tx,
			alive_flag: Arc::new(AtomicBool::new(false)),
			is_connection_based: false,
		}
	}*/

	pub fn is_alive(&self) -> bool { self.alive_flag.load(Ordering::Relaxed) }

	pub fn is_connection_based(&self) -> bool { self.is_connection_based }

	pub fn keep_alive(&self) -> bool {
		self.sender.send(TransporterTask::KeepAlive.trace()).is_ok()
	}

	/// Instructs the Receiver's task to start receiving a message, which will
	/// make all received packets available on the returned receiver stream.
	/// Blocks until the transporter task is able to start the task.
	pub async fn receive(&mut self) -> Option<(Option<u32>, impl Stream<Item = Result<Vec<u8>>>)> {
		let (size_tx, size_rx) = oneshot::channel();
		let (tx, rx) = unbounded_channel::<Result<Vec<u8>>>();
		self.sender
			.send(TransporterTask::Receive(size_tx, tx, None).trace())
			.ok()?;
		Some((size_rx.await.ok(), UnboundedReceiverStream::new(rx)))
	}

	/// Instructs the Receiver's task to start receiving a message, which will
	/// make all received packets available on the returned receiver stream.
	/// Blocks until the transporter task is able to start the task.
	pub async fn wait_for(
		&mut self, wait_time: Duration,
	) -> Option<(Option<u32>, impl Stream<Item = Result<Vec<u8>>>)> {
		let (size_tx, size_rx) = oneshot::channel();
		let (tx, rx) = unbounded_channel::<Result<Vec<u8>>>();
		self.sender
			.send(TransporterTask::Receive(size_tx, tx, Some(wait_time)).trace())
			.ok()?;
		Some((size_rx.await.ok(), UnboundedReceiverStream::new(rx)))
	}

	/// Sends the provided message on the connection.
	/// Blocks if it is still sending or receiving something.
	pub async fn send(&mut self, message: Vec<u8>) -> Option<Result<()>> {
		debug_assert!(message.len() > 0, "empty message");
		let (tx, rx) = oneshot::channel();
		self.sender
			.send(TransporterTask::Send(message, tx).trace())
			.ok()?;
		let result = rx.await.ok()?;
		Some(result)
	}

	pub fn send_async(&self, message: Vec<u8>) -> Option<()> {
		debug_assert!(message.len() > 0, "empty message");
		self.sender
			.send(TransporterTask::SendAsync(message).trace())
			.ok()?;
		Some(())
	}
}

impl fmt::Display for TransporterTask {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Receive(_, _, wait_time) => match wait_time {
				None => write!(f, "receive"),
				Some(t) => write!(f, "receive for {:?}", t),
			},
			Self::Send(..) => write!(f, "send"),
			Self::SendAsync(_) => write!(f, "send async"),
			Self::Close(_) => write!(f, "close"),
			Self::CloseAsync => write!(f, "close async"),
			Self::KeepAlive => write!(f, "keep alive"),
		}
	}
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
			size: INITIAL_WINDOW_SIZE,
		}
	}
}


#[cfg(test)]
mod tests {

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

	/*#[tokio::test]
	async fn test_packet() {
		let mut rng = test::initialize_rng();

		// Set up pseudo socket
		let server = UdpServerV4::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1000)).await.unwrap();
		let socket = server.connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1001)).unwrap();
		let (sender, _) = socket.split();

		// Set up DH keys
		let private_key1 = x25519::StaticSecret::random_from_rng(&mut rng);
		let private_key2 = x25519::StaticSecret::random_from_rng(&mut rng);
		//let public_key1 = x25519::PublicKey::from(&private_key1);
		let public_key2 = x25519::PublicKey::from(&private_key2);

		let (transporter, processor) = Transporter::new(
			1, 2,
			Arc::new(sender),
			IdType::default(),
			IdType::default(),
			Duration::from_secs(1),
			private_key1,
			public_key2
		);
	}*/
}

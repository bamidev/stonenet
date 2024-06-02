use std::{future::Future, pin::Pin, sync::Mutex as StdMutex};

use futures::{future::BoxFuture, FutureExt};
use tokio::{
	select,
	sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender},
};

use super::*;
use crate::trace::Mutex;


const DEFAULT_KEEP_ALIVE_IDLE_TIME: Duration = Duration::from_secs(120);

const PACKET_TYPE_HELLO: u8 = 0;
const PACKET_TYPE_HELLO_ACK: u8 = 1;
const PACKET_TYPE_HELLO_ACK_ACK: u8 = 2;
pub(super) const PACKET_TYPE_CRYPTED: u8 = 3;
const PACKET_TYPE_PUNCH_HOLE: u8 = 4;
const PACKET_TYPE_RELAY_HELLO: u8 = 5;
const PACKET_TYPE_RELAY_HELLO_ACK: u8 = 6;
const PACKET_TYPE_RELAY_HELLO_RELAY_ACK: u8 = 7;
const PACKET_TYPE_RELAY_HELLO_ACK_ACK: u8 = 8;
const PACKET_TYPE_RELAYED_HELLO: u8 = 9;
const PACKET_TYPE_RELAYED_HELLO_ACK: u8 = 10;
const PACKET_TYPE_RELAYED_HELLO_ACK_ACK: u8 = 11;


pub type MessageProcessor = dyn Fn(
		Vec<u8>,
		ContactOption,
		NodeContactInfo,
	) -> Pin<Box<dyn Future<Output = MessageProcessorResult> + Send>>
	+ Send
	+ Sync
	+ 'static;
pub type MessageProcessorResult = Option<(Vec<u8>, Option<Box<dyn MessageWorkToDo>>)>;

pub type MessageFinishProcessor = dyn Fn(Result<()>, NodeContactInfo) -> Pin<Box<dyn Future<Output = ()> + Send>>
	+ Send
	+ Sync
	+ 'static;


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayHelloPacket {
	header: RelayHelloPacketHeader,
	body: RelayHelloPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RelayHelloPacketBody {
	target_node_id: NodeAddress,
	base: HelloPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RelayHelloPacketHeader {
	target: SocketAddrSstp,
	base: HelloPacketHeader,
}

pub type RelayHelloAckPacket = RelayedHelloAckPacket;

pub struct RelayInitiationInfo {
	pub local_session_id: u16,
	pub(super) session: Arc<Mutex<SessionData>>,
	pub hello_receiver: HelloReceiver,
	pub(super) packet_receiver: UnboundedReceiver<CryptedPacket>,
	pub dh_private_key: x25519::StaticSecret,
	pub packet: RelayHelloPacket,
}

#[derive(Deserialize, Serialize)]
pub struct RelayedHelloPacketHeader {
	relayer_session_id: u16,
	relayer_public_key: NodePublicKey,
	pub base: HelloPacketHeader,
}

type RelayedHelloPacketBody = RelayHelloPacketBody;

#[derive(Deserialize, Serialize)]
pub struct RelayedHelloPacket {
	pub header: RelayedHelloPacketHeader,
	body: RelayedHelloPacketBody,
}

type RelayedHelloAckPacketHeader = HelloAckPacketHeader;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RelayedHelloAckPacketBody {
	relayer_session_id: u16,
	base: HelloAckPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayedHelloAckPacket {
	header: RelayedHelloAckPacketHeader,
	body: RelayedHelloAckPacketBody,
}

#[derive(Deserialize, Serialize)]
struct HelloAckAckPacket {
	session_id: u16,
	signature: NodeSignature,
}

#[derive(Debug, Deserialize, Serialize)]
struct RelayHelloRelayAckPacket {
	header: RelayHelloRelayAckPacketHeader,
	body: RelayHelloRelayAckPacketBody,
}

type RelayHelloRelayAckPacketHeader = HelloAckPacketHeader;

#[derive(Debug, Deserialize, Serialize)]
struct RelayHelloRelayAckPacketBody {
	source_session_id: u16,
	relayer_session_id: u16,
}

type RelayHelloAckAckPacket = HelloAckAckPacket;

type RelayedHelloAckAckPacket = HelloAckAckPacket;

#[derive(Deserialize, Serialize)]
struct HelloAckPacket {
	header: HelloAckPacketHeader,
	body: HelloAckPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HelloAckPacketHeader {
	node_public_key: identity::NodePublicKey,
	signature: NodeSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HelloAckPacketBody {
	dh_public_key: x25519::PublicKey,
	source_session_id: u16,
	target_session_id: u16,
	contact_info: ContactInfo,
	link_address: SocketAddrSstp,
}

#[derive(Deserialize, Serialize)]
struct HelloPacket {
	header: HelloPacketHeader,
	body: HelloPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct HelloPacketBody {
	dh_public_key: x25519::PublicKey,
	session_id: u16,
	contact_info: ContactInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HelloPacketHeader {
	pub node_public_key: identity::NodePublicKey,
	signature: NodeSignature,
}

type HelloReceiver = mpsc::Receiver<HelloResult>;
pub struct HelloResult {
	node_id: NodeAddress,
	contact_info: ContactInfo,
	encrypt_session_id: u16,
	dest_session_id: u16,
	dh_public_key: x25519::PublicKey,
	opt_response: Option<Vec<u8>>,
}
type HelloSender = mpsc::Sender<HelloResult>;


/// The role of the SSTP server is to receive packets on any available
/// communication method, most notably UDP and TCP over IPv4 or IPv6, and then
/// forward them to the corresponding receiver to be processed.
pub struct Server {
	stop_flag: Arc<AtomicBool>,
	sockets: SocketCollection,
	our_contact_info: StdMutex<ContactInfo>,
	pub(super) sessions: Mutex<Sessions>,
	node_id: NodeAddress,
	private_key: identity::NodePrivateKey,
	default_timeout: Duration,
	// TODO: Remove pub in following line:
	pub message_processors: OnceCell<(Box<MessageProcessor>, Box<MessageFinishProcessor>)>,
}

pub(super) struct SessionData {
	hello_ack_channel: Option<Sender<()>>,
	their_node_id: Option<NodeAddress>,
	last_activity: Arc<StdMutex<SystemTime>>,
	transport_data: SessionTransportData,
	pub(super) keep_alive_timeout: Duration,
}

enum SessionTransportData {
	Direct(SessionTransportDataDirect),
	Relay(SessionTransportDataRelay),
}

struct SessionTransportDataDirect {
	alive_flag: Arc<AtomicBool>,
	dest_session_id: Option<u16>,
	dest_public_key: Option<NodePublicKey>,
	hello_channel: Option<HelloSender>,
	hello_relay_ack_sender: Option<Sender<u16>>,
	packet_processor: mpsc::UnboundedSender<CryptedPacket>,
	relay_node_id: Option<NodeAddress>,
	relay_public_key: Option<NodePublicKey>,
}

struct SessionTransportDataRelay {
	source_session_id: u16,
	source_addr: SocketAddr,
	source_public_key: NodePublicKey,
	source_sender: Arc<dyn LinkSocketSender>,
	target_session_id: u16,
	target_addr: SocketAddr,
	target_node_id: NodeAddress,
	target_public_key: Option<NodePublicKey>,
	target_sender: Option<Arc<dyn LinkSocketSender>>,
	relay_hello_sender: Sender<RelayHelloAckPacket>,
	relay_hello_ack_ack_sender: Option<Sender<u16>>,
}

pub(super) struct Sessions {
	pub(super) map: HashMap<u16, Arc<Mutex<SessionData>>>,
	next_id: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum SocketAddrSstp {
	V4(SocketAddrSstpV4),
	V6(SocketAddrSstpV6),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SocketAddrSstpV4 {
	ip: Ipv4Addr,
	port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SocketAddrSstpV6 {
	ip: Ipv6Addr,
	port: u16,
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


impl Server {
	/// Sets up all necessary sockets internally.
	/// default_timeout: The timeout that incomming connection will be
	/// configured for
	pub async fn bind(
		stop_flag: Arc<AtomicBool>, config: &Config, node_id: NodeAddress,
		private_key: NodePrivateKey, default_timeout: Duration,
	) -> StdResult<Arc<Self>, SocketBindError> {
		let contact_info = ContactInfo::from_config(config);
		Ok(Arc::new(Self {
			stop_flag,
			sockets: SocketCollection::bind(config).await?,
			our_contact_info: StdMutex::new(contact_info),
			sessions: Mutex::new(Sessions::new()),
			node_id,
			private_key,
			default_timeout,
			message_processors: OnceCell::new(),
		}))
	}

	pub async fn clean_sessions(self: &Arc<Self>) {
		let mut sessions = self.sessions.lock().await;
		let mut done_ids = Vec::with_capacity(0);
		for (session_id, session_mutex) in sessions.map.iter() {
			let mut session = session_mutex.lock().await;
			let last_activity = *session.last_activity.lock().unwrap();
			if SystemTime::now().duration_since(last_activity).unwrap()
				>= session.keep_alive_timeout
			{
				match &mut session.transport_data {
					SessionTransportData::Direct(data) =>
						if !data.alive_flag.load(Ordering::Relaxed) {
							done_ids.push(*session_id);
						},
					SessionTransportData::Relay(_) => {
						done_ids.push(*session_id);
					}
				}
			}
		}

		for done_id in done_ids {
			trace!("Closed session during cleanup routine {}.", done_id);
			sessions.map.remove(&done_id).unwrap();
		}
	}

	pub async fn complete_outgoing_relay(
		self: &Arc<Server>, sender: Arc<dyn LinkSocketSender>,
		initiation_data: RelayInitiationInfo, establish_info: HelloResult,
		target_node_id: &NodeAddress, target_addr: SocketAddr, timeout: Duration,
	) -> Result<Box<Connection>> {
		debug_assert!(establish_info.opt_response.is_none());

		// If a specific node ID is expected, test it
		if &establish_info.node_id != target_node_id {
			return trace::err(Error::InvalidNodeId.into());
		}

		let alive_flag = match &mut initiation_data.session.lock().await.transport_data {
			SessionTransportData::Direct(data) => data.alive_flag.clone(),
			_ => panic!("invalid session transport data type"),
		};

		let transporter = Transporter::new_with_receiver(
			alive_flag,
			establish_info.encrypt_session_id,
			initiation_data.local_session_id,
			establish_info.dest_session_id,
			sender,
			self.node_id.clone(),
			establish_info.node_id.clone(),
			timeout,
			initiation_data.dh_private_key,
			establish_info.dh_public_key,
			initiation_data.packet_receiver,
		);
		let transporter_handle = transporter.spawn();

		Ok(Box::new(Connection {
			transporter: transporter_handle,
			server: self.clone(),
			keep_alive_timeout: DEFAULT_KEEP_ALIVE_IDLE_TIME,
			peer_address: target_addr,
			peer_node_info: NodeContactInfo {
				address: establish_info.node_id,
				contact_info: establish_info.contact_info,
			},
			dest_session_id: establish_info.dest_session_id,
			local_session_id: initiation_data.local_session_id,
		}))
	}

	/// Fills the packet data into the given buffer.
	/// Returns whether the request was able to be included into the hello
	/// packet or not.
	fn compose_hello_packet(
		&self, max_len: usize, private_key: &x25519::StaticSecret, session_id: u16,
		request: Option<&[u8]>,
	) -> (Vec<u8>, bool) {
		let dh_public_key = x25519::PublicKey::from(private_key);
		let body = HelloPacketBody {
			dh_public_key,
			session_id,
			contact_info: self.our_contact_info(),
		};

		let body_offset = 1 + 96;
		let request_offset = body_offset + binserde::serialized_size(&body).unwrap();
		let mut buffer =
			vec![PACKET_TYPE_HELLO; request_offset + request.map(|b| b.len()).unwrap_or(0)];

		// Sign request
		binserde::serialize_into(&mut buffer[body_offset..], &body).unwrap();

		// The request can't be encrypted yet because we don't have the public key yet.
		let mut request_included = false;
		if let Some(request_buffer) = request {
			if request_offset + request_buffer.len() < max_len {
				let request_offset = body_offset + binserde::serialized_size(&body).unwrap();
				buffer[request_offset..].copy_from_slice(request_buffer);
				request_included = true;
			}
		}

		// Sign the body with the request together
		let signature = self.private_key.sign(&buffer[body_offset..]);

		// Add the request to the buffer.
		let header = HelloPacketHeader {
			node_public_key: self.private_key.public().clone(),
			signature,
		};
		binserde::serialize_into(&mut buffer[1..], &header).unwrap();

		debug_assert!(request_included || buffer.len() == request_offset);
		(buffer, request_included)
	}

	fn compose_hello_ack_ack_packet(&self, their_session_id: u16) -> Vec<u8> {
		self._compose_hello_ack_ack_packet(PACKET_TYPE_HELLO_ACK_ACK, their_session_id)
	}

	pub async fn connect(
		self: &Arc<Self>, target: &ContactOption, node_id: Option<&NodeAddress>,
		request: Option<&[u8]>,
	) -> Result<(Box<Connection>, Option<Vec<u8>>)> {
		let stop_flag = Arc::new(AtomicBool::new(false));
		self.connect_with_timeout(stop_flag, target, node_id, request, DEFAULT_TIMEOUT)
			.await
	}

	pub async fn connect_with_timeout(
		self: &Arc<Self>, stop_flag: Arc<AtomicBool>, target: &ContactOption,
		node_id: Option<&NodeAddress>, request: Option<&[u8]>, timeout: Duration,
	) -> Result<(Box<Connection>, Option<Vec<u8>>)> {
		let sender = self.link_connect(target, timeout).await?;

		// Spawn transporter before sending out the hello packet, so that it is ready
		// before the hello-ack arrives
		let (packet_sender, packet_receiver) = mpsc::unbounded_channel();
		let (hello_sender, mut hello_receiver) = mpsc::channel(1);
		let alive_flag = Arc::new(AtomicBool::new(true));
		let data = SessionTransportData::Direct(SessionTransportDataDirect {
			alive_flag: alive_flag.clone(),
			relay_node_id: None,
			relay_public_key: None,
			dest_session_id: None,
			dest_public_key: None,
			hello_channel: Some(hello_sender),
			hello_relay_ack_sender: None,
			packet_processor: packet_sender,
		});
		let dh_private_key = x25519::StaticSecret::random_from_rng(OsRng);
		let (local_session_id, _session) = self
			.new_outgoing_session(node_id.map(|id| id.clone()), data, timeout)
			.await
			.ok_or(Error::OutOfSessions)?;

		// Wait for the hello response to arrive while we keep sending hello packets
		let started = SystemTime::now();
		let sleep_time = min(timeout / 4, MAXIMUM_RETRY_TIMEOUT);
		let (hello_packet, hello_request_included) = self.new_hello_packet(
			sender.max_packet_length(),
			&dh_private_key,
			local_session_id,
			request,
		);
		while !stop_flag.load(Ordering::Relaxed)
			&& SystemTime::now().duration_since(started).unwrap() < timeout
		{
			sender.send(&hello_packet).await?;

			tokio::select! {
				result = hello_receiver.recv() => {
					//let (their_node_id, their_contact_info, encrypt_session_id, dest_session_id, their_public_key, mut opt_response) = result.expect("hello oneshot didn't work");
					let mut establish_info = result.unwrap();
					debug_assert!(establish_info.opt_response.is_none() || hello_request_included, "got response in hello-ack even though hello packet didn't contain a request");

					if let Some(mut response_buffer) = establish_info.opt_response.as_mut() {
						// TODO: Prevent the diffie hellman from being generated twice
						let key = KeyState::calculate_initial_key(&dh_private_key, &establish_info.dh_public_key);
						decrypt(local_session_id, 0, 0, &mut response_buffer, &key);
					}

					// If a specific node ID is expected, test it
					match node_id {
						None => {},
						Some(id) => {
							if &establish_info.node_id != id {
								return trace::err(Error::InvalidNodeId.into());
							}
						}
					}

					let transporter = Transporter::new_with_receiver(
						alive_flag,
						establish_info.encrypt_session_id,
						local_session_id,
						establish_info.dest_session_id,
						sender.clone(),
						self.node_id.clone(),
						establish_info.node_id.clone(),
						timeout,
						dh_private_key,
						establish_info.dh_public_key,
						packet_receiver
					);
					let transporter_handle = transporter.spawn();

					if !target.use_tcp {
						self.send_hello_ack_ack_packet(&*sender, establish_info.dest_session_id).await?;
					}
					return Ok((Box::new(Connection {
						transporter: transporter_handle,
						server: self.clone(),
						keep_alive_timeout: DEFAULT_KEEP_ALIVE_IDLE_TIME,
						peer_address: target.target.clone(),
						peer_node_info: NodeContactInfo {
							address: establish_info.node_id,
							contact_info: establish_info.contact_info,
						},
						dest_session_id: establish_info.dest_session_id,
						local_session_id,
					}), establish_info.opt_response));
				},
				_ = sleep(sleep_time) => {}
			}
		}

		// If the connecting task was stopped from an outside force, don't give a
		// timeout error
		if stop_flag.load(Ordering::Relaxed) {
			trace::err(Error::ConnectionClosed)
		} else {
			trace::err(Error::Timeout(timeout))
		}
	}

	/// Gives the connection away to be start listening on it for requests
	pub async fn handle_connection(
		self: &Arc<Self>, connection: Box<Connection>, timeout: Option<Duration>,
	) {
		handle_connection_loop(self.clone(), connection, timeout.unwrap_or(DEFAULT_TIMEOUT)).await;
	}

	/// Connects to the best available IP version and transport option. Only
	/// tries one option. If no matching options were found, returns None.
	/// If successful, returns a sender and a receiver. The receiver is only
	/// relevant if the underlying link socket is connection based.
	pub async fn link_connect(
		self: &Arc<Self>, contact: &ContactOption, timeout: Duration,
	) -> Result<Arc<dyn LinkSocketSender>> {
		fn recursive(
			this: Arc<Server>, contact: ContactOption, sender: Arc<dyn LinkSocketSender>,
			receiver: Box<dyn LinkSocketReceiver>,
		) -> BoxFuture<'static, ()> {
			let sender2 = sender.clone();
			let target2 = contact.target.clone();
			Server::serve_connection_based_socket(
				this.stop_flag.clone(),
				sender2.clone(),
				receiver,
				target2,
				Arc::new(move |_link_socket, address, packet| {
					let this2 = this.clone();
					let sender3 = sender2.clone();
					let address2 = address.clone();
					// FIXME: Make sure packet is received in an arc or box, so that cloning it
					// is effecient
					let packet2 = packet.to_vec();
					spawn(async move {
						match this2.process_packet(sender3, &address2, &packet2).await {
							Ok(()) => {}
							Err(e) => warn!("Sstp io error: {}", e),
						}
					});
				}),
			)
			.boxed()
		}

		let (sender, receiver) = self.sockets.connect(contact, timeout).await?;

		// If we're connecting with a connection-based link protocol, make sure to
		// listen for incomming packets on it
		if sender.is_connection_based() {
			let this = self.clone();
			let contact2 = contact.clone();
			let sender2 = sender.clone();
			spawn(async move {
				recursive(this, contact2, sender2, receiver).await;
			});
		}

		Ok(sender)
	}

	pub fn listen(
		&self,
		message_processor: impl Fn(
			Vec<u8>,
			ContactOption,
			NodeContactInfo,
		) -> Pin<Box<dyn Future<Output = MessageProcessorResult> + Send>>
		+ Send
		+ Sync
		+ 'static,
		on_finish: impl Fn(Result<()>, NodeContactInfo) -> Pin<Box<dyn Future<Output = ()> + Send>>
		+ Send
		+ Sync
		+ 'static,
	) -> bool {
		self.message_processors
			.set((Box::new(message_processor), Box::new(on_finish)))
			.is_ok()
	}

	fn new_hello_packet(
		&self, max_len: usize, private_key: &x25519::StaticSecret, my_session_id: u16,
		request: Option<&[u8]>,
	) -> (Vec<u8>, bool) {
		let (buffer, request_included) =
			self.compose_hello_packet(max_len, private_key, my_session_id, request);
		debug_assert!(buffer.len() <= max_len);
		(buffer, request_included)
	}

	fn new_hello_ack_packet(
		&self, max_len: usize, dh_public_key: x25519::PublicKey, our_session_id: u16,
		their_session_id: u16, addr: &SocketAddr, response: Option<&[u8]>,
	) -> (Vec<u8>, bool) {
		let contact_info = self.our_contact_info();
		let body = HelloAckPacketBody {
			dh_public_key: dh_public_key.clone(),
			source_session_id: their_session_id,
			target_session_id: our_session_id,
			contact_info: contact_info.clone(),
			link_address: addr.clone().into(),
		};

		let body_offset = 1 + 96;
		let response_offset = body_offset + binserde::serialized_size(&body).unwrap();
		let packet_len = response_offset + response.map(|b| b.len()).unwrap_or(0);
		debug_assert!(packet_len <= max_len);
		let mut buffer = vec![PACKET_TYPE_HELLO_ACK; packet_len];
		binserde::serialize_into(&mut buffer[body_offset..], &body).unwrap();

		let response_included = if let Some(response_buffer) = response {
			buffer[response_offset..].copy_from_slice(response_buffer);
			true
		} else {
			false
		};

		let signature = self.private_key.sign(&buffer[body_offset..]);
		let header = HelloAckPacketHeader {
			node_public_key: self.private_key.public(),
			signature,
		};
		binserde::serialize_into(&mut buffer[1..], &header).unwrap();

		(buffer, response_included)
	}

	fn new_relayed_hello_ack_packet(
		&self, max_len: usize, dh_public_key: x25519::PublicKey, relayer_session_id: u16,
		our_session_id: u16, their_session_id: u16, addr: &SocketAddr, response: Option<&[u8]>,
	) -> (Vec<u8>, bool) {
		let contact_info = self.our_contact_info();
		let body = RelayedHelloAckPacketBody {
			relayer_session_id,
			base: HelloAckPacketBody {
				dh_public_key: dh_public_key.clone(),
				source_session_id: their_session_id,
				target_session_id: our_session_id,
				contact_info: contact_info.clone(),
				link_address: addr.clone().into(),
			},
		};

		let body_offset = 1 + 96;
		let response_offset = body_offset + binserde::serialized_size(&body).unwrap();
		let packet_len = response_offset + response.map(|b| b.len()).unwrap_or(0);
		debug_assert!(packet_len <= max_len);
		let mut buffer = vec![PACKET_TYPE_RELAYED_HELLO_ACK; packet_len];
		binserde::serialize_into(&mut buffer[body_offset..], &body).unwrap();

		let response_included = if let Some(response_buffer) = response {
			buffer[response_offset..].copy_from_slice(response_buffer);
			true
		} else {
			false
		};

		let signature = self.private_key.sign(&buffer[body_offset..]);
		let header = RelayedHelloAckPacketHeader {
			node_public_key: self.private_key.public(),
			signature,
		};
		binserde::serialize_into(&mut buffer[1..], &header).unwrap();

		(buffer, response_included)
	}

	async fn new_relay_session(
		&self, source_session_id: u16, source_addr: SocketAddr, source_public_key: NodePublicKey,
		source_sender: Arc<dyn LinkSocketSender>, target_node_id: NodeAddress,
		target_addr: SocketAddr, hello_sender: Sender<RelayedHelloAckPacket>,
		relay_hello_ack_ack_sender: Option<Sender<u16>>, keep_alive_timeout: Duration,
	) -> Result<(u16, Arc<Mutex<SessionData>>)> {
		let transport_data = SessionTransportData::Relay(SessionTransportDataRelay {
			source_session_id,
			source_addr,
			source_public_key,
			source_sender,
			target_session_id: 0,
			target_addr,
			target_node_id: target_node_id.clone(),
			target_public_key: None,
			target_sender: None,
			relay_hello_sender: hello_sender,
			relay_hello_ack_ack_sender,
		});
		let session_data = Arc::new(Mutex::new(SessionData::new(
			Some(target_node_id),
			transport_data,
			keep_alive_timeout,
		)));

		let mut sessions = self.sessions.lock().await;
		let session_id = match sessions.next_id() {
			None => return trace::err(Error::OutOfSessions),
			Some(id) => id,
		};
		sessions.map.insert(session_id, session_data.clone());
		return Ok((session_id, session_data));
	}

	async fn new_incomming_session(
		&self, alive_flag: Arc<AtomicBool>, their_node_id: NodeAddress,
		their_public_key: NodePublicKey, dest_session_id: u16,
		packet_sender: UnboundedSender<CryptedPacket>, timeout: Duration,
	) -> Result<(u16, bool, Arc<Mutex<SessionData>>)> {
		// Check if session doesn't already exists
		let mut sessions = self.sessions.lock().await;
		match sessions
			.find_their_session(&their_node_id, dest_session_id)
			.await
		{
			None => {}
			// If it exists, return None
			Some((our_session_id, session_data)) =>
				return Ok((our_session_id, false, session_data)),
		}
		let transport_data = SessionTransportData::Direct(SessionTransportDataDirect {
			alive_flag,
			dest_session_id: Some(dest_session_id),
			dest_public_key: Some(their_public_key),
			hello_channel: None,
			relay_node_id: None,
			relay_public_key: None,
			packet_processor: packet_sender,
			hello_relay_ack_sender: None,
		});
		let session_data = Arc::new(Mutex::new(SessionData::new(
			Some(their_node_id),
			transport_data,
			timeout,
		)));

		let session_id = match sessions.next_id() {
			None => return trace::err(Error::OutOfSessions),
			Some(id) => id,
		};
		sessions.map.insert(session_id, session_data.clone());
		return Ok((session_id, true, session_data));
	}

	async fn new_outgoing_session(
		&self, their_node_id: Option<NodeAddress>, transport_data: SessionTransportData,
		timeout: Duration,
	) -> Option<(u16, Arc<Mutex<SessionData>>)> {
		let session_data = Arc::new(Mutex::new(SessionData::new(
			their_node_id,
			transport_data,
			timeout,
		)));

		let mut sessions = self.sessions.lock().await;
		let session_id = match sessions.next_id() {
			None => return None,
			Some(id) => id,
		};
		sessions.map.insert(session_id, session_data.clone());
		return Some((session_id, session_data));
	}

	pub fn new_relay_hello_packet(
		&self, target_node_id: NodeAddress, target: &SocketAddr, local_session_id: u16,
		dh_public_key: x25519::PublicKey,
	) -> RelayHelloPacket {
		let target2: SocketAddrSstp = target.clone().into();
		let body = RelayHelloPacketBody {
			target_node_id,
			base: HelloPacketBody {
				dh_public_key,
				session_id: local_session_id,
				contact_info: self.our_contact_info(),
			},
		};
		let buffer = binserde::serialize(&body).unwrap();

		// Sign body and copy header with signature into the buffer
		let signature = self.private_key.sign(&buffer);
		let header = RelayHelloPacketHeader {
			target: target2,
			base: HelloPacketHeader {
				node_public_key: self.private_key.public(),
				signature,
			},
		};

		RelayHelloPacket { header, body }
	}

	pub fn our_contact_info(&self) -> ContactInfo { self.our_contact_info.lock().unwrap().clone() }

	fn parse_hello_packet(buffer: &[u8]) -> Result<(HelloPacket, Option<&[u8]>)> {
		let header: HelloPacketHeader = binserde::deserialize_with_trailing(buffer)?;

		// Verify that the signature is correct
		let body_offset = binserde::serialized_size(&header).unwrap();
		if !header
			.node_public_key
			.verify(&buffer[body_offset..], &header.signature)
		{
			return trace::err(Error::InvalidSignature);
		}

		// Parse the remainder of the hello packet
		let body: HelloPacketBody = binserde::deserialize_with_trailing(&buffer[body_offset..])?;

		let request_offset = body_offset + binserde::serialized_size(&body).unwrap();
		let request = if request_offset < buffer.len() {
			Some(&buffer[request_offset..])
		} else {
			None
		};

		Ok((HelloPacket { header, body }, request))
	}

	pub fn pick_contact_option(&self, target: &ContactInfo) -> Option<(ContactOption, Openness)> {
		self.sockets.pick_contact_option(target)
	}

	async fn process_crypted_packet(&self, buffer: &[u8], sender: &SocketAddr) {
		let session_id = u16::from_le_bytes(*array_ref![buffer, 0, 2]);
		let ks_seq = u16::from_le_bytes(*array_ref![buffer, 2, 2]);
		let seq = u16::from_le_bytes(*array_ref![buffer, 4, 2]);
		let data = buffer[6..].to_vec();
		let packet = CryptedPacket { ks_seq, seq, data };

		let should_close = {
			let sessions = self.sessions.lock().await;
			if let Some(s) = sessions.map.get(&session_id).map(|s| s.clone()) {
				drop(sessions);
				let mut session = s.lock().await;
				*session.last_activity.lock().unwrap() = SystemTime::now();

				match &mut session.transport_data {
					SessionTransportData::Direct(data) =>
						data.packet_processor.send(packet).is_err(),
					SessionTransportData::Relay(data) =>
						if sender == &data.source_addr {
							if let Some(target_socket) = &data.target_sender {
								Self::relay_crypted_packet(
									target_socket,
									data.target_session_id,
									&buffer[2..],
								)
								.await
								.is_err()
							} else {
								error!(
									"Received transport data packet before relay connected with \
									 target."
								);
								false
							}
						} else if sender == &data.target_addr {
							Self::relay_crypted_packet(
								&data.source_sender,
								data.source_session_id,
								&buffer[2..],
							)
							.await
							.is_err()
						} else {
							warn!(
								"Relay transport data packet received from unknown socket address."
							);
							false
						},
				}
			// If the result is an error, the receiving end of the queue has
			// been closed. This happens all the time because connections get
			// closed and then dropped before the other side may be able to send
			// a close packet.
			} else {
				trace!("Invalid session ID: {}", session_id);
				false
			}
		};

		if should_close {
			debug!(
				"Closing session {} because channel is closed already.",
				session_id
			);
			let mut sessions = self.sessions.lock().await;
			sessions.map.remove(&session_id);
		}
	}

	async fn process_relay_hello_ack_packet(self: &Arc<Self>, buffer: &[u8]) -> Result<()> {
		let packet: RelayHelloAckPacket = binserde::deserialize(buffer)?;

		let our_session_id = packet.body.base.source_session_id;
		let session = {
			let sessions = self.sessions.lock().await;
			sessions
				.map
				.get(&our_session_id)
				.ok_or(Error::InvalidSessionId(our_session_id))?
				.clone()
		};
		let (their_node_id, hello_channel) = {
			let session = session.lock().await;

			match &session.transport_data {
				SessionTransportData::Direct(data) => {
					// If the hello_watch is already gone, we've processed this response before
					if data.hello_channel.is_none() {
						trace!("Processed relay-hello-ack packet before.");
						return Ok(());
					}
					// Check if this session is used for relaying
					if data.relay_node_id.is_none() {
						debug!("Session {} is not used for relaying.", our_session_id);
						return Ok(());
					}

					(
						session.their_node_id.clone().unwrap(),
						data.hello_channel.clone().unwrap(),
					)
				}
				_ => panic!("unexpected session transport data type"),
			}
		};

		let body_offset = binserde::serialized_size(&packet.header).unwrap();
		Self::verify_hello_ack_packet_raw(
			&their_node_id,
			&packet.header.node_public_key,
			&packet.header.signature,
			&buffer[body_offset..],
		)?;

		let their_session_id = packet.body.base.target_session_id;
		let relay_session_id = packet.body.relayer_session_id;
		if hello_channel
			.send(HelloResult {
				node_id: their_node_id,
				contact_info: packet.body.base.contact_info,
				encrypt_session_id: their_session_id,
				dest_session_id: relay_session_id,
				dh_public_key: packet.body.base.dh_public_key,
				opt_response: None,
			})
			.await
			.is_err()
		{
			warn!("Unable to send relay-hello-ack info back on hello channel");
		}
		Ok(())
	}

	pub async fn process_relayed_hello_packet_raw(
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, contact: &ContactOption, buffer: &[u8],
	) -> Result<()> {
		let packet: RelayedHelloPacket = binserde::deserialize(buffer)?;
		self.process_relayed_hello_packet(sender, contact, packet)
			.await
	}

	pub async fn process_relayed_hello_packet(
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, contact: &ContactOption,
		packet: RelayedHelloPacket,
	) -> Result<()> {
		Self::verify_hello_packet(
			&packet.header.base.node_public_key,
			&packet.header.base.signature,
			&packet.body,
		)?;

		self._process_hello_packet(
			sender,
			contact,
			packet.header.relayer_session_id,
			packet.body.base.session_id,
			packet.header.base.node_public_key,
			packet.body.base.dh_public_key,
			packet.body.base.contact_info,
			None,
			Some(packet.header.relayer_public_key),
			|max_len,
			 dh_public_key,
			 encrypt_session_id,
			 local_session_id,
			 dest_session_id,
			 addr,
			 response| {
				self.clone().new_relayed_hello_ack_packet(
					max_len,
					dh_public_key.clone(),
					dest_session_id,
					local_session_id,
					encrypt_session_id,
					addr,
					response,
				)
			},
		)
		.await
	}

	pub async fn process_relayed_hello_ack_packet(
		&self, target_socket: &Arc<dyn LinkSocketSender>, target_addr: &SocketAddr,
		packet: RelayedHelloAckPacket,
	) -> Result<()> {
		let relayer_session_id = packet.body.relayer_session_id;
		let session = {
			let sessions = self.sessions.lock().await;
			sessions
				.map
				.get(&relayer_session_id)
				.ok_or(Error::InvalidSessionId(relayer_session_id))?
				.clone()
		};
		let target_session_id = packet.body.base.target_session_id;

		let mut session = session.lock().await;
		match &mut session.transport_data {
			SessionTransportData::Relay(data) => {
				if &data.target_addr != target_addr {
					warn!("Received packets from wrong socket address.");
					return trace::err(Error::InvalidSessionAddress(target_addr.clone()));
				}
				let target_public_key = packet.header.node_public_key.clone();
				if target_public_key.generate_address() != data.target_node_id {
					warn!(
						"Received relayed-hello-ack packet with invalid public key: {:?}",
						&target_public_key
					);
					return Ok(());
				}
				data.target_public_key = Some(target_public_key);
				if data.source_session_id != packet.body.base.source_session_id {
					return trace::err(Error::InvalidSessionId(packet.body.base.source_session_id));
				}
				data.target_session_id = target_session_id;

				let relay_ack_packet: RelayedHelloAckPacket = packet;
				let _ = data.relay_hello_sender.send(relay_ack_packet.clone()).await;
			}
			_ => panic!("unexpected session transport data type"),
		};

		self.send_relayed_hello_ack_ack_packet(&**target_socket, target_session_id)
			.await?;
		Ok(())
	}

	async fn process_relayed_hello_ack_packet_raw(
		&self, buffer: &[u8], target_socket: &Arc<dyn LinkSocketSender>, target_addr: &SocketAddr,
	) -> Result<()> {
		let packet: RelayedHelloAckPacket = binserde::deserialize(buffer)?;
		let body_offset = 96;
		Self::verify_hello_packet_raw(
			&packet.header.node_public_key,
			&packet.header.signature,
			&buffer[body_offset..],
		)?;

		self.process_relayed_hello_ack_packet(target_socket, target_addr, packet)
			.await?;
		Ok(())
	}

	async fn process_first_request(
		&self, buffer: Vec<u8>, contact: ContactOption, node_id: &NodeAddress,
		contact_info: &ContactInfo,
	) -> Option<(Vec<u8>, Option<Box<dyn MessageWorkToDo>>)> {
		let node_info = NodeContactInfo {
			address: node_id.clone(),
			contact_info: contact_info.clone(),
		};
		if let Some((processor, _)) = self.message_processors.get() {
			processor(buffer, contact, node_info).await
		} else {
			warn!("Tried to process message while message processor is not yet set.");
			None
		}
	}

	pub async fn process_relay_hello_packet(
		self: &Arc<Self>, source_socket: Arc<dyn LinkSocketSender>, source_addr: &SocketAddr,
		packet: RelayHelloPacket, relay_hello_ack_ack_sender: Option<Sender<u16>>,
	) -> Result<(
		Arc<dyn LinkSocketSender>,
		RelayedHelloPacket,
		Receiver<RelayedHelloAckPacket>,
	)> {
		Self::verify_hello_packet(
			&packet.header.base.node_public_key,
			&packet.header.base.signature,
			&packet.body,
		)?;

		let target_contact = ContactOption::new(
			packet.header.target.clone().into(),
			source_socket.is_connection_based(),
		);
		let target_node_id = packet.body.target_node_id.clone();
		let (hello_tx, hello_rx) = mpsc::channel(1);
		let (relayer_session_id, session) = self
			.new_relay_session(
				packet.body.base.session_id,
				source_addr.clone(),
				packet.header.base.node_public_key.clone(),
				source_socket.clone(),
				target_node_id,
				packet.header.target.into(),
				hello_tx,
				relay_hello_ack_ack_sender,
				DEFAULT_TIMEOUT,
			)
			.await?;
		if !source_socket.is_connection_based() {
			self.send_relay_hello_relay_ack_packet(
				&*source_socket,
				packet.body.base.session_id,
				relayer_session_id,
			)
			.await?;
		}

		// Open a socket to the target node and put the socket into our session
		let target_tx = self.link_connect(&target_contact, DEFAULT_TIMEOUT).await?;
		match &mut session.lock().await.transport_data {
			SessionTransportData::Relay(data) => {
				data.target_sender = Some(target_tx.clone());
			}
			_ => panic!("invalid session transport data"),
		}

		// Exchange the relayed hello packet
		let relayed_hello = RelayedHelloPacket {
			header: RelayedHelloPacketHeader {
				relayer_session_id,
				relayer_public_key: self.private_key.public(),
				base: packet.header.base,
			},
			body: packet.body,
		};

		Ok((target_tx, relayed_hello, hello_rx))
	}

	async fn process_relay_hello_packet_raw(
		self: &Arc<Self>, source_socket: Arc<dyn LinkSocketSender>, source_addr: &SocketAddr,
		buffer: &[u8],
	) -> Result<()> {
		let packet: RelayHelloPacket = binserde::deserialize(buffer)?;
		let (hello_ack_ack_tx, mut hello_ack_ack_rx) = mpsc::channel(1);
		let (target_tx, relayed_hello, mut hello_rx) = self
			.process_relay_hello_packet(
				source_socket.clone(),
				source_addr,
				packet,
				Some(hello_ack_ack_tx),
			)
			.await?;

		let mut i = 0;
		let hello_result = loop {
			Self::send_packet(&*target_tx, PACKET_TYPE_RELAYED_HELLO, &relayed_hello).await?;

			select! {
				result = hello_rx.recv() => break result,
				_ = sleep(DEFAULT_TIMEOUT / 8) => {
					i += 1;
					if i == 8 {
						return trace::err(Error::Timeout(DEFAULT_TIMEOUT))
					}
				}
			}
		};

		// Send the relayed hello packet back, and wait for the hello-ack-ack packet
		if let Some(relay_hello_ack) = hello_result {
			i = 0;
			loop {
				Self::send_packet(
					&*source_socket,
					PACKET_TYPE_RELAY_HELLO_ACK,
					&relay_hello_ack,
				)
				.await?;

				select! {
					_ = hello_ack_ack_rx.recv() => break,
					_ = sleep(DEFAULT_TIMEOUT / 8) => {
						i += 1;
						if i == 8 {
							return trace::err(Error::Timeout(DEFAULT_TIMEOUT))
						}
					}
				}
			}
		} else {
			warn!("Source node did not respond to relayed hello request.")
		}
		Ok(())
	}

	async fn _process_hello_packet(
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, contact: &ContactOption,
		dest_session_id: u16, encrypt_session_id: u16, public_key: NodePublicKey,
		dh_public_key: x25519::PublicKey, contact_info: ContactInfo, opt_request: Option<&[u8]>,
		relayer_public_key: Option<NodePublicKey>,
		new_packet: impl FnOnce(
			usize,
			&x25519::PublicKey,
			u16,
			u16,
			u16,
			&SocketAddr,
			Option<&[u8]>,
		) -> (Vec<u8>, bool),
	) -> Result<()> {
		let their_node_id = public_key.generate_address();
		let alive_flag = Arc::new(AtomicBool::new(true));
		let (packet_sender, packet_receiver) = mpsc::unbounded_channel();
		let (our_session_id, is_new, session) = self
			.new_incomming_session(
				alive_flag.clone(),
				their_node_id.clone(),
				public_key,
				dest_session_id,
				packet_sender,
				self.default_timeout,
			)
			.await?;

		// Generate DH keypair
		let dh_private_key = x25519::StaticSecret::random_from_rng(OsRng);
		let our_dh_public_key = x25519::PublicKey::from(&dh_private_key);

		let (opt_response, opt_todo) = if let Some(first_request) = opt_request {
			if let Some((mut response, todo)) = self
				.process_first_request(
					first_request.to_vec(),
					contact.clone(),
					&their_node_id,
					&contact_info,
				)
				.await
			{
				// Decrypt the response (TODO: Use the initial key for the newly created
				// transporter)
				let shared_secret =
					KeyState::calculate_initial_key(&dh_private_key, &dh_public_key);
				decrypt(encrypt_session_id, 0, 0, &mut response, &shared_secret);

				(Some(response), todo)
			} else {
				if sender.is_connection_based() {
					spawn(async move {
						sender.close().await.unwrap();
					});
				}
				return Ok(());
			}
		} else {
			(None, None)
		};

		// FIXME: Send back the relayed-hello-ack packet if this is handling a
		// relayed-hello packet
		let (hello_ack, response_included) = new_packet(
			sender.max_packet_length(),
			&our_dh_public_key,
			encrypt_session_id,
			our_session_id,
			dest_session_id,
			&contact.target,
			opt_response.as_ref().map(|b| &**b),
		);

		// If the connection was already created before, just return the response again.
		// The other side might not have received the hello response packet
		if !is_new {
			{
				let session = session.lock().await;
				*session.last_activity.lock().unwrap() = SystemTime::now();
			}

			sender.send(&hello_ack).await?;
			return Ok(());
		}

		let (hello_ack_tx, mut hello_ack_rx) = mpsc::channel(1);
		{
			let mut s = session.lock().await;
			match &mut s.transport_data {
				SessionTransportData::Direct(data) => {
					data.relay_public_key = relayer_public_key;
				}
				_ => {
					panic!("unexpected transport type");
				}
			};

			s.hello_ack_channel = Some(hello_ack_tx);
		};

		// Spawn transporter
		let transporter = Transporter::new_with_receiver(
			alive_flag,
			encrypt_session_id,
			our_session_id,
			dest_session_id,
			sender.clone(),
			self.node_id.clone(),
			their_node_id.clone(),
			self.default_timeout,
			dh_private_key,
			dh_public_key,
			packet_receiver,
		);
		let transporter_handle = transporter.spawn();

		// Send hello-ack packet back after the session has been set up, and wait until
		// it has been received by the other side.
		// Or if on a connection-based socket already, don't wait fo the ack from the
		// other side.
		if sender.is_connection_based() {
			sender.send(&hello_ack).await?;
		} else {
			for i in 0..8 {
				sender.send(&hello_ack).await?;

				select! {
					_ = hello_ack_rx.recv() => break,
					_ = sleep(self.default_timeout / 8) => {
						if i == 7 {
							return Err(Error::Timeout(self.default_timeout).trace());
						}
					}
				}
			}
		}

		// Transporter is running, set up the connection object and pass it along
		let peer_node_info = NodeContactInfo {
			address: their_node_id,
			contact_info,
		};
		let connection = Box::new(Connection {
			transporter: transporter_handle.clone(),
			server: self.clone(),
			keep_alive_timeout: self.default_timeout,
			peer_address: contact.target.clone(),
			peer_node_info: peer_node_info.clone(),
			dest_session_id,
			local_session_id: our_session_id,
		});

		// If there is a response already, but we've not been able to send it on the
		// back already on the hello-ack packet, do it as the first task on the
		// connection transporter.
		if let Some(response) = opt_response {
			if !response_included {
				transporter_handle.send_async(response).unwrap();
			}
		}

		// Perform the remaining communication work if the request was passed along on
		// the hello packet.
		let result = if let Some(mut todo) = opt_todo {
			// If the connection required more work to be done on it, do that before passing
			// it to the connection handler
			todo.run(connection).await
		} else {
			Ok(Some(connection))
		};

		if let Some((_, on_finish)) = self.message_processors.get() {
			match result {
				Err(e) => on_finish(Err(e), peer_node_info).await,
				Ok(opt_connection) => {
					on_finish(Ok(()), peer_node_info).await;

					if let Some(c) = opt_connection {
						handle_connection_loop(self.clone(), c, DEFAULT_TIMEOUT).await;
					}
				}
			}
		}
		Ok(())
	}

	async fn process_hello_packet(
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, addr: &ContactOption, buffer: &[u8],
	) -> Result<()> {
		let (hello, first_request_opt) = Self::parse_hello_packet(buffer)?;

		let mut their_contact_info = hello.body.contact_info.clone();
		their_contact_info.update(&addr.target, addr.use_tcp);

		self._process_hello_packet(
			sender,
			addr,
			hello.body.session_id,
			hello.body.session_id,
			hello.header.node_public_key,
			hello.body.dh_public_key,
			hello.body.contact_info,
			first_request_opt,
			None,
			|max_len, dh_public_key, _, local_session_id, dest_session_id, addr, response| {
				self.clone().new_hello_ack_packet(
					max_len,
					dh_public_key.clone(),
					local_session_id,
					dest_session_id,
					addr,
					response,
				)
			},
		)
		.await
	}

	async fn process_hello_ack_packet(
		&self, link_socket: &Arc<dyn LinkSocketSender>, sender: &SocketAddr,
		connection_based: bool, buffer: &[u8],
	) -> Result<()> {
		let body_offset = 96;
		let packet: HelloAckPacket = binserde::deserialize_with_trailing(buffer)?;
		debug_assert!(sender.is_ipv4() == packet.body.link_address.is_ipv4());
		let response_offset = binserde::serialized_size(&packet).unwrap();

		// Get some info from the session the packet is directed to
		let our_session_id = packet.body.source_session_id;
		let session = {
			let sessions = self.sessions.lock().await;
			sessions
				.map
				.get(&our_session_id)
				.ok_or(Error::InvalidSessionId(our_session_id))?
				.clone()
		};

		let (their_node_id, hello_channel) = {
			let mut session = session.lock().await;
			let their_node_id = session
				.their_node_id
				.clone()
				.unwrap_or(packet.header.node_public_key.generate_address());

			// Verify if the packet is correct
			Self::verify_hello_ack_packet_raw(
				&their_node_id,
				&packet.header.node_public_key,
				&packet.header.signature,
				&buffer[body_offset..],
			)?;

			// Update our own contact info
			self.our_contact_info
				.lock()
				.unwrap()
				.update(&packet.body.link_address.into(), connection_based);

			match &mut session.transport_data {
				SessionTransportData::Direct(data) => {
					// If the hello_watch is already gone, we've processed this response before
					if data.hello_channel.is_none() {
						return Ok(());
					}
					// Check if this session is used for relaying
					if data.relay_node_id.is_some() {
						debug!("Session {} is not used for relaying.", our_session_id);
						return Ok(());
					}

					(their_node_id, data.hello_channel.take())
				}
				_ => panic!("unexpected session transport data type"),
			}
		};

		// Send the hello-ack-ack packet to the other side
		let their_session_id = packet.body.target_session_id;
		if !connection_based {
			let packet = self.compose_hello_ack_ack_packet(their_session_id);
			let r = link_socket.send(&packet).await;
			debug_assert!(r.is_ok(), "unable to send hello-ack-ack packet");
		}

		// Move the HelloResult data to the hello channel
		if let Some(tx) = hello_channel {
			let opt_response = if buffer.len() > response_offset {
				Some(buffer[response_offset..].to_vec())
			} else {
				None
			};
			if tx
				.send(HelloResult {
					node_id: their_node_id,
					contact_info: packet.body.contact_info,
					dest_session_id: their_session_id,
					encrypt_session_id: their_session_id,
					dh_public_key: packet.body.dh_public_key,
					opt_response,
				})
				.await
				.is_err()
			{
				error!("Unable to send hello-ack info back on hello channel");
			}
		} else {
			error!("Unable to send hello-ack info back on hello channel");
		}
		Ok(())
	}

	async fn process_hello_ack_ack_packet(&self, buffer: &[u8]) -> Result<()> {
		let packet: HelloAckAckPacket = binserde::deserialize(&buffer)?;

		let sessions = self.sessions.lock().await;
		if let Some(s) = sessions.map.get(&packet.session_id) {
			let s2 = s.clone();
			drop(sessions);

			let mut session = s2.lock().await;
			match &session.transport_data {
				SessionTransportData::Direct(data) => {
					let public_key = data.dest_public_key.as_ref().unwrap();
					if !public_key.verify(&packet.session_id.to_le_bytes(), &packet.signature) {
						warn!("Received hello-ack-ack packet with invalid signature.");
						return Ok(());
					}
				}
				_ => panic!("invalid session transport data"),
			}
			if let Some(tx) = session.hello_ack_channel.take() {
				let _ = tx.send(()).await;
			}
		}
		Ok(())
	}

	async fn process_relay_hello_ack_ack_packet(&self, buffer: &[u8]) -> Result<()> {
		let packet: RelayHelloAckAckPacket = binserde::deserialize(&buffer)?;

		let sessions = self.sessions.lock().await;
		if let Some(s) = sessions.map.get(&packet.session_id) {
			let s2 = s.clone();
			drop(sessions);

			let mut session = s2.lock().await;
			let hello_relay_ack_sender = match &mut session.transport_data {
				SessionTransportData::Relay(data) => {
					// Verify signature
					if !data
						.source_public_key
						.verify(&packet.session_id.to_le_bytes(), &packet.signature)
					{
						warn!("Received relay-hello-ack-ack packet with invalid signature.");
						return Ok(());
					}

					data.relay_hello_ack_ack_sender.take()
				}
				_ => panic!("invalid session transport data"),
			};

			if let Some(tx) = hello_relay_ack_sender {
				let _ = tx.send(packet.session_id).await;
			}
		}
		Ok(())
	}

	async fn process_relay_hello_relay_ack_packet(&self, buffer: &[u8]) -> Result<()> {
		let packet: RelayHelloRelayAckPacket = binserde::deserialize(&buffer)?;

		let sessions = self.sessions.lock().await;
		if let Some(s) = sessions.map.get(&packet.body.source_session_id) {
			let s2 = s.clone();
			drop(sessions);
			let mut session = s2.lock().await;
			let hello_relay_ack_sender = match &mut session.transport_data {
				SessionTransportData::Direct(data) => {
					// Verify public key
					let relay_public_key = packet.header.node_public_key;
					if &relay_public_key.generate_address() != data.relay_node_id.as_ref().unwrap()
					{
						warn!("Received relay-hello-relay-ack packet with invalid public key.");
						return Ok(());
					}

					// Verify signature
					let body_offset = 96;
					if !relay_public_key.verify(&buffer[body_offset..], &packet.header.signature) {
						warn!("Received relay-hello-relay-ack packet with invalid signature.");
						return Ok(());
					}

					data.hello_relay_ack_sender.take()
				}
				_ => panic!("invalid session transport data"),
			};
			if let Some(tx) = hello_relay_ack_sender {
				let _ = tx.send(packet.body.relayer_session_id).await;
			}
		}
		Ok(())
	}

	async fn process_relayed_hello_ack_ack_packet(&self, buffer: &[u8]) -> Result<()> {
		let packet: RelayedHelloAckAckPacket = binserde::deserialize(&buffer)?;

		let sessions = self.sessions.lock().await;
		if let Some(s) = sessions.map.get(&packet.session_id) {
			let s2 = s.clone();
			drop(sessions);

			let mut session = s2.lock().await;
			match &mut session.transport_data {
				SessionTransportData::Direct(data) => {
					let public_key = data.relay_public_key.as_ref().unwrap();
					if !public_key.verify(&packet.session_id.to_le_bytes(), &packet.signature) {
						warn!("Received relayed-hello-ack-ack packet with invalid signature.");
						return Ok(());
					}
				}
				_ => panic!("invalid session transport data"),
			}

			if let Some(tx) = session.hello_ack_channel.take() {
				let _ = tx.send(()).await;
			}
		}
		Ok(())
	}

	async fn process_packet(
		self: &Arc<Self>, link_socket: Arc<dyn LinkSocketSender>, contact: &ContactOption,
		packet: &[u8],
	) -> Result<()> {
		let message_type = packet[0];
		let buffer = &packet[1..];
		match message_type {
			PACKET_TYPE_HELLO =>
				self.process_hello_packet(link_socket, contact, buffer)
					.await,
			PACKET_TYPE_HELLO_ACK =>
				self.process_hello_ack_packet(
					&link_socket,
					&contact.target,
					link_socket.is_connection_based(),
					buffer,
				)
				.await,
			PACKET_TYPE_HELLO_ACK_ACK => self.process_hello_ack_ack_packet(&buffer).await,
			PACKET_TYPE_CRYPTED => {
				self.process_crypted_packet(buffer, &contact.target).await;
				Ok(())
			}
			PACKET_TYPE_RELAY_HELLO =>
				self.process_relay_hello_packet_raw(link_socket, &contact.target, buffer)
					.await,
			PACKET_TYPE_RELAY_HELLO_ACK => self.process_relay_hello_ack_packet(buffer).await,
			PACKET_TYPE_RELAY_HELLO_RELAY_ACK =>
				self.process_relay_hello_relay_ack_packet(&buffer).await,
			PACKET_TYPE_RELAY_HELLO_ACK_ACK =>
				self.process_relay_hello_ack_ack_packet(&buffer).await,
			PACKET_TYPE_RELAYED_HELLO =>
				self.process_relayed_hello_packet_raw(link_socket, contact, buffer)
					.await,
			PACKET_TYPE_RELAYED_HELLO_ACK =>
				self.process_relayed_hello_ack_packet_raw(buffer, &link_socket, &contact.target)
					.await,
			PACKET_TYPE_RELAYED_HELLO_ACK_ACK =>
				self.process_relayed_hello_ack_ack_packet(&buffer).await,
			// Hole punching packets don't need to be responded to. They don't have any data other
			// than the message type anyway.
			PACKET_TYPE_PUNCH_HOLE => Ok(()),
			other => trace::err(Error::InvalidMessageType(other)),
		}
	}

	/// Opens a relay connection to another node, through a relay node. This
	/// only works if the relay node has relaying enabled.
	/// The only use this has is for when the target node is able to receive
	/// connections (bidirectional), but we know our external IP address is
	/// blocked by their firewall somehow.
	#[allow(dead_code)]
	pub async fn relay(
		self: &Arc<Self>, relay: &ContactOption, relay_node_id: NodeAddress, target: SocketAddr,
		target_node_id: &NodeAddress,
	) -> Result<Box<Connection>> {
		let stop_flag = Arc::new(AtomicBool::new(false));
		self.relay_with_timeout(
			stop_flag,
			relay,
			relay_node_id,
			target,
			target_node_id,
			2 * DEFAULT_TIMEOUT,
		)
		.await
	}

	pub async fn relay_with_timeout(
		self: &Arc<Self>, stop_flag: Arc<AtomicBool>, relay: &ContactOption,
		relay_node_id: NodeAddress, target_addr: SocketAddr, target_node_id: &NodeAddress,
		timeout: Duration,
	) -> Result<Box<Connection>> {
		let sender = self.link_connect(relay, timeout).await?;

		let (hello_relay_ack_tx, mut hello_relay_ack_rx) = mpsc::channel(1);
		let mut initiation_info = self
			.setup_outgoing_relay(
				relay_node_id,
				target_node_id.clone(),
				&target_addr,
				timeout,
				Some(hello_relay_ack_tx),
			)
			.await?;

		let sleep_time = min(timeout / 8, MAXIMUM_RETRY_TIMEOUT);

		// Send hello packet to relay node
		let mut raw_packet = vec![
			PACKET_TYPE_RELAY_HELLO;
			1 + binserde::serialized_size(&initiation_info.packet).unwrap()
		];
		binserde::serialize_into(&mut raw_packet[1..], &initiation_info.packet).unwrap();
		let started = SystemTime::now();
		loop {
			sender.send(&raw_packet).await?;

			select! {
				_ = hello_relay_ack_rx.recv() => break,
				_ = sleep(sleep_time) => {
					if stop_flag.load(Ordering::Relaxed) || SystemTime::now().duration_since(started).unwrap() >= timeout {
						return trace::err(Error::Timeout(timeout));
					}
				}
			}
		}

		// Receive relay-hello-ack packet from relay node
		tokio::select! {
			result = initiation_info.hello_receiver.recv() => {
				let establish_info = result.unwrap();

				if !relay.use_tcp {
					self.send_relay_hello_ack_ack_packet(&*sender, establish_info.dest_session_id).await?;
				}

				let connection = self.complete_outgoing_relay(sender, initiation_info, establish_info, target_node_id, target_addr, timeout).await?;
				Ok(connection)
			},
			_ = sleep(timeout) => {
				trace::err(Error::Timeout(timeout))
			}
		}
	}

	async fn relay_crypted_packet(
		sender: &Arc<dyn LinkSocketSender>, new_session_id: u16, buffer: &[u8],
	) -> io::Result<()> {
		let mut new_buffer = Vec::with_capacity(3 + buffer.len());
		new_buffer.push(PACKET_TYPE_CRYPTED);
		new_buffer.extend(new_session_id.to_le_bytes());
		new_buffer.extend(buffer);

		sender.send(&new_buffer).await
	}

	async fn send_hello_ack_ack_packet(
		&self, sender: &dyn LinkSocketSender, session_id: u16,
	) -> Result<()> {
		let buffer = self._compose_hello_ack_ack_packet(PACKET_TYPE_HELLO_ACK_ACK, session_id);
		sender.send(&buffer).await?;
		Ok(())
	}

	pub async fn send_punch_hole_packet(self: &Arc<Self>, contact: &ContactOption) -> Result<()> {
		let tx = self.link_connect(contact, self.default_timeout).await?;
		let buffer = vec![PACKET_TYPE_PUNCH_HOLE; 1];
		tx.send(&buffer).await?;
		Ok(())
	}

	async fn send_packet<P>(
		sender: &dyn LinkSocketSender, packet_type: u8, packet: &P,
	) -> Result<()>
	where
		P: Serialize,
	{
		let packet_len = binserde::serialized_size(packet).unwrap();
		let mut buffer = vec![packet_type; 1 + packet_len];
		binserde::serialize_into(&mut buffer[1..], packet).unwrap();
		sender.send(&buffer).await?;
		Ok(())
	}

	fn _compose_hello_ack_ack_packet(&self, packet_type: u8, session_id: u16) -> Vec<u8> {
		let signature = self.private_key.sign(&session_id.to_le_bytes());
		let packet = HelloAckAckPacket {
			session_id,
			signature,
		};
		let packet_len = binserde::serialized_size(&packet).unwrap();
		let mut buffer = vec![packet_type; 1 + packet_len];
		binserde::serialize_into(&mut buffer[1..], &packet).unwrap();
		buffer
	}

	async fn send_relay_hello_relay_ack_packet(
		&self, sender: &dyn LinkSocketSender, source_session_id: u16, relayer_session_id: u16,
	) -> Result<()> {
		let body_offset = 1 + 96;
		let body = RelayHelloRelayAckPacketBody {
			source_session_id,
			relayer_session_id,
		};
		let packet_len = body_offset + binserde::serialized_size(&body).unwrap();
		let mut buffer = vec![PACKET_TYPE_RELAY_HELLO_RELAY_ACK; packet_len];

		binserde::serialize_into(&mut buffer[body_offset..packet_len], &body).unwrap();
		let signature = self.private_key.sign(&buffer[body_offset..]);

		let header = RelayHelloRelayAckPacketHeader {
			node_public_key: self.private_key.public(),
			signature,
		};
		binserde::serialize_into(&mut buffer[1..], &header).unwrap();
		sender.send(&buffer).await?;
		Ok(())
	}

	async fn send_relay_hello_ack_ack_packet(
		&self, sender: &dyn LinkSocketSender, session_id: u16,
	) -> Result<()> {
		let buffer =
			self._compose_hello_ack_ack_packet(PACKET_TYPE_RELAY_HELLO_ACK_ACK, session_id);
		sender.send(&buffer).await?;
		Ok(())
	}

	async fn send_relayed_hello_ack_ack_packet(
		&self, sender: &dyn LinkSocketSender, session_id: u16,
	) -> Result<()> {
		let buffer =
			self._compose_hello_ack_ack_packet(PACKET_TYPE_RELAYED_HELLO_ACK_ACK, session_id);
		sender.send(&buffer).await?;
		Ok(())
	}

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
							trace!("TCP connection closed {}.", &addr);
							let _ = sender.close().await;
						}
						_ => warn!("TCP I/O error: {}", e),
					}
					return;
				}
				Ok(packet) => on_packet(sender.clone(), &ContactOption::new(addr, true), &packet),
			}
		}
	}

	pub fn set_contact_info(&self, contact_info: ContactInfo) {
		*self.our_contact_info.lock().unwrap() = contact_info;
	}

	pub async fn set_next_session_id(&self, id: u16) { self.sessions.lock().await.next_id = id; }

	pub async fn setup_outgoing_relay(
		&self, relay_node_id: NodeAddress, target_node_id: NodeAddress, target: &SocketAddr,
		timeout: Duration, hello_relay_ack_sender: Option<Sender<u16>>,
	) -> Result<RelayInitiationInfo> {
		let (packet_sender, packet_receiver) = mpsc::unbounded_channel();
		let (hello_sender, hello_receiver) = mpsc::channel(1);
		let transport_data = SessionTransportData::Direct(SessionTransportDataDirect {
			alive_flag: Arc::new(AtomicBool::new(true)),
			dest_session_id: None,
			dest_public_key: None,
			packet_processor: packet_sender,
			hello_channel: Some(hello_sender),
			hello_relay_ack_sender,
			relay_node_id: Some(relay_node_id),
			relay_public_key: None,
		});
		let (local_session_id, session) = self
			.new_outgoing_session(Some(target_node_id.clone()), transport_data, timeout)
			.await
			.ok_or(Error::OutOfSessions)?;

		let dh_private_key = x25519::StaticSecret::random_from_rng(OsRng);
		let dh_public_key = x25519::PublicKey::from(&dh_private_key);
		let packet =
			self.new_relay_hello_packet(target_node_id, target, local_session_id, dh_public_key);
		Ok(RelayInitiationInfo {
			local_session_id,
			session,
			hello_receiver,
			packet_receiver,
			dh_private_key,
			packet,
		})
	}

	pub fn spawn(self: &Arc<Self>) {
		self.clone().spawn_garbage_collector();

		let this = self.clone();
		self.sockets
			.spawn_servers(self.stop_flag.clone(), move |sender, contact, packet| {
				let this2 = this.clone();
				let sender2 = sender.clone();
				let contact2 = contact.clone();
				let packet2 = packet.to_vec();
				spawn(async move {
					match this2.process_packet(sender2, &contact2, &packet2).await {
						Ok(()) => {}
						Err(e) => match *e {
							// A connection could be closed by the other end at any time, which is
							// considered reasonable.
							Error::ConnectionClosed => {}
							Error::Timeout(timeout) =>
								warn!("Timeout ({:?}) with {}.", timeout, &contact2),
							_ => warn!("SSTP I/O error with {}: {:?}", &contact2, e),
						},
					}
				});
			});
	}

	/// Gives the connection away to be start listening on it for requests
	pub fn spawn_connection(
		self: &Arc<Self>, connection: Box<Connection>, timeout: Option<Duration>,
	) {
		let this = self.clone();
		spawn(async move {
			handle_connection_loop(this, connection, timeout.unwrap_or(DEFAULT_TIMEOUT)).await;
		});
	}

	/// Starts garbage collecting the unresponded requests.
	pub fn spawn_garbage_collector(self: Arc<Self>) {
		tokio::task::spawn(async move {
			let this = self.clone();
			while !self.stop_flag.load(Ordering::Relaxed) {
				sleep(DEFAULT_TIMEOUT).await;
				this.clean_sessions().await;
			}
		});
	}

	fn verify_hello_ack_packet_raw(
		node_id: &NodeAddress, public_key: &NodePublicKey, signature: &NodeSignature, buffer: &[u8],
	) -> Result<()> {
		// Verify node ID
		if &public_key.generate_address_v1() != node_id.as_id().as_ref() {
			return trace::err(Error::InvalidNodeId);
		}

		// Verify signature
		if !public_key.verify(buffer, signature) {
			return trace::err(Error::InvalidSignature);
		}
		Ok(())
	}

	fn verify_hello_packet<B>(
		public_key: &NodePublicKey, signature: &NodeSignature, body: &B,
	) -> Result<()>
	where
		B: Serialize,
	{
		// Verify signature
		let signature_message = binserde::serialize(body).unwrap();
		if !public_key.verify(&signature_message, signature) {
			return trace::err(Error::InvalidSignature);
		}
		Ok(())
	}

	fn verify_hello_packet_raw(
		public_key: &NodePublicKey, signature: &NodeSignature, buffer: &[u8],
	) -> Result<()> {
		// Verify signature
		if !public_key.verify(buffer, signature) {
			return trace::err(Error::InvalidSignature);
		}
		Ok(())
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
		on_packet: impl Fn(Arc<dyn LinkSocketSender>, &ContactOption, &[u8]) + Send + Sync + 'static,
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

impl SessionData {
	fn new(
		their_node_id: Option<NodeAddress>, transport_data: SessionTransportData, timeout: Duration,
	) -> Self {
		Self {
			hello_ack_channel: None,
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
			their_node_id,
			keep_alive_timeout: timeout,
			transport_data,
		}
	}
}

impl Sessions {
	pub async fn find_their_session(
		&self, their_node_id: &NodeAddress, their_session_id: u16,
	) -> Option<(u16, Arc<Mutex<SessionData>>)> {
		for (our_session_id, session_data_mutex) in self.map.iter() {
			let session_data = session_data_mutex.lock().await;
			match &session_data.transport_data {
				SessionTransportData::Direct(data) => {
					if session_data.their_node_id.is_some()
						&& session_data.their_node_id.as_ref().unwrap() == their_node_id
						&& data.dest_session_id.is_some()
						&& data.dest_session_id.unwrap() == their_session_id
					{
						return Some((*our_session_id, session_data_mutex.clone()));
					}
				}
				_ => {}
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
			self.next_id = self.next_id.wrapping_add(1);
			i += 1;

			if i == 0xFFFF {
				return None;
			}
		}
		let new_id = self.next_id;
		self.next_id = self.next_id.wrapping_add(1);
		Some(new_id)
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

impl SocketCollection {
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

	#[allow(dead_code)]
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

	async fn connect(
		&self, contact: &ContactOption, timeout: Duration,
	) -> Result<(Arc<dyn LinkSocketSender>, Box<dyn LinkSocketReceiver>)> {
		match &contact.target {
			SocketAddr::V4(a) => match &self.ipv4 {
				None => {}
				Some(servers) =>
					if !contact.use_tcp {
						match &servers.udp {
							None => {}
							Some(server) => {
								let (tx, rx) = server.inner.connect(a.clone())?.split();
								return Ok((Arc::new(tx), Box::new(rx)));
							}
						}
					} else {
						match &servers.tcp {
							None => {}
							Some(server) => {
								let (tx, rx) =
									server.inner.connect(a.clone(), timeout).await?.split();
								return Ok((Arc::new(tx), Box::new(rx)));
							}
						}
					},
			},
			SocketAddr::V6(a) => match &self.ipv6 {
				None => {}
				Some(servers) =>
					if !contact.use_tcp {
						match &servers.udp {
							None => {}
							Some(server) => {
								let (tx, rx) = server.inner.connect(a.clone())?.split();
								return Ok((Arc::new(tx), Box::new(rx)));
							}
						}
					} else {
						match &servers.tcp {
							None => {}
							Some(server) => {
								let (tx, rx) =
									server.inner.connect(a.clone(), timeout).await?.split();
								return Ok((Arc::new(tx), Box::new(rx)));
							}
						}
					},
			},
		}
		trace::err(Error::NoConnectionOptions)
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
						let contact = ContactOption::new(addr2, false);
						let (sender, _) = this
							.inner
							.connect(addr.try_into().unwrap())
							.expect("no error expected")
							.split();
						on_packet(Arc::new(sender), &contact, &packet);
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


impl SocketAddrSstp {
	fn is_ipv4(&self) -> bool {
		match self {
			Self::V4(_) => true,
			_ => false,
		}
	}
}

impl From<SocketAddr> for SocketAddrSstp {
	fn from(original: SocketAddr) -> Self {
		match original {
			SocketAddr::V4(v4) => {
				let addr = SocketAddrSstpV4 {
					ip: v4.ip().clone(),
					port: v4.port(),
				};
				Self::V4(addr)
			}
			SocketAddr::V6(v6) => {
				let addr = SocketAddrSstpV6 {
					ip: v6.ip().clone(),
					port: v6.port(),
				};
				Self::V6(addr)
			}
		}
	}
}

impl From<RelayHelloAckPacket> for HelloResult {
	fn from(other: RelayHelloAckPacket) -> Self {
		Self {
			node_id: other.header.node_public_key.generate_address(),
			contact_info: other.body.base.contact_info,
			encrypt_session_id: other.body.base.target_session_id,
			dest_session_id: other.body.relayer_session_id,
			dh_public_key: other.body.base.dh_public_key,
			opt_response: None,
		}
	}
}

impl Into<SocketAddr> for SocketAddrSstp {
	fn into(self) -> SocketAddr {
		match self {
			SocketAddrSstp::V4(v4) => {
				let addr = SocketAddrV4::new(v4.ip, v4.port);
				SocketAddr::V4(addr)
			}
			SocketAddrSstp::V6(v6) => {
				let addr = SocketAddrV6::new(v6.ip, v6.port, 0, 0);
				SocketAddr::V6(addr)
			}
		}
	}
}


async fn handle_connection_loop(
	server: Arc<Server>, connection_original: Box<Connection>, timeout: Duration,
) {
	let mut result = Some(connection_original);
	while let Some(mut connection) = result.take() {
		match connection.wait_for(timeout).await {
			Err(e) => {
				match &*e {
					Error::ConnectionClosed => {}
					_ => {
						error!("Unable to receive request from connection: {:?}", e);
					}
				}
				return;
			}
			Ok(message) => {
				if message.len() == 0 {
					error!("Received empty message.");
					return;
				}

				let (processor, on_finish) = if let Some(r) = server.message_processors.get() {
					r
				} else {
					error!(
						"Not processing the connection {}, because the message processors aren't \
						 set.",
						connection.local_session_id
					);
					return;
				};
				if let Some((response, opt_todo)) = processor(
					message,
					connection.contact_option(),
					connection.their_node_info().clone(),
				)
				.await
				{
					// An empty response means: send nothing.
					if response.len() > 0 {
						match connection.send(response).await {
							Ok(_) => {}
							Err(e) => {
								warn!("Unable to respond to request on connection: {:?}", e);
								return;
							}
						}
					}

					let node_info = connection.their_node_info().clone();
					if let Some(mut todo) = opt_todo {
						match todo.run(connection).await {
							Err(e) => on_finish(Err(e), node_info).await,
							Ok(r) => {
								result = r;
								on_finish(Ok(()), node_info).await;
							}
						}
					} else {
						result = Some(connection);
					}
				} else {
					result = None;
				}
			}
		}
	}
}

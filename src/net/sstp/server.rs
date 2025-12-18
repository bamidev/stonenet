//! The server module of SSTP takes care of all packet communication between nodes.
//! The packets are processed and passed along to the functions/processors that correspond with the
//! appropriate connection.
//!
//! A regular SSTP connection flows as follows:
//! * Source node sents a hello packet to target node.
//! * Target node sents a hello-ack packet back to source node upon receiving the hello packet.
//! * Source node sents a hello-ack-ack packet back to the target node.
//! * A connection has been established, and the source node starts sending a window
//! *
//! A relayed SSTP connection flows as follows:
//! * Source node sents a relay-hello packet to relay node.
//! * Relay node sents a relay-ack packet to relay node.
//! * Relay node sents a relayed-hello packet to target node.
//! * Target node sents a relayed-hello-ack packet to relay node.
//! * Relay node sents a relay-ready packet back to source node.The target node is ready to receive
//!   any data packets at this point.
//! * Source node sents a relay-ready-ack packet back to relay node.
use std::{future::Future, pin::Pin, sync::Mutex as StdMutex};

use futures::{future::BoxFuture, FutureExt};
use tokio::{
	select,
	sync::mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender},
};

use super::*;
use crate::{
	net::socket::{TcpServerV4, TcpServerV6, UdpServerV4, UdpServerV6},
	trace::Mutex,
};
use std::backtrace::Backtrace;

const DEFAULT_KEEP_ALIVE_IDLE_TIME: Duration = Duration::from_secs(120);

const PACKET_TYPE_HELLO: u8 = 0;
const PACKET_TYPE_HELLO_ACK: u8 = 1;
const PACKET_TYPE_HELLO_ACK_ACK: u8 = 2;
pub(super) const PACKET_TYPE_CRYPTED: u8 = 3;
const PACKET_TYPE_PUNCH_HOLE: u8 = 4;
const PACKET_TYPE_RELAY_HELLO: u8 = 5;
const PACKET_TYPE_RELAY_HELLO_ACK: u8 = 6;
const PACKET_TYPE_RELAY_READY: u8 = 7;
const PACKET_TYPE_RELAY_READY_ACK: u8 = 8;
const PACKET_TYPE_RELAYED_HELLO: u8 = 9;
const PACKET_TYPE_RELAYED_HELLO_ACK: u8 = 10;

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
	pub header: RelayHelloPacketHeader,
	pub body: RelayHelloPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayHelloPacketBody {
	pub target_node_id: NodeAddress,
	pub base: HelloPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayHelloPacketHeader {
	pub target: SocketAddrSstp,
	pub target_use_tcp: bool,
	pub base: HelloPacketHeader,
}

pub type RelayReadyPacket = RelayedHelloAckPacket;

pub struct RelayInitiationInfo {
	pub local_session_id: u16,
	pub(super) session: Arc<Mutex<SessionData>>,
	pub ready_receiver: HelloReceiver,
	pub(super) packet_receiver: UnboundedReceiver<CryptedPacket>,
	pub dh_private_key: x25519::StaticSecret,
	pub packet: RelayHelloPacket,
}

#[derive(Deserialize, Serialize)]
pub struct RelayedHelloPacketHeader {
	relayer_session_id: u16,
	relayer_public_key: NodePublicKey,
	source: SocketAddrSstp,
	source_use_tcp: bool,
	pub base: HelloPacketHeader,
}

pub type RelayedHelloPacketBody = RelayHelloPacketBody;

#[derive(Deserialize, Serialize)]
pub struct RelayedHelloPacket {
	pub header: RelayedHelloPacketHeader,
	body: RelayedHelloPacketBody,
}

pub type RelayedHelloAckPacketHeader = HelloAckPacketHeader;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayedHelloAckPacketBody {
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
pub struct RelayHelloAckPacket {
	header: RelayHelloAckPacketHeader,
	body: RelayHelloAckPacketBody,
}

pub type RelayHelloAckPacketHeader = HelloAckPacketHeader;

#[derive(Debug, Deserialize, Serialize)]
pub struct RelayHelloAckPacketBody {
	source_session_id: u16,
	relayer_session_id: u16,
}

pub type RelayHelloAckAckPacket = HelloAckAckPacket;

pub type RelayedReadyAckPacket = HelloAckAckPacket;

#[derive(Deserialize, Serialize)]
pub struct HelloAckPacket {
	header: HelloAckPacketHeader,
	body: HelloAckPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HelloAckPacketHeader {
	node_public_key: identity::NodePublicKey,
	signature: NodeSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HelloAckPacketBody {
	dh_public_key: x25519::PublicKey,
	source_session_id: u16,
	target_session_id: u16,
	contact_info: ContactInfo,
	link_address: SocketAddrSstp,
}

#[derive(Deserialize, Serialize)]
pub struct HelloPacket {
	header: HelloPacketHeader,
	body: HelloPacketBody,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HelloPacketBody {
	pub dh_public_key: x25519::PublicKey,
	pub session_id: u16,
	pub contact_info: ContactInfo,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HelloPacketHeader {
	pub node_public_key: identity::NodePublicKey,
	pub signature: NodeSignature,
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

pub(crate) struct SessionData {
	hello_ack_channel: Option<Sender<()>>,
	initial_dh_private_key: Option<x25519::StaticSecret>,
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
	source_contact: ContactOption,
	source_public_key: NodePublicKey,
	source_sender: Arc<dyn LinkSocketSender>,
	target_session_id: u16,
	target_contact: ContactOption,
	target_node_id: NodeAddress,
	target_public_key: Option<NodePublicKey>,
	target_sender: Option<Arc<dyn LinkSocketSender>>,
	relayed_hello_sender: Sender<RelayedHelloAckPacket>,
	relay_ready_ack_sender: Option<Sender<u16>>,
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
	port: u16,
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
		let mut contact_info = ContactInfo::from_config(config);
		let sockets = SocketCollection::bind(config).await?;

		// Update the contact info data with the actual ports used
		if let Some(servers) = &sockets.ipv4 {
			if let Some(server) = &servers.udp {
				contact_info
					.ipv4
					.as_mut()
					.unwrap()
					.availability
					.udp
					.as_mut()
					.unwrap()
					.port = server.port;
			}
			if let Some(server) = &servers.tcp {
				contact_info
					.ipv4
					.as_mut()
					.unwrap()
					.availability
					.tcp
					.as_mut()
					.unwrap()
					.port = server.port;
			}
		}
		if let Some(servers) = &sockets.ipv6 {
			if let Some(server) = &servers.udp {
				contact_info
					.ipv6
					.as_mut()
					.unwrap()
					.availability
					.udp
					.as_mut()
					.unwrap()
					.port = server.port;
			}
			if let Some(server) = &servers.tcp {
				contact_info
					.ipv6
					.as_mut()
					.unwrap()
					.availability
					.tcp
					.as_mut()
					.unwrap()
					.port = server.port;
			}
		}

		Ok(Arc::new(Self {
			stop_flag,
			sockets,
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
			let session = session_mutex.lock().await;

			// If the transporter has exited the loop to handle tasks, the connection is done.
			if let SessionTransportData::Direct(data) = &session.transport_data {
				if !data.alive_flag.load(Ordering::Relaxed) {
					done_ids.push(*session_id);
					continue;
				}
			}

			// Check if the connection has not receiving anything longer than the keep-alive
			// timeout.
			let last_activity = *session.last_activity.lock().unwrap();
			if SystemTime::now().duration_since(last_activity).unwrap()
				>= session.keep_alive_timeout
			{
				done_ids.push(*session_id);
			}
		}

		for done_id in done_ids {
			trace!("Closed session during cleanup routine {}.", done_id);
			sessions.map.remove(&done_id).unwrap();
		}
	}

	/// Finish setting up an outgoing relay connection.
	pub async fn complete_outgoing_relay(
		self: &Arc<Server>, sender: Arc<dyn LinkSocketSender>,
		initiation_data: RelayInitiationInfo, establish_info: HelloResult,
		target_node_id: &NodeAddress, target_contact: ContactOption, timeout: Duration,
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

		let max_packet_len = min(
			sender.max_packet_length(),
			target_contact.max_packet_length(),
		);
		let underlying_protocol_is_reliable =
			sender.is_connection_based() && target_contact.use_tcp;
		let transporter = Transporter::new_with_receiver(
			alive_flag,
			max_packet_len,
			underlying_protocol_is_reliable,
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

		// When relaying, the max packet length is infered by taking the lowest support max packet
		// length between the underlying transport protocol of the two nodes.
		Ok(Box::new(Connection {
			transporter: transporter_handle,
			server: self.clone(),
			keep_alive_timeout: DEFAULT_KEEP_ALIVE_IDLE_TIME,
			peer_address: target_contact.target,
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
		let session_transport_data = SessionTransportData::Direct(SessionTransportDataDirect {
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
			.new_outgoing_session(
				node_id.map(|id| id.clone()),
				session_transport_data,
				timeout,
			)
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
						sender.max_packet_length(),
						sender.is_connection_based(),
						establish_info.encrypt_session_id,
						local_session_id,
						establish_info.dest_session_id,
						sender.clone(),
						self.node_id.clone(),
						establish_info.node_id.clone(),
						timeout,
						dh_private_key,
						establish_info.dh_public_key,
						packet_receiver,
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

	pub async fn forget_session(self: &Arc<Self>, session_id: u16) {
		self.sessions.lock().await.map.remove(&session_id);
	}

	pub fn forget_session_async(self: &Arc<Self>, session_id: u16) {
		let this = self.clone();
		spawn(async move {
			this.forget_session(session_id).await;
		});
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
		our_session_id: u16, their_session_id: u16, addr: SocketAddr, response: Option<&[u8]>,
	) -> (Vec<u8>, bool) {
		let contact_info = self.our_contact_info();
		let body = RelayedHelloAckPacketBody {
			relayer_session_id,
			base: HelloAckPacketBody {
				dh_public_key: dh_public_key.clone(),
				source_session_id: their_session_id,
				target_session_id: our_session_id,
				contact_info: contact_info.clone(),
				link_address: addr.into(),
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

	/// Creates a new session for a relay connection to be established.
	/// Returns None is the session already exists.
	pub async fn new_relay_session(
		&self, source_session_id: u16, source_contact: ContactOption,
		source_public_key: NodePublicKey, source_sender: Arc<dyn LinkSocketSender>,
		target_node_id: NodeAddress, target_contact: ContactOption,
		relayed_hello_sender: Sender<RelayedHelloAckPacket>, ready_ack_sender: Option<Sender<u16>>,
		keep_alive_timeout: Duration,
	) -> Result<Option<(u16, Arc<Mutex<SessionData>>)>> {
		let mut sessions = self.sessions.lock().await;
		if sessions.has_relay_session(source_session_id).await {
			return Ok(None);
		}
		// FIXME: The keep alive timeout should be default, and the provided timeout should be used
		// until the relay connection is established.
		let transport_data = SessionTransportData::Relay(SessionTransportDataRelay {
			source_session_id,
			source_contact,
			source_public_key,
			source_sender,
			target_session_id: 0,
			target_contact,
			target_node_id: target_node_id.clone(),
			target_public_key: None,
			target_sender: None,
			relayed_hello_sender,
			relay_ready_ack_sender: ready_ack_sender,
		});
		let session_data = Arc::new(Mutex::new(SessionData::new(
			Some(target_node_id),
			transport_data,
			keep_alive_timeout,
		)));

		let session_id = match sessions.next_id() {
			None => return trace::err(Error::OutOfSessions),
			Some(id) => id,
		};
		sessions.map.insert(session_id, session_data.clone());
		return Ok(Some((session_id, session_data)));
	}

	pub async fn new_relay_session2(
		&self, source_contact: ContactOption, source_sender: Arc<dyn LinkSocketSender>,
		packet: &RelayHelloPacket, timeout: Duration, ready_ack_sender: Option<Sender<u16>>,
	) -> Result<
		Option<(
			Arc<Mutex<SessionData>>,
			RelayedHelloPacket,
			mpsc::Receiver<RelayedHelloAckPacket>,
		)>,
	> {
		let (hello_tx, hello_rx) = mpsc::channel(1);
		let (relayer_session_id, session) = match self
			.new_relay_session(
				packet.body.base.session_id,
				source_contact.clone(),
				packet.header.base.node_public_key.clone(),
				source_sender,
				packet.body.target_node_id.clone(),
				ContactOption::new(
					packet.header.target.clone().into(),
					packet.header.target_use_tcp,
				),
				hello_tx,
				ready_ack_sender,
				timeout,
			)
			.await?
		{
			Some(r) => r,
			None => return Ok(None),
		};

		// The packet to pass to the assistant node.
		let relayed_hello_packet = RelayedHelloPacket {
			header: RelayedHelloPacketHeader {
				source: source_contact.target.clone().into(),
				source_use_tcp: source_contact.use_tcp,
				relayer_session_id,
				relayer_public_key: self.private_key.public(),
				base: packet.header.base.clone(),
			},
			body: packet.body.clone(),
		};
		Ok(Some((session, relayed_hello_packet, hello_rx)))
	}

	async fn new_incomming_session(
		&self, alive_flag: Arc<AtomicBool>, their_node_id: NodeAddress,
		their_public_key: NodePublicKey, dest_session_id: u16,
		packet_sender: UnboundedSender<CryptedPacket>, timeout: Duration,
	) -> Result<(u16, Arc<Mutex<SessionData>>, bool)> {
		// Check if session doesn't already exists, and return that session
		let mut sessions = self.sessions.lock().await;
		match sessions
			.find_their_session(&their_node_id, dest_session_id)
			.await
		{
			None => {}
			Some((session_id, session_data)) => {
				return Ok((session_id, session_data, false));
			}
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
		return Ok((session_id, session_data, true));
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
		&self, target_node_id: NodeAddress, target: &ContactOption, local_session_id: u16,
		dh_public_key: x25519::PublicKey,
	) -> RelayHelloPacket {
		let target2: SocketAddrSstp = target.target.clone().into();
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
			target_use_tcp: target.use_tcp,
			base: HelloPacketHeader {
				node_public_key: self.private_key.public(),
				signature,
			},
		};

		RelayHelloPacket { header, body }
	}

	pub fn our_contact_info(&self) -> ContactInfo {
		self.our_contact_info.lock().unwrap().clone()
	}

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

	async fn process_crypted_packet(&self, buffer: &[u8], sender: &ContactOption) {
		let session_id = u16::from_le_bytes(*array_ref![buffer, 0, 2]);
		// TODO: Decide if putting an extra 2-byte session_id to the packet, so that we can identify wether a
		// relay packet comes from the source or the target, is a good idea.
		// We can use that for cases where someone's IP address may change mid-connection.
		// But I'm not sure how often that happends in real life situations.
		let ks_seq = u16::from_le_bytes(*array_ref![buffer, 2, 2]);
		let seq = u16::from_le_bytes(*array_ref![buffer, 4, 2]);
		let data = buffer[6..].to_vec();
		let packet = CryptedPacket { ks_seq, seq, data };

		let should_close =
			{
				let sessions = self.sessions.lock().await;
				if let Some(s) = sessions.map.get(&session_id).map(|s| s.clone()) {
					drop(sessions);
					let mut session = s.lock().await;
					*session.last_activity.lock().unwrap() = SystemTime::now();

					match &mut session.transport_data {
						SessionTransportData::Direct(data) => {
							data.packet_processor.send(packet).is_err()
						}
						SessionTransportData::Relay(data) => {
							// The packet buffer size should always be small enough to be able to be
							// sent on both sides.
							debug_assert!(
                            buffer.len() <= min(
                                data.source_contact.max_packet_length(),
                                data.target_contact.max_packet_length()
                            ),
                            "packet too big for relay connection (packet={}, source={}, target={})",
                            buffer.len(),
                            data.source_contact.max_packet_length(),
                            data.target_contact.max_packet_length(),
                        );

							// The port of both sides need only be used to distinguish them from
							// eachother when their IP and chosen protocol is the same. Otherwise, we
							// can easily figure out who has send what packet.
							let port_is_unimportant = data.source_contact.use_tcp
								!= data.target_contact.use_tcp
								|| data.source_contact.target.ip()
									!= data.target_contact.target.ip();
							if sender.use_tcp == data.source_contact.use_tcp
								&& sender.target.ip() == data.source_contact.target.ip()
								&& (port_is_unimportant
									|| sender.target.port() == data.source_contact.target.port())
							{
								if let Some(target_socket) = &data.target_sender {
									let result = Self::relay_crypted_packet(
										target_socket,
										data.target_session_id,
										&buffer[2..],
									)
									.await;
									if let Err(e) = &result {
										warn!(
										"Unable to pass relayed crypted packet to target {}: {:?}",
										&data.target_contact, e
									);
									}
									result.is_err()
								} else {
									error!(
									"Received transport data packet before relay connected with \
									 target."
								);
									false
								}
							} else if sender.use_tcp == data.target_contact.use_tcp
								&& sender.target.ip() == data.target_contact.target.ip()
								&& (port_is_unimportant
									|| sender.target.port() == data.target_contact.target.port())
							{
								let result = Self::relay_crypted_packet(
									&data.source_sender,
									data.source_session_id,
									&buffer[2..],
								)
								.await;
								if let Err(e) = &result {
									warn!(
									"Unable to pass relayed crypted packet to source[{}] {}: {:?}",
									buffer.len(), &data.target_contact, e
								);
								}
								result.is_err()
							} else {
								warn!(
								"Relay transport data packet received from unknown socket address. {} {} {}",
                                sender, &data.source_contact, &data.target_contact
							);
								false
							}
						}
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

	async fn process_relay_ready_packet(self: &Arc<Self>, buffer: &[u8]) -> Result<()> {
		let packet: RelayReadyPacket = binserde::deserialize(buffer)?;

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
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, relay_contact: &ContactOption,
		buffer: &[u8],
	) -> Result<()> {
		let packet: RelayedHelloPacket = binserde::deserialize(buffer)?;
		self.process_relayed_hello_packet(sender, relay_contact, packet)
			.await
	}

	pub async fn process_relayed_hello_packet(
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, relay_contact: &ContactOption,
		packet: RelayedHelloPacket,
	) -> Result<()> {
		Self::verify_hello_packet(
			&packet.header.base.node_public_key,
			&packet.header.base.signature,
			&packet.body,
		)?;

		// Take the smallest max packet length of the two connections
		let source_contact = ContactOption {
			target: packet.header.source.clone().into(),
			use_tcp: packet.header.source_use_tcp,
		};
		let max_packet_length = min(
			sender.max_packet_length(),
			source_contact.max_packet_length(),
		);
		let underlying_protocol_is_reliable =
			sender.is_connection_based() && source_contact.use_tcp;
		self._process_hello_packet(
			sender,
			&source_contact,
			max_packet_length,
			underlying_protocol_is_reliable,
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
			 response| {
				self.clone().new_relayed_hello_ack_packet(
					max_len,
					dh_public_key.clone(),
					dest_session_id,
					local_session_id,
					encrypt_session_id,
					relay_contact.target.clone(),
					response,
				)
			},
		)
		.await
	}

	pub async fn process_relayed_hello_ack_packet(
		&self, socket_sender: Arc<dyn LinkSocketSender>, addr: &SocketAddr,
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
				let target_public_key = packet.header.node_public_key.clone();
				if target_public_key.generate_address() != data.target_node_id {
					warn!(
						"Received relayed-hello-ack packet with invalid public key: {:?}",
						&target_public_key
					);
					return Ok(());
				}

				// Remember anything we've learned about the target node & used transport protocol
				// info.
				data.target_public_key = Some(target_public_key);
				if data.source_session_id != packet.body.base.source_session_id {
					return trace::err(Error::InvalidSessionId(packet.body.base.source_session_id));
				}
				data.target_session_id = target_session_id;
				data.target_contact.target = addr.clone();
				data.target_sender = Some(socket_sender);

				let _ = data.relayed_hello_sender.send(packet).await;
			}
			_ => panic!("unexpected session transport data type"),
		};

		Ok(())
	}

	async fn process_relayed_hello_ack_packet_raw(
		&self, socket_sender: Arc<dyn LinkSocketSender>, buffer: &[u8], addr: &SocketAddr,
	) -> Result<()> {
		let packet: RelayedHelloAckPacket = binserde::deserialize(buffer)?;
		let body_offset = 96;
		Self::verify_hello_packet_raw(
			&packet.header.node_public_key,
			&packet.header.signature,
			&buffer[body_offset..],
		)?;

		self.process_relayed_hello_ack_packet(socket_sender, addr, packet)
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

	/// The complete relay connection establishment procedure from the perspective of the relay
	/// node.
	pub async fn bring_together_relay_connection(
		self: &Arc<Self>, source_socket: Arc<dyn LinkSocketSender>, source_contact: &ContactOption,
		packet: RelayHelloPacket,
	) -> Result<()> {
		// Set up the relay session and send back a relay-hello-ack packet.
		let target_contact = ContactOption::new(
			packet.header.target.clone().into(),
			packet.header.target_use_tcp,
		);
		let target_node_id = packet.body.target_node_id.clone();
		let (ready_ack_tx, mut ready_ack_rx) = mpsc::channel(1);
		let (session, relayed_hello_packet, mut relayed_hello_rx) = match self
			.new_relay_session2(
				source_contact.clone(),
				source_socket.clone(),
				&packet,
				DEFAULT_TIMEOUT,
				Some(ready_ack_tx),
			)
			.await?
		{
			Some(r) => r,
			None => {
				trace!(
					"Relay with source session ID {} already exists.",
					packet.body.base.session_id
				);
				return Ok(());
			}
		};
		let relayer_session_id = relayed_hello_packet.header.relayer_session_id;
		if !source_socket.is_connection_based() {
			// TODO: This can be made to happen at the same time as establishing a connection to the target
			// node.
			self.send_relay_hello_ack_packet(
				&*source_socket,
				packet.body.base.session_id,
				relayer_session_id,
			)
			.await?;
		}

		// Open a socket to the target node and put the socket into our session
		let target_socket_sender = self.link_connect(&target_contact, DEFAULT_TIMEOUT).await?;
		match &mut session.lock().await.transport_data {
			SessionTransportData::Relay(data) => {
				data.target_sender = Some(target_socket_sender.clone());
			}
			_ => panic!("invalid session transport data"),
		}

		// Send the relayed-hello packet and wait for the relayed-hello-ack packet.
		let mut i = 0;
		let hello_result = loop {
			Self::send_packet(
				&*target_socket_sender,
				PACKET_TYPE_RELAYED_HELLO,
				&relayed_hello_packet,
			)
			.await?;

			select! {
				result = relayed_hello_rx.recv() => break result,
				_ = sleep(DEFAULT_TIMEOUT / 8) => {
					i += 1;
					if i == 8 {
						return trace::err(Error::Timeout(DEFAULT_TIMEOUT))
					}
				}
			}
		};

		// Send the relay-ready packet to the source node, and wait for a relay-ready-ack packet.
		if let Some(relayed_hello_ack) = hello_result {
			i = 0;
			loop {
				Self::send_packet(&*source_socket, PACKET_TYPE_RELAY_READY, &relayed_hello_ack)
					.await?;

				if !source_socket.is_connection_based() {
					select! {
						_ = ready_ack_rx.recv() => break,
						_ = sleep(DEFAULT_TIMEOUT / 8) => {
							i += 1;
							if i == 8 {
								return trace::err(Error::Timeout(DEFAULT_TIMEOUT))
							}
						}
					}
				}
			}
		} else {
			trace!("Source node did not respond to relayed hello request.");
			// TODO: Close the relay session
		}
		Ok(())
	}

	async fn process_relay_hello_packet(
		self: &Arc<Self>, source_socket: Arc<dyn LinkSocketSender>, relay_contact: &ContactOption,
		buffer: &[u8],
	) -> Result<()> {
		let packet: RelayHelloPacket = binserde::deserialize(buffer)?;
		Self::verify_hello_packet(
			&packet.header.base.node_public_key,
			&packet.header.base.signature,
			&packet.body,
		)?;

		self.bring_together_relay_connection(source_socket.clone(), &relay_contact, packet)
			.await
	}

	async fn _process_hello_packet(
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, contact: &ContactOption,
		max_packet_length: usize, underlying_protocol_is_reliable: bool, dest_session_id: u16,
		encrypt_session_id: u16, public_key: NodePublicKey, dh_public_key: x25519::PublicKey,
		contact_info: ContactInfo, opt_request: Option<&[u8]>,
		relayer_public_key: Option<NodePublicKey>,
		new_packet: impl FnOnce(
			usize,
			&x25519::PublicKey,
			u16,
			u16,
			u16,
			Option<&[u8]>,
		) -> (Vec<u8>, bool),
	) -> Result<()> {
		let their_node_id = public_key.generate_address();
		let alive_flag = Arc::new(AtomicBool::new(true));
		let (packet_sender, packet_receiver) = mpsc::unbounded_channel();
		let (our_session_id, session, is_new) = self
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
		let dh_private_key = {
			let mut s = session.lock().await;
			if let Some(key) = &s.initial_dh_private_key {
				key.clone()
			} else {
				let key = x25519::StaticSecret::random_from_rng(OsRng);
				s.initial_dh_private_key = Some(key.clone());
				key
			}
		};
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
				// Decrypt the response
				let shared_secret =
					KeyState::calculate_initial_key(&dh_private_key, &dh_public_key);
				decrypt(encrypt_session_id, 0, 0, &mut response, &shared_secret);

				(Some(response), todo)
			} else {
				if sender.is_connection_based() {
					spawn(async move {
						sender.close().await.unwrap();
						// If the hello packet is invalid, but we're receiving it over TCP, close the TCP
						// connection itself.
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
			max_packet_length,
			&our_dh_public_key,
			encrypt_session_id,
			our_session_id,
			dest_session_id,
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

		//let (hello_ack_tx, mut hello_ack_rx) = mpsc::channel(1);
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

			//s.hello_ack_channel = Some(hello_ack_tx);
		};

		// Spawn transporter
		let transporter = Transporter::new_with_receiver(
			alive_flag,
			max_packet_length,
			underlying_protocol_is_reliable,
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
		sender.send(&hello_ack).await?;

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

		// If there is a response already, but we've not been able to send it back on he connection
		// already on the hello-ack packet, do it as the first task on the
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
		self: &Arc<Self>, sender: Arc<dyn LinkSocketSender>, contact: &ContactOption, buffer: &[u8],
	) -> Result<()> {
		let (hello, first_request_opt) = Self::parse_hello_packet(buffer)?;

		let mut their_contact_info = hello.body.contact_info.clone();
		their_contact_info.update(&contact.target, contact.use_tcp);

		let max_packet_length = sender.max_packet_length();
		let is_connection_based = sender.is_connection_based();
		self._process_hello_packet(
			sender,
			contact,
			max_packet_length,
			is_connection_based,
			hello.body.session_id,
			hello.body.session_id,
			hello.header.node_public_key,
			hello.body.dh_public_key,
			hello.body.contact_info,
			first_request_opt,
			None,
			|max_len, dh_public_key, _, local_session_id, dest_session_id, response| {
				self.clone().new_hello_ack_packet(
					max_len,
					dh_public_key.clone(),
					local_session_id,
					dest_session_id,
					&contact.target,
					response,
				)
			},
		)
		.await
	}

	async fn process_hello_ack_packet(
		&self, link_socket: &Arc<dyn LinkSocketSender>, sender: &SocketAddr, buffer: &[u8],
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
			self.our_contact_info.lock().unwrap().update(
				&packet.body.link_address.into(),
				link_socket.is_connection_based(),
			);

			match &mut session.transport_data {
				SessionTransportData::Direct(data) => {
					// If the hello_channel is already gone, we've processed this response before
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
		if !link_socket.is_connection_based() {
			self.send_hello_ack_ack_packet(&**link_socket, their_session_id)
				.await?;
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

	async fn process_relay_ready_ack_packet(&self, buffer: &[u8]) -> Result<()> {
		let packet: RelayHelloAckAckPacket = binserde::deserialize(&buffer)?;

		let sessions = self.sessions.lock().await;
		if let Some(s) = sessions.map.get(&packet.session_id) {
			let s2 = s.clone();
			drop(sessions);

			let mut session = s2.lock().await;
			let relay_ready_ack_sender = match &mut session.transport_data {
				SessionTransportData::Relay(data) => {
					// Verify signature
					if !data
						.source_public_key
						.verify(&packet.session_id.to_le_bytes(), &packet.signature)
					{
						warn!("Received relay-hello-ack-ack packet with invalid signature.");
						return Ok(());
					}

					data.relay_ready_ack_sender.take()
				}
				_ => panic!("invalid session transport data"),
			};

			if let Some(tx) = relay_ready_ack_sender {
				let _ = tx.send(packet.session_id).await;
			}
		}
		Ok(())
	}

	async fn process_relay_hello_ack_packet(&self, buffer: &[u8]) -> Result<()> {
		let packet: RelayHelloAckPacket = binserde::deserialize(&buffer)?;

		let sessions = self.sessions.lock().await;
		if let Some(s) = sessions.map.get(&packet.body.source_session_id) {
			let s2 = s.clone();
			drop(sessions);
			let mut session = s2.lock().await;
			let relay_hello_ack_sender = match &mut session.transport_data {
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
			if let Some(tx) = relay_hello_ack_sender {
				warn!(
					"process_relay_hello_ack_packet {}",
					packet.body.relayer_session_id
				);
				let _ = tx.send(packet.body.relayer_session_id).await;
			}
		}

		// FIXME: Send a relay-Hello_relay_ack_ack packet
		Ok(())
	}

	async fn process_packet(
		self: &Arc<Self>, link_socket: Arc<dyn LinkSocketSender>, contact: &ContactOption,
		packet: &[u8],
	) -> Result<()> {
		let message_type = packet[0];
		let buffer = &packet[1..];
		match message_type {
			PACKET_TYPE_HELLO => {
				self.process_hello_packet(link_socket, contact, buffer)
					.await
			}
			PACKET_TYPE_HELLO_ACK => {
				self.process_hello_ack_packet(&link_socket, &contact.target, buffer)
					.await
			}
			PACKET_TYPE_HELLO_ACK_ACK => self.process_hello_ack_ack_packet(&buffer).await,
			PACKET_TYPE_CRYPTED => {
				self.process_crypted_packet(buffer, &contact).await;
				Ok(())
			}
			PACKET_TYPE_RELAY_HELLO => {
				self.process_relay_hello_packet(link_socket, &contact, buffer)
					.await
			}
			PACKET_TYPE_RELAY_HELLO_ACK => self.process_relay_hello_ack_packet(buffer).await,
			PACKET_TYPE_RELAY_READY => self.process_relay_ready_packet(buffer).await,
			PACKET_TYPE_RELAY_READY_ACK => self.process_relay_ready_ack_packet(&buffer).await,
			PACKET_TYPE_RELAYED_HELLO => {
				self.process_relayed_hello_packet_raw(link_socket, contact, buffer)
					.await
			}
			PACKET_TYPE_RELAYED_HELLO_ACK => {
				self.process_relayed_hello_ack_packet_raw(link_socket, buffer, &contact.target)
					.await
			}
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
		self: &Arc<Self>, relay: &ContactOption, relay_node_id: NodeAddress,
		target_contact: ContactOption, target_node_id: &NodeAddress,
	) -> Result<Box<Connection>> {
		let stop_flag = Arc::new(AtomicBool::new(false));
		self.relay_with_timeout(
			stop_flag,
			relay,
			relay_node_id,
			target_contact,
			target_node_id,
			2 * DEFAULT_TIMEOUT,
		)
		.await
	}

	pub async fn relay_with_timeout(
		self: &Arc<Self>, stop_flag: Arc<AtomicBool>, relay_contact: &ContactOption,
		relay_node_id: NodeAddress, target_contact: ContactOption, target_node_id: &NodeAddress,
		timeout: Duration,
	) -> Result<Box<Connection>> {
		let sender = self.link_connect(relay_contact, timeout).await?;

		let (hello_relay_ack_tx, mut hello_relay_ack_rx) = mpsc::channel(1);
		let mut initiation_info = self
			.setup_outgoing_relay(
				relay_node_id,
				target_node_id.clone(),
				&target_contact,
				timeout,
				Some(hello_relay_ack_tx),
			)
			.await?;

		// Wait twice as long as normal
		let initial_sleep_time = min(timeout * 2 / 4, MAXIMUM_RETRY_TIMEOUT);

		// Send hello packet to relay node
		// TODO: Put the sending of this packet into its own function
		let mut raw_packet = vec![
			PACKET_TYPE_RELAY_HELLO;
			1 + binserde::serialized_size(&initiation_info.packet).unwrap()
		];
		binserde::serialize_into(&mut raw_packet[1..], &initiation_info.packet).unwrap();
		let started = SystemTime::now();
		loop {
			sender.send(&raw_packet).await?;

			if !relay_contact.use_tcp {
				select! {
					_relay_session_id = hello_relay_ack_rx.recv() => break,
					_ = sleep(initial_sleep_time) => {
						if stop_flag.load(Ordering::Relaxed) || SystemTime::now().duration_since(started).unwrap() >= timeout {
							warn!("No hello-relay-ack packet received from the relay.");
							return trace::err(Error::Timeout(timeout));
						}
					}
				}
			}
		}

		// TODO: Make the relay respond with a relay-ack packet first, then wait on a relay-ready
		// packet.
		// Because now we don't really know when the relay node messed up or when the target node
		// did, and then we don't know what node we should blacklist if needed.

		// Receive a relay-ready packet from relay node, and respond with a relay-ready-ack
		tokio::select! {
			result = initiation_info.ready_receiver.recv() => {
				let establish_info = result.unwrap();

				if !relay_contact.use_tcp {
					self.send_relay_ready_ack_packet(&*sender, establish_info.dest_session_id).await?;
				}

				let connection = self.complete_outgoing_relay(sender, initiation_info, establish_info, target_node_id, target_contact, timeout).await?;
				Ok(connection)
			},
			_ = sleep(timeout) => {
				warn!("No relayed-hello packet received from the relay.");
				// TODO: Provide mode specific timeout types so that we know what packet we were
				// expecting.
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

	async fn send_relay_hello_ack_packet(
		&self, sender: &dyn LinkSocketSender, source_session_id: u16, relayer_session_id: u16,
	) -> Result<()> {
		let body_offset = 1 + 96;
		let body = RelayHelloAckPacketBody {
			source_session_id,
			relayer_session_id,
		};
		let packet_len = body_offset + binserde::serialized_size(&body).unwrap();
		let mut buffer = vec![PACKET_TYPE_RELAY_HELLO_ACK; packet_len];

		binserde::serialize_into(&mut buffer[body_offset..packet_len], &body).unwrap();
		let signature = self.private_key.sign(&buffer[body_offset..]);

		let header = RelayHelloAckPacketHeader {
			node_public_key: self.private_key.public(),
			signature,
		};
		binserde::serialize_into(&mut buffer[1..], &header).unwrap();
		sender.send(&buffer).await?;
		Ok(())
	}

	async fn send_relay_ready_ack_packet(
		&self, sender: &dyn LinkSocketSender, session_id: u16,
	) -> Result<()> {
		let buffer = self._compose_hello_ack_ack_packet(PACKET_TYPE_RELAY_READY_ACK, session_id);
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

	pub async fn set_next_session_id(&self, id: u16) {
		self.sessions.lock().await.next_id = id;
	}

	pub async fn setup_outgoing_relay(
		&self, relay_node_id: NodeAddress, target_node_id: NodeAddress,
		target_option: &ContactOption, timeout: Duration,
		hello_relay_ack_sender: Option<Sender<u16>>,
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

		// TODO: The exact same thing is done when opening a regular connection. Put this code in
		// some function.
		let dh_private_key = {
			let mut s = session.lock().await;
			if let Some(key) = &s.initial_dh_private_key {
				key.clone()
			} else {
				let key = x25519::StaticSecret::random_from_rng(OsRng);
				s.initial_dh_private_key = Some(key.clone());
				key
			}
		};
		let dh_public_key = x25519::PublicKey::from(&dh_private_key);
		let packet = self.new_relay_hello_packet(
			target_node_id,
			target_option,
			local_session_id,
			dh_public_key,
		);
		Ok(RelayInitiationInfo {
			local_session_id,
			session,
			ready_receiver: hello_receiver,
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
							Error::Timeout(timeout) => {
								warn!("Timeout ({:?}) with {}.", timeout, &contact2)
							}
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

	pub(crate) fn verify_hello_packet<B>(
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
	fn from(other: io::Error) -> Self {
		Self::Io(other)
	}
}

async fn bind_udpv4(addr: Ipv4Addr, port: u16) -> io::Result<(UdpServerV4, u16)> {
	if port > 0 {
		Ok((UdpServer::bind(SocketAddrV4::new(addr, port)).await?, port))
	} else {
		bind_first_free_udpv4(addr).await
	}
}

async fn bind_tcpv4(addr: Ipv4Addr, port: u16) -> io::Result<(TcpServerV4, u16)> {
	if port > 0 {
		Ok((TcpServer::bind(SocketAddrV4::new(addr, port)).await?, port))
	} else {
		bind_first_free_tcpv4(addr).await
	}
}

async fn bind_udpv6(addr: Ipv6Addr, port: u16) -> io::Result<(UdpServerV6, u16)> {
	if port > 0 {
		Ok((
			UdpServer::bind(SocketAddrV6::new(addr, port, 0, 0)).await?,
			port,
		))
	} else {
		bind_first_free_udpv6(addr).await
	}
}

async fn bind_tcpv6(addr: Ipv6Addr, port: u16) -> io::Result<(TcpServerV6, u16)> {
	if port > 0 {
		Ok((
			TcpServer::bind(SocketAddrV6::new(addr, port, 0, 0)).await?,
			port,
		))
	} else {
		bind_first_free_tcpv6(addr).await
	}
}

async fn bind_first_free_udpv4(addr: Ipv4Addr) -> io::Result<(UdpServerV4, u16)> {
	// TODO: Start at a port that has not been tried yet by another call to this function
	let mut i = 10000;
	loop {
		match UdpServer::bind(SocketAddrV4::new(addr, i)).await {
			Ok(s) => return Ok((s, i)),
			Err(e) => match e.kind() {
				io::ErrorKind::AddrInUse => {
					if i == 60000 {
						return Err(e.into());
					}
				}
				_ => return Err(e.into()),
			},
		}

		i += 1;
	}
}

async fn bind_first_free_tcpv4(addr: Ipv4Addr) -> io::Result<(TcpServerV4, u16)> {
	// TODO: Start at a port that has not been tried yet by another call to this function
	let mut i = 10000;
	loop {
		match TcpServer::bind(SocketAddrV4::new(addr, i)).await {
			Ok(s) => return Ok((s, i)),
			Err(e) => match e.kind() {
				io::ErrorKind::AddrInUse => {
					if i == 60000 {
						return Err(e.into());
					}
				}
				_ => return Err(e.into()),
			},
		}

		i += 1;
	}
}

async fn bind_first_free_udpv6(addr: Ipv6Addr) -> io::Result<(UdpServerV6, u16)> {
	// TODO: Start at a port that has not been tried yet by another call to this function
	let mut i = 10000;
	loop {
		match UdpServer::bind(SocketAddrV6::new(addr, i, 0, 0)).await {
			Ok(s) => return Ok((s, i)),
			Err(e) => match e.kind() {
				io::ErrorKind::AddrInUse => {
					if i == 60000 {
						return Err(e.into());
					}
				}
				_ => return Err(e.into()),
			},
		}

		i += 1;
	}
}

async fn bind_first_free_tcpv6(addr: Ipv6Addr) -> io::Result<(TcpServerV6, u16)> {
	// TODO: Start at a port that has not been tried yet by another call to this function
	let mut i = 10000;
	loop {
		match TcpServer::bind(SocketAddrV6::new(addr, i, 0, 0)).await {
			Ok(s) => return Ok((s, i)),
			Err(e) => match e.kind() {
				io::ErrorKind::AddrInUse => {
					if i == 60000 {
						return Err(e.into());
					}
				}
				_ => return Err(e.into()),
			},
		}

		i += 1;
	}
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
				match bind_udpv4(addr, port).await {
					Err(e) => error!(
						"Unable to bind node to IPv6 socket address {}:{} for UDP: {}",
						addr, port, e
					),
					Ok((inner, new_port)) => {
						servers.udp = Some(Arc::new(SstpSocketServer {
							inner,
							port: new_port,
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
						}))
					}
				}
			}

			// Parse TCPv4 configuration
			if let Some(port) = config.ipv4_tcp_port {
				match bind_tcpv4(addr, port).await {
					Err(e) => error!(
						"Unable to bind node to IPv4 socket address {}:{} for TCP: {}",
						addr, port, e
					),
					Ok((inner, new_port)) => {
						servers.tcp = Some(Arc::new(SstpSocketServer {
							inner,
							port: new_port,
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
						}))
					}
				}
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
				match bind_udpv6(addr, port).await {
					Err(e) => error!(
						"Unable to bind node to IPv6 socket address {}:{} for UDP: {}",
						addr, port, e
					),
					Ok((inner, new_port)) => {
						servers.udp = Some(Arc::new(SstpSocketServer {
							inner,
							port: new_port,
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
						}))
					}
				}
			}

			// Parse TCPv6 configuration
			if let Some(port) = config.ipv6_tcp_port {
				match bind_tcpv6(addr, port).await {
					Err(e) => error!(
						"Unable to bind node to IPv6 socket address {}:{} for TCP: {}",
						addr, port, e
					),
					Ok((inner, new_port)) => {
						servers.tcp = Some(Arc::new(SstpSocketServer {
							inner,
							port: new_port,
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
						}))
					}
				}
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
			initial_dh_private_key: None,
			keep_alive_timeout: timeout,
			last_activity: Arc::new(StdMutex::new(SystemTime::now())),
			their_node_id,
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

	/// Checks whether a relay session already exists, based on the source node's session ID and the
	/// target node's ID.
	pub async fn has_relay_session(&self, source_session_id: u16) -> bool {
		for (_, session) in self.map.iter() {
			if let SessionTransportData::Relay(data) = &session.lock().await.transport_data {
				if data.source_session_id == source_session_id {
					return true;
				}
			}
		}
		false
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
		&self, target: &ContactInfo, mut openness: Openness,
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
								if openness == Openness::Punchable {
									openness = Openness::Unidirectional;
								}
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
								if openness == Openness::Punchable {
									openness = Openness::Unidirectional;
								}
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
				Some(servers) => {
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
					}
				}
			},
			SocketAddr::V6(a) => match &self.ipv6 {
				None => {}
				Some(servers) => {
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
					}
				}
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
	fn port(&self) -> u16 {
		self.port
	}

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

impl From<RelayedHelloAckPacket> for HelloResult {
	fn from(other: RelayedHelloAckPacket) -> Self {
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

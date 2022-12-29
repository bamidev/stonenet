//! Connections in Stonenet are 

use std::{
	collections::HashMap,
	io,
	net::{SocketAddr},
	ops::Add,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering}
	},
	time::*
};

use crate::common::*;

use log::*;
use tokio::{
	net::{UdpSocket, ToSocketAddrs},
	sync::{Mutex, oneshot},
	time::sleep
};


pub const DEFAULT_TIMEOUT: u32 = 10;    // 10 seconds
//const UDP_PACKET_MAX: usize = 65507;


pub type ResultCallback = dyn FnOnce(io::Result<(IdType, Vec<u8>)>) + Send;

pub struct ConnectionManager {
	socket: UdpSocket,
	connections: Mutex<ConnectionInfo>
}

struct ConnectionInfo {
	/// The callback to be called with either the error or the response.
	callback: Box<ResultCallback>,
	/// The moment in time when a timeout error should occur
	timeout_moment: SystemTime
}

struct ExchangeData {
	sessions: HashMap<u32, ExchangeData>,
	next_exchange_id: u32
}


impl ExchangeManager {

	pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
		Ok(Self::new(UdpSocket::bind(addr).await?))
	}
	
	pub async fn clean_sessions(self: &Arc<Self>) {
		let mut exchanges = self.exchanges.lock().await;
		let sessions = &mut exchanges.sessions;
		let mut done_ids = Vec::with_capacity(0);
		for (exchange_id, info) in sessions.iter() {
			//error!("XX {}", &info.timeout_moment.duration_since(SystemTime::now()).unwrap().as_millis());
			if info.timeout_moment.elapsed().is_ok() {
				done_ids.push(*exchange_id)
			}
		}

		for done_id in done_ids {
			let info = sessions.remove(&done_id).unwrap();
			// Trigger callback, but don't execute immediately.
			tokio::task::spawn(async { (info.callback)(Err(io::ErrorKind::TimedOut.into())) });
		}
	}

	pub fn new(socket: UdpSocket) -> Self {
		Self {
			socket,
			exchanges: Mutex::new(ExchangesData {
				sessions: HashMap::new(),
				next_exchange_id: 0
			})
		}
	}

	async fn trigger_response(&self,
		sender_node_id: &IdType,
		exchange_id: u32,
		buffer: &[u8]
	) -> bool {
		let mut exchanges = self.exchanges.lock().await;
		match exchanges.sessions.remove(&exchange_id) {
			None => false,
			Some(exchange_data) => {
				(exchange_data.callback)(Ok((sender_node_id.clone(), buffer.to_vec())));
				true
			}
		}
	}

	pub async fn serve<'a, F: 'a>(self: Arc<Self>,
		stop_flag: Arc<AtomicBool>,
		handle_request: F
	) where F: Fn(SocketAddr, IdType, u8, u32, Vec<u8>) {
		let mut buffer = [0u8; UDP_PACKET_MAX];

		self.clone().spawn_garbage_collector(stop_flag.clone());
		// Wait for an incoming UDP packet, interupting every second to see if
		// the loop needs to break.
		while !stop_flag.load(Ordering::Relaxed) {
			tokio::select! {
				r = self.socket.recv_from(&mut buffer) => {
					match r {
						Err(e) => {
							error!("Error during receiving UDP packet: {}", e);
							continue;
						},
						Ok((received, address)) => {
							if buffer.len() < 35 {
								error!(
									"Packet received from {} smaller than header: only {} bytes.",
									address, buffer.len()
								);
								continue;
							}
							let message_type = buffer[0];
							if message_type == 0xFF {	// Transport messages
								self.trans.process_message(address, &buffer[1..]);
							}
							else if message_type == 0xFE {
								self.trans.process_ack(address, &buffer[1..]);
							}
							else {
								let sender_node_id: IdType = bincode::deserialize(&buffer[1..33]).unwrap();
								let exchange_id = u32::from_le_bytes(buffer[33..37].try_into().unwrap());
								if message_type %2 == 0 {
									(handle_request)(
										address,
										sender_node_id,
										message_type,
										exchange_id,
										buffer[37..received].to_vec()
									);
								}
								else {
									self.trigger_response(&sender_node_id, exchange_id, &buffer).await;
								}
							}
						}
					}
				},
				_ = sleep(Duration::from_secs(1)) => {}
			}
		}
	}

	pub async fn send_message(&self,
		sender_node_id: &IdType,
		target: &SocketAddr,
		message_type_id: u8,
		exchange_id: u32,
		message: &[u8]
	) -> io::Result<()> {
		// Prepare header
		let mut buffer = vec![0u8; 5 + 32 + message.len()];
		buffer[0] = message_type_id;
		buffer[1..5].clone_from_slice(&exchange_id.to_le_bytes());
		buffer[5..37].clone_from_slice(&sender_node_id.0);
		buffer[37..].clone_from_slice(message);

		// Actually send buffer
		let send = self.socket.send_to(&buffer, target).await?;
		if send != buffer.len() {
			error!(
				"Request with exchange ID {} sent to {} was incomplete, only {} bytes sent.",
				exchange_id,
				target,
				send
			);
		}
		Ok(())
	}

	pub async fn send_request<F: 'static>(&self,
		sender_node_id: &IdType,
		target: &SocketAddr,
		message_type_id: u8,
		message: &[u8],
		on_result: F,
		timeout: Option<u32>
	) -> io::Result<()> where F: FnOnce(io::Result<(IdType, Vec<u8>)>) + Send {
		// Remember the exchange id and its callback
		let next_exchange_id = {
			let mut exchanges = self.exchanges.lock().await;
			let next_exchange_id = exchanges.next_exchange_id;

			exchanges.sessions.insert(next_exchange_id, ExchangeData {
				callback: Box::new(on_result),
				timeout_moment: SystemTime::now().add(
					Duration::from_secs(timeout.unwrap_or(DEFAULT_TIMEOUT) as _)
				)
			});
			exchanges.next_exchange_id += 1;
			next_exchange_id
		};

		// Send the message
		self.send_message(
			sender_node_id,
			target,
			message_type_id,
			next_exchange_id,
			message
		).await
	}

	/// Sents `message` to `target`, and returns the raw response upon
	/// receiving it. If the timeout has exceeded, `None` is returned.
	pub async fn request(&self,
		sender_node_id: &IdType,
		target: &SocketAddr,
		message_id: u8,
		buffer: &[u8],
		timeout: Option<u32>
	) -> io::Result<(IdType, Vec<u8>)> {
		let (tx, rx) = oneshot::channel();
		self.send_request(sender_node_id, target, message_id, &*buffer, |r| {
			tx.send(r).unwrap();
		}, timeout).await?;

		rx.await.expect("Unable to receive response from channel.")
	}

	/// Starts garbage collecting the unresponded requests.
	pub fn spawn_garbage_collector(self: Arc<Self>, stop_flag: Arc<AtomicBool>) {
		tokio::task::spawn(async move {
			let this = self.clone();
			while !stop_flag.load(Ordering::Relaxed) {
				sleep(Duration::from_secs(1)).await;
				this.clean_sessions().await;
			}
		});
	}
}
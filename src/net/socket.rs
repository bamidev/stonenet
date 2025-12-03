use std::{io, marker::PhantomData, mem, net::*, str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{io::*, select, sync::Mutex, time::sleep};
use unsafe_send_sync::*;

const TCP_BACKLOG: u32 = 1024;
const UDP_MAX_PACKET_SIZE: usize = 65536;

#[async_trait]
pub trait LinkSocket: Send + Sync {
	type Receiver: LinkSocketReceiver + 'static;
	type Sender: LinkSocketSender + 'static;

	/// Should be implemented to fully close the socket.
	/// Note: This method is async because TCP sockets for example, need to have
	/// their internal handle dropped before another connection to the same
	/// outbound and inbound address pair can be made. But before the internal
	/// handle can be even dropped, it needs to be shutdown so that the
	/// TCP connection can be shutdown cleanly, and that operation needs to
	/// wait, further necessitating this method's async form.
	async fn close(&mut self) -> io::Result<()>;

	/// Should be implemented to return the max size a packet should be to be
	/// able to be delivered, all circumstances considered.
	fn max_packet_length(&self) -> usize;

	fn split(self) -> (Self::Sender, Self::Receiver);
}

#[async_trait]
pub trait LinkSocketReceiver: Send + Sync {
	fn max_packet_length(&self) -> usize;

	/// Should be implemented to wait and return one packet.
	async fn receive(&self, timeout: Duration) -> io::Result<Vec<u8>>;
}

#[async_trait]
pub trait LinkSocketSender: Send + Sync {
	/// Should be implemented to close the socket. See the `close` method in
	/// `LinkSocket` for more info.
	async fn close(&self) -> io::Result<()>;

	fn max_packet_length(&self) -> usize;

	fn is_connection_based(&self) -> bool {
		false
	}

	/// Should be implemented to send one packet. May wait on reciepment.
	async fn send(&self, message: &[u8]) -> io::Result<()>;
}

#[async_trait]
pub trait LinkServer: Send + Sized + Sync {
	type Socket: LinkSocket;
	type Target: Into<SocketAddr> + Clone + Send + 'static;

	async fn bind(addr: Self::Target) -> io::Result<Self>;

	fn is_connection_based(&self) -> bool;
}

#[async_trait]
pub trait ConnectionBasedLinkServer: LinkServer {
	async fn connect(&self, addr: Self::Target, timeout: Duration) -> io::Result<Self::Socket>;
	async fn accept(
		&self, timeout: Duration,
	) -> io::Result<Option<(<Self as LinkServer>::Socket, <Self as LinkServer>::Target)>>;
}

#[async_trait]
pub trait ConnectionLessLinkServer: LinkServer {
	fn connect(&self, addr: Self::Target) -> io::Result<Self::Socket>;
	async fn listen(&self) -> io::Result<(Vec<u8>, Self::Target)>;
}

pub struct UdpServer<V>
where
	V: Into<SocketAddr>,
{
	inner: Arc<tokio::net::UdpSocket>,
	_phantom: PhantomData<UnsafeSendSync<V>>,
}
pub struct UdpSocket<V>
where
	V: Into<SocketAddr>,
{
	inner: Arc<tokio::net::UdpSocket>,
	// endpoint will never be changed after initialization so this should be safe:
	endpoint: UnsafeSync<V>,
}
pub struct UdpSocketSender<V>
where
	V: Into<SocketAddr>,
{
	inner: Arc<tokio::net::UdpSocket>,
	// endpoint will never be changed after initialization so this should be safe:
	endpoint: UnsafeSync<V>,
}
pub struct UdpSocketReceiver<V>
where
	V: Into<SocketAddr>,
{
	inner: Arc<tokio::net::UdpSocket>,
	_phantom: PhantomData<UnsafeSendSync<V>>,
}

pub struct TcpServer<V>
where
	V: Into<SocketAddr>,
{
	inner: tokio::net::TcpListener,
	addr: UnsafeSync<V>,
}
pub struct TcpSocket<V>
where
	V: Into<SocketAddr>,
{
	inner: Option<tokio::net::TcpStream>,
	_phantom: PhantomData<UnsafeSendSync<V>>,
}
pub struct TcpSocketReceiver<V>
where
	V: Into<SocketAddr>,
{
	inner: Mutex<tokio::net::tcp::OwnedReadHalf>,
	_phantom: PhantomData<UnsafeSendSync<V>>,
}
pub struct TcpSocketSender<V>
where
	V: Into<SocketAddr>,
{
	inner: Option<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
	_phantom: PhantomData<UnsafeSendSync<V>>,
}

pub type UdpServerV4 = UdpServer<SocketAddrV4>;
pub type UdpServerV6 = UdpServer<SocketAddrV6>;
//pub type UdpSocketV4 = UdpSocket<SocketAddrV4>;
//pub type UdpSocketV6 = UdpSocket<SocketAddrV6>;
//pub type UdpSocketSenderV4 = UdpSocketSender<SocketAddrV4>;
//pub type UdpSocketSenderV6 = UdpSocketSender<SocketAddrV6>;
pub type TcpServerV4 = TcpServer<SocketAddrV4>;
pub type TcpServerV6 = TcpServer<SocketAddrV6>;
//pub type TcpSocketV4 = TcpSocket<SocketAddrV4>;
//pub type TcpSocketV6 = TcpSocket<SocketAddrV6>;
//pub type TcpSocketSenderV4 = TcpSocketSender<SocketAddrV4>;
//pub type TcpSocketSenderV6 = TcpSocketSender<SocketAddrV6>;

// A workaround of something that should actually be fixed with specialization
// somehow...
fn udp_max_packet_length<V>() -> usize {
	if mem::size_of::<V>() == mem::size_of::<SocketAddrV4>() {
		576 - 60 /* Max IP header size */ - 8 /* UDP header size */
	} else if mem::size_of::<V>() == mem::size_of::<SocketAddrV6>() {
		1280 - 40 /* Fixed IP header size */ - 8 /* UDP header size */
	} else {
		panic!("should be unreachable");
	}
}

#[async_trait]
impl<V> LinkServer for UdpServer<V>
where
	V: Into<SocketAddr> + Send + Clone + 'static,
{
	type Socket = UdpSocket<V>;
	type Target = V;

	async fn bind(addr: Self::Target) -> io::Result<Self> {
		let inner = Arc::new(tokio::net::UdpSocket::bind(addr.into()).await?);
		Ok(Self {
			inner,
			_phantom: PhantomData,
		})
	}

	fn is_connection_based(&self) -> bool {
		false
	}
}

#[async_trait]
impl<V> LinkSocket for UdpSocket<V>
where
	V: Into<SocketAddr> + Send + Clone + 'static,
{
	type Receiver = UdpSocketReceiver<V>;
	type Sender = UdpSocketSender<V>;

	// Dropping the struct should already take care of closing the socket
	async fn close(&mut self) -> io::Result<()> {
		Ok(())
	}

	fn max_packet_length(&self) -> usize {
		udp_max_packet_length::<V>()
	}

	fn split(self) -> (Self::Sender, Self::Receiver) {
		(
			UdpSocketSender {
				inner: self.inner.clone(),
				endpoint: self.endpoint,
			},
			UdpSocketReceiver {
				inner: self.inner.clone(),
				_phantom: PhantomData,
			},
		)
	}
}

#[async_trait]
impl<V> LinkSocketReceiver for UdpSocketReceiver<V>
where
	V: Into<SocketAddr>,
{
	fn max_packet_length(&self) -> usize {
		udp_max_packet_length::<V>()
	}

	async fn receive(&self, timeout: Duration) -> io::Result<Vec<u8>> {
		let mut buffer = vec![0u8; self.max_packet_length()];
		select! {
			result = self.inner.recv_from(&mut buffer) => {
				let (read, _) = result?;
				buffer.resize(read, 0);
				Ok(buffer)
			},
			_ = sleep(timeout) => {
				Err(io::ErrorKind::TimedOut.into())
			}
		}
	}
}

#[async_trait]
impl<V> LinkSocketSender for UdpSocketSender<V>
where
	V: Into<SocketAddr> + Send + Clone,
{
	// Dropping the struct should already take care of closing the socket
	async fn close(&self) -> io::Result<()> {
		Ok(())
	}

	fn max_packet_length(&self) -> usize {
		udp_max_packet_length::<V>()
	}

	async fn send(&self, message: &[u8]) -> io::Result<()> {
		let socket_addr: SocketAddr = Into::<SocketAddr>::into((*self.endpoint).clone());
		let written = self.inner.send_to(message, socket_addr).await?;
		if written != message.len() {
			// TODO: Throw ErrorKind::Other with a custom error.
			return Err(io::ErrorKind::UnexpectedEof.into());
		}
		Ok(())
	}
}

#[async_trait]
impl<V> ConnectionLessLinkServer for UdpServer<V>
where
	V: Into<SocketAddr> + FromStr + Send + Clone + 'static,
{
	fn connect(&self, addr: Self::Target) -> io::Result<Self::Socket> {
		Ok(UdpSocket::<V> {
			inner: self.inner.clone(),
			endpoint: UnsafeSync::new(addr),
		})
	}

	async fn listen(&self) -> io::Result<(Vec<u8>, V)> {
		let mut buffer = vec![0u8; UDP_MAX_PACKET_SIZE];
		let (received, addr) = self.inner.recv_from(&mut *buffer).await?;
		buffer.truncate(received);
		let unwrapped_addr = V::from_str(&addr.to_string()).ok().unwrap();
		Ok((buffer, unwrapped_addr))
	}
}

impl<V> TcpServer<V>
where
	V: Into<SocketAddr>,
{
	fn new_inner() -> io::Result<tokio::net::TcpSocket> {
		if mem::size_of::<V>() == mem::size_of::<SocketAddrV6>() {
			tokio::net::TcpSocket::new_v6()
		} else {
			tokio::net::TcpSocket::new_v4()
		}
	}
}

#[async_trait]
impl<V> LinkServer for TcpServer<V>
where
	V: Into<SocketAddr> + Clone + Send + 'static,
{
	type Socket = TcpSocket<V>;
	type Target = V;

	async fn bind(addr: Self::Target) -> io::Result<Self> {
		let inner = Self::new_inner()?;
		inner.bind(addr.clone().into())?;
		inner.set_keepalive(true)?;
		Ok(Self {
			inner: inner.listen(TCP_BACKLOG)?,
			addr: UnsafeSync::new(addr),
		})
	}

	fn is_connection_based(&self) -> bool {
		true
	}
}

#[async_trait]
impl<V> ConnectionBasedLinkServer for TcpServer<V>
where
	V: Clone + Into<SocketAddr> + FromStr + Send + 'static,
{
	async fn connect(&self, addr: Self::Target, timeout: Duration) -> io::Result<Self::Socket> {
		let inner = Self::new_inner()?;
		inner.set_keepalive(true)?;

		select! {
			result = inner.connect(addr.into()) => {
				Ok(TcpSocket {
					inner: Some(result?),
					_phantom: PhantomData
				})
			},
			_ = sleep(timeout) => {
				Err(io::ErrorKind::TimedOut.into())
			}
		}
	}

	async fn accept(
		&self, timeout: Duration,
	) -> io::Result<Option<(<Self as LinkServer>::Socket, V)>> {
		select! {
			result = self.inner.accept() => {
				let (socket, addr) = result?;
				Ok(Some((
					TcpSocket {
						inner: Some(socket),
						_phantom: PhantomData
					},
					// FIXME: Find a way to cast SocketAddr into SocketAddrV* more appropriately
					V::from_str(&addr.to_string()).ok().unwrap()
				)))
			},
			_ = sleep(timeout) => {
				Err(io::ErrorKind::TimedOut.into())
			}
		}
	}
}

#[async_trait]
impl<V> LinkSocket for TcpSocket<V>
where
	V: Into<SocketAddr> + Send + 'static,
{
	type Receiver = TcpSocketReceiver<V>;
	type Sender = TcpSocketSender<V>;

	async fn close(&mut self) -> io::Result<()> {
		self.inner.as_mut().unwrap().shutdown().await
	}

	fn split(self) -> (Self::Sender, Self::Receiver) {
		let (rx, tx) = self.inner.unwrap().into_split();
		(
			TcpSocketSender {
				inner: Some(Mutex::new(tx)),
				_phantom: PhantomData,
			},
			TcpSocketReceiver {
				inner: Mutex::new(rx),
				_phantom: PhantomData,
			},
		)
	}

	// Because TCP is actually a reliable transport protocol, we can safely use any
	// max packet size. Keep in mind that we should not pick a max packet size that
	// is too large, as each packet gets encrypted by a new key.
	fn max_packet_length(&self) -> usize {
		0xFFFF
	}
}

#[async_trait]
impl<V> LinkSocketReceiver for TcpSocketReceiver<V>
where
	V: Into<SocketAddr>,
{
	fn max_packet_length(&self) -> usize {
		0xFFFF
	}

	async fn receive(&self, timeout: Duration) -> io::Result<Vec<u8>> {
		// Read 2 bytes for the packet size
		let packet_size;
		let mut socket = self.inner.lock().await;
		select! {
			result = socket.read_u32_le() => {
				packet_size = result? as usize;
			},
			_ = sleep(timeout) => {
				return Err(io::ErrorKind::TimedOut.into());
			}
		}

		// Read the actual packet into a buffer
		let mut buffer = vec![0u8; packet_size];
		let read = socket.read_exact(&mut buffer).await?;
		if read < packet_size {
			#[cfg(test)]
			panic!(
				"Packet over TCP did not sent whole packet: {} < {}",
				read, packet_size
			);

			#[cfg(not(test))]
			return Err(io::ErrorKind::UnexpectedEof.into());
		}
		Ok(buffer)
	}
}

#[async_trait]
impl<V> LinkSocketSender for TcpSocketSender<V>
where
	V: Into<SocketAddr>,
{
	async fn close(&self) -> io::Result<()> {
		self.inner.as_ref().unwrap().lock().await.shutdown().await
	}

	fn is_connection_based(&self) -> bool {
		true
	}

	fn max_packet_length(&self) -> usize {
		0xFFFF
	}

	async fn send(&self, packet: &[u8]) -> io::Result<()> {
		let packet_size = packet.len() as u32;
		let mut socket = self.inner.as_ref().unwrap().lock().await;
		socket.write_u32_le(packet_size).await?;
		socket.write_all(&packet).await?;
		socket.flush().await?;
		Ok(())
	}
}

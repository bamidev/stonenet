use std::{
	io,
	net::*
};

use async_trait::async_trait;


#[async_trait]
pub trait LinkSocket: Sized {
	type Target: Sized;

	async fn bind(addr: &Self::Target) -> io::Result<Self>;

	/// Should be implemented to return the max size a packet should be to be
	/// able to be delivered, all circumstances considered.
	fn max_packet_length() -> usize;

	/// Should be implemented to wait and return one packet.
	async fn receive(&self) -> io::Result<(Self::Target, Vec<u8>)>;

	async fn send(&self, target: &Self::Target, message: &[u8]) -> io::Result<()>;

	async fn unbound() -> io::Result<Self>;
}

// A trick to still be able to split into two without having to keep 2 instances
// of the original UdpSocket struct.
pub struct UdpSocket (async_std::net::UdpSocket);


#[async_trait]
impl LinkSocket for UdpSocket {
	type Target = SocketAddr;

	async fn bind(addr: &Self::Target) -> io::Result<Self> {
		Ok(Self (
			async_std::net::UdpSocket::bind(addr).await?
		))
	}

	async fn receive(&self) -> io::Result<(Self::Target, Vec<u8>)> {
		let mut buffer = vec![0u8; Self::max_packet_length()];
		let (read, peer) = self.0.recv_from(&mut buffer).await?;
		buffer.resize(read, 0);
		Ok((peer, buffer))
	}

	async fn send(&self, target: &Self::Target, message: &[u8]) -> io::Result<()> {
		let written = self.0.send_to(message, target).await?;
		if written != message.len() {
			// TODO: Throw ErrorKind::Other with a custom error.
			return Err(io::ErrorKind::UnexpectedEof.into());
		}
		Ok(())
	}

	// A packet size of 1500 or less tends to not be dropped over ethernet.
	fn max_packet_length() -> usize { 1500 - 20 - 8 }

	async fn unbound() -> io::Result<Self> {
		let addr = SocketAddr::new(
			IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
			0
		);
		Self::bind(&addr).await
	}
}

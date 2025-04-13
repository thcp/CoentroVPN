use std::net::{SocketAddr, UdpSocket};
use std::io;
use coentrovpn::packet_utils::ReassemblyBuffer;

pub fn bind_socket(addr: &str) -> io::Result<UdpSocket> {
    let socket_addr: SocketAddr = addr.parse().expect("Invalid socket address");
    UdpSocket::bind(socket_addr)
}

pub fn initialize_reassembly_buffer(buffer_size: usize) -> ReassemblyBuffer {
    ReassemblyBuffer::new(buffer_size)
}

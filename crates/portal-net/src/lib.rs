//! The registration portal's network services (Panopticon NAC, 0.2.7 N5, see
//! `docs/roadmap/0.2.7.md`): a small DHCP server ([`dhcp`]) and a captive DNS
//! responder ([`dns`]) for the registration VLAN, in the PacketFence style.
//!
//! An unregistered device that RADIUS put on the registration VLAN gets a
//! short lease from [`dhcp`] (Panopticon as router and DNS server, and the
//! portal's URL as the RFC 8910 captive-portal option), and [`dns`] answers
//! every name with the portal's address, so the OS's captive-portal check
//! lands on the portal and pops up its sign-in sheet.
//!
//! Both bind to the registration interface only ([`bound_udp`] uses
//! `SO_BINDTODEVICE`), so they never answer anything on another network,
//! and the DHCP server ignores relayed requests.

pub mod dhcp;
pub mod dns;

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use socket2::{Domain, Protocol, Socket, Type};

/// A UDP socket on `port`, bound to the interface `device` only, with
/// broadcast allowed. Binding to a device needs `CAP_NET_RAW`, a port below
/// 1024 `CAP_NET_BIND_SERVICE` (the Dockerfile grants both to the binary).
pub fn bound_udp(device: &str, port: u16) -> io::Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.bind_device(Some(device.as_bytes()))?;
    socket.set_nonblocking(true)?;
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    socket.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

//! Runs the registration VLAN's DHCP and DNS servers on their own, for
//! testing against real clients (`deploy/registration/test/run.sh`):
//!
//!     portal_net <interface> <server-ip>/<prefix> <range-start> <range-end> <lease-secs>
//!
//! Needs root (or CAP_NET_RAW + CAP_NET_BIND_SERVICE).

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use abyssal_portal_net::{bound_udp, dhcp, dns};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: portal_net <interface> <ip>/<prefix> <range-start> <range-end> <lease-secs>"
        );
        std::process::exit(2);
    }
    let (ip, prefix) = args[2].split_once('/').expect("ip/prefix");
    let server_ip: Ipv4Addr = ip.parse().expect("server ip");
    let cfg = dhcp::Config {
        server_ip,
        prefix_len: prefix.parse().expect("prefix"),
        range_start: args[3].parse().expect("range start"),
        range_end: args[4].parse().expect("range end"),
        lease: Duration::from_secs(args[5].parse().expect("lease")),
        portal_url: format!("http://{server_ip}/"),
    };
    cfg.validate().expect("config");
    let pool = Arc::new(Mutex::new(dhcp::LeasePool::new(cfg.clone())));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            println!("FINGERPRINT {f:?}");
        }
    });
    let dhcp_socket = bound_udp(&args[1], 67).expect("bind 67");
    let dns_socket = bound_udp(&args[1], 53).expect("bind 53");
    println!("READY");
    tokio::select! {
        r = dhcp::serve(dhcp_socket, cfg, pool, Some(tx)) => r.expect("dhcp"),
        r = dns::serve(dns_socket, server_ip) => r.expect("dns"),
    }
}

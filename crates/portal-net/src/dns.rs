//! The registration VLAN's captive DNS: every A question is answered with
//! the portal's address, so whatever a device looks up -- its OS's
//! captive-portal check included -- leads to the portal. AAAA questions get
//! an empty answer (no IPv6 here), so clients fall back to IPv4.
//!
//! The answer is authoritative-looking and short-lived (`TTL`), so nothing
//! is cached for long once the device moves to its real VLAN.

use std::net::Ipv4Addr;

/// Seconds a captive answer may be cached.
pub const TTL: u32 = 15;

const TYPE_A: u16 = 1;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

/// The response to one DNS query datagram, or `None` to drop it (not a
/// standard query, or malformed).
pub fn answer(query: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0x0f;
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if is_response || qdcount != 1 {
        return None;
    }

    // The question: labels (no compression in a question), type, class.
    let mut i = 12;
    let mut name_len = 0usize;
    loop {
        let len = usize::from(*query.get(i)?);
        if len == 0 {
            i += 1;
            break;
        }
        if len > 63 {
            return None;
        }
        name_len += len + 1;
        if name_len > 255 {
            return None;
        }
        i += 1 + len;
    }
    let qtype = u16::from_be_bytes([*query.get(i)?, *query.get(i + 1)?]);
    let qclass = u16::from_be_bytes([*query.get(i + 2)?, *query.get(i + 3)?]);
    let question = &query[12..i + 4];

    let mut out = Vec::with_capacity(question.len() + 28);
    out.extend_from_slice(&query[0..2]); // id
    // QR, opcode echoed, AA, RD echoed; RCODE 4 (not implemented) for
    // anything but a standard query.
    let rd = flags & 0x0100;
    let rcode = if opcode == 0 { 0 } else { 4 };
    let out_flags = 0x8000 | (opcode << 11) | 0x0400 | rd | rcode;
    out.extend_from_slice(&out_flags.to_be_bytes());
    let answers: u16 =
        (opcode == 0 && qclass == CLASS_IN && matches!(qtype, TYPE_A | TYPE_ANY)).into();
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    out.extend_from_slice(question);
    if answers == 1 {
        out.extend_from_slice(&[0xc0, 0x0c]); // the question's name
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    Some(out)
}

/// Answers DNS on `socket` (from [`crate::bound_udp`] on port 53) until the
/// socket fails.
pub async fn serve(socket: tokio::net::UdpSocket, ip: Ipv4Addr) -> std::io::Result<()> {
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        if let Some(reply) = answer(&buf[..n], ip)
            && let Err(e) = socket.send_to(&reply, from).await
        {
            tracing::debug!(error = %e, %from, "registration DNS: send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    const PORTAL: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);

    #[test]
    fn every_a_question_gets_the_portal() {
        let q = query("captive.apple.com", TYPE_A);
        let r = answer(&q, PORTAL).unwrap();
        assert_eq!(&r[0..2], &[0xab, 0xcd]);
        assert_eq!(r[2] & 0x80, 0x80, "a response");
        assert_eq!(r[2] & 0x04, 0x04, "authoritative");
        assert_eq!(r[2] & 0x01, 0x01, "recursion desired echoed");
        assert_eq!(&r[6..8], &[0, 1], "one answer");
        assert_eq!(&r[12..q.len()], &q[12..], "question echoed");
        assert_eq!(&r[r.len() - 4..], &[10, 99, 0, 1]);
        let ttl = u32::from_be_bytes(r[r.len() - 10..r.len() - 6].try_into().unwrap());
        assert_eq!(ttl, TTL);
    }

    #[test]
    fn aaaa_and_other_types_get_no_answer() {
        for t in [28u16, 15, 16] {
            let r = answer(&query("example.com", t), PORTAL).unwrap();
            assert_eq!(&r[6..8], &[0, 0]);
            assert_eq!(r[3] & 0x0f, 0, "NOERROR");
        }
    }

    #[test]
    fn non_queries_and_garbage_are_dropped_or_refused() {
        let mut resp = query("a.b", TYPE_A);
        resp[2] |= 0x80;
        assert!(answer(&resp, PORTAL).is_none());
        let mut update = query("a.b", TYPE_A);
        update[2] = 0x28; // opcode 5 (UPDATE)
        let r = answer(&update, PORTAL).unwrap();
        assert_eq!(r[3] & 0x0f, 4, "NOTIMP");
        assert_eq!(&r[6..8], &[0, 0]);
        let mut two = query("a.b", TYPE_A);
        two[5] = 2;
        assert!(answer(&two, PORTAL).is_none());
        let mut long_label = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64];
        long_label.extend_from_slice(&[b'a'; 64]);
        assert!(answer(&long_label, PORTAL).is_none());
        let q = query("captive.apple.com", TYPE_A);
        for cut in 0..q.len() {
            assert!(answer(&q[..cut], PORTAL).is_none());
        }
    }
}

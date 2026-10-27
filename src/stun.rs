//! Minimal STUN client (RFC 5389 binding request) to learn this node's public address,
//! so browsers outside the LAN can reach it directly through typical home NATs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const MAGIC: u32 = 0x2112_A442;
pub const SERVERS: &[&str] = &["stun.cloudflare.com:3478", "stun.l.google.com:19302"];

pub fn binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut m = Vec::with_capacity(20);
    m.extend_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    m.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    m.extend_from_slice(&MAGIC.to_be_bytes());
    m.extend_from_slice(txid);
    m
}

/// If `packet` is a binding success response for `txid`, returns the mapped address.
pub fn parse_response(packet: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if packet.len() < 20 || packet[0..2] != [0x01, 0x01] || packet[4..8] != MAGIC.to_be_bytes() {
        return None;
    }
    if &packet[8..20] != txid {
        return None;
    }
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let body = packet.get(20..20 + len)?;
    let mut i = 0;
    let mut fallback = None;
    while i + 4 <= body.len() {
        let typ = u16::from_be_bytes([body[i], body[i + 1]]);
        let alen = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let val = body.get(i + 4..i + 4 + alen)?;
        if val.len() >= 8 && val[1] == 0x01 {
            let port = u16::from_be_bytes([val[2], val[3]]);
            let ip = [val[4], val[5], val[6], val[7]];
            match typ {
                0x0020 => {
                    let m = MAGIC.to_be_bytes();
                    let xport = port ^ 0x2112;
                    let xip = Ipv4Addr::new(ip[0] ^ m[0], ip[1] ^ m[1], ip[2] ^ m[2], ip[3] ^ m[3]);
                    return Some(SocketAddr::new(IpAddr::V4(xip), xport));
                }
                0x0001 => fallback = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)),
                _ => {}
            }
        }
        i += 4 + ((alen + 3) & !3);
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xor_mapped_address() {
        let txid = [3u8; 12];
        // Response mapping to 203.0.113.7:54321
        let addr: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let m = MAGIC.to_be_bytes();
        let IpAddr::V4(v4) = addr.ip() else { unreachable!() };
        let o = v4.octets();
        let mut attr = vec![0x00, 0x20, 0x00, 0x08, 0x00, 0x01];
        attr.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
        attr.extend_from_slice(&[o[0] ^ m[0], o[1] ^ m[1], o[2] ^ m[2], o[3] ^ m[3]]);
        let mut pkt = vec![0x01, 0x01];
        pkt.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&m);
        pkt.extend_from_slice(&txid);
        pkt.extend_from_slice(&attr);
        assert_eq!(parse_response(&pkt, &txid), Some(addr));
        assert_eq!(parse_response(&pkt, &[4u8; 12]), None, "other transaction");
        assert_eq!(binding_request(&txid).len(), 20);
    }
}

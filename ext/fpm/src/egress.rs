//! Outbound connections from the microVM guest, by hostname (addiscorp/securecore#72). Linux only.
//!
//! The guest has no network device and no DNS. A `layer1.network.connect` port with neither a
//! `socket` nor an `address` (443) is an egress port: the guest reaches named hosts on it through
//! the host, never by IP:
//!
//! ```text
//!   guest  php-fpm's getaddrinfo("api.wordpress.org") → 127.77.0.1, a name the preload keeps
//!          (libsc-vsock-connect.so); connect(127.77.0.1:443) → vsock host:1517, then one line
//!          "api.wordpress.org 443", then the host's "OK" or "ERR <why>", then the bytes
//!   host   this module: the name and port checked against the config, the name resolved
//!          here, only public addresses connected, then a byte pipe (TLS stays end to end)
//! ```
//!
//! **What may be reached** is what layer 1 and layer 2 together allow: the port must be one of
//! the egress ports, and, with layer 2 on, the name must match one of its host patterns (core's,
//! `default`'s or a component's, with layer 2's own matcher, [`host_allowed`]). Layer 2 then
//! checks the caller, per component, inside the guest, as it does on the host. With layer 2 off,
//! any name on an egress port, as gelada's port rules allow any host. Whatever the name, the
//! host connects only to globally routable addresses (never loopback, private, link-local,
//! shared or unique-local ones), unless the name is that IP literal and the config lists it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use securecore_attribution::hosts::host_allowed;
use securecore_config::Loaded;

/// The host port the guest's named connections arrive on.
pub const EGRESS_PORT: u32 = 1517;
/// The longest request line ("<name> <port>\n").
pub const MAX_REQUEST: u64 = 300;
/// How long the guest may take to send its line, and the host to connect.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What the guest may reach by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    pub ports: Vec<u16>,
    /// Layer 2's host patterns (all of them); `None`: layer 2 is off, any name.
    pub hosts: Option<Vec<String>>,
}

impl Egress {
    /// The egress ports given (the plan's `connect` ports with neither socket nor address), and
    /// layer 2's patterns from `loaded`.
    pub fn new(loaded: &Loaded, ports: Vec<u16>) -> Egress {
        let l2 = &loaded.config.layer2;
        let hosts = l2.enabled.then(|| {
            let mut all: Vec<String> = l2.core.hosts.clone();
            all.extend(l2.default.hosts.iter().flatten().cloned());
            for rules in l2.components.values() {
                all.extend(rules.hosts.iter().flatten().cloned());
            }
            all.sort();
            all.dedup();
            all
        });
        Egress { ports, hosts }
    }

    /// Whether `name:port` may be reached, or why not.
    pub fn allows(&self, name: &str, port: u16) -> Result<(), String> {
        if !self.ports.contains(&port) {
            return Err(format!("port {port} is not an egress port (layer1.network.connect)"));
        }
        if let Some(hosts) = &self.hosts
            && !host_allowed(hosts, name).is_allowed()
        {
            return Err(format!("{name} is in none of layer 2's host lists"));
        }
        Ok(())
    }
}

/// `<name> <port>`: a host name (or IP literal) of at most 253 bytes, and a port.
pub fn parse_request(line: &str) -> Result<(String, u16), String> {
    let line = line.strip_suffix('\n').ok_or("no whole request line")?;
    let (name, port) = line.split_once(' ').ok_or("want \"<name> <port>\"")?;
    if name.is_empty() || name.len() > 253 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b)) {
        return Err(format!("{name:?} is not a host name"));
    }
    let port = port.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| format!("{port:?} is not a port"))?;
    Ok((name.to_ascii_lowercase(), port))
}

/// Whether the host may connect to `ip` for a guest: only globally routable addresses.
pub fn routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return routable(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || s[0] == 0x0064)
        }
    }
}

/// The addresses to try for `name:port`: an IP literal the config lists as itself, or the
/// name's routable addresses from the host's resolver.
fn addresses(name: &str, port: u16, egress: &Egress) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = name.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
        // A literal is reachable only when layer 2 lists it as itself (its matcher never lets a
        // name pattern match an IP).
        if egress.hosts.is_none() && !routable(ip) {
            return Err(format!("{ip} is not a public address"));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let all: Vec<SocketAddr> = (name, port).to_socket_addrs().map_err(|e| format!("resolving {name}: {e}"))?.collect();
    let ok: Vec<SocketAddr> = all.iter().copied().filter(|a| routable(a.ip())).collect();
    if ok.is_empty() {
        return Err(format!("{name} resolves to no public address ({all:?})"));
    }
    Ok(ok)
}

/// One guest connection: its request line, the decision, the host's connect, then the pipe.
/// Returns what happened, for the log.
pub fn serve(conn: UnixStream, egress: &Egress) -> Result<String, String> {
    conn.set_read_timeout(Some(REQUEST_TIMEOUT)).map_err(|e| e.to_string())?;
    let mut line = String::new();
    let mut r = BufReader::new((&conn).take(MAX_REQUEST));
    r.read_line(&mut line).map_err(|e| format!("the request: {e}"))?;
    if !r.buffer().is_empty() {
        return Err("bytes after the request line, before the host's answer".into());
    }
    drop(r);
    let refuse = |why: String| {
        let _ = (&conn).write_all(format!("ERR {why}\n").as_bytes());
        Err(why)
    };
    let (name, port) = match parse_request(&line) {
        Ok(t) => t,
        Err(e) => return refuse(e),
    };
    if let Err(e) = egress.allows(&name, port) {
        return refuse(format!("{name}:{port}: {e}"));
    }
    let addrs = match addresses(&name, port, egress) {
        Ok(a) => a,
        Err(e) => return refuse(format!("{name}:{port}: {e}")),
    };
    let mut last = String::new();
    for a in &addrs {
        match TcpStream::connect_timeout(a, CONNECT_TIMEOUT) {
            Ok(tcp) => {
                let _ = tcp.set_nodelay(true);
                conn.set_read_timeout(None).map_err(|e| e.to_string())?;
                (&conn).write_all(b"OK\n").map_err(|e| e.to_string())?;
                crate::vm::pipe_both(conn, tcp);
                return Ok(format!("{name}:{port} via {a}"));
            }
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    refuse(format!("{name}:{port}: {last}"))
}

/// Reads the host's answer on a guest connection (the guest side's half, in C in the preload;
/// here for the tests).
pub fn read_answer(r: &mut impl Read) -> io::Result<String> {
    let mut line = String::new();
    BufReader::new(r.take(MAX_REQUEST)).read_line(&mut line)?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn egress(hosts: Option<&[&str]>) -> Egress {
        Egress { ports: vec![443, 8443], hosts: hosts.map(|h| h.iter().map(|s| (*s).to_owned()).collect()) }
    }

    #[test]
    fn only_listed_names_on_egress_ports() {
        let e = egress(Some(&["api.wordpress.org", "*.stripe.com"]));
        e.allows("api.wordpress.org", 443).expect("core's host");
        e.allows("x.api.stripe.com", 443).expect("a wildcard");
        assert!(e.allows("evil.example", 443).expect_err("not listed").contains("none of layer 2's host lists"));
        assert!(e.allows("api.wordpress.org", 22).expect_err("port").contains("not an egress port"));
        assert!(e.allows("stripe.com", 443).is_err(), "a wildcard never matches the bare name");
        egress(None).allows("anything.example", 443).expect("layer 2 off: any name, as gelada's ports");
    }

    #[test]
    fn requests_are_one_plain_line() {
        assert_eq!(parse_request("API.WordPress.org 443\n"), Ok(("api.wordpress.org".into(), 443)));
        for bad in ["api.wordpress.org 443", "a b c\n", "x 0\n", "x 70000\n", "\n", "a/b 443\n", "a\0b 443\n", " 443\n"] {
            assert!(parse_request(bad).is_err(), "{bad:?}");
        }
        assert!(parse_request(&format!("{} 443\n", "a".repeat(254))).is_err(), "too long");
    }

    #[test]
    fn only_public_addresses_are_connected() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1", "198.18.0.1"] {
            assert!(!routable(ip.parse().expect("ip")), "{ip}");
        }
        for ip in ["198.143.164.252", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(routable(ip.parse().expect("ip")), "{ip}");
        }
        let e = egress(None);
        assert!(addresses("127.0.0.1", 443, &e).expect_err("loopback").contains("not a public address"));
        assert!(addresses("localhost", 443, &e).expect_err("a name for loopback").contains("no public address"));
    }

    /// The host's side of a guest connection, against a local listener allowed by literal.
    #[test]
    fn a_request_gets_ok_and_a_pipe_or_err_and_nothing() {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().expect("addr").port();
        let e = Egress { ports: vec![port], hosts: Some(vec!["127.0.0.1".into()]) };
        thread::spawn(move || {
            for mut c in l.incoming().flatten() {
                let mut b = [0u8; 4];
                if c.read_exact(&mut b).is_ok() {
                    let _ = c.write_all(&b);
                }
            }
        });
        let (mut guest, host) = UnixStream::pair().expect("pair");
        let e2 = e.clone();
        let t = thread::spawn(move || serve(host, &e2));
        guest.write_all(format!("127.0.0.1 {port}\n").as_bytes()).expect("request");
        assert_eq!(read_answer(&mut guest).expect("answer"), "OK\n");
        guest.write_all(b"ping").expect("ping");
        let mut b = [0u8; 4];
        guest.read_exact(&mut b).expect("echo");
        assert_eq!(&b, b"ping", "the bytes go through");
        drop(guest);
        assert!(t.join().expect("join").expect("served").contains("127.0.0.1"));
        // Refused: an unlisted name, a non-egress port.
        for req in ["evil.example 443\n".to_owned(), format!("127.0.0.1 {}\n", port.wrapping_add(1))] {
            let (mut guest, host) = UnixStream::pair().expect("pair");
            let e2 = e.clone();
            let t = thread::spawn(move || serve(host, &e2));
            guest.write_all(req.as_bytes()).expect("request");
            let answer = read_answer(&mut guest).expect("answer");
            assert!(answer.starts_with("ERR "), "{req:?}: {answer}");
            assert!(t.join().expect("join").is_err());
        }
    }
}

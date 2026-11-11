//! Just enough of a FastCGI client for the microVM driver (addiscorp/securecore#71): php-fpm's
//! `/fpm-ping` (the guest is ready when php-fpm answers it) and the warm-up requests run before a
//! snapshot is taken. One request per connection, as nginx does without keepalive.

use std::io::{self, Read, Write};

const BEGIN_REQUEST: u8 = 1;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const RESPONDER: [u8; 8] = [0, 1, 0, 0, 0, 0, 0, 0];

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut r = vec![1, kind, 0, 1, (n >> 8) as u8, (n & 0xff) as u8, 0, 0];
    r.extend_from_slice(body);
    r
}

fn length(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
    }
}

/// The bytes of one request with `params` and an empty body.
pub fn encode(params: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (k, v) in params {
        length(&mut body, k.len());
        length(&mut body, v.len());
        body.extend_from_slice(k.as_bytes());
        body.extend_from_slice(v.as_bytes());
    }
    let mut req = record(BEGIN_REQUEST, &RESPONDER);
    // A PARAMS record holds at most 65535 bytes; these requests are far smaller.
    req.extend(record(PARAMS, &body));
    req.extend(record(PARAMS, &[]));
    req.extend(record(STDIN, &[]));
    req
}

/// Sends one request on `stream` and returns its STDOUT (headers and body).
pub fn request<S: Read + Write>(stream: &mut S, params: &[(&str, &str)]) -> io::Result<Vec<u8>> {
    stream.write_all(&encode(params))?;
    let mut out = Vec::new();
    loop {
        let mut h = [0u8; 8];
        stream.read_exact(&mut h)?;
        let len = ((h[4] as usize) << 8) | h[5] as usize;
        let mut content = vec![0u8; len + h[6] as usize];
        stream.read_exact(&mut content)?;
        match h[1] {
            STDOUT => out.extend_from_slice(&content[..len]),
            END_REQUEST => return Ok(out),
            _ => {}
        }
    }
}

/// php-fpm's own ping (`ping.path = /fpm-ping` in the guest's pool): `Ok` when it answers `pong`.
pub fn ping<S: Read + Write>(stream: &mut S) -> io::Result<()> {
    let out = request(
        stream,
        &[
            ("REQUEST_METHOD", "GET"),
            ("SCRIPT_NAME", "/fpm-ping"),
            ("SCRIPT_FILENAME", "/fpm-ping"),
            ("REQUEST_URI", "/fpm-ping"),
            ("DOCUMENT_URI", "/fpm-ping"),
            ("SERVER_PROTOCOL", "HTTP/1.1"),
        ],
    )?;
    if out.windows(4).any(|w| w == b"pong") {
        Ok(())
    } else {
        Err(io::Error::other(format!("php-fpm's ping answered {:?}", String::from_utf8_lossy(&out))))
    }
}

/// A GET of `/` through `<root>/index.php`, as nginx sends it: the snapshot's warm-up.
pub fn get_front_page<S: Read + Write>(stream: &mut S, root: &str) -> io::Result<Vec<u8>> {
    let script = format!("{}/index.php", root.trim_end_matches('/'));
    request(
        stream,
        &[
            ("REQUEST_METHOD", "GET"),
            ("SCRIPT_NAME", "/index.php"),
            ("SCRIPT_FILENAME", &script),
            ("DOCUMENT_ROOT", root),
            ("REQUEST_URI", "/"),
            ("DOCUMENT_URI", "/index.php"),
            ("QUERY_STRING", ""),
            ("SERVER_PROTOCOL", "HTTP/1.1"),
            ("SERVER_NAME", "localhost"),
            ("SERVER_PORT", "80"),
            ("REMOTE_ADDR", "127.0.0.1"),
            ("GATEWAY_INTERFACE", "CGI/1.1"),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A stream that reads a canned reply and records what was written.
    struct Fake {
        reply: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }
    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reply.read(buf)
        }
    }
    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn reply(stdout: &[u8]) -> Vec<u8> {
        let mut r = record(STDOUT, stdout);
        r.extend(record(STDOUT, &[]));
        r.extend(record(END_REQUEST, &[0; 8]));
        r
    }

    #[test]
    fn ping_reads_stdout_until_end_request() {
        let mut ok = Fake { reply: Cursor::new(reply(b"Content-type: text/plain\r\n\r\npong")), sent: vec![] };
        ping(&mut ok).expect("pong");
        assert_eq!(&ok.sent[..8], &[1, BEGIN_REQUEST, 0, 1, 0, 8, 0, 0], "a BEGIN_REQUEST record first");
        let mut bad = Fake { reply: Cursor::new(reply(b"Status: 404\r\n\r\nFile not found.")), sent: vec![] };
        assert!(ping(&mut bad).is_err(), "anything but pong is not ready");
        let mut cut = Fake { reply: Cursor::new(record(STDOUT, b"po")), sent: vec![] };
        assert!(ping(&mut cut).is_err(), "a reply cut short is an error");
    }

    #[test]
    fn long_values_use_four_byte_lengths() {
        let long = "x".repeat(300);
        let req = encode(&[("SCRIPT_FILENAME", &long)]);
        let params = &req[16..];
        assert_eq!(params[8], 15, "the name's length in one byte");
        assert_eq!(&params[9..13], &(300u32 | 0x8000_0000).to_be_bytes(), "the value's in four");
    }
}

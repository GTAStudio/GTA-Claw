//! Headless GTA Claw daemon and native health endpoint.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use claw_application::Application;
use claw_platform::NativeSystemProbe;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:3978";
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_ACTIVE_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const OVERLOAD_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonMode {
    Serve,
    Probe,
    ProbeHttp,
}

fn parse_mode<I, S>(arguments: I) -> io::Result<DaemonMode>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let first = arguments.next();
    let second = arguments.next();

    match (first.as_deref(), second) {
        (None, None) => Ok(DaemonMode::Serve),
        (Some("--probe"), None) => Ok(DaemonMode::Probe),
        (Some("--probe-http"), None) => Ok(DaemonMode::ProbeHttp),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: gta-claw-daemon [--probe|--probe-http]",
        )),
    }
}

fn probe(mut output: impl Write) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);

    writeln!(output, "{}", application.health())?;
    output.flush()?;
    Ok(())
}

fn configured_address() -> String {
    std::env::var("GTA_CLAW_BIND").unwrap_or_else(|_| DEFAULT_BIND_ADDRESS.to_owned())
}

fn serve(mut output: impl Write, address: &str) -> io::Result<()> {
    let application = Application::new(NativeSystemProbe);
    let listener = TcpListener::bind(address)?;

    writeln!(output, "{}", application.ready())?;
    writeln!(output, "{}", application.health())?;
    output.flush()?;

    let active_connections = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let active_connections = Arc::clone(&active_connections);
                let permit = active_connections.fetch_update(
                    Ordering::AcqRel,
                    Ordering::Acquire,
                    |active| (active < MAX_ACTIVE_CONNECTIONS).then_some(active + 1),
                );
                if permit.is_err() {
                    reject_busy_connection(stream);
                    continue;
                }
                let permit = ConnectionPermit(active_connections);
                let worker = std::thread::Builder::new()
                    .name("gta-claw-http".to_owned())
                    .spawn(move || {
                        let _permit = permit;
                        let mut stream = stream;
                        if let Err(error) = handle_connection(&mut stream) {
                            eprintln!("health endpoint connection failed: {error}");
                        }
                    });
                if let Err(error) = worker {
                    eprintln!("health endpoint worker failed to start: {error}");
                }
            }
            Err(error) => eprintln!("health endpoint accept failed: {error}"),
        }
    }

    Ok(())
}

struct ConnectionPermit(Arc<AtomicUsize>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reject_busy_connection(mut stream: TcpStream) {
    let response = b"HTTP/1.1 503 Service Unavailable\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: 27\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {\"error\":\"server is busy\"}\n";
    if let Err(error) = stream.set_write_timeout(Some(OVERLOAD_WRITE_TIMEOUT)) {
        eprintln!("health endpoint overload timeout failed: {error}");
        return;
    }
    if let Err(error) = stream.write_all(response) {
        eprintln!("health endpoint overload response failed: {error}");
        return;
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    let _ = read_request_line_with_timeout(&mut stream, OVERLOAD_WRITE_TIMEOUT);
}

fn handle_connection(stream: &mut TcpStream) -> io::Result<()> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let request_line = read_request_line(stream)?;
    let (status, body) = if matches!(
        request_line.as_deref(),
        Some("GET /health HTTP/1.1" | "GET /health HTTP/1.0")
    ) {
        (
            "200 OK",
            format!(
                "{{\"status\":\"ok\",\"runtime\":{{\"os\":\"{}\",\"arch\":\"{}\"}}}}\n",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        )
    } else {
        ("404 Not Found", "{\"error\":\"not found\"}\n".to_owned())
    };

    write!(
        stream,
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )?;
    stream.flush()
}

fn read_request_line(stream: &mut TcpStream) -> io::Result<Option<String>> {
    read_request_line_with_timeout(stream, IO_TIMEOUT)
}

fn read_request_line_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> io::Result<Option<String>> {
    let deadline = Instant::now() + timeout;
    let mut request = Vec::with_capacity(1024);
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n")
            || request.windows(2).any(|window| window == b"\n\n")
        {
            break;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP request deadline exceeded",
            ));
        };
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP request deadline exceeded",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let mut buffer = [0_u8; 1024];
        let available = (MAX_REQUEST_BYTES + 1 - request.len()).min(buffer.len());
        let bytes = stream.read(&mut buffer[..available])?;
        if bytes == 0 {
            if request.is_empty() {
                return Ok(None);
            }
            break;
        }
        request.extend_from_slice(&buffer[..bytes]);
        if request.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request headers exceed limit",
            ));
        }
    }

    let request_line_end = request
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(request.len());
    let request_line = std::str::from_utf8(&request[..request_line_end]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP request line is not UTF-8: {error}"),
        )
    })?;
    Ok(Some(request_line.trim_end_matches('\r').to_owned()))
}

fn probe_http(address: &str, mut output: impl Write) -> io::Result<()> {
    let mut address: SocketAddr = address.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid GTA_CLAW_BIND address: {error}"),
        )
    })?;
    if address.ip().is_unspecified() {
        address.set_ip(match address.ip() {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        });
    }

    let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;

    let mut response = String::new();
    stream
        .take(MAX_REQUEST_BYTES as u64)
        .read_to_string(&mut response)?;
    if !response.starts_with("HTTP/1.1 200 OK\r\n")
        || !response.contains("\r\n\r\n{\"status\":\"ok\"")
    {
        return Err(io::Error::other(
            "health endpoint returned an unhealthy response",
        ));
    }

    writeln!(output, "healthy endpoint=http://{address}/health")?;
    output.flush()
}

fn run<I, S>(arguments: I, output: impl Write) -> Result<(), Box<dyn std::error::Error>>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    match parse_mode(arguments)? {
        DaemonMode::Serve => serve(output, &configured_address())?,
        DaemonMode::Probe => probe(output)?,
        DaemonMode::ProbeHttp => probe_http(&configured_address(), output)?,
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(std::env::args().skip(1), io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::{DaemonMode, handle_connection, parse_mode, read_request_line_with_timeout, run};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    #[test]
    fn normal_mode_is_persistent_and_probe_is_explicit() {
        assert_eq!(
            parse_mode(std::iter::empty::<String>()).expect("default mode"),
            DaemonMode::Serve
        );
        assert_eq!(
            parse_mode(["--probe"]).expect("probe mode"),
            DaemonMode::Probe
        );
        assert_eq!(
            parse_mode(["--probe-http"]).expect("HTTP probe mode"),
            DaemonMode::ProbeHttp
        );
    }

    #[test]
    fn one_shot_probe_emits_only_health() {
        let mut output = Vec::new();

        run(["--probe"], &mut output).expect("daemon probe succeeds");

        let output = String::from_utf8(output).expect("output is UTF-8");
        assert!(output.starts_with("healthy runtime="));
        assert!(!output.contains("ready protocol="));
    }

    #[test]
    fn unsupported_arguments_are_rejected() {
        let error = parse_mode(["--serve"]).expect_err("unknown mode must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn health_route_returns_native_json_and_unknown_routes_fail_closed() {
        for (request, expected_status) in [
            ("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n", "200 OK"),
            (
                "GET /chat HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "404 Not Found",
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
            let address = listener.local_addr().expect("test listener address");
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept test request");
                handle_connection(&mut stream).expect("handle test request");
            });
            let mut client = TcpStream::connect(address).expect("connect test client");
            client
                .write_all(request.as_bytes())
                .expect("write test request");
            let mut response = String::new();
            client
                .read_to_string(&mut response)
                .expect("read test response");
            worker.join().expect("health worker joins");

            assert!(response.starts_with(&format!("HTTP/1.1 {expected_status}\r\n")));
        }
    }

    #[test]
    fn request_deadline_is_absolute_across_slow_trickle_reads() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect trickle client");
            for byte in b"GET /health HTTP/1.1\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let (mut stream, _) = listener.accept().expect("accept trickle client");
        let started = Instant::now();

        let error = read_request_line_with_timeout(&mut stream, Duration::from_millis(150))
            .expect_err("slow trickle must exceed one absolute request deadline");

        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "request deadline reset after partial reads"
        );
        drop(stream);
        client.join().expect("trickle client joins");
    }
}

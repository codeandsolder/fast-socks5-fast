# fast-socks5-fast

A small, transport-independent **SOCKS5 server protocol** crate built on Tokio async I/O.

This maintained fork implements the RFC 1928 state machine and RFC 1929
username/password authentication. It deliberately **does not own the network
stack**: DNS resolution, outbound TCP connections, BIND listeners, UDP
associations, access rules, and data forwarding belong to the consumer.

## Features

- No-authentication, username/password, and custom authentication methods
- Compile-time authentication/command state transitions
- CONNECT, BIND, and UDP ASSOCIATE request parsing
- IPv4, IPv6, and unresolved domain-name destinations
- SOCKS5 reply encoding with explicit failure codes
- No unsafe code or platform-specific system dependencies

## Using the protocol

Wrap any `AsyncRead + AsyncWrite + Unpin + Send` stream. After negotiating
authentication, the returned authenticated state can parse a command. The
caller handles the command and sends its own success/failure reply.

```rust,no_run
use fast_socks5::{
    ReplyError, Socks5Command,
    server::{Socks5ServerProtocol, SocksServerError},
};
use tokio::io::{AsyncRead, AsyncWrite};

async fn handle<T>(stream: T) -> Result<(), SocksServerError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let protocol = Socks5ServerProtocol::accept_no_auth(stream).await?;
    let (protocol, command, _target) = protocol.read_command().await?;

    match command {
        Socks5Command::TcpConnect
        | Socks5Command::TcpBind
        | Socks5Command::UdpAssociate => {
            // Replace this with a caller-owned transport implementation.
            protocol.reply_error(&ReplyError::CommandNotSupported).await
        }
    }
}
```

For complete, runnable in-memory exchanges, see
[`tests/server_protocol.rs`](tests/server_protocol.rs) and
[`tests/protocol_edge_cases.rs`](tests/protocol_edge_cases.rs).

## Contract and security

- Domain targets stay unresolved; clients must choose their DNS policy.
- RFC 1929 usernames and passwords are opaque 1–255-byte fields, not
  necessarily UTF-8. `accept_password_auth` passes borrowed `&[u8]` fields
  to the verifier; lower-level `read_username_password` returns `Vec<u8>`
  fields. Callers may compare with `expected.as_bytes()` or decode explicitly.
- The library does not log credential contents. SOCKS5 itself does not
  encrypt the authentication exchange; use an appropriate secure transport.
- Consumers must enforce connection timeouts, resource limits, and outbound
  access-control policy.

The crate retains the published package name `fast-socks5` and targets
Rust 1.99 or newer.

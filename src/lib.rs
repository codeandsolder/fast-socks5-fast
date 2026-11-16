//! Asynchronous SOCKS5 server protocol negotiation, authentication, and request parsing.
//!
//! The crate operates on a caller-owned Tokio-compatible async stream. It does not
//! establish outbound connections, resolve domain names, or implement TCP/UDP relays.
//! The caller decides how to handle [`Socks5Command`] and
//! [`util::target_addr::TargetAddr`] after parsing a request.
//!
//! # Supported protocol
//!
//! - RFC 1928 no-authentication and username/password method negotiation.
//! - RFC 1929 arbitrary-octet username/password authentication and custom authentication methods.
//! - CONNECT, BIND, and UDP ASSOCIATE command parsing (transport behavior is caller-owned).
//! - IPv4, IPv6, and unresolved domain-form targets.
//! - Typed state progression from authentication to request parsing and reply encoding.
//!
//! # Examples
//!
//! See [`tests/server_protocol.rs`](https://github.com/codeandsolder/fast-socks5-fast/blob/master/tests/server_protocol.rs)
//! for an in-memory SOCKS5 exchange, including unsupported UDP ASSOCIATE handling.
//!
//! # Security
//!
//! Authentication credentials are not logged. The caller must arrange transport
//! confidentiality, authentication policy, connection timeouts, and outbound access rules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Internal I/O helper; public APIs use Tokio async I/O traits.
macro_rules! read_exact {
    ($stream:expr, $array:expr) => {{
        let mut buffer = $array;
        $stream.read_exact(&mut buffer).await.map(|_| buffer)
    }};
}

/// Server-side SOCKS5 authentication and command-parsing state machines.
pub mod server;
/// Shared SOCKS5 wire-format utilities.
pub mod util;

use thiserror::Error;

#[rustfmt::skip]
/// Wire constants from RFC 1928 and RFC 1929.
pub mod consts {
    /// SOCKS5 protocol version byte.
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    /// Success status for RFC 1929 username/password authentication.
    pub const SOCKS5_AUTH_STATUS_SUCCESS: u8 = 0x00;
    /// Failure status for RFC 1929 username/password authentication.
    pub const SOCKS5_AUTH_STATUS_FAILURE: u8 = 0x01;

    /// No-authentication method identifier.
    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    /// GSSAPI authentication method identifier.
    pub const SOCKS5_AUTH_METHOD_GSSAPI:               u8 = 0x01;
    /// Username/password authentication method identifier.
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    /// No mutually supported authentication method.
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    /// TCP CONNECT command identifier.
    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    /// TCP BIND command identifier.
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    /// UDP ASSOCIATE command identifier.
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    /// IPv4 address-type identifier.
    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    /// Domain-name address-type identifier.
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    /// IPv6 address-type identifier.
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    /// Success reply status.
    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    /// General failure reply status.
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    /// Connection rejected by ruleset status.
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    /// Network unreachable reply status.
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    /// Host unreachable reply status.
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    /// Connection refused reply status.
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    /// TTL expired reply status.
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    /// Unsupported command reply status.
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    /// Unsupported address type reply status.
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// SOCKS5 commands requested by clients.
pub enum Socks5Command {
    /// Establish a TCP connection to a target.
    TcpConnect,
    /// Listen for an incoming TCP connection.
    TcpBind,
    /// Establish a UDP association.
    UdpAssociate,
}

impl Socks5Command {
    #[inline]
    #[rustfmt::skip]
    const fn from_u8(code: u8) -> Option<Self> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT      => Some(Self::TcpConnect),
            consts::SOCKS5_CMD_TCP_BIND         => Some(Self::TcpBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE    => Some(Self::UdpAssociate),
            _ => None,
        }
    }
}

/// SOCKS5 reply code
#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReplyError {
    /// The request succeeded.
    #[error("succeeded")]
    Succeeded,
    /// A general proxy-server failure occurred.
    #[error("general failure")]
    GeneralFailure,
    /// The connection was rejected by access rules.
    #[error("connection not allowed by ruleset")]
    ConnectionNotAllowed,
    /// The destination network is unreachable.
    #[error("network unreachable")]
    NetworkUnreachable,
    /// The destination host is unreachable.
    #[error("host unreachable")]
    HostUnreachable,
    /// The target refused the connection.
    #[error("connection refused")]
    ConnectionRefused,
    /// The IP time-to-live expired.
    #[error("TTL expired")]
    TtlExpired,
    /// The requested SOCKS5 command is unsupported.
    #[error("command not supported")]
    CommandNotSupported,
    /// The requested address type is unsupported.
    #[error("address type not supported")]
    AddressTypeNotSupported,
    //    OtherReply(u8),
}

impl ReplyError {
    #[inline]
    #[rustfmt::skip]
    #[must_use]
    /// Encode this reply as an RFC 1928 status octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Succeeded               => consts::SOCKS5_REPLY_SUCCEEDED,
            Self::GeneralFailure          => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            Self::ConnectionNotAllowed    => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Self::NetworkUnreachable      => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Self::HostUnreachable         => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            Self::ConnectionRefused       => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            Self::TtlExpired           => consts::SOCKS5_REPLY_TTL_EXPIRED,
            Self::CommandNotSupported     => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Self::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
//            ReplyError::OtherReply(c)           => c,
        }
    }

    #[inline]
    #[rustfmt::skip]
    /// Decode a SOCKS5 reply code, returning `None` for an unknown wire value.
    #[must_use]
    pub const fn from_u8(code: u8) -> Option<Self> {
        match code {
            consts::SOCKS5_REPLY_SUCCEEDED                  => Some(Self::Succeeded),
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => Some(Self::GeneralFailure),
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => Some(Self::ConnectionNotAllowed),
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => Some(Self::NetworkUnreachable),
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => Some(Self::HostUnreachable),
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => Some(Self::ConnectionRefused),
            consts::SOCKS5_REPLY_TTL_EXPIRED                => Some(Self::TtlExpired),
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => Some(Self::CommandNotSupported),
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Some(Self::AddressTypeNotSupported),
//            _                                               => ReplyError::OtherReply(code),
            _                                               => None,
        }
    }
}

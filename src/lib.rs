//! Fast SOCKS5 server protocol implementation written in Rust async/.await (with tokio).
//!
//! This library is maintained by [anyip.io](https://anyip.io/) a residential and mobile socks5 proxy provider.
//!
//! ## Features
//!
//! - An `async`/`.await` [SOCKS5](https://tools.ietf.org/html/rfc1928) implementation.
//! - No **unsafe** code
//! - Built on top of the [Tokio](https://tokio.rs/) runtime
//! - Ultra lightweight and scalable
//! - No system dependencies
//! - Cross-platform
//! - Infinitely extensible, explicit server API based on typestates for safety
//!   - You control the request handling, the library only ensures you follow the proper protocol flow
//!   - Domain targets are returned unresolved so the caller owns DNS policy
//!   - Can skip the authentication/handshake process (not RFC-compliant, for private use, to save on useless round-trips)
//!   - Dialing and relay are caller-owned; this crate only parses protocol state and encodes replies
//! - Authentication methods:
//!   - No-Auth method (`0x00`)
//!   - Username/Password auth method (`0x02`)
//!   - Custom auth methods can be implemented on the server side via the `AuthMethod` Trait
//!     - Multiple auth methods with runtime negotiation can be supported, with fast *static* dispatch (enums can be generated with the `auth_method_enums` macro)
//! - All SOCKS5 RFC errors (replies) should be mapped
//! - `IPv4`, `IPv6`, and `Domains` types are supported
//!
//! ## Install
//!
//! Open in [crates.io](https://crates.io/crates/fast-socks5).
//!
//!
//! ## Examples
//!
//! Please check [`examples`](https://github.com/codeandsolder/fast-socks5-fast/tree/master/examples) directory.

#![forbid(unsafe_code)]
#[macro_use]
extern crate log;

#[macro_export]
macro_rules! read_exact {
    ($stream:expr, $array:expr) => {{
        let mut buffer = $array;
        $stream.read_exact(&mut buffer).await.map(|_| buffer)
    }};
}

pub mod server;
pub mod util;

use thiserror::Error;

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI:               u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Socks5Command {
    TCPConnect,
    TCPBind,
    UDPAssociate,
}

impl Socks5Command {
    #[inline]
    #[rustfmt::skip]
    const fn from_u8(code: u8) -> Option<Self> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT      => Some(Self::TCPConnect),
            consts::SOCKS5_CMD_TCP_BIND         => Some(Self::TCPBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE    => Some(Self::UDPAssociate),
            _ => None,
        }
    }
}

/// SOCKS5 reply code
#[derive(Error, Debug, Copy, Clone)]
pub enum ReplyError {
    #[error("Succeeded")]
    Succeeded,
    #[error("General failure")]
    GeneralFailure,
    #[error("Connection not allowed by ruleset")]
    ConnectionNotAllowed,
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("TTL expired")]
    TtlExpired,
    #[error("Command not supported")]
    CommandNotSupported,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    //    OtherReply(u8),
}

impl ReplyError {
    #[inline]
    #[rustfmt::skip]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Succeeded               => consts::SOCKS5_REPLY_SUCCEEDED,
            Self::GeneralFailure          => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            Self::ConnectionNotAllowed    => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Self::NetworkUnreachable      => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Self::HostUnreachable         => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            Self::ConnectionRefused       => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            Self::ConnectionTimeout | Self::TtlExpired => consts::SOCKS5_REPLY_TTL_EXPIRED,
            Self::CommandNotSupported     => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Self::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
//            ReplyError::OtherReply(c)           => c,
        }
    }

    #[inline]
    #[rustfmt::skip]
    #[must_use]
    pub fn from_u8(code: u8) -> Self {
        match code {
            consts::SOCKS5_REPLY_SUCCEEDED                  => Self::Succeeded,
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => Self::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => Self::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => Self::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => Self::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => Self::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED                => Self::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => Self::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Self::AddressTypeNotSupported,
//            _                                               => ReplyError::OtherReply(code),
            _                                               => unreachable!("ReplyError code unsupported."),
        }
    }
}

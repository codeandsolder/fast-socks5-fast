use crate::ReplyError;
use crate::consts;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(thiserror::Error, Debug)]
pub enum AddrError {
    #[error("Can't read IPv4: {0}")]
    IPv4Unreadable(#[source] io::Error),
    #[error("Can't read IPv6: {0}")]
    IPv6Unreadable(#[source] io::Error),
    #[error("Can't read port number: {0}")]
    PortNumberUnreadable(#[source] io::Error),
    #[error("Can't read domain len: {0}")]
    DomainLenUnreadable(#[source] io::Error),
    #[error("Can't read domain content: {0}")]
    DomainContentUnreadable(#[source] io::Error),
    #[error("Malformed UTF-8")]
    Utf8(#[source] std::string::FromUtf8Error),
    #[error("Unknown address type")]
    IncorrectAddressType,
}

impl AddrError {
    #[must_use]
    pub const fn to_reply_error(&self) -> ReplyError {
        match self {
            Self::IncorrectAddressType => ReplyError::AddressTypeNotSupported,
            _ => ReplyError::ConnectionRefused,
        }
    }
}

/// A SOCKS5 connection target parsed from a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    /// Connect to an IP address.
    Ip(SocketAddr),
    /// Connect to a domain name. Resolution belongs to the caller.
    Domain(String, u16),
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(domain, port) => write!(f, "{domain}:{port}"),
        }
    }
}

enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String),
}

pub(crate) async fn read_address<T: AsyncRead + Unpin>(
    stream: &mut T,
    atyp: u8,
) -> Result<TargetAddr, AddrError> {
    let addr = match atyp {
        consts::SOCKS5_ADDR_TYPE_IPV4 => {
            debug!("Address type `IPv4`");
            Addr::V4(read_exact!(stream, [0_u8; 4]).map_err(AddrError::IPv4Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_IPV6 => {
            debug!("Address type `IPv6`");
            Addr::V6(read_exact!(stream, [0_u8; 16]).map_err(AddrError::IPv6Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            debug!("Address type `domain`");
            let len = read_exact!(stream, [0_u8]).map_err(AddrError::DomainLenUnreadable)?[0];
            let domain = read_exact!(stream, vec![0_u8; usize::from(len)])
                .map_err(AddrError::DomainContentUnreadable)?;
            Addr::Domain(String::from_utf8(domain).map_err(AddrError::Utf8)?)
        }
        _ => return Err(AddrError::IncorrectAddressType),
    };

    let port = u16::from_be_bytes(
        read_exact!(stream, [0_u8; 2]).map_err(AddrError::PortNumberUnreadable)?,
    );

    Ok(match addr {
        Addr::V4([a, b, c, d]) => TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(a, b, c, d),
            port,
        ))),
        Addr::V6(bytes) => TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(bytes),
            port,
            0,
            0,
        ))),
        Addr::Domain(domain) => TargetAddr::Domain(domain, port),
    })
}

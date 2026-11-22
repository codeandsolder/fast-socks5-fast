use crate::ReplyError;
use crate::consts;
use log::debug;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(thiserror::Error, Debug)]
/// Errors while decoding a SOCKS5 destination address.
pub enum AddrError {
    #[error("cannot read IPv4 address and port: {0}")]
    /// IPv4 destination body (address and port) could not be read.
    Ipv4Unreadable(#[source] io::Error),
    #[error("cannot read IPv6 address and port: {0}")]
    /// IPv6 destination body (address and port) could not be read.
    Ipv6Unreadable(#[source] io::Error),
    #[error("cannot read port number: {0}")]
    /// A domain destination's two-byte port could not be read.
    PortNumberUnreadable(#[source] io::Error),
    #[error("cannot read domain length: {0}")]
    /// The domain-length octet could not be read.
    DomainLenUnreadable(#[source] io::Error),
    #[error("cannot read domain contents: {0}")]
    /// The declared domain bytes could not be read.
    DomainContentUnreadable(#[source] io::Error),
    #[error("malformed UTF-8")]
    /// A domain contained invalid UTF-8.
    Utf8(#[source] std::str::Utf8Error),
    #[error("unknown address type")]
    /// The address-type octet is not recognized.
    IncorrectAddressType,
    #[error("domain target cannot be empty")]
    /// A domain-form target declared zero bytes.
    EmptyDomain,
}

impl AddrError {
    /// Translate a malformed address into a SOCKS5 reply status.
    #[must_use = "the returned status is needed to report the address-decoding error"]
    pub const fn to_reply_error(&self) -> ReplyError {
        match self {
            Self::IncorrectAddressType => ReplyError::AddressTypeNotSupported,
            _ => ReplyError::GeneralFailure,
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

pub(crate) async fn read_address<T: AsyncRead + Unpin>(
    stream: &mut T,
    atyp: u8,
) -> Result<TargetAddr, AddrError> {
    match atyp {
        consts::SOCKS5_ADDR_TYPE_IPV4 => {
            debug!("Address type `IPv4`");
            let mut body = [0_u8; 6];
            stream
                .read_exact(&mut body)
                .await
                .map_err(AddrError::Ipv4Unreadable)?;
            let [a, b, c, d, high, low] = body;
            Ok(TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(a, b, c, d),
                u16::from_be_bytes([high, low]),
            ))))
        }
        consts::SOCKS5_ADDR_TYPE_IPV6 => {
            debug!("Address type `IPv6`");
            let mut body = [0_u8; 18];
            stream
                .read_exact(&mut body)
                .await
                .map_err(AddrError::Ipv6Unreadable)?;
            let [bytes @ .., high, low] = body;
            Ok(TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(bytes),
                u16::from_be_bytes([high, low]),
                0,
                0,
            ))))
        }
        consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            debug!("Address type `domain`");
            let len = stream
                .read_u8()
                .await
                .map_err(AddrError::DomainLenUnreadable)?;
            if len == 0 {
                return Err(AddrError::EmptyDomain);
            }
            let mut bytes = vec![0; usize::from(len)];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(AddrError::DomainContentUnreadable)?;
            // Decode before reading the port so an invalid domain fails without
            // waiting for more bytes, regardless of how the transport fragments it.
            let domain =
                String::from_utf8(bytes).map_err(|err| AddrError::Utf8(err.utf8_error()))?;
            let port = stream
                .read_u16()
                .await
                .map_err(AddrError::PortNumberUnreadable)?;
            Ok(TargetAddr::Domain(domain, port))
        }
        _ => Err(AddrError::IncorrectAddressType),
    }
}

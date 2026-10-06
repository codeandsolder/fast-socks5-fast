use crate::ReplyError;
use crate::consts;
use crate::consts::SOCKS5_ADDR_TYPE_IPV4;
use crate::read_exact;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::vec::IntoIter;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::lookup_host;

/// SOCKS5 reply code
#[derive(thiserror::Error, Debug)]
pub enum AddrError {
    #[error("DNS Resolution failed: {0}")]
    DNSResolutionFailed(#[source] io::Error),
    #[error("DNS returned no appropriate records")]
    NoDNSRecords,
    #[error("Domain length {0} exceeded maximum")]
    DomainLenTooLong(usize),
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
    #[error("Can't convert address: {0}")]
    AddrConversionFailed(#[source] io::Error),
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

/// A description of a connection target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    /// Connect to an IP address.
    Ip(SocketAddr),
    /// Connect to a fully qualified domain name.
    ///
    /// The domain name will be passed along to the proxy server and DNS lookup
    /// will happen there.
    Domain(String, u16),
}

impl TargetAddr {
    ///
    /// # Errors
    ///
    /// Returns an error if DNS lookup fails or returns no usable address.
    pub async fn resolve_dns(self) -> Result<Self, AddrError> {
        match self {
            Self::Ip(ip) => Ok(Self::Ip(ip)),
            Self::Domain(domain, port) => {
                debug!("Attempt to DNS resolve the domain {domain}...");

                let socket_addr = lookup_host((&domain[..], port))
                    .await
                    .map_err(AddrError::DNSResolutionFailed)?
                    .next()
                    .ok_or(AddrError::NoDNSRecords)?;
                debug!("domain name resolved to {socket_addr}");

                // has been converted to an ip
                Ok(Self::Ip(socket_addr))
            }
        }
    }

    #[must_use]
    pub const fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    #[must_use]
    pub const fn is_domain(&self) -> bool {
        !self.is_ip()
    }

    ///
    /// # Errors
    ///
    /// Returns an error if a domain name is too long for the SOCKS5 one-byte length field.
    pub fn to_be_bytes(&self) -> Result<Vec<u8>, AddrError> {
        let mut buf = vec![];
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                debug!("TargetAddr::IpV4");

                buf.extend_from_slice(&[SOCKS5_ADDR_TYPE_IPV4]);

                debug!("addr ip {:?}", (*addr.ip()).octets());
                buf.extend_from_slice(&(addr.ip()).octets()); // ip
                buf.extend_from_slice(&addr.port().to_be_bytes()); // port
            }
            Self::Ip(SocketAddr::V6(addr)) => {
                debug!("TargetAddr::IpV6");
                buf.extend_from_slice(&[consts::SOCKS5_ADDR_TYPE_IPV6]);

                debug!("addr ip {:?}", (*addr.ip()).octets());
                buf.extend_from_slice(&(addr.ip()).octets()); // ip
                buf.extend_from_slice(&addr.port().to_be_bytes()); // port
            }
            Self::Domain(domain, port) => {
                debug!("TargetAddr::Domain");
                if domain.len() > u8::MAX as usize {
                    return Err(AddrError::DomainLenTooLong(domain.len()));
                }
                let domain_len = u8::try_from(domain.len())
                    .map_err(|_| AddrError::DomainLenTooLong(domain.len()))?;
                buf.extend_from_slice(&[consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME, domain_len]);
                buf.extend_from_slice(domain.as_bytes()); // domain content
                buf.extend_from_slice(&port.to_be_bytes());
                // port content (.to_be_bytes() convert from u16 to u8 type)
            }
        }
        Ok(buf)
    }

    #[must_use]
    pub fn into_string_and_port(self) -> (String, u16) {
        match self {
            Self::Ip(socket_addr) => (socket_addr.ip().to_string(), socket_addr.port()),
            Self::Domain(domain, port) => (domain, port),
        }
    }
}

// async-std ToSocketAddrs doesn't supports external trait implementation
// @see https://github.com/async-rs/async-std/issues/539
impl std::net::ToSocketAddrs for TargetAddr {
    type Iter = IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<IntoIter<SocketAddr>> {
        match *self {
            Self::Ip(addr) => Ok(vec![addr].into_iter()),
            Self::Domain(_, _) => Err(io::Error::other(
                "Domain name has to be explicitly resolved, please use TargetAddr::resolve_dns().",
            )),
        }
    }
}

impl fmt::Display for TargetAddr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Ip(ref addr) => write!(f, "{addr}"),
            Self::Domain(ref addr, ref port) => write!(f, "{addr}:{port}"),
        }
    }
}

/// A trait for objects that can be converted to `TargetAddr`.
pub trait ToTargetAddr {
    /// Converts the value of `self` to a `TargetAddr`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be converted into a SOCKS target address.
    fn to_target_addr(&self) -> io::Result<TargetAddr>;
}

impl ToTargetAddr for (&str, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        // try to parse as an IP first
        if let Ok(addr) = self.0.parse::<Ipv4Addr>() {
            return (addr, self.1).to_target_addr();
        }

        if let Ok(addr) = self.0.parse::<Ipv6Addr>() {
            return (addr, self.1).to_target_addr();
        }

        Ok(TargetAddr::Domain(self.0.to_owned(), self.1))
    }
}

impl ToTargetAddr for SocketAddr {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        Ok(TargetAddr::Ip(*self))
    }
}

impl ToTargetAddr for SocketAddrV4 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V4(*self).to_target_addr()
    }
}

impl ToTargetAddr for SocketAddrV6 {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddr::V6(*self).to_target_addr()
    }
}

impl ToTargetAddr for (IpAddr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        match self.0 {
            IpAddr::V4(ipv4_addr) => (ipv4_addr, self.1).to_target_addr(),
            IpAddr::V6(ipv6_addr) => (ipv6_addr, self.1).to_target_addr(),
        }
    }
}

impl ToTargetAddr for (Ipv4Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV4::new(self.0, self.1).to_target_addr()
    }
}

impl ToTargetAddr for (Ipv6Addr, u16) {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        SocketAddrV6::new(self.0, self.1, 0, 0).to_target_addr()
    }
}

impl ToTargetAddr for TargetAddr {
    fn to_target_addr(&self) -> io::Result<TargetAddr> {
        Ok(self.clone())
    }
}

#[derive(Debug)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(String), // Vec<[u8]> or Box<[u8]> or String ?
}

/// This function is used by the client & the server
pub(crate) async fn read_address<T: AsyncRead + Unpin>(
    stream: &mut T,
    atyp: u8,
) -> Result<TargetAddr, AddrError> {
    let addr = match atyp {
        consts::SOCKS5_ADDR_TYPE_IPV4 => {
            debug!("Address type `IPv4`");
            Addr::V4(read_exact!(stream, [0u8; 4]).map_err(AddrError::IPv4Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_IPV6 => {
            debug!("Address type `IPv6`");
            Addr::V6(read_exact!(stream, [0u8; 16]).map_err(AddrError::IPv6Unreadable)?)
        }
        consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            debug!("Address type `domain`");
            let len = read_exact!(stream, [0]).map_err(AddrError::DomainLenUnreadable)?[0];
            let domain = read_exact!(stream, vec![0u8; len as usize])
                .map_err(AddrError::DomainContentUnreadable)?;
            // make sure the bytes are correct utf8 string
            let domain = String::from_utf8(domain).map_err(AddrError::Utf8)?;

            Addr::Domain(domain)
        }
        _ => return Err(AddrError::IncorrectAddressType),
    };

    // Find port number
    let port = read_exact!(stream, [0u8; 2]).map_err(AddrError::PortNumberUnreadable)?;
    // Convert (u8 * 2) into u16
    let port = u16::from(port[0]) << 8 | u16::from(port[1]);

    // Merge ADDRESS + PORT into a TargetAddr
    let addr: TargetAddr = match addr {
        Addr::V4([a, b, c, d]) => (Ipv4Addr::new(a, b, c, d), port)
            .to_target_addr()
            .map_err(AddrError::AddrConversionFailed)?,
        Addr::V6(x) => (Ipv6Addr::from(x), port)
            .to_target_addr()
            .map_err(AddrError::AddrConversionFailed)?,
        Addr::Domain(domain) => TargetAddr::Domain(domain, port),
    };

    Ok(addr)
}

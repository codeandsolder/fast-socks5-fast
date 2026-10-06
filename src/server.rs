use crate::util::stream::{ConnectError, tcp_connect_with_timeout};
use crate::util::target_addr::{AddrError, TargetAddr, read_address};
use crate::{
    ReplyError, Socks5Command, UdpHeaderError, consts, new_udp_header, parse_udp_request,
    read_exact,
};
use socket2::{Domain, Socket, Type};
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use std::string::FromUtf8Error;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::try_join;

#[derive(thiserror::Error, Debug)]
pub enum SocksServerError {
    #[error("i/o error when {context}: {source}")]
    Io {
        source: io::Error,
        context: &'static str,
    },
    #[error("string error when {context}: {source}")]
    FromUtf8 {
        source: FromUtf8Error,
        context: &'static str,
    },
    #[error(transparent)]
    ConnectError(#[from] ConnectError),
    #[error(transparent)]
    UdpHeaderError(#[from] UdpHeaderError),
    #[error(transparent)]
    AddrError(#[from] AddrError),
    #[error("BUG: {0}")] // should be unreachable
    Bug(&'static str),
    #[error("Auth method unacceptable `{0:?}`.")]
    AuthMethodUnacceptable(Vec<u8>),
    #[error("Unsupported SOCKS version `{0}`.")]
    UnsupportedSocksVersion(u8),
    #[error("Unsupported SOCKS command `{0}`.")]
    UnknownCommand(u8),
    #[error("Unexpected garbage received on TCP stream used for UDP proxy keep-alive: `{0}`")]
    UnexpectedUdpControlGarbage(u8),
    #[error("Empty username received")]
    EmptyUsername,
    #[error("Empty password received")]
    EmptyPassword,
    #[error("Authentication rejected")]
    AuthenticationRejected,
    #[error("End of stream")]
    Eof,
}

impl SocksServerError {
    #[must_use]
    pub const fn to_reply_error(&self) -> ReplyError {
        match self {
            Self::UnknownCommand(_) => ReplyError::CommandNotSupported,
            Self::AddrError(err) => err.to_reply_error(),
            _ => ReplyError::GeneralFailure,
        }
    }
}

trait ErrorContext<T> {
    fn err_when(self, context: &'static str) -> Result<T, SocksServerError>;
}

impl<T> ErrorContext<T> for Result<T, io::Error> {
    fn err_when(self, context: &'static str) -> Result<T, SocksServerError> {
        self.map_err(|source| SocksServerError::Io { source, context })
    }
}

impl<T> ErrorContext<T> for Result<T, FromUtf8Error> {
    fn err_when(self, context: &'static str) -> Result<T, SocksServerError> {
        self.map_err(|source| SocksServerError::FromUtf8 { source, context })
    }
}

pub mod states {
    pub struct Opened;
    pub struct Authenticated;
    pub struct CommandRead;
}

pub struct Socks5ServerProtocol<T, S> {
    inner: T,
    _state: PhantomData<S>,
}

impl<T, S> Socks5ServerProtocol<T, S> {
    const fn new(inner: T) -> Self {
        Self {
            inner,
            _state: PhantomData,
        }
    }
}

impl<T> Socks5ServerProtocol<T, states::Opened> {
    /// Start handling the SOCKS5 protocol flow, wrapping a client socket.
    pub const fn start(inner: T) -> Self {
        Self::new(inner)
    }
}

pub trait CheckResult {
    fn is_good(&self) -> bool;
}

impl CheckResult for bool {
    fn is_good(&self) -> bool {
        *self
    }
}

impl<T> CheckResult for Option<T> {
    fn is_good(&self) -> bool {
        self.is_some()
    }
}

impl<T, E> CheckResult for Result<T, E> {
    fn is_good(&self) -> bool {
        self.is_ok()
    }
}

impl<T> Socks5ServerProtocol<T, states::Authenticated> {
    /// Finish handling the authentication method-specific part of the protocol,
    /// returning back to the overall SOCKS5 flow.
    pub fn finish_auth<A: AuthMethodSuccessState<T>>(auth: A) -> Self {
        Self::new(auth.into_inner())
    }

    /// Wrap a socket in a SOCKS5 flow handler that's already marked as authenticated.
    ///
    /// This is not actually part of the official SOCKS5 protocol, but allows you to
    /// only use the post-authentication subset of it.
    pub const fn skip_auth_this_is_not_rfc_compliant(inner: T) -> Self {
        Self::new(inner)
    }

    /// Handle the SOCKS5 auth negotiation supporting only the `NoAuthentication` method.
    ///
    /// # Errors
    ///
    /// Returns an error if the client sends an invalid handshake or the negotiation I/O fails.
    pub async fn accept_no_auth(inner: T) -> Result<Self, SocksServerError>
    where
        T: AsyncWrite + AsyncRead + Unpin + Send,
    {
        Ok(Socks5ServerProtocol::start(inner)
            .negotiate_auth(&[NoAuthentication])
            .await?
            .finish_auth())
    }

    /// Handle the SOCKS5 auth negotiation supporting only the `PasswordAuthentication` method,
    /// and verify the provided username and password using the provided closure.
    ///
    /// The closure can mutate state variables and/or return a result as `Option`/`Result`.
    ///
    /// # Errors
    ///
    /// Returns an error if negotiation or credential parsing fails, or if `check` rejects the credentials.
    pub async fn accept_password_auth<F, R>(
        inner: T,
        mut check: F,
    ) -> Result<(Self, R), SocksServerError>
    where
        T: AsyncWrite + AsyncRead + Unpin + Send,
        F: FnMut(String, String) -> R + Send,
        R: CheckResult + Send,
    {
        let (user, pass, auth) = Socks5ServerProtocol::start(inner)
            .negotiate_auth(&[PasswordAuthentication])
            .await?
            .read_username_password()
            .await?;
        let check_result = check(user, pass);
        if check_result.is_good() {
            Ok((auth.accept().await?.finish_auth(), check_result))
        } else {
            auth.reject().await?;
            Err(SocksServerError::AuthenticationRejected)
        }
    }
}

/// A trait for the final successful state of an authentication method's implementation.
///
/// This allows `Socks5ServerProtocol<T, states::Authenticated>::finish_authentication` to
/// let the user continue with the protocol after the socket has been handed off to the
/// authentication method.
pub trait AuthMethodSuccessState<T> {
    fn into_inner(self) -> T;

    fn finish_auth(self) -> Socks5ServerProtocol<T, states::Authenticated>
    where
        Self: Sized,
    {
        Socks5ServerProtocol::finish_auth(self)
    }
}

/// A metadata trait for authentication methods, essentially binding an ID value
/// (as used in the method negotiation) to an actual implementation of the method.
///
/// Use blank structs for individual protocol implementations and
/// enums for sets of supported protocols (you'll need a matching enum for the `Impl`).
pub trait AuthMethod<T>: Copy {
    type StartingState;
    fn method_id(self) -> u8;
    fn start(self, inner: T) -> Self::StartingState;
}

pub struct NoAuthenticationImpl<T>(T);

impl<T> AuthMethodSuccessState<T> for NoAuthenticationImpl<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// The "NO AUTHENTICATION REQUIRED" auth method, ID 00h as specifed by RFC 1928.
///
/// As the dummy no-auth method, it only has one state. Once it's been negotiated,
/// you can immediately continue with `finish_authentication`.
///
/// Or not so immediately: if you want to use no-authentication with e.g. IP address
/// allowlisting or TLS client certificate auth for TLS-wrapped SOCKS5, this is your
/// opportunity to reject the no-authentication by dropping the connection!
#[derive(Debug, Clone, Copy)]
pub struct NoAuthentication;

impl<T> AuthMethod<T> for NoAuthentication {
    type StartingState = NoAuthenticationImpl<T>;

    fn method_id(self) -> u8 {
        0x00
    }

    fn start(self, inner: T) -> Self::StartingState {
        NoAuthenticationImpl(inner)
    }
}

mod password_states {
    pub struct Started;
    pub struct Received;
    pub struct Finished;
}

pub struct PasswordAuthenticationImpl<T, S> {
    inner: T,
    _state: PhantomData<S>,
}

pub type PasswordAuthenticationStarted<T> = PasswordAuthenticationImpl<T, password_states::Started>;

impl<T, S> PasswordAuthenticationImpl<T, S> {
    const fn new(inner: T) -> Self {
        Self {
            inner,
            _state: PhantomData,
        }
    }
}

impl<T: AsyncRead + Unpin> PasswordAuthenticationImpl<T, password_states::Started> {
    /// Handle the username and password sent by the client.
    ///
    /// # Errors
    ///
    /// Returns an error if the RFC 1929 credential frame is malformed, empty, invalid UTF-8, or cannot be read.
    pub async fn read_username_password(
        self,
    ) -> Result<
        (
            String,
            String,
            PasswordAuthenticationImpl<T, password_states::Received>,
        ),
        SocksServerError,
    > {
        let mut socket = self.inner;
        trace!("PasswordAuthenticationStarted: read_username_password()");
        let [version, user_len] = read_exact!(socket, [0u8; 2]).err_when("reading user len")?;
        debug!("Auth: [version: {version}, user len: {user_len}]");

        if user_len < 1 {
            return Err(SocksServerError::EmptyUsername);
        }

        let username =
            read_exact!(socket, vec![0u8; user_len as usize]).err_when("reading username")?;
        debug!("username bytes: {username:?}");

        let [pass_len] = read_exact!(socket, [0u8; 1]).err_when("reading password len")?;
        debug!("Auth: [pass len: {pass_len}]");

        if pass_len < 1 {
            return Err(SocksServerError::EmptyPassword);
        }

        let password =
            read_exact!(socket, vec![0u8; pass_len as usize]).err_when("reading password")?;
        debug!("password bytes: {password:?}");

        let username = String::from_utf8(username).err_when("converting username")?;
        let password = String::from_utf8(password).err_when("converting password")?;

        Ok((username, password, PasswordAuthenticationImpl::new(socket)))
    }
}

impl<T: AsyncWrite + Unpin> PasswordAuthenticationImpl<T, password_states::Received> {
    /// Notify the client with a "SUCCEEDED" reply and proceed to finish the authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the authentication success response cannot be written.
    pub async fn accept(
        mut self,
    ) -> Result<PasswordAuthenticationImpl<T, password_states::Finished>, SocksServerError> {
        self.inner
            .write_all(&[1, consts::SOCKS5_REPLY_SUCCEEDED])
            .await
            .err_when("replying auth success")?;

        debug!("Password authentication accepted.");
        Ok(PasswordAuthenticationImpl::new(self.inner))
    }

    /// Notify the client with a "`NOT_ACCEPTABLE`" reply and drop the socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the authentication rejection response cannot be written.
    pub async fn reject(mut self) -> Result<(), SocksServerError> {
        self.inner
            .write_all(&[1, consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE])
            .await
            .err_when("replying with auth method not acceptable")?;

        debug!("Password authentication rejected.");
        Ok(())
    }
}

impl<T> AuthMethodSuccessState<T> for PasswordAuthenticationImpl<T, password_states::Finished> {
    fn into_inner(self) -> T {
        self.inner
    }
}

/// The "USERNAME/PASSWORD" auth method, ID 02h as specified by RFC 1928.
#[derive(Debug, Clone, Copy)]
pub struct PasswordAuthentication;

impl<T> AuthMethod<T> for PasswordAuthentication {
    type StartingState = PasswordAuthenticationImpl<T, password_states::Started>;

    fn method_id(self) -> u8 {
        0x02
    }

    fn start(self, inner: T) -> Self::StartingState {
        PasswordAuthenticationImpl::new(inner)
    }
}

#[macro_export]
macro_rules! auth_method_enums {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $enum:ident / $(#[$state_enum_meta:meta])* $state_enum:ident<$state_enum_par:ident> {
            $($method:ident($state:ty)),+ $(,)?
        }
    ) => {
        $(#[$state_enum_meta])*
        $vis enum $state_enum<$state_enum_par> {
            $($method($state)),+
        }

        #[derive(Clone, Copy)]
        $(#[$enum_meta])*
        $vis enum $enum {
            $($method($method)),+
        }

        impl<T> AuthMethod<T> for $enum {
            type StartingState = $state_enum<T>;

            fn method_id(self) -> u8 {
                match self {
                    $($enum::$method(auth) => AuthMethod::<T>::method_id(auth)),+
                }
            }

            fn start(self, inner: T) -> Self::StartingState {
                match self {
                    $($enum::$method(auth) => $state_enum::$method(auth.start(inner))),+
                }
            }
        }
    };
}

auth_method_enums! {
    /// The combination of all authentication methods supported by this crate out of the box,
    /// as an enum appropriate for static dispatch.
    ///
    /// If you want to add your own custom methods, you can generate a similar enum using the `auth_method_enums` macro.
    pub enum StandardAuthentication / StandardAuthenticationStarted<T> {
        NoAuthentication(NoAuthenticationImpl<T>),
        PasswordAuthentication(PasswordAuthenticationImpl<T, password_states::Started>),
    }
}

impl StandardAuthentication {
    /// Return a slice containing either both supported methods or only `PasswordAuthentication`.
    #[must_use]
    pub const fn allow_no_auth(allow: bool) -> &'static [Self] {
        if allow {
            &[
                // The order of authentication methods can be tested by clients in sequence,
                // so list more secure or preferred methods first
                Self::PasswordAuthentication(PasswordAuthentication),
                Self::NoAuthentication(NoAuthentication),
            ]
        } else {
            &[Self::PasswordAuthentication(PasswordAuthentication)]
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socks5ServerProtocol<T, states::Opened> {
    /// Negotiate an authentication method from a list of supported ones and initialize it.
    ///
    /// Internally, this reads the list of authentication methods provided by the client, and
    /// picks the first one for which there exists an implementation in `server_methods`.
    ///
    /// If none of the auth methods requested by the client are in `server_methods`,
    /// returns a `SocksServerError::AuthMethodUnacceptable`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid SOCKS version, no mutually supported method, or handshake I/O failure.
    pub async fn negotiate_auth<M: AuthMethod<T> + Sync>(
        mut self,
        server_methods: &[M],
    ) -> Result<M::StartingState, SocksServerError> {
        trace!("Socks5ServerProtocol: negotiate_auth()");
        let [version, methods_len] =
            read_exact!(self.inner, [0u8; 2]).err_when("reading methods")?;
        debug!("Handshake headers: [version: {version}, methods len: {methods_len}]");

        if version != consts::SOCKS5_VERSION {
            return Err(SocksServerError::UnsupportedSocksVersion(version));
        }

        // {METHODS available from the client}
        // eg. (non-auth) {0, 1}
        // eg. (auth)     {0, 1, 2}
        let methods =
            read_exact!(self.inner, vec![0u8; methods_len as usize]).err_when("reading methods")?;
        debug!("methods supported sent by the client: {methods:?}");

        // server_methods order matter!
        // the server could choose to prioritize methods
        for server_method in server_methods {
            for client_method_id in &methods {
                if server_method.method_id() == *client_method_id {
                    debug!("Reply with method {}", *client_method_id);
                    self.inner
                        .write_all(&[consts::SOCKS5_VERSION, *client_method_id])
                        .await
                        .err_when("replying with auth method")?;
                    return Ok(server_method.start(self.inner));
                }
            }
        }

        debug!("No auth method supported by both client and server, reply with (0xff)");
        self.inner
            .write_all(&[
                consts::SOCKS5_VERSION,
                consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
            ])
            .await
            .err_when("replying with method not acceptable")?;
        Err(SocksServerError::AuthMethodUnacceptable(methods))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Socks5ServerProtocol<T, states::CommandRead> {
    /// Reply success to the client according to the RFC.
    /// This consumes the wrapper as after this message actual proxying should begin.
    ///
    /// # Errors
    ///
    /// Returns an error if the success reply cannot be written or flushed.
    pub async fn reply_success(mut self, sock_addr: SocketAddr) -> Result<T, SocksServerError> {
        let (reply, reply_len) = new_reply(ReplyError::Succeeded, sock_addr);
        self.inner
            .write_all(&reply[..reply_len])
            .await
            .err_when("writing successful reply")?;

        self.inner.flush().await.err_when("flushing auth reply")?;

        debug!("Wrote success");
        Ok(self.inner)
    }

    /// Reply error to the client with the reply code according to the RFC.
    ///
    /// # Errors
    ///
    /// Returns an error if the failure reply cannot be written or flushed.
    pub async fn reply_error(mut self, error: &ReplyError) -> Result<(), SocksServerError> {
        let (reply, reply_len) = new_reply(
            *error,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        );
        debug!("reply error to be written: {reply:?}");

        self.inner
            .write_all(&reply[..reply_len])
            .await
            .err_when("writing unsuccessful reply")?;

        self.inner.flush().await.err_when("flushing auth reply")?;

        Ok(())
    }
}

macro_rules! try_notify {
    ($proto:expr, $e:expr) => {
        match $e {
            Ok(res) => res,
            Err(err) => {
                if let Err(rep_err) = $proto.reply_error(&err.to_reply_error()).await {
                    error!(
                        "extra error while reporting an error to the client: {}",
                        rep_err
                    );
                }
                return Err(err.into());
            }
        }
    };
}

impl<T: AsyncRead + AsyncWrite + Unpin> Socks5ServerProtocol<T, states::Authenticated> {
    /// Decide to whether or not, accept the authentication method.
    /// Don't forget that the methods list sent by the client, contains one or more methods.
    ///
    /// # Request
    /// ```text
    ///          +----+-----+-------+------+----------+----------+
    ///          |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///          +----+-----+-------+------+----------+----------+
    ///          | 1  |  1  |   1   |  1   | Variable |    2     |
    ///          +----+-----+-------+------+----------+----------+
    /// ```
    ///
    /// Returns the requested socket address when the command is valid.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if the command frame is malformed, unsupported, or cannot be read. Protocol
    /// errors are reported to the client before returning when possible.
    pub async fn read_command(
        mut self,
    ) -> Result<
        (
            Socks5ServerProtocol<T, states::CommandRead>,
            Socks5Command,
            TargetAddr,
        ),
        SocksServerError,
    > {
        let [version, cmd, rsv, address_type] =
            read_exact!(self.inner, [0u8; 4]).err_when("reading command")?;
        debug!(
            "Request: [version: {version}, command: {cmd}, rev: {rsv}, address_type: {address_type}]",
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksServerError::UnsupportedSocksVersion(version));
        }

        let mut proto = Socks5ServerProtocol::new(self.inner);

        // Guess address type
        let target_addr = try_notify!(proto, read_address(&mut proto.inner, address_type).await);

        debug!("Request target is {target_addr}");

        let cmd = try_notify!(
            proto,
            Socks5Command::from_u8(cmd).ok_or(SocksServerError::UnknownCommand(cmd))
        );

        Ok((proto, cmd, target_addr))
    }
}

/// Resolve the target address in a parsed SOCKS5 request while preserving protocol error replies.
///
/// # Errors
///
/// Returns an error if DNS resolution fails or the resulting protocol error reply cannot be written.
pub async fn resolve_request_dns<T>(
    request: (
        Socks5ServerProtocol<T, states::CommandRead>,
        Socks5Command,
        TargetAddr,
    ),
) -> Result<
    (
        Socks5ServerProtocol<T, states::CommandRead>,
        Socks5Command,
        TargetAddr,
    ),
    SocksServerError,
>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (proto, cmd, target_addr) = request;
    let resolved_addr = try_notify!(proto, target_addr.resolve_dns().await);
    Ok((proto, cmd, resolved_addr))
}

/// Handle the connect command by running a TCP proxy until the connection is done.
///
/// # Errors
///
/// Returns an error if connecting to the target times out or fails, if the SOCKS5 reply cannot be
/// written, or if bidirectional proxy I/O fails.
pub async fn run_tcp_proxy<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    addr: &TargetAddr,
    request_timeout: Duration,
    nodelay: bool,
) -> Result<T, SocksServerError> {
    let addr = try_notify!(
        proto,
        addr.to_socket_addrs()
            .err_when("converting to socket addr")
            .and_then(|mut addrs| addrs.next().ok_or(SocksServerError::Bug("no socket addrs")))
    );

    // TCP connect with timeout, to avoid memory leak for connection that takes forever
    let outbound = match tcp_connect_with_timeout(addr, request_timeout).await {
        Ok(stream) => stream,
        Err(err) => {
            proto.reply_error(&err.to_reply_error()).await?;
            return Err(err.into());
        }
    };

    // Disable Nagle's algorithm if config specifies to do so.
    try_notify!(
        proto,
        outbound.set_nodelay(nodelay).err_when("setting nodelay")
    );

    debug!("Connected to remote destination");

    let mut inner = proto
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await?;

    transfer(&mut inner, outbound).await;
    Ok(inner)
}

fn udp_bind_random_port(addr: Option<IpAddr>) -> io::Result<Socket> {
    if let Some(addr) = addr {
        let sock_addr = SocketAddr::new(addr, 0);
        let socket = Socket::new(Domain::for_address(sock_addr), Type::DGRAM, None)?;
        socket.bind(&sock_addr.into())?;
        Ok(socket)
    } else {
        const V4_UNSPEC: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        const V6_UNSPEC: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        Socket::new(Domain::IPV6, Type::DGRAM, None)
            .and_then(|socket| socket.set_only_v6(false).map(|()| socket))
            .and_then(|socket| socket.bind(&V6_UNSPEC.into()).map(|()| socket))
            .or_else(|_| {
                Socket::new(Domain::IPV4, Type::DGRAM, None)
                    .and_then(|socket| socket.bind(&V4_UNSPEC.into()).map(|()| socket))
            })
    }
    .and_then(|socket| socket.set_nonblocking(true).map(|()| socket))
}

/// Handle the associate command by running a UDP proxy until the connection is done.
///
/// # Errors
///
/// Returns an error if UDP socket setup, the SOCKS5 association reply, control-channel handling,
/// or UDP forwarding fails.
pub async fn run_udp_proxy<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    addr: &TargetAddr,
    peer_bind_ip: Option<IpAddr>,
    reply_ip: IpAddr,
    outbound_bind_ip: Option<IpAddr>,
) -> Result<T, SocksServerError> {
    run_udp_proxy_custom(
        proto,
        addr,
        peer_bind_ip,
        reply_ip,
        move |inbound| async move {
            let outbound =
                udp_bind_random_port(outbound_bind_ip).err_when("binding outbound udp socket")?;

            transfer_udp(inbound, outbound).await
        },
    )
    .await
}

/// Handle the associate command by running a UDP proxy until the connection is done.
///
/// This version allows passing in a custom transfer function while reusing the initialization code.
async fn run_udp_proxy_custom<T, F, R>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    _addr: &TargetAddr,
    peer_bind_ip: Option<IpAddr>,
    reply_ip: IpAddr,
    transfer: F,
) -> Result<T, SocksServerError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(Socket) -> R,
    R: Future<Output = Result<(), SocksServerError>>,
{
    // The DST.ADDR and DST.PORT fields contain the address and port that
    // the client expects to use to send UDP datagrams on for the
    // association. The server MAY use this information to limit access
    // to the association.
    // @see Page 6, https://datatracker.ietf.org/doc/html/rfc1928.
    //
    // We do NOT limit the access from the client currently in this implementation.

    // By default, listen on a UDP6 socket, so that the client can connect
    // to it with either IPv4 or IPv6.
    let peer_sock = try_notify!(
        proto,
        udp_bind_random_port(peer_bind_ip).err_when("binding client udp socket")
    );

    let peer_addr = try_notify!(
        proto,
        peer_sock.local_addr().err_when("getting peer's local addr")
    );

    let reply_port = peer_addr
        .as_socket()
        .ok_or(SocksServerError::Bug("addr not IP"))?
        .port();

    // Respect the pre-populated reply IP address.
    let mut inner = proto
        .reply_success(SocketAddr::new(reply_ip, reply_port))
        .await?;

    let udp_fut = transfer(peer_sock);
    let tcp_fut = wait_on_tcp(&mut inner);
    match try_join!(udp_fut, tcp_fut) {
        Ok(_) => warn!("unreachable"),
        Err(SocksServerError::Eof) => debug!("EOF on controlling TCP stream, closed UDP proxy"),
        Err(err) => warn!("while UDP proxying: {err}"),
    }
    Ok(inner)
}

/// Wait until a TCP stream (that's not supposed to receive anything) closes.
///
/// This is intended for cancelling the `transfer_udp` task.
async fn wait_on_tcp<I>(stream: &mut I) -> Result<(), SocksServerError>
where
    I: AsyncRead + Unpin,
{
    let mut buf = [0; 1];
    match stream.read(&mut buf).await {
        Ok(0) => Err(SocksServerError::Eof),
        Ok(_) => Err(SocksServerError::UnexpectedUdpControlGarbage(buf[0])),
        Err(err) => Err(err).err_when("waiting on UDP control stream"),
    }
}

/// Run a bidirectional proxy between two streams.
/// Using 2 different generators, because they could be different structs with same traits.
pub async fn transfer<I, O>(mut inbound: I, mut outbound: O)
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(res) => debug!("transfer closed ({}, {})", res.0, res.1),
        Err(err) => error!("transfer error: {err:?}"),
    }
}

async fn handle_udp_request(
    inbound: &UdpSocket,
    outbound: &UdpSocket,
    outbound_v6: bool,
    buf: &mut [u8],
) -> Result<(), SocksServerError> {
    let (size, client_addr) = inbound
        .recv_from(buf)
        .await
        .err_when("udp receiving from")?;
    debug!("Server recieve udp from {client_addr}");
    inbound
        .connect(client_addr)
        .await
        .err_when("connecting udp inbound")?;

    let (frag, target_addr, data) = parse_udp_request(&buf[..size]).await?;

    if frag != 0 {
        debug!("Discard UDP frag packets sliently.");
        return Ok(());
    }

    debug!("Server forward to packet to {target_addr}");
    let mut target_addr = target_addr
        .resolve_dns()
        .await?
        .to_socket_addrs()
        .err_when("udp target to socket addrs")?
        .next()
        .ok_or(SocksServerError::Bug("no socket addrs"))?;

    if outbound_v6 {
        target_addr.set_ip(match target_addr.ip() {
            std::net::IpAddr::V4(v4) => std::net::IpAddr::V6(v4.to_ipv6_mapped()),
            v6 @ std::net::IpAddr::V6(_) => v6,
        });
    }
    outbound
        .send_to(data, target_addr)
        .await
        .err_when("udp sending to")?;
    Ok(())
}

async fn handle_udp_requests(
    inbound: &UdpSocket,
    outbound: &UdpSocket,
) -> Result<(), SocksServerError> {
    let mut buf = vec![0u8; 8192];
    let outbound_v6 = outbound
        .local_addr()
        .err_when("udp outbound local addr")?
        .is_ipv6();
    loop {
        match handle_udp_request(inbound, outbound, outbound_v6, &mut buf).await {
            Ok(()) => trace!("handled udp response"),
            Err(err) => debug!("error in handling udp response: {err}"),
        }
    }
}

async fn handle_udp_response(
    inbound: &UdpSocket,
    outbound: &UdpSocket,
    buf: &mut [u8],
) -> Result<(), SocksServerError> {
    let (size, mut remote_addr) = outbound
        .recv_from(buf)
        .await
        .err_when("udp receiving from")?;
    debug!("Recieve packet from {remote_addr}");

    // Clients don't tend to expect v6-mapped addresses when they connect to v4 ones
    if let std::net::IpAddr::V6(v6) = remote_addr.ip()
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        remote_addr.set_ip(std::net::IpAddr::V4(v4));
    }

    let mut data = new_udp_header(&remote_addr)?;
    data.extend_from_slice(&buf[..size]);
    inbound.send(&data).await.err_when("udp sending")?;

    Ok(())
}

async fn handle_udp_responses(
    inbound: &UdpSocket,
    outbound: &UdpSocket,
) -> Result<(), SocksServerError> {
    let mut buf = vec![0u8; 8192];
    loop {
        match handle_udp_response(inbound, outbound, &mut buf).await {
            Ok(()) => trace!("handled udp response"),
            Err(err) => debug!("error in handling udp response: {err}"),
        }
    }
}

/// Run a bidirectional UDP SOCKS proxy for a given pair of inbound (SOCKS client) and outbound sockets.
async fn transfer_udp(inbound: Socket, outbound: Socket) -> Result<(), SocksServerError> {
    let inbound = UdpSocket::from_std(inbound.into()).err_when("wrapping inbound socket")?;
    let outbound = UdpSocket::from_std(outbound.into()).err_when("wrapping outbound socket")?;
    let request_future = handle_udp_requests(&inbound, &outbound);
    let response_future = handle_udp_responses(&inbound, &outbound);
    try_join!(request_future, response_future).map(|_| ())
}

/// Generate reply code according to the RFC.
fn new_reply(error: ReplyError, sock_addr: SocketAddr) -> ([u8; 22], usize) {
    let mut reply = [0_u8; 22];
    reply[0] = consts::SOCKS5_VERSION;
    reply[1] = error.as_u8();
    reply[2] = 0;

    let len = match sock_addr {
        SocketAddr::V4(sock) => {
            reply[3] = consts::SOCKS5_ADDR_TYPE_IPV4;
            reply[4..8].copy_from_slice(&sock.ip().octets());
            reply[8..10].copy_from_slice(&sock.port().to_be_bytes());
            10
        }
        SocketAddr::V6(sock) => {
            reply[3] = consts::SOCKS5_ADDR_TYPE_IPV6;
            reply[4..20].copy_from_slice(&sock.ip().octets());
            reply[20..22].copy_from_slice(&sock.port().to_be_bytes());
            22
        }
    };
    (reply, len)
}

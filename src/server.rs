use crate::util::target_addr::{AddrError, TargetAddr, read_address};
use crate::{ReplyError, Socks5Command, consts};
use log::{debug, error, trace};
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(thiserror::Error, Debug)]
/// Errors from SOCKS5 negotiation, credential handling, and command parsing.
pub enum SocksServerError {
    #[error("i/o error when {context}: {source}")]
    /// Socket I/O failed while processing a protocol step.
    Io {
        /// Underlying transport error.
        source: io::Error,
        /// Protocol step being processed.
        context: &'static str,
    },
    #[error(transparent)]
    /// A target address could not be decoded.
    AddrError(#[from] AddrError),
    #[error("auth method unacceptable `{0:?}`")]
    /// No offered authentication method was supported by the server.
    AuthMethodUnacceptable(Vec<u8>),
    #[error("unsupported SOCKS version `{0}`")]
    /// SOCKS5 protocol version does not match the supported version.
    UnsupportedSocksVersion(u8),
    #[error("unsupported SOCKS command `{0}`")]
    /// Unknown command octet in a SOCKS5 request.
    UnknownCommand(u8),
    #[error("empty username received")]
    /// The RFC 1929 username length was zero.
    EmptyUsername,
    #[error("empty password received")]
    /// The RFC 1929 password length was zero.
    EmptyPassword,
    #[error("authentication rejected")]
    /// The credential-verification callback rejected authentication.
    AuthenticationRejected,
    #[error("unsupported username/password subnegotiation version `{0}`")]
    /// Unsupported RFC 1929 subnegotiation version.
    UnsupportedPasswordVersion(u8),
    #[error("invalid SOCKS5 request reserved byte `{0}`")]
    /// The SOCKS5 request reserved octet was not zero.
    InvalidReservedByte(u8),
}

impl SocksServerError {
    /// Map this error to a protocol reply status.
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

/// Type markers enforcing the authentication/command protocol progression.
pub mod states {
    /// Authentication method negotiation has not completed.
    pub struct Opened;
    /// Authentication has completed.
    pub struct Authenticated;
    /// The client request has been parsed and is ready for a reply.
    pub struct CommandRead;
}

/// SOCKS5 server state machine wrapping a caller-owned async stream.
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

/// Authentication acceptance predicate.
///
/// For `Result<T, E>`, every `Ok` counts as accepted (including `Ok(false)`);
/// return a `bool` directly when false should reject.
pub trait CheckResult {
    /// Whether the credential verifier accepted the provided credentials.
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
    /// The verifier receives borrowed opaque credential bytes. RFC 1929 does not
    /// require UTF-8, so callers can interpret or compare the octets as needed.
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
        F: FnMut(&[u8], &[u8]) -> R + Send,
        R: CheckResult + Send,
    {
        let (user, pass, auth) = Socks5ServerProtocol::start(inner)
            .negotiate_auth(&[PasswordAuthentication])
            .await?
            .read_username_password()
            .await?;
        let check_result = check(&user, &pass);
        // Neither credential buffer needs to survive the verifier, particularly
        // across the next network I/O await.
        drop((user, pass));
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
/// This allows `Socks5ServerProtocol<T, states::Authenticated>::finish_auth` to
/// let the user continue with the protocol after the socket has been handed off to the
/// authentication method.
pub trait AuthMethodSuccessState<T> {
    /// Recover the transport after successful authentication.
    fn into_inner(self) -> T;

    /// Complete the authentication state transition.
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
    /// Initial authentication state after method negotiation.
    type StartingState;
    /// RFC 1928 authentication method identifier.
    fn method_id(self) -> u8;
    /// Begin method-specific authentication on the stream.
    fn start(self, inner: T) -> Self::StartingState;
}

/// Successfully negotiated no-authentication method.
pub struct NoAuthenticationImpl<T>(T);

impl<T> AuthMethodSuccessState<T> for NoAuthenticationImpl<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// The "NO AUTHENTICATION REQUIRED" auth method, ID 00h as specified by RFC 1928.
///
/// As the dummy no-auth method, it only has one state. Once it's been negotiated,
/// you can immediately continue with `finish_auth`.
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

/// RFC 1929 password-authentication state machine.
pub struct PasswordAuthenticationImpl<T, S> {
    inner: T,
    _state: PhantomData<S>,
}

/// Starting state for RFC 1929 username/password authentication.
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
    /// Returns an error if the RFC 1929 credential frame is malformed, empty, or cannot be read.
    /// Credentials are returned as opaque octets; RFC 1929 does not define a character encoding.
    pub async fn read_username_password(
        self,
    ) -> Result<
        (
            Vec<u8>,
            Vec<u8>,
            PasswordAuthenticationImpl<T, password_states::Received>,
        ),
        SocksServerError,
    > {
        let mut socket = self.inner;
        trace!("PasswordAuthenticationStarted: read_username_password()");
        let [version, user_len] = read_exact!(socket, [0u8; 2]).err_when("reading user len")?;
        trace!("Password authentication username field length: {user_len}");
        if version != 1 {
            return Err(SocksServerError::UnsupportedPasswordVersion(version));
        }

        if user_len < 1 {
            return Err(SocksServerError::EmptyUsername);
        }

        let username =
            read_exact!(socket, vec![0u8; usize::from(user_len)]).err_when("reading username")?;
        // Credential bytes are never logged.

        let [pass_len] = read_exact!(socket, [0u8; 1]).err_when("reading password len")?;
        trace!("Password authentication password field length: {pass_len}");

        if pass_len < 1 {
            return Err(SocksServerError::EmptyPassword);
        }

        let password =
            read_exact!(socket, vec![0u8; usize::from(pass_len)]).err_when("reading password")?;
        // The password must never be logged.

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
            .write_all(&[1, consts::SOCKS5_AUTH_STATUS_SUCCESS])
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
            .write_all(&[1, consts::SOCKS5_AUTH_STATUS_FAILURE])
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

/// Generate static-dispatch enums and authentication-method metadata for custom method sets.
#[macro_export]
macro_rules! auth_method_enums {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $enum:ident / $(#[$state_enum_meta:meta])* $state_enum:ident<$state_enum_par:ident> {
            $($method:ident($state:ty)),+ $(,)?
        }
    ) => {
        $(#[$state_enum_meta])*
        #[doc = "Method-specific states while authentication is in progress."]
        $vis enum $state_enum<$state_enum_par> {
            $(#[doc = concat!("Starting state of the `", stringify!($method), "` authentication method.")] $method($state)),+
        }

        #[derive(Clone, Copy)]
        $(#[$enum_meta])*
        #[doc = "Supported authentication method variants."]
        $vis enum $enum {
            $(#[doc = concat!("The `", stringify!($method), "` authentication method.")] $method($method)),+
        }

        impl<T> $crate::server::AuthMethod<T> for $enum {
            type StartingState = $state_enum<T>;

            fn method_id(self) -> u8 {
                match self {
                    $($enum::$method(auth) => $crate::server::AuthMethod::<T>::method_id(auth)),+
                }
            }

            fn start(self, inner: T) -> Self::StartingState {
                match self {
                    $($enum::$method(auth) => $state_enum::$method($crate::server::AuthMethod::<T>::start(auth, inner))),+
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
        let methods = read_exact!(self.inner, vec![0u8; usize::from(methods_len)])
            .err_when("reading methods")?;
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

        // Reject an invalid header before reading a potentially missing address body.
        if rsv != 0 {
            let err = SocksServerError::InvalidReservedByte(rsv);
            proto.reply_error(&err.to_reply_error()).await?;
            return Err(err);
        }
        let cmd = try_notify!(
            proto,
            Socks5Command::from_u8(cmd).ok_or(SocksServerError::UnknownCommand(cmd))
        );
        let target_addr = try_notify!(proto, read_address(&mut proto.inner, address_type).await);
        trace!("Request target parsed");

        Ok((proto, cmd, target_addr))
    }
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

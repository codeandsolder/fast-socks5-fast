#![forbid(unsafe_code)]
#[macro_use]
extern crate log;

use anyhow::Result;
use clap::Parser;
use fast_socks5::{
    ReplyError, Socks5Command, auth_method_enums,
    server::{
        AuthMethod, AuthMethodSuccessState, PasswordAuthentication, PasswordAuthenticationStarted,
        Socks5ServerProtocol, resolve_request_dns, run_tcp_proxy,
    },
};
use std::{future::Future, time::Duration};
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
use tokio::task;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpListener,
};

/// # How to use it:
///
/// Listen on a local address:
///     `$ RUST_LOG=debug cargo run --example custom_auth_server -- --listen-addr 127.0.0.1:1337`
///
/// or via a cURL command
///     `curl -v -s --proxy "socks5://user:correct_horse_battery_staple@127.0.0.1:1337" "https://httpbin.org/get"`
///
#[derive(Debug, Parser)]
#[command(
    name = "socks5-server-custom-auth",
    about = "A socks5 server with a curious secret."
)]
struct Opt {
    /// Bind on address address. eg. `127.0.0.1:1080`
    #[arg(short, long)]
    pub listen_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    let opt: Opt = Opt::parse();

    let listener = TcpListener::bind(&opt.listen_addr).await?;

    info!("Listen for socks connections @ {}", opt.listen_addr);

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                spawn_and_log_error(serve_socks5(socket));
            }
            Err(err) => {
                error!("accept error = {err:?}");
            }
        }
    }
}

pub struct BackdoorAuthenticationStarted<T>(T);
pub struct BackdoorAuthenticationSuccess<T>(T);

impl<T: AsyncRead + Unpin> BackdoorAuthenticationStarted<T> {
    ///
    /// # Errors
    /// Returns an error when the timing or secret bytes do not satisfy this example method.
    pub async fn verify_timing(self) -> Result<BackdoorAuthenticationSuccess<T>> {
        let mut socket = self.0;
        let mut buf = vec![0u8; 2];
        if tokio::time::timeout(Duration::from_millis(500), socket.read_exact(&mut buf))
            .await
            .is_ok()
        {
            debug!("too early!");
            anyhow::bail!("authentication rejected");
        }
        if tokio::time::timeout(Duration::from_millis(500), socket.read_exact(&mut buf))
            .await
            .is_err()
        {
            debug!("too late!");
            anyhow::bail!("authentication rejected");
        }
        if buf[0] == 0x13 && buf[1] == 0x37 {
            Ok(BackdoorAuthenticationSuccess(socket))
        } else {
            debug!("wrong contents!");
            Err(anyhow::anyhow!("authentication rejected"))
        }
    }
}

impl<T> AuthMethodSuccessState<T> for BackdoorAuthenticationSuccess<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// A silly example of a custom authentication method.
#[derive(Debug, Clone, Copy)]
pub struct BackdoorAuthentication;

impl<T> AuthMethod<T> for BackdoorAuthentication {
    type StartingState = BackdoorAuthenticationStarted<T>;

    fn method_id(self) -> u8 {
        0xF0 // From the "RESERVED FOR PRIVATE METHODS" range
    }

    fn start(self, inner: T) -> Self::StartingState {
        BackdoorAuthenticationStarted(inner)
    }
}

auth_method_enums! {
    pub enum Auth / AuthStarted<T> {
        PasswordAuthentication(PasswordAuthenticationStarted<T>),
        BackdoorAuthentication(BackdoorAuthenticationStarted<T>),
    }
}

async fn serve_socks5(socket: tokio::net::TcpStream) -> Result<()> {
    let proto = match Socks5ServerProtocol::start(socket)
        .negotiate_auth(&[
            // The order of authentication methods can be tested by clients in sequence,
            // so list more secure or preferred methods first
            Auth::PasswordAuthentication(PasswordAuthentication),
            Auth::BackdoorAuthentication(BackdoorAuthentication),
        ])
        .await?
    {
        AuthStarted::PasswordAuthentication(auth) => {
            let (user, pass, auth) = auth.read_username_password().await?;
            if user == "user" && pass == "correct_horse_battery_staple" {
                // better to not use spaces for trying out with cURL
                auth.accept().await?.finish_auth()
            } else {
                auth.reject().await?;
                anyhow::bail!("authentication rejected: wrong username/password");
            }
        }
        AuthStarted::BackdoorAuthentication(auth) => auth.verify_timing().await?.finish_auth(),
    };

    let (proto, cmd, target_addr) = resolve_request_dns(proto.read_command().await?).await?;

    if cmd == Socks5Command::TCPConnect {
        run_tcp_proxy(proto, &target_addr, REQUEST_TIMEOUT, false).await?;
    } else {
        proto.reply_error(&ReplyError::CommandNotSupported).await?;
        return Err(ReplyError::CommandNotSupported.into());
    }
    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        match fut.await {
            Ok(()) => {}
            Err(err) => error!("{err:#}"),
        }
    })
}

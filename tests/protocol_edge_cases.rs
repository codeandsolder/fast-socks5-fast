use fast_socks5::{
    ReplyError, Socks5Command,
    server::{
        NoAuthentication, NoAuthenticationImpl, PasswordAuthentication, Socks5ServerProtocol,
        SocksServerError,
    },
    util::target_addr::TargetAddr,
};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

type TestResult = Result<(), Box<dyn Error>>;

async fn negotiate_no_auth(client: &mut DuplexStream) -> TestResult {
    client.write_all(&[5, 1, 0]).await?;
    let mut response = [0; 2];
    client.read_exact(&mut response).await?;
    assert_eq!(response, [5, 0]);
    Ok(())
}

async fn rejected_request(
    request: &[u8],
    expected_code: u8,
) -> Result<SocksServerError, Box<dyn Error>> {
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        let protocol = Socks5ServerProtocol::accept_no_auth(server).await?;
        let _ = protocol.read_command().await?;
        Ok::<(), SocksServerError>(())
    });
    negotiate_no_auth(&mut client).await?;
    client.write_all(request).await?;
    let mut response = [0; 10];
    client.read_exact(&mut response).await?;
    assert_eq!(response, [5, expected_code, 0, 1, 0, 0, 0, 0, 0, 0]);
    match task.await? {
        Ok(()) => Err("invalid request was accepted".into()),
        Err(error) => Ok(error),
    }
}

#[test]
fn reply_codes_are_total_and_round_trip() {
    for wire in 0_u8..=u8::MAX {
        match ReplyError::from_u8(wire) {
            Some(reply) => assert_eq!(reply.as_u8(), wire),
            None => assert!(wire > 8),
        }
    }
}

#[tokio::test]
async fn rejects_nonzero_request_reserved_byte_without_waiting_for_body() -> TestResult {
    let error = rejected_request(&[5, 1, 1, 3], 1).await?;
    assert!(matches!(error, SocksServerError::InvalidReservedByte(1)));
    Ok(())
}

#[tokio::test]
async fn rejects_unknown_command_without_waiting_for_body() -> TestResult {
    let error = rejected_request(&[5, 0xf0, 0, 3], 7).await?;
    assert!(matches!(error, SocksServerError::UnknownCommand(0xf0)));
    Ok(())
}

#[tokio::test]
async fn rejects_unknown_address_type() -> TestResult {
    let error = rejected_request(&[5, 1, 0, 0xff], 8).await?;
    assert!(matches!(
        error,
        SocksServerError::AddrError(
            fast_socks5::util::target_addr::AddrError::IncorrectAddressType
        )
    ));
    Ok(())
}

#[tokio::test]
async fn rejects_empty_domain_without_waiting_for_port() -> TestResult {
    let error = rejected_request(&[5, 1, 0, 3, 0], 1).await?;
    assert!(matches!(
        error,
        SocksServerError::AddrError(fast_socks5::util::target_addr::AddrError::EmptyDomain)
    ));
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_password_subnegotiation_version() -> TestResult {
    let (mut client, server) = tokio::io::duplex(256);
    let task = tokio::spawn(async move {
        let auth = Socks5ServerProtocol::start(server)
            .negotiate_auth(&[PasswordAuthentication])
            .await?;
        let _ = auth.read_username_password().await?;
        Ok::<(), SocksServerError>(())
    });
    client.write_all(&[5, 1, 2]).await?;
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await?;
    assert_eq!(selection, [5, 2]);
    client.write_all(&[2, 1]).await?;
    assert!(matches!(
        task.await?,
        Err(SocksServerError::UnsupportedPasswordVersion(2))
    ));
    Ok(())
}

#[tokio::test]
async fn password_authentication_accepts_and_rejects_credentials() -> TestResult {
    for (password, expected_status) in [("secret", 0), ("wrong", 1)] {
        let (mut client, server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            Socks5ServerProtocol::accept_password_auth(server, |user, password| {
                user == "user" && password == "secret"
            })
            .await
        });
        client.write_all(&[5, 1, 2]).await?;
        let mut selection = [0; 2];
        client.read_exact(&mut selection).await?;
        assert_eq!(selection, [5, 2]);
        client.write_all(&[1, 4]).await?;
        client.write_all(b"user").await?;
        client.write_all(&[u8::try_from(password.len())?]).await?;
        client.write_all(password.as_bytes()).await?;
        let mut status = [0; 2];
        client.read_exact(&mut status).await?;
        assert_eq!(status, [1, expected_status]);
        match task.await? {
            Ok(_) if expected_status == 0 => (),
            Err(SocksServerError::AuthenticationRejected) if expected_status != 0 => (),
            _ => return Err("unexpected password authentication result".into()),
        }
    }
    Ok(())
}

#[tokio::test]
async fn parses_ipv4_and_ipv6_requests_and_replies() -> TestResult {
    for address in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)), 443),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353),
    ] {
        let (mut client, server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            let protocol = Socks5ServerProtocol::accept_no_auth(server).await?;
            let (protocol, cmd, target) = protocol.read_command().await?;
            assert_eq!(cmd, Socks5Command::TcpConnect);
            assert_eq!(target, TargetAddr::Ip(address));
            let _ = protocol.reply_success(address).await?;
            Ok::<(), SocksServerError>(())
        });
        negotiate_no_auth(&mut client).await?;
        let mut req = vec![5, 1, 0];
        match address.ip() {
            IpAddr::V4(ip) => {
                req.push(1);
                req.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                req.push(4);
                req.extend_from_slice(&ip.octets());
            }
        }
        req.extend_from_slice(&address.port().to_be_bytes());
        client.write_all(&req).await?;
        let mut reply = vec![0; req.len()];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply[0..4], [5, 0, 0, req[3]]);
        assert_eq!(&reply[4..], &req[4..]);
        task.await??;
    }
    Ok(())
}

fast_socks5::auth_method_enums! {
    /// External call-site: no `AuthMethod` trait imported.
    pub enum ExternalMethods / ExternalMethodState<T> {
        NoAuthentication(NoAuthenticationImpl<T>),
    }
}

#[tokio::test]
async fn exported_authentication_macro_is_hygienic() -> TestResult {
    let (mut client, server) = tokio::io::duplex(256);
    let task = tokio::spawn(async move {
        let auth = Socks5ServerProtocol::start(server)
            .negotiate_auth(&[ExternalMethods::NoAuthentication(NoAuthentication)])
            .await?;
        match auth {
            ExternalMethodState::NoAuthentication(state) => {
                let _protocol = Socks5ServerProtocol::finish_auth(state);
            }
        }
        Ok::<(), SocksServerError>(())
    });
    negotiate_no_auth(&mut client).await?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn exhaustively_rejects_invalid_single_byte_command_headers() -> TestResult {
    for reserved in 1..=u8::MAX {
        let err = rejected_request(&[5, 1, reserved, 1], 1).await?;
        assert!(matches!(err, SocksServerError::InvalidReservedByte(_)));
    }
    for command in 0..=u8::MAX {
        if [1, 2, 3].contains(&command) {
            continue;
        }
        let err = rejected_request(&[5, command, 0, 1], 7).await?;
        assert!(matches!(err, SocksServerError::UnknownCommand(_)));
    }
    for atyp in 0..=u8::MAX {
        if [1, 3, 4].contains(&atyp) {
            continue;
        }
        let err = rejected_request(&[5, 1, 0, atyp], 8).await?;
        assert!(matches!(
            err,
            SocksServerError::AddrError(
                fast_socks5::util::target_addr::AddrError::IncorrectAddressType
            )
        ));
    }
    Ok(())
}

#[tokio::test]
async fn negotiation_prefers_server_order_and_handles_no_matching_method() -> TestResult {
    use fast_socks5::server::{StandardAuthentication, StandardAuthenticationStarted};
    let (mut client, server) = tokio::io::duplex(256);
    let task = tokio::spawn(async move {
        let auth = Socks5ServerProtocol::start(server)
            .negotiate_auth(StandardAuthentication::allow_no_auth(true))
            .await?;
        assert!(matches!(
            auth,
            StandardAuthenticationStarted::PasswordAuthentication(_)
        ));
        Ok::<(), SocksServerError>(())
    });
    client.write_all(&[5, 2, 0, 2]).await?;
    let mut selected = [0; 2];
    client.read_exact(&mut selected).await?;
    assert_eq!(selected, [5, 2]);
    task.await??;

    let (mut client, server) = tokio::io::duplex(256);
    let task = tokio::spawn(async move {
        Socks5ServerProtocol::start(server)
            .negotiate_auth(&[NoAuthentication])
            .await
    });
    client.write_all(&[5, 1, 0x77]).await?;
    client.read_exact(&mut selected).await?;
    assert_eq!(selected, [5, 0xff]);
    assert!(matches!(
        task.await?,
        Err(SocksServerError::AuthMethodUnacceptable(methods)) if methods == [0x77]
    ));
    Ok(())
}

#[tokio::test]
async fn accepts_longest_domain_field() -> TestResult {
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        let protocol = Socks5ServerProtocol::accept_no_auth(server).await?;
        let (_protocol, command, target) = protocol.read_command().await?;
        assert_eq!(command, Socks5Command::TcpConnect);
        assert_eq!(target, TargetAddr::Domain("a".repeat(255), 65535));
        Ok::<(), SocksServerError>(())
    });
    negotiate_no_auth(&mut client).await?;
    let mut request = vec![5, 1, 0, 3, 255];
    request.extend_from_slice(&[b'a'; 255]);
    request.extend_from_slice(&u16::MAX.to_be_bytes());
    client.write_all(&request).await?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn truncated_greeting_returns_transport_error_without_panicking() -> TestResult {
    for greeting in [&[][..], &[5][..], &[5, 2, 0][..]] {
        let (mut client, server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move { Socks5ServerProtocol::accept_no_auth(server).await });
        client.write_all(greeting).await?;
        client.shutdown().await?;
        assert!(matches!(task.await?, Err(SocksServerError::Io { .. })));
    }
    Ok(())
}

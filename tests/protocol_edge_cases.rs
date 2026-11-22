use fast_socks5::{
    ReplyError, Socks5Command,
    server::{
        AuthMethod, NoAuthentication, NoAuthenticationImpl, PasswordAuthentication,
        Socks5ServerProtocol, SocksServerError,
    },
    util::target_addr::TargetAddr,
};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream, DuplexStream};
use tokio::time::{Duration, timeout};

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
        let _ = auth.read_username_password(|_, _| ()).await?;
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
                user == b"user" && password == b"secret"
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

#[tokio::test]
async fn arbitrary_binary_credentials_reach_verifier_unchanged() -> TestResult {
    let username = [0x00, 0x80, 0xff];
    let password = [0xff, 0x00, 0xc3, 0x28];
    let (mut client, server) = tokio::io::duplex(256);
    let task = tokio::spawn(async move {
        Socks5ServerProtocol::accept_password_auth(server, |user, pass| {
            user == username && pass == password
        })
        .await
    });
    client.write_all(&[5, 1, 2]).await?;
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await?;
    assert_eq!(selection, [5, 2]);

    client
        .write_all(&[1, u8::try_from(username.len())?])
        .await?;
    client.write_all(&username).await?;
    client.write_all(&[u8::try_from(password.len())?]).await?;
    client.write_all(&password).await?;
    let mut status = [0; 2];
    client.read_exact(&mut status).await?;
    assert_eq!(status, [1, 0]);
    assert!(task.await?.is_ok());
    Ok(())
}

#[tokio::test]
async fn password_parser_preserves_255_octets_without_text_conversion() -> TestResult {
    let username: Vec<u8> = (0..=254).collect();
    let password: Vec<u8> = (1..=255).collect();
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        let auth = Socks5ServerProtocol::start(server)
            .negotiate_auth(&[PasswordAuthentication])
            .await?;
        let ((), auth) = auth
            .read_username_password(|user, pass| {
                assert_eq!(user, username);
                assert_eq!(pass, password);
            })
            .await?;
        let _ = auth.finish(true).await?;
        Ok::<(), SocksServerError>(())
    });
    client.write_all(&[5, 1, 2]).await?;
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await?;
    assert_eq!(selection, [5, 2]);
    client.write_all(&[1, 255]).await?;
    client.write_all(&(0..=254).collect::<Vec<u8>>()).await?;
    client.write_all(&[255]).await?;
    client.write_all(&(1..=255).collect::<Vec<u8>>()).await?;
    client.read_exact(&mut selection).await?;
    assert_eq!(selection, [1, 0]);
    task.await??;
    Ok(())
}

#[tokio::test]
async fn malformed_utf8_target_reports_failure_without_carrying_domain_bytes() -> TestResult {
    let mut request = vec![5, 1, 0, 3, 8];
    request.extend_from_slice(b"secret!\xff");
    let error = rejected_request(&request, 1).await?;
    let SocksServerError::AddrError(fast_socks5::util::target_addr::AddrError::Utf8(source)) =
        error
    else {
        return Err("unexpected address error kind".into());
    };
    assert_eq!(source.valid_up_to(), 7);
    assert!(!format!("{source:?}").contains("secret"));
    Ok(())
}

#[tokio::test]
async fn buffered_method_selection_is_flushed() -> TestResult {
    let (mut client, server) = tokio::io::duplex(64);
    let task =
        tokio::spawn(
            async move { Socks5ServerProtocol::accept_no_auth(BufStream::new(server)).await },
        );
    client.write_all(&[5, 1, 0]).await?;
    let mut selected = [0; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut selected)).await??;
    assert_eq!(selected, [5, 0]);
    task.await??;
    Ok(())
}

#[tokio::test]
async fn buffered_method_rejection_is_flushed_before_drop() -> TestResult {
    let (mut client, server) = tokio::io::duplex(64);
    let task = tokio::spawn(async move {
        Socks5ServerProtocol::start(BufStream::new(server))
            .negotiate_auth(&[NoAuthentication])
            .await
    });
    client.write_all(&[5, 1, 2]).await?;
    let mut selected = [0; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut selected)).await??;
    assert_eq!(selected, [5, 0xff]);
    assert!(matches!(
        task.await?,
        Err(SocksServerError::AuthMethodUnacceptable(_))
    ));
    Ok(())
}

#[tokio::test]
async fn buffered_password_success_and_failure_are_flushed() -> TestResult {
    for accepted in [true, false] {
        let (mut client, server) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            Socks5ServerProtocol::accept_password_auth(BufStream::new(server), move |_, _| accepted)
                .await
        });
        client.write_all(&[5, 1, 2]).await?;
        let mut selected = [0; 2];
        timeout(Duration::from_secs(1), client.read_exact(&mut selected)).await??;
        assert_eq!(selected, [5, 2]);
        client.write_all(&[1, 1, b'u', 1, b'p']).await?;
        timeout(Duration::from_secs(1), client.read_exact(&mut selected)).await??;
        assert_eq!(selected, [1, u8::from(!accepted)]);
        match task.await? {
            Ok(_) if accepted => (),
            Err(SocksServerError::AuthenticationRejected) if !accepted => (),
            _ => return Err("unexpected authentication result".into()),
        }
    }
    Ok(())
}

#[tokio::test]
async fn offered_methods_max_length_and_fragmented_transport() -> TestResult {
    for selected in [true, false] {
        // Capacity one forces partial reads/writes even for a single-octet send.
        let (mut client, server) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            Socks5ServerProtocol::start(server)
                .negotiate_auth(&[NoAuthentication])
                .await
        });
        // Offered methods contain a full 255-octet list. In the accepted
        // case, method 0 occurs at the very end of the list.
        let mut methods = [0x77u8; 255];
        if selected {
            methods[254] = 0;
        }
        for octet in [5, 255].into_iter().chain(methods) {
            timeout(Duration::from_secs(1), client.write_all(&[octet])).await??;
        }
        let mut reply = [0u8; 2];
        timeout(Duration::from_secs(1), client.read_exact(&mut reply)).await??;
        assert_eq!(reply, [5, if selected { 0 } else { 0xff }]);
        match timeout(Duration::from_secs(1), task).await?? {
            Ok(_) if selected => {}
            Err(SocksServerError::AuthMethodUnacceptable(methods))
                if !selected && methods == [0x77; 255] => {}
            _ => return Err("unexpected maximum-length negotiation result".into()),
        }
    }
    Ok(())
}

#[tokio::test]
async fn empty_offered_method_list_is_rejected() -> TestResult {
    let (mut client, server) = tokio::io::duplex(2);
    let task = tokio::spawn(async move {
        Socks5ServerProtocol::start(server)
            .negotiate_auth(&[NoAuthentication])
            .await
    });
    client.write_all(&[5, 0]).await?;
    let mut reply = [0u8; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut reply)).await??;
    assert_eq!(reply, [5, 0xff]);
    assert!(matches!(
        task.await?,
        Err(SocksServerError::AuthMethodUnacceptable(methods)) if methods.is_empty()
    ));
    Ok(())
}

#[derive(Clone, Copy)]
struct TestMethod(u8);

impl<T> AuthMethod<T> for TestMethod {
    type StartingState = u8;

    fn method_id(self) -> u8 {
        self.0
    }

    fn start(self, _inner: T) -> Self::StartingState {
        self.0
    }
}

#[tokio::test]
async fn custom_method_negotiation_respects_server_order_and_rejects_reserved_id() -> TestResult {
    for (offered, expected) in [(&[0xff, 0x80, 0x81][..], Some(0x81)), (&[0xff][..], None)] {
        let (mut client, server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            Socks5ServerProtocol::start(server)
                .negotiate_auth(&[TestMethod(0xff), TestMethod(0x81), TestMethod(0x80)])
                .await
        });
        client.write_all(&[5, u8::try_from(offered.len())?]).await?;
        client.write_all(offered).await?;
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, expected.unwrap_or(0xff)]);
        match (expected, task.await?) {
            (Some(expected), Ok(actual)) => assert_eq!(actual, expected),
            (None, Err(SocksServerError::AuthMethodUnacceptable(actual))) => {
                assert_eq!(actual, offered);
            }
            _ => return Err("unexpected custom method negotiation result".into()),
        }
    }
    Ok(())
}

#[tokio::test]
async fn failed_error_reply_preserves_original_protocol_error() -> TestResult {
    for (header, reserved) in [([5, 1, 1, 3], true), ([5, 0xf0, 0, 3], false)] {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(&header).await?;
        drop(client);
        let protocol = Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(server);
        let result = protocol.read_command().await;
        assert!(matches!(
            (reserved, result),
            (true, Err(SocksServerError::InvalidReservedByte(1)))
                | (false, Err(SocksServerError::UnknownCommand(0xf0)))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn truncated_ip_destination_body_reports_address_error() -> TestResult {
    use fast_socks5::util::target_addr::AddrError;

    for (atyp, body_len) in [(1_u8, 6), (4, 18)] {
        for partial_len in 0..body_len {
            let (mut client, server) = tokio::io::duplex(64);
            client.write_all(&[5, 1, 0, atyp]).await?;
            client.write_all(&vec![0; partial_len]).await?;
            client.shutdown().await?;
            let protocol = Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(server);
            let result = protocol.read_command().await;
            assert!(matches!(
                (atyp, result),
                (
                    1,
                    Err(SocksServerError::AddrError(AddrError::Ipv4Unreadable(_)))
                ) | (
                    4,
                    Err(SocksServerError::AddrError(AddrError::Ipv6Unreadable(_)))
                )
            ));
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await?;
            assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn ip_destination_read_leaves_pipelined_payload_for_caller() -> TestResult {
    for (atyp, body) in [
        (1_u8, vec![127, 0, 0, 1, 0, 80]),
        (4, [vec![0; 15], vec![1, 0, 80]].concat()),
    ] {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(&[5, 1, 0, atyp]).await?;
        client.write_all(&body).await?;
        client.write_all(b"data").await?;
        let protocol = Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(server);
        let (proto, command, target) = protocol.read_command().await?;
        assert_eq!(command, Socks5Command::TcpConnect);
        let expected: SocketAddr = if atyp == 1 {
            "127.0.0.1:80".parse()?
        } else {
            "[::1]:80".parse()?
        };
        assert_eq!(target, TargetAddr::Ip(expected));
        let mut stream = proto.reply_success(([0, 0, 0, 0], 0).into()).await?;
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"data");
    }
    Ok(())
}

#[tokio::test]
async fn large_custom_method_sets_preserve_server_preference_and_rejection_bytes() -> TestResult {
    for (offers, expected) in [
        ([0xff, 0x80, 0x81, 0x80], Some(0x81)),
        ([0xff, 0x83, 0x83, 0xff], None),
    ] {
        let (mut client, server) = tokio::io::duplex(1);
        let task = tokio::spawn(async move {
            let mut methods = vec![TestMethod(0xff); 65];
            methods[32] = TestMethod(0x81);
            methods[64] = TestMethod(0x80);
            Socks5ServerProtocol::start(server)
                .negotiate_auth(&methods)
                .await
        });
        for byte in [5, 4].into_iter().chain(offers) {
            timeout(Duration::from_secs(1), client.write_all(&[byte])).await??;
        }
        let mut reply = [0; 2];
        timeout(Duration::from_secs(1), client.read_exact(&mut reply)).await??;
        assert_eq!(reply, [5, expected.unwrap_or(0xff)]);
        match (expected, timeout(Duration::from_secs(1), task).await??) {
            (Some(expected), Ok(actual)) => assert_eq!(actual, expected),
            (None, Err(SocksServerError::AuthMethodUnacceptable(actual))) => {
                assert_eq!(actual, offers);
            }
            _ => return Err("unexpected indexed negotiation result".into()),
        }
    }
    Ok(())
}

#[tokio::test]
async fn password_verifier_is_not_called_for_any_truncated_frame() -> TestResult {
    let fields = [1, 3, 0, 0xff, 0xc3, 4, 0xf0, 0, 0x80, 0xff];
    for prefix_len in 0..fields.len() {
        let (mut client, server) = tokio::io::duplex(32);
        let visited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let checked = visited.clone();
        let task = tokio::spawn(async move {
            Socks5ServerProtocol::accept_password_auth(server, |_, _| {
                checked.store(true, std::sync::atomic::Ordering::Relaxed);
                true
            })
            .await
        });
        client.write_all(&[5, 1, 2]).await?;
        let mut selection = [0; 2];
        client.read_exact(&mut selection).await?;
        assert_eq!(selection, [5, 2]);
        client.write_all(&fields[..prefix_len]).await?;
        client.shutdown().await?;
        let result = timeout(Duration::from_secs(1), task).await??;
        assert!(!visited.load(std::sync::atomic::Ordering::Relaxed));
        let Err(SocksServerError::Io { source, context }) = result else {
            return Err("expected an I/O error for truncated credential frame".into());
        };
        assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
        let expected = match prefix_len {
            0..=1 => "reading user len",
            2..=4 => "reading username",
            5 => "reading password len",
            _ => "reading password",
        };
        assert_eq!(context, expected);
    }
    Ok(())
}

#[tokio::test]
async fn fragmented_maximum_credentials_leave_pipelined_request_and_payload() -> TestResult {
    let (mut client, server) = tokio::io::duplex(1);
    let task = tokio::spawn(async move {
        let protocol = Socks5ServerProtocol::accept_password_auth(server, |user, pass| {
            user.iter().copied().eq(0..=254) && pass.iter().copied().eq(1..=255)
        })
        .await?;
        let (protocol, command, target) = protocol.read_command().await?;
        assert_eq!(command, Socks5Command::TcpConnect);
        assert_eq!(
            target,
            TargetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 80)))
        );
        let mut stream = protocol
            .reply_success(SocketAddr::from(([127, 0, 0, 1], 1080)))
            .await?;
        let mut payload = [0; 3];
        stream.read_exact(&mut payload).await?;
        assert_eq!(payload, [0xff, 0, 0x7f]);
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });
    timeout(Duration::from_secs(1), client.write_all(&[5, 1, 2])).await??;
    let mut selection = [0; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut selection)).await??;
    assert_eq!(selection, [5, 2]);
    let mut credentials = vec![1, 255];
    credentials.extend(0..=254);
    credentials.push(255);
    credentials.extend(1..=255);
    timeout(Duration::from_secs(5), client.write_all(&credentials)).await??;
    let mut status = [0; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut status)).await??;
    assert_eq!(status, [1, 0]);
    timeout(
        Duration::from_secs(1),
        client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]),
    )
    .await??;
    let mut response = [0; 10];
    timeout(Duration::from_secs(1), client.read_exact(&mut response)).await??;
    assert_eq!(response, [5, 0, 0, 1, 127, 0, 0, 1, 4, 56]);
    timeout(Duration::from_secs(1), client.write_all(&[0xff, 0, 0x7f])).await??;
    timeout(Duration::from_secs(1), task)
        .await??
        .map_err(|error| -> Box<dyn Error> { error })?;
    Ok(())
}

#[tokio::test]
async fn truncated_domain_reports_the_failed_wire_field() -> TestResult {
    use fast_socks5::util::target_addr::AddrError;
    // Exercise every truncation position for the smallest field and several
    // sizes spanning typical names, UTF-8 and SIMD/word-size boundaries.
    for len in [1_u8, 2, 16, 63, 64, 127, 255] {
        let mut body = vec![len];
        body.extend(std::iter::repeat_n(b'a', usize::from(len)));
        body.extend_from_slice(&443_u16.to_be_bytes());
        for prefix in 0..body.len() {
            let (mut client, server) = tokio::io::duplex(512);
            client.write_all(&[5, 1, 0, 3]).await?;
            client.write_all(&body[..prefix]).await?;
            client.shutdown().await?;
            let protocol = Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(server);
            let result = protocol.read_command().await;
            let Err(SocksServerError::AddrError(error)) = result else {
                return Err("expected a destination read error".into());
            };
            let source = match (prefix, error) {
                (0, AddrError::DomainLenUnreadable(source)) => source,
                (n, AddrError::DomainContentUnreadable(source)) if n <= usize::from(len) => source,
                (n, AddrError::PortNumberUnreadable(source)) if n > usize::from(len) => source,
                _ => return Err("wrong destination read error".into()),
            };
            assert_eq!(source.kind(), std::io::ErrorKind::UnexpectedEof);
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await?;
            assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn domain_destination_leaves_pipelined_payload_at_every_length() -> TestResult {
    for len in 1_u8..=u8::MAX {
        // Include an arbitrary valid multi-byte code point wherever it fits.
        let mut domain = "a".repeat(usize::from(len));
        if len >= 4 {
            domain.replace_range(..4, "🌐");
        }
        let (mut client, server) = tokio::io::duplex(512);
        client.write_all(&[5, 1, 0, 3, len]).await?;
        client.write_all(domain.as_bytes()).await?;
        client.write_all(&443_u16.to_be_bytes()).await?;
        client.write_all(b"payload").await?;
        let protocol = Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(server);
        let (proto, command, target) = protocol.read_command().await?;
        assert_eq!(command, Socks5Command::TcpConnect);
        assert_eq!(target, TargetAddr::Domain(domain, 443));
        let mut stream = proto.reply_success(([0, 0, 0, 0], 0).into()).await?;
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"payload");
    }
    Ok(())
}

#[tokio::test]
async fn command_error_replies_flush_each_wire_status() -> TestResult {
    for code in 0_u8..=8 {
        let Some(error) = ReplyError::from_u8(code) else {
            return Err("missing RFC 1928 reply code".into());
        };
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await?;
        let protocol =
            Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(BufStream::new(server));
        let (protocol, _, _) = protocol.read_command().await?;
        protocol.reply_error(&error).await?;
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Fault {
    Never,
    Write(usize),
    Flush(usize),
}

struct AuthReplyFaultStream<'a> {
    input: &'a [u8],
    output: &'a std::cell::RefCell<Vec<u8>>,
    fault: Fault,
    writes: usize,
    flushes: usize,
}

impl AuthReplyFaultStream<'_> {
    const fn new<'a>(
        input: &'a [u8],
        output: &'a std::cell::RefCell<Vec<u8>>,
        fault: Fault,
    ) -> AuthReplyFaultStream<'a> {
        AuthReplyFaultStream {
            input,
            output,
            fault,
            writes: 0,
            flushes: 0,
        }
    }
}

impl tokio::io::AsyncRead for AuthReplyFaultStream<'_> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let count = self.input.len().min(buf.remaining());
        buf.put_slice(&self.input[..count]);
        self.input = &self.input[count..];
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for AuthReplyFaultStream<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if matches!(self.fault, Fault::Write(index) if index == self.writes) {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        self.writes += 1;
        self.output.borrow_mut().extend_from_slice(bytes);
        std::task::Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if matches!(self.fault, Fault::Flush(index) if index == self.flushes) {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        self.flushes += 1;
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn authentication_reply_io_error_context_is_stage_specific() -> TestResult {
    for (method, status, context_write, context_flush) in [
        (
            0,
            0,
            "replying with auth method",
            "flushing selected auth method",
        ),
        (
            2,
            0xff,
            "replying with method not acceptable",
            "flushing rejected methods",
        ),
    ] {
        for (fault, context, expected) in [
            (Fault::Write(0), context_write, &[][..]),
            (Fault::Flush(0), context_flush, &[5, status][..]),
        ] {
            let output = std::cell::RefCell::new(Vec::new());
            let input = [5, 1, method];
            let stream = AuthReplyFaultStream::new(&input, &output, fault);
            let Err(SocksServerError::Io {
                source,
                context: actual,
            }) = Socks5ServerProtocol::accept_no_auth(stream).await
            else {
                return Err("expected method reply I/O error".into());
            };
            assert_eq!(source.kind(), std::io::ErrorKind::BrokenPipe);
            assert_eq!(context, actual);
            assert_eq!(output.borrow().as_slice(), expected);
        }
    }
    for (accepted, status, context_write, context_flush) in [
        (true, 0, "replying auth success", "flushing auth success"),
        (
            false,
            1,
            "replying with auth method not acceptable",
            "flushing auth failure",
        ),
    ] {
        for (fault, context, expected) in [
            (Fault::Write(1), context_write, &[5, 2][..]),
            (Fault::Flush(1), context_flush, &[5, 2, 1, status][..]),
        ] {
            let output = std::cell::RefCell::new(Vec::new());
            let stream = AuthReplyFaultStream::new(&[5, 1, 2, 1, 1, b'u', 1, b'p'], &output, fault);
            let Err(SocksServerError::Io {
                source,
                context: actual,
            }) = Socks5ServerProtocol::accept_password_auth(stream, |user, pass| {
                assert_eq!(user, b"u");
                assert_eq!(pass, b"p");
                accepted
            })
            .await
            else {
                return Err("expected password reply I/O error".into());
            };
            assert_eq!(source.kind(), std::io::ErrorKind::BrokenPipe);
            assert_eq!(context, actual);
            assert_eq!(output.borrow().as_slice(), expected);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct LocalAuthentication<'a>(&'a std::cell::Cell<usize>);

impl<'io> AuthMethod<AuthReplyFaultStream<'io>> for LocalAuthentication<'_> {
    type StartingState = AuthReplyFaultStream<'io>;

    fn method_id(self) -> u8 {
        self.0.set(self.0.get() + 1);
        0x80
    }

    fn start(self, inner: AuthReplyFaultStream<'io>) -> Self::StartingState {
        assert_eq!(inner.flushes, 1);
        inner
    }
}

#[tokio::test]
async fn local_transport_and_method_metadata_need_not_cross_threads() -> TestResult {
    let calls = std::cell::Cell::new(0);
    let output = std::cell::RefCell::new(Vec::new());
    let stream = AuthReplyFaultStream::new(&[5, 1, 0x80], &output, Fault::Never);
    let stream = Socks5ServerProtocol::start(stream)
        .negotiate_auth(&[LocalAuthentication(&calls)])
        .await?;
    assert!(stream.input.is_empty());
    assert_eq!(calls.get(), 1);
    assert_eq!(output.borrow().as_slice(), &[5, 0x80]);

    let output = std::cell::RefCell::new(Vec::new());
    let stream = AuthReplyFaultStream::new(&[5, 1, 2, 1, 1, b'u', 1, b'p'], &output, Fault::Never);
    let expected = std::rc::Rc::new([b'u', b'p']);
    let _ = Socks5ServerProtocol::accept_password_auth(stream, move |user, pass| {
        let expected = expected;
        user == &expected[..1] && pass == &expected[1..]
    })
    .await?;
    assert_eq!(output.borrow().as_slice(), &[5, 2, 1, 0]);
    Ok(())
}

#[tokio::test]
async fn explicit_low_level_password_rejection_flushes_before_returning_error() -> TestResult {
    let output = std::cell::RefCell::new(Vec::new());
    let stream = AuthReplyFaultStream::new(&[5, 1, 2, 1, 1, b'u', 1, b'p'], &output, Fault::Never);
    let auth = Socks5ServerProtocol::start(BufStream::new(stream))
        .negotiate_auth(&[PasswordAuthentication])
        .await?;
    let (accepted, auth) = auth.read_username_password(|_, _| false).await?;
    assert!(matches!(
        auth.finish(accepted).await,
        Err(SocksServerError::AuthenticationRejected)
    ));
    assert_eq!(output.borrow().as_slice(), &[5, 2, 1, 1]);
    Ok(())
}

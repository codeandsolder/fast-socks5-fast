use fast_socks5::{
    ReplyError, Socks5Command,
    server::{Socks5ServerProtocol, SocksServerError},
    util::target_addr::TargetAddr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn parses_udp_associate_without_implementing_a_relay()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut client, server) = tokio::io::duplex(256);

    let server_task = tokio::spawn(async move {
        let protocol = Socks5ServerProtocol::accept_no_auth(server).await?;
        let (protocol, command, target) = protocol.read_command().await?;

        assert_eq!(command, Socks5Command::UDPAssociate);
        assert_eq!(target, TargetAddr::Domain("example.com".to_owned(), 53));

        protocol.reply_error(&ReplyError::CommandNotSupported).await
    });

    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut auth_reply = [0_u8; 2];
    client.read_exact(&mut auth_reply).await?;
    assert_eq!(auth_reply, [0x05, 0x00]);

    let domain = b"example.com";
    let mut request = vec![0x05, 0x03, 0x00, 0x03, u8::try_from(domain.len())?];
    request.extend_from_slice(domain);
    request.extend_from_slice(&53_u16.to_be_bytes());
    client.write_all(&request).await?;

    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await?;
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x07);

    server_task.await??;
    Ok(())
}

#[tokio::test]
async fn parses_tcp_connect_domain_target() -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, server) = tokio::io::duplex(256);

    let server_task = tokio::spawn(async move {
        let protocol = Socks5ServerProtocol::accept_no_auth(server).await?;
        let (_protocol, command, target) = protocol.read_command().await?;

        assert_eq!(command, Socks5Command::TCPConnect);
        assert_eq!(target, TargetAddr::Domain("example.com".to_owned(), 443));
        Ok::<_, SocksServerError>(())
    });

    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut auth_reply = [0_u8; 2];
    client.read_exact(&mut auth_reply).await?;
    assert_eq!(auth_reply, [0x05, 0x00]);

    let domain = b"example.com";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, u8::try_from(domain.len())?];
    request.extend_from_slice(domain);
    request.extend_from_slice(&443_u16.to_be_bytes());
    client.write_all(&request).await?;

    server_task.await??;
    Ok(())
}

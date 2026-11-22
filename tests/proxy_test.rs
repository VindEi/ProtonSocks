use proton_socks::proxy::auth::{AuthPolicy, Socks5Auth};
use proton_socks::proxy::router::ProxyRouter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_socks5_no_auth_handshake() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let policy = AuthPolicy::none();

    let server_task = tokio::spawn(async move {
        Socks5Auth::handshake(&mut server, &policy).await
    });

    // Client sends greeting with NO AUTH (0x00)
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]); // SOCKS5, NO AUTH accepted

    let res = server_task.await.unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_socks5_auth_rejection_on_bad_credentials() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let policy = AuthPolicy::new("valid_user", "valid_pass");

    let server_task = tokio::spawn(async move {
        Socks5Auth::handshake(&mut server, &policy).await
    });

    // Client sends greeting with USER/PASS (0x02)
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x02]); // SOCKS5, USER/PASS required

    // Client sends wrong password
    // [VER=1, ULEN=10, 'valid_user', PLEN=9, 'wrongpass']
    let mut bad_auth = vec![0x01, 10];
    bad_auth.extend_from_slice(b"valid_user");
    bad_auth.push(9);
    bad_auth.extend_from_slice(b"wrongpass");
    client.write_all(&bad_auth).await.unwrap();

    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp, [0x01, 0x01]); // 0x01 failure

    let server_res = server_task.await.unwrap();
    assert!(server_res.is_err());
}

#[tokio::test]
async fn test_router_base_port_routing() {
    let router = ProxyRouter::new(25000);
    assert_eq!(router.base_port, 25000);

    // Initial state: no winner, no tunnel
    assert!(router.get_tunnel_for_port(25000).await.is_none());

    // Set best account
    router.set_best_account(Some("acc_1_nl".to_string())).await;
    assert_eq!(router.get_best_account_id().await, Some("acc_1_nl".to_string()));
}

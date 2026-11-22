use proton_socks::api::srp::ProtonSrp;

#[test]
fn test_srp_modulus_parsing() {
    let parsed = ProtonSrp::parse_modulus(ProtonSrp::DEFAULT_MODULUS_HEX);
    assert!(parsed.is_ok(), "Default modulus should parse successfully");
    let modulus = parsed.unwrap();
    assert!(modulus > num_bigint::BigUint::from(0u32));
}

#[test]
fn test_srp_generator() {
    let g = ProtonSrp::get_generator();
    assert_eq!(g, num_bigint::BigUint::from(2u32));
}

#[test]
fn test_srp_password_hash() {
    let salt = [0x01u8; 16];
    let hash = ProtonSrp::hash_password(4, "MySecretPass123", &salt);
    assert!(hash.is_ok());
}

#[test]
fn test_srp_proof_generation() {
    let salt_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1u8; 16]);
    let server_ephemeral_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[2u8; 32]);

    let res = ProtonSrp::compute_proofs(
        "testpass",
        ProtonSrp::DEFAULT_MODULUS_HEX,
        &server_ephemeral_b64,
        &salt_b64,
        4,
    );

    assert!(res.is_ok());
    let proofs = res.unwrap();
    assert!(!proofs.client_ephemeral_b64.is_empty());
    assert!(!proofs.client_proof_b64.is_empty());
}

use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::fmt;

#[derive(Debug)]
pub enum SrpError {
    InvalidParameter(String),
    CryptoError(String),
}

impl fmt::Display for SrpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrpError::InvalidParameter(msg) => write!(f, "Invalid SRP parameter: {}", msg),
            SrpError::CryptoError(msg) => write!(f, "SRP crypto error: {}", msg),
        }
    }
}

impl std::error::Error for SrpError {}

pub struct SrpProofs {
    pub client_ephemeral_b64: String,
    pub client_proof_b64: String,
    pub expected_server_proof: Vec<u8>,
}

pub struct ProtonSrp;

impl ProtonSrp {
    // RFC 5054 2048-bit modulus default for Proton SRP
    pub const DEFAULT_MODULUS_HEX: &'static str = concat!(
        "D4C7F8A2B32C11B8FBA9581EC4BA4F1B04215642EF7355E37C0F3CAEEB33A",
        "999203C35282F3B1B4CFD34FEFC77C83F679741BEF45AFE758FA61E14CA745",
        "06933A44688B895E877954388C430B480ECB6886FF37442C12D537E224922C",
        "B9BE83C3D457D5C4F418F6387B4B38650F258414D4A09D6A0243048A22F079",
        "76E54E636A0FB3BB11122D08E7A24D43FEEB5F00E6169830A7CFD5D27AC325",
        "5E3AC107B1257440D2D32FBC1E5DA50584140D18080AC77A634E3D9E56E0D2",
        "7A3C08F6D43BE546DB32345402E4168864E0F865E2D1E51B220FBACBFB1FAFB",
        "3504F1A0F1D910119EC9B52DE5007664450A4E156EAE73660D97F3359B80103B0C77"
    );

    pub fn get_generator() -> BigUint {
        BigUint::from(2u32)
    }

    pub fn parse_modulus(modulus_str: &str) -> Result<BigUint, SrpError> {
        // Strip armored PGP header/footer if present
        let clean_b64 = if modulus_str.contains("-----BEGIN") {
            modulus_str
                .lines()
                .filter(|l| !l.starts_with("-----") && !l.contains(':'))
                .collect::<Vec<_>>()
                .join("")
        } else {
            modulus_str.trim().to_string()
        };

        if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, clean_b64.trim()) {
            return Ok(BigUint::from_bytes_be(&bytes));
        }

        // Try hex fallback
        if let Some(num) = BigUint::parse_bytes(modulus_str.trim().as_bytes(), 16) {
            return Ok(num);
        }

        // Default to Proton 2048-bit modulus
        BigUint::parse_bytes(Self::DEFAULT_MODULUS_HEX.as_bytes(), 16)
            .ok_or_else(|| SrpError::InvalidParameter("Failed to parse modulus".into()))
    }

    pub fn hash_password(version: u8, password: &str, salt: &[u8]) -> Result<BigUint, SrpError> {
        let mut hasher = Sha512::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        hasher.update(&[version]);
        let hash = hasher.finalize();
        Ok(BigUint::from_bytes_be(&hash))
    }

    pub fn compute_proofs(
        password: &str,
        modulus_str: &str,
        server_ephemeral_b64: &str,
        salt_b64: &str,
        version: u8,
    ) -> Result<SrpProofs, SrpError> {
        let n = Self::parse_modulus(modulus_str)?;
        let g = Self::get_generator();

        let salt = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, salt_b64.trim())
            .map_err(|e| SrpError::InvalidParameter(format!("Invalid salt base64: {}", e)))?;

        let b_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, server_ephemeral_b64.trim())
            .map_err(|e| SrpError::InvalidParameter(format!("Invalid server ephemeral base64: {}", e)))?;
        let b = BigUint::from_bytes_be(&b_bytes);

        // Compute multiplier k = H(N | pad(g))
        let k = {
            let mut hasher = Sha512::new();
            hasher.update(&n.to_bytes_be());
            let g_bytes = g.to_bytes_be();
            let mut padded_g = vec![0u8; n.to_bytes_be().len().saturating_sub(g_bytes.len())];
            padded_g.extend_from_slice(&g_bytes);
            hasher.update(&padded_g);
            BigUint::from_bytes_be(&hasher.finalize())
        };

        // Compute private key x = H(password, salt, version)
        let x = Self::hash_password(version, password, &salt)?;

        // Generate random secret a (256-bit)
        let mut a_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);

        // A = g^a mod N
        let big_a = g.modpow(&a, &n);
        let big_a_bytes = big_a.to_bytes_be();

        // u = H(A | B)
        let u = {
            let mut hasher = Sha512::new();
            hasher.update(&big_a_bytes);
            hasher.update(&b_bytes);
            BigUint::from_bytes_be(&hasher.finalize())
        };

        if u == BigUint::from(0u32) {
            return Err(SrpError::CryptoError("Scrambling parameter u is zero".into()));
        }

        // S = (B - (k * g^x mod N)) ^ (a + u * x) mod N
        let gx = g.modpow(&x, &n);
        let kgx = (k * gx) % &n;
        let base = if b >= kgx {
            (b - kgx) % &n
        } else {
            (&n - ((kgx - b) % &n)) % &n
        };
        let exp = a + (u * x);
        let s = base.modpow(&exp, &n);
        let s_bytes = s.to_bytes_be();

        // M1 = H(A | B | S)
        let mut m1_hasher = Sha512::new();
        m1_hasher.update(&big_a_bytes);
        m1_hasher.update(&b_bytes);
        m1_hasher.update(&s_bytes);
        let m1 = m1_hasher.finalize();

        // M2 = H(A | M1 | S)
        let mut m2_hasher = Sha512::new();
        m2_hasher.update(&big_a_bytes);
        m2_hasher.update(&m1);
        m2_hasher.update(&s_bytes);
        let m2 = m2_hasher.finalize();

        Ok(SrpProofs {
            client_ephemeral_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &big_a_bytes),
            client_proof_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &m1),
            expected_server_proof: m2.to_vec(),
        })
    }
}

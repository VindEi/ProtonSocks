use crate::api::srp::SrpProofs;
use crate::config::WireguardConfig;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use x25519_dalek::{PublicKey, StaticSecret};

const PROTON_API_BASE: &str = "https://account.proton.me/api";
const APP_VERSION: &str = "Other";

#[derive(Debug, Deserialize)]
pub struct AuthInfoResponse {
    #[serde(rename = "Code")]
    pub code: i32,
    #[serde(rename = "Modulus")]
    pub modulus: Option<String>,
    #[serde(rename = "ServerEphemeral")]
    pub server_ephemeral: Option<String>,
    #[serde(rename = "Salt")]
    pub salt: Option<String>,
    #[serde(rename = "SRPSession")]
    pub srp_session: Option<String>,
    #[serde(rename = "Version")]
    pub version: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "Code")]
    pub code: i32,
    #[serde(rename = "Error")]
    pub error: Option<String>,
    #[serde(rename = "UID")]
    pub uid: Option<String>,
    #[serde(rename = "AccessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "RefreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "TwoFactor")]
    pub two_factor: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct VpnUserResponse {
    #[serde(rename = "Code")]
    pub code: i32,
    #[serde(rename = "VPN")]
    pub vpn: Option<VpnUserInfo>,
}

#[derive(Debug, Deserialize)]
pub struct VpnUserInfo {
    #[serde(rename = "MaxTier")]
    pub max_tier: Option<u8>,
    #[serde(rename = "Status")]
    pub status: Option<i32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogicalServer {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "EntryCountry")]
    pub entry_country: String,
    #[serde(rename = "ExitCountry")]
    pub exit_country: String,
    #[serde(rename = "Tier")]
    pub tier: u8,
    #[serde(rename = "Score")]
    pub score: f64,
    #[serde(rename = "Status")]
    pub status: i32,
    #[serde(rename = "Servers")]
    pub servers: Option<Vec<PhysicalServer>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PhysicalServer {
    #[serde(rename = "EntryIP")]
    pub entry_ip: String,
    #[serde(rename = "ExitIP")]
    pub exit_ip: String,
    #[serde(rename = "PublicKey")]
    pub public_key: Option<String>,
    #[serde(rename = "Status")]
    pub status: i32,
}

#[derive(Debug, Deserialize)]
pub struct CertificateResponse {
    #[serde(rename = "Code")]
    pub code: i32,
    #[serde(rename = "Certificate")]
    pub certificate: Option<String>,
    #[serde(rename = "IP")]
    pub ip: Option<String>,
    #[serde(rename = "DNS")]
    pub dns: Option<String>,
}

pub struct ProtonApiClient {
    http: reqwest::Client,
}

impl ProtonApiClient {
    pub fn new() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("x-pm-appversion", HeaderValue::from_static(APP_VERSION));
        headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.protonmail.v1+json"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap_or_default();

        Self { http }
    }

    pub async fn fetch_auth_info(&self, username: &str) -> Result<AuthInfoResponse, String> {
        let url = format!("{}/auth/v4/info", PROTON_API_BASE);
        let payload = serde_json::json!({ "Username": username });

        let resp = self.http.post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to request auth info: {}", e))?;

        resp.json::<AuthInfoResponse>()
            .await
            .map_err(|e| format!("Failed to parse auth info response: {}", e))
    }

    pub async fn authenticate(
        &self,
        username: &str,
        proofs: &SrpProofs,
        srp_session: &str,
    ) -> Result<AuthResponse, String> {
        let url = format!("{}/auth/v4", PROTON_API_BASE);
        let payload = serde_json::json!({
            "Username": username,
            "ClientEphemeral": proofs.client_ephemeral_b64,
            "ClientProof": proofs.client_proof_b64,
            "SRPSession": srp_session,
        });

        let resp = self.http.post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to submit authentication: {}", e))?;

        resp.json::<AuthResponse>()
            .await
            .map_err(|e| format!("Failed to parse auth response: {}", e))
    }

    pub async fn submit_2fa(
        &self,
        uid: &str,
        access_token: &str,
        totp_code: &str,
    ) -> Result<AuthResponse, String> {
        let url = format!("{}/auth/v4/2fa", PROTON_API_BASE);
        let payload = serde_json::json!({ "TwoFactorCode": totp_code });

        let resp = self.http.post(&url)
            .header("x-pm-uid", uid)
            .bearer_auth(access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to submit 2FA: {}", e))?;

        resp.json::<AuthResponse>()
            .await
            .map_err(|e| format!("Failed to parse 2FA response: {}", e))
    }

    pub async fn get_user_tier(&self, uid: &str, access_token: &str) -> Result<u8, String> {
        let url = format!("{}/vpn/v1/user", PROTON_API_BASE);
        let resp = self.http.get(&url)
            .header("x-pm-uid", uid)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch user tier: {}", e))?;

        let user_info = resp.json::<VpnUserResponse>()
            .await
            .map_err(|e| format!("Failed to parse user info: {}", e))?;

        Ok(user_info.vpn.and_then(|v| v.max_tier).unwrap_or(0))
    }

    pub async fn get_best_logical_server(
        &self,
        access_token: &str,
        target_country: &str,
        max_tier: u8,
    ) -> Result<LogicalServer, String> {
        let url = format!("{}/vpn/v1/logicals", PROTON_API_BASE);
        let resp = self.http.get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch logical servers: {}", e))?;

        #[derive(Deserialize)]
        struct LogicalsWrapper {
            #[serde(rename = "LogicalServers")]
            logical_servers: Vec<LogicalServer>,
        }

        let data = resp.json::<LogicalsWrapper>()
            .await
            .map_err(|e| format!("Failed to parse logical servers: {}", e))?;

        let country_upper = target_country.to_uppercase();
        let mut candidates: Vec<LogicalServer> = data.logical_servers
            .into_iter()
            .filter(|s| s.exit_country.to_uppercase() == country_upper && s.tier <= max_tier && s.status == 1)
            .collect();

        if candidates.is_empty() {
            return Err(format!("No available Proton servers found for country {}", target_country));
        }

        // Sort by load score (lowest is least loaded)
        candidates.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
        Ok(candidates.remove(0))
    }

    pub fn generate_wireguard_keypair() -> (String, String) {
        let mut rng = rand::thread_rng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&secret);

        let private_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret.to_bytes());
        let public_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public.as_bytes());
        (private_b64, public_b64)
    }

    pub async fn register_wireguard_key(
        &self,
        access_token: &str,
        client_public_key: &str,
    ) -> Result<CertificateResponse, String> {
        let url = format!("{}/vpn/v1/certificate", PROTON_API_BASE);
        let payload = serde_json::json!({ "ClientKey": client_public_key });

        let resp = self.http.post(&url)
            .bearer_auth(access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to register WireGuard certificate: {}", e))?;

        resp.json::<CertificateResponse>()
            .await
            .map_err(|e| format!("Failed to parse certificate response: {}", e))
    }

    pub fn parse_wg_conf(conf_content: &str) -> Result<WireguardConfig, String> {
        let mut private_key = String::new();
        let mut address = String::new();
        let mut dns = "10.2.0.1".to_string();
        let mut public_key = String::new();
        let mut endpoint = String::new();
        let mut server_name = "Proton-Custom".to_string();

        for line in conf_content.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                let comment = line.trim_start_matches('#').trim();
                if !comment.is_empty() && !comment.contains('=') {
                    server_name = comment.to_string();
                }
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_lowercase();
                let val = v.trim();
                match key.as_str() {
                    "privatekey" => private_key = val.to_string(),
                    "address" => {
                        // Take primary IPv4 address
                        let primary = val.split(',').next().unwrap_or(val).trim();
                        address = primary.to_string();
                    }
                    "dns" => {
                        let primary = val.split(',').next().unwrap_or(val).trim();
                        dns = primary.to_string();
                    }
                    "publickey" => public_key = val.to_string(),
                    "endpoint" => endpoint = val.to_string(),
                    _ => {}
                }
            }
        }

        if private_key.is_empty() || public_key.is_empty() || endpoint.is_empty() {
            return Err("Missing required fields in WireGuard config (PrivateKey, PublicKey, Endpoint)".to_string());
        }

        if address.is_empty() {
            address = "10.2.0.2/32".to_string();
        }

        Ok(WireguardConfig {
            private_key,
            public_key: String::new(),
            client_ip: address,
            dns,
            server_name,
            server_public_key: public_key,
            server_endpoint: endpoint,
        })
    }
}

use std::thread::sleep;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine as _};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use rand::Rng;
use std::time::Duration;
use time::OffsetDateTime;
pub fn gen_nonce(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let n = rng.gen_range(0..36);
            std::char::from_digit(n as u32, 36).unwrap()
        })
        .collect()
}
pub fn now_ts() -> String {
    OffsetDateTime::now_utc().unix_timestamp().to_string()
}
pub fn rsa_sign_sha256_pem(private_key_pem: &str, data: &str) -> anyhow::Result<String> {
    let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(data.as_bytes())?;
    let sig = signer.sign_to_vec()?;
    Ok(general_purpose::STANDARD.encode(sig))
}
pub fn rsa_verify_sha256_pem(
    public_key_pem: &str,
    data: &str,
    signature_base64: &str,
) -> anyhow::Result<bool> {
    use openssl::sign::Verifier;
    let pkey = PKey::public_key_from_pem(public_key_pem.as_bytes())?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verifier.update(data.as_bytes())?;
    let sig = general_purpose::STANDARD.decode(signature_base64)?;
    Ok(verifier.verify(&sig)?)
}
pub fn aes_gcm_decrypt(
    api_v3_key: &str,
    associated_data: &str,
    nonce: &str,
    ciphertext_b64: &str,
) -> anyhow::Result<String> {
    let key = api_v3_key.as_bytes();
    if key.len() != 32 {
        anyhow::bail!("api_v3_key must be 32 bytes");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let nonce_bytes = nonce.as_bytes();
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(ciphertext_b64)?;
    let plain = cipher.decrypt(
        nonce,
        aes_gcm::aead::Payload {
            msg: &ciphertext,
            aad: associated_data.as_bytes(),
        },
    );
    let plain = plain.map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(String::from_utf8(plain)?)
}
pub async fn retry_async<F, Fut, T, E>(mut attempts: usize, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut delay = 200u64;
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                attempts -= 1;
                if attempts == 0 {
                    return Err(e);
                }
                sleep(Duration::from_millis(delay));
                delay = std::cmp::min(delay * 2, 5000);
            }
        }
    }
}

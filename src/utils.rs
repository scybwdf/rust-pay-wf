use std::thread::sleep;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, DecodeError, Engine as _};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer,x509::X509};
use rand::Rng;
use std::time::Duration;
use time::OffsetDateTime;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::Path;
use tracing::debug;
use x509_parser::prelude::*;
use gostd::strings;

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
    let private_key_pem = load_private_key(private_key_pem);
    println!("private_key_pem: {:?}", private_key_pem);
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


pub fn extract_pubkey_from_cert(cert_pem: &str) -> anyhow::Result<String> {
    let cert = X509::from_pem(cert_pem.as_bytes())?;
    let pubkey: PKey<openssl::pkey::Public> = cert.public_key()?;
    let pub_pem = pubkey.public_key_to_pem()?;
    Ok(String::from_utf8(pub_pem)?)
}

pub fn get_cert_sn(cert_path: impl AsRef<str>) -> Result<String> {
    debug!("cert_path: {}", cert_path.as_ref());
    let cert_data: &[u8] = &fs::read(cert_path.as_ref())?;
    cert_sn_from_utf8(cert_data)
}
///  cert_sn_from_utf8 从文本计算证书序列号(app_cert_sn、alipay_cert_sn)
pub fn cert_sn_from_utf8(cert_content: impl AsRef<[u8]>) -> Result<String> {
    let cert_data = cert_content.as_ref();
    if let Err(err) = parse_x509_pem(cert_data) {
        return Err(Error::new(
            ErrorKind::Other,
            format!("parse_x509_pem: {}", err.to_string()),
        ));
    }

    let (_, cert) = parse_x509_pem(cert_data).ok().expect("Pem is None");
    if let Ok(x509) = cert.parse_x509() {
        let mut name = x509.tbs_certificate.issuer().to_string();
        //提取出的证书的issuer本身是以CN开头的，则无需逆序，直接返回
        if !strings::HasPrefix(&name, "CN") {
            let mut attributes = strings::Split(&name, ", ");
            attributes.reverse();
            name = strings::Join(attributes, ",");
        }
        let serial_number = x509.serial.to_str_radix(10);
        Ok(format!("{:x}", md5::compute(name + &serial_number)))
    } else {
        Err(Error::new(ErrorKind::Other, "parse_x509 failed"))
    }
}

/// get_root_cert_sn 获取root证书序列号SN
///    root_cert_path：X.509证书文件路径(alipayRootCert.crt)
///    返回 sn：证书序列号(alipay_root_cert_sn)
pub fn get_root_cert_sn(root_cert_path: impl AsRef<str>) -> Result<String> {
    debug!("root_cert_path: {:?}", root_cert_path.as_ref());
    let certs_data = &fs::read(root_cert_path.as_ref())?;
    root_cert_sn_from_utf8(certs_data)
}

/// root_cert_sn_from_utf8 从文本计算根证书序列号(alipay_root_cert_sn)
pub fn root_cert_sn_from_utf8(cert_contents: impl AsRef<[u8]>) -> Result<String> {
    let cert_end = "-----END CERTIFICATE-----";
    let certs_str = String::from_utf8(cert_contents.as_ref().to_vec())
        .or(Err(Error::new(ErrorKind::Other, "form_utf8 failed")))?;
    let pems = strings::Split(&certs_str, &cert_end);
    let mut sn = String::new();
    for c in pems {
        let cert_data = c.to_owned() + cert_end;
        if let Err(_) = parse_x509_pem(cert_data.as_bytes()) {
            continue;
        }

        let (_, cert) = parse_x509_pem(cert_data.as_bytes())
            .ok()
            .expect("Pem is None");
        if let Ok(x509) = cert.parse_x509() {
            if !x509
                .signature_algorithm
                .algorithm
                .to_id_string()
                .starts_with("1.2.840.113549.1.1")
            {
                continue;
            }

            if sn.is_empty() {
                sn += &cert_sn_from_utf8(cert_data.as_bytes())?;
            } else {
                sn += &("_".to_owned() + &cert_sn_from_utf8(cert_data.as_bytes())?);
            }
        }
    }

    if sn.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            "failed to get sn,please check your cert",
        ));
    }
    Ok(sn)
}

/// 从支付宝公钥证书文件中提取支付宝公钥(alipayCertPublicKey_RSA2.crt)
pub fn get_public_key_with_path<'a>(alipay_cert_path: impl AsRef<str>) -> Result<String> {
    debug!("alipay_cert_path: {:?}", alipay_cert_path.as_ref());
    let cert_data = &fs::read(alipay_cert_path.as_ref())?;
    let cert = load_certificate(cert_data)?;
    match cert.parse_x509() {
        Ok(certificate) => Ok(base64_encode(certificate.public_key().raw)),
        Err(err) => Err(Error::new(ErrorKind::Other, err.to_string())),
    }
}

/// 通过证书的文本内容加载证书
pub fn load_certificate(cert_content: impl AsRef<[u8]>) -> Result<Pem> {
    let cert_data = cert_content.as_ref();
    if let Err(err) = parse_x509_pem(cert_data) {
        return Err(Error::new(
            ErrorKind::Other,
            format!("parse_x509_pem: {}", err.to_string()),
        ));
    }

    let (_, cert) = parse_x509_pem(cert_data).ok().expect("Pem is None");
    if cert.label != "CERTIFICATE" {
        return Err(Error::new(ErrorKind::Other, "Failed to decode certificate"));
    }
    Ok(cert)
}


/// 从证书文件提取 SN（失败返回空字符串）
/*pub fn get_cert_sn(cert_path: &str) -> String {
    let data = match fs::read(cert_path) {
        Ok(d) => d,
        Err(_) => return "".to_string(),
    };

    let cert = match X509::from_pem(&data) {
        Ok(c) => c,
        Err(_) => return "".to_string(),
    };

    let issuer = cert
        .issuer_name()
        .entries()
        .map(|e| {
            let key = e.object().nid().short_name().unwrap_or("");
            let val = e.data().as_utf8().ok().map(|s| s.to_string()).unwrap_or_default();
            format!("{}={}", key, val)
        })
        .collect::<Vec<_>>()
        .join(",");

    let sn_hex = match cert.serial_number().to_bn().and_then(|bn| bn.to_hex_str()) {
        Ok(s) => s.to_string(),
        Err(_) => return "".to_string(),
    };

    let raw = format!("{}{}", issuer, sn_hex);
    format!("{:x}", md5::compute(raw))
}

pub fn get_root_cert_sn(root_path: &str) -> String {
    let text = match fs::read_to_string(root_path) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("Failed to read root cert file: {}", root_path);
            return "".to_string();
        }
    };

    let mut sns = vec![];

    for block in text.split("-----END CERTIFICATE-----") {
        if block.contains("-----BEGIN CERTIFICATE-----") {
            let cert_data = format!("{}-----END CERTIFICATE-----", block);
            let cert = match X509::from_pem(cert_data.as_bytes()) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to parse cert block: {}", e);
                    continue;
                }
            };

            let issuer = cert
                .issuer_name()
                .entries()
                .map(|e| {
                    let key = e.object().nid().short_name().unwrap_or("");
                    let val = e.data().as_utf8().ok().map(|s| s.to_string()).unwrap_or_default();
                    format!("{}={}", key, val)
                })
                .collect::<Vec<_>>()
                .join(",");

            let sn_hex = match cert.serial_number().to_bn().and_then(|bn| bn.to_hex_str()) {
                Ok(s) => s.to_string(),
                Err(e) => {
                    eprintln!("Failed to get serial number: {}", e);
                    continue;
                }
            };

            let raw = format!("{}{}", issuer, sn_hex);
            sns.push(format!("{:x}", md5::compute(raw)));
        }
    }

    if sns.is_empty() {
        eprintln!("No valid cert SN found in {}", root_path);
        "".to_string()
    } else {
        sns.join("_")
    }
}*/
/// 加载私钥字符串，自动识别 `.pem` 文件 / 原始字符串
#[inline]
pub fn load_private_key(source: &str) -> String {
    // 优先判断是否是文件路径
    let path = Path::new(source);
    if path.exists() {
        // 直接读取文件内容（.pem 或其他）
        let data = fs::read_to_string(path).unwrap_or_default();
        if source.ends_with(".pem") || data.contains("-----BEGIN") {
            return data; // 已经是 PEM 格式
        }
        return wrap_rsa_key(&data);
    }

    // 不是文件路径，直接判断字符串是否 PEM 格式
    if source.contains("-----BEGIN") {
        source.to_string()
    } else {
        wrap_rsa_key(source)
    }
}

/// 自动包装成 PEM 格式 (最小化分配、64列换行)
#[inline]
fn wrap_rsa_key(raw: &str) -> String {
    let mut key = String::with_capacity(raw.len() + 80);
    key.push_str("-----BEGIN RSA PRIVATE KEY-----\n");

    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = usize::min(i + 64, bytes.len());
        key.push_str(unsafe { std::str::from_utf8_unchecked(&bytes[i..end]) });
        key.push('\n');
        i = end;
    }

    key.push_str("-----END RSA PRIVATE KEY-----");
    key
}

pub fn base64_encode<T>(input: T) -> String
where
    T: AsRef<[u8]>,
{
    general_purpose::STANDARD.encode(input)
}

pub fn base64_decode<T>(input: T) -> Result<Vec<u8>, DecodeError>
where
    T: AsRef<[u8]>,
{
    general_purpose::STANDARD.decode(input)
}

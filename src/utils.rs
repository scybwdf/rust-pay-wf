use std::thread::sleep;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, DecodeError, Engine as _};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer,x509::X509};
use rand::Rng;
use std::time::Duration;
use std::fs;
use std::path::Path;
use openssl::encrypt::Encrypter;
use openssl::hash::hash;
use openssl::nid::Nid;
use openssl::rsa::Rsa;

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
    ::time::OffsetDateTime::now_utc().unix_timestamp().to_string()
}
pub fn rsa_sign_sha256_pem(private_key_pem: &str, data: &str) -> anyhow::Result<String> {
    let private_key_pem = load_private_key(private_key_pem);
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
    // 判断是证书还是公钥
    let pkey = if public_key_pem.contains("BEGIN CERTIFICATE") {
        // 解析 X.509 证书，从证书提取公钥
        let cert = X509::from_pem(public_key_pem.as_bytes())?;
        cert.public_key()?
    } else {
        // 直接解析公钥 PEM
        PKey::public_key_from_pem(public_key_pem.as_bytes())?
    };
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
    //let nonce = Nonce::clone_from_slice(nonce_bytes); // Nonce 类型别名
    #[allow(deprecated)]
    let nonce= Nonce::from_slice(nonce_bytes);
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

// get cert sn by cert file by alipay
pub fn get_cert_sn(cert: &str) -> anyhow::Result<String> {
    let cert = std::fs::read_to_string(cert)?;
    get_cert_sn_by_content(cert.as_ref())
}

/// get alipay root cert sn
pub fn get_root_cert_sn(cert_content: &str) -> anyhow::Result<String> {
    let cert_content = std::fs::read_to_string(cert_content)?;
    let root_cert_sn = cert_content
        .split_inclusive("-----END CERTIFICATE-----")
        .filter(|cert| {
            let ssl = X509::from_pem(cert.as_ref()).unwrap();
            let algorithm = ssl.signature_algorithm().object().nid();
            algorithm == Nid::SHA256WITHRSAENCRYPTION || algorithm == Nid::SHA1WITHRSAENCRYPTION
        })
        .filter_map(|cert| get_cert_sn_by_content(cert.as_ref()).ok())
        .collect::<Vec<String>>()
        .join("_");
    Ok(root_cert_sn)
}

pub fn get_cert_sn_by_content(cert_content: &[u8]) -> anyhow::Result<String> {
    //let cert_content = std::fs::read(cert_content)?;
    let cert = X509::from_pem(cert_content).unwrap();
    /* */
    let mut sumary = cert
        //.clone()
        .issuer_name()
        .entries()
        .map(|item| {
            item.object().nid().short_name().unwrap().to_string()
                + "="
                + &item.data().as_utf8().unwrap().to_string()
        })
        .collect::<Vec<String>>();
    sumary.reverse();
    let sumary = sumary.join(",");
    //println!("sumary==={}\n", sumary);
    let serial_number = cert.serial_number().to_bn()?.to_dec_str()?;
    let sumary = sumary + &serial_number;

    let md5_digest = hash(MessageDigest::md5(), sumary.as_bytes())?;

    // Convert the hash to a hexadecimal string
    let cert_sn: &String = &md5_digest
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();
    //.to_string();
    let mut cert_sn = cert_sn.to_string();

    while cert_sn.len() < 32 {
        cert_sn.insert(0, '0');
    }

    Ok(cert_sn)
}

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

/// RSA-OAEP加密函数（微信支付接收方名称加密专用）
/// 使用微信支付平台证书公钥进行加密
pub fn rsa_encrypt_oaep_with_public_key_pem(
    public_key_pem: &str,
    plaintext: &str,
) -> anyhow::Result<String> {
    use openssl::encrypt::Encrypter;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    // 1. 加载公钥PEM
    let rsa = Rsa::public_key_from_pem(public_key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse public key PEM: {}", e))?;

    // 2. 创建PKey
    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| anyhow::anyhow!("Failed to create PKey from RSA: {}", e))?;

    // 3. 配置加密器
    let mut encrypter = Encrypter::new(&pkey)
        .map_err(|e| anyhow::anyhow!("Failed to create encrypter: {}", e))?;

    encrypter.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
        .map_err(|e| anyhow::anyhow!("Failed to set padding: {}", e))?;

    // 修正这里：使用 MessageDigest::sha1() 而不是 Md::sha1()
    encrypter.set_rsa_mgf1_md(MessageDigest::sha1())
        .map_err(|e| anyhow::anyhow!("Failed to set MGF1 hash: {}", e))?;

    encrypter.set_rsa_oaep_md(MessageDigest::sha1())
        .map_err(|e| anyhow::anyhow!("Failed to set OAEP hash: {}", e))?;

    // 4. 计算加密长度并执行加密
    let buffer_len = encrypter.encrypt_len(plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to get encrypt length: {}", e))?;
    let mut encrypted = vec![0; buffer_len];

    let enc_len = encrypter.encrypt(plaintext.as_bytes(), &mut encrypted)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt data: {}", e))?;

    // 5. 截取实际加密数据并Base64编码
    encrypted.truncate(enc_len);
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

/// 从微信支付平台证书中提取序列号（16进制，大写）
/// 微信支付要求使用16进制格式的证书序列号，且为大写
pub fn extract_wechat_cert_serial_number(cert_pem: &str) -> anyhow::Result<String> {
    // 1. 解析证书
    let cert = X509::from_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate PEM: {}", e))?;

    // 2. 获取序列号（Asn1IntegerRef类型）
    let serial = cert.serial_number();

    // 3. 将Asn1Integer转换为BigNum，然后转换为16进制字符串
    // 注意：Asn1IntegerRef没有to_hex_str方法，需要先转换为BigNum
    let bn = serial.to_bn()
        .map_err(|e| anyhow::anyhow!("Failed to convert serial to BigNum: {}", e))?;

    // 4. 将BigNum转换为16进制字符串
    let serial_hex = bn.to_hex_str()
        .map_err(|e| anyhow::anyhow!("Failed to convert BigNum to hex: {}", e))?;

    // 5. 转换为大写（微信支付要求）并去掉可能的"0x"前缀
    let hex_str = serial_hex.to_string().trim_start_matches("0x").to_uppercase();

    Ok(hex_str)
}

/// 从微信支付平台证书中提取序列号和公钥
pub fn extract_wechat_platform_cert_info(cert_pem: &str) -> anyhow::Result<(String, String)> {
    // 1. 提取序列号
    let cert_sn = extract_wechat_cert_serial_number(cert_pem)?;

    // 2. 提取公钥（使用您已有的函数）
    let public_key_pem = extract_pubkey_from_cert(cert_pem)?;

    Ok((cert_sn, public_key_pem))
}
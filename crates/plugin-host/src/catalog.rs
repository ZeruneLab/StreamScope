use crate::{HOST_API_VERSION, PluginError, Result, VerifiedPackage, verify_package};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;
use url::Url;

const MAX_CATALOG: u64 = 1024 * 1024;
const MAX_PACKAGE: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub generated_at: String,
    pub packages: Vec<CatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntry {
    pub id: String,
    pub version: String,
    pub package_url: String,
    pub package_sha256: String,
    pub publisher_fingerprint: String,
    pub host_api: String,
    pub os: String,
    pub arch: String,
}

pub fn verify_catalog(bytes: &[u8], signature_base64: &str, public_key_base64: &str) -> Result<Catalog> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CATALOG { return Err(invalid("官方插件目录超出限制")); }
    let key: [u8; 32] = base64::engine::general_purpose::STANDARD.decode(public_key_base64.trim())
        .map_err(|_| invalid("目录公钥不是 Base64"))?.try_into().map_err(|_| invalid("目录公钥长度无效"))?;
    let signature: [u8; 64] = base64::engine::general_purpose::STANDARD.decode(signature_base64.trim())
        .map_err(|_| invalid("目录签名不是 Base64"))?.try_into().map_err(|_| invalid("目录签名长度无效"))?;
    VerifyingKey::from_bytes(&key).map_err(|_| invalid("目录公钥无效"))?
        .verify_strict(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| invalid("官方插件目录签名验证失败"))?;
    let catalog: Catalog = serde_json::from_slice(bytes)?;
    if catalog.schema_version != 1 || catalog.packages.len() > 1000 { return Err(invalid("目录版本或条目数量无效")); }
    let mut seen = HashSet::new();
    for entry in &catalog.packages {
        if !crate::package::valid_id(&entry.id)
            || !seen.insert((entry.id.clone(), entry.version.clone(), entry.os.clone(), entry.arch.clone()))
            || Version::parse(&entry.version).is_err()
            || VersionReq::parse(&entry.host_api).is_err()
            || !valid_digest(&entry.package_sha256)
            || !valid_digest(&entry.publisher_fingerprint)
            || !valid_https(&entry.package_url)
            || entry.os.is_empty() || entry.arch.is_empty()
        {
            return Err(invalid("官方插件目录条目无效"));
        }
    }
    Ok(catalog)
}

impl CatalogEntry {
    pub fn matches_confirmation(&self, package_sha256: &str, fingerprint: &str) -> bool {
        self.package_sha256.strip_prefix("sha256:") == Some(package_sha256)
            && self.publisher_fingerprint == fingerprint
    }

    pub fn compatible(&self) -> bool {
        self.os == std::env::consts::OS && self.arch == std::env::consts::ARCH
            && VersionReq::parse(&self.host_api).is_ok_and(|requirement| {
                Version::parse(HOST_API_VERSION).is_ok_and(|version| requirement.matches(&version))
            })
    }
}

pub fn version_satisfies(version: &str, requirements: &[String]) -> Result<bool> {
    if requirements.is_empty() || requirements.len() > 100 { return Err(invalid("依赖版本约束数量无效")); }
    let version = Version::parse(version).map_err(|_| invalid("插件版本无效"))?;
    let requirements = requirements.iter().map(|value| VersionReq::parse(value)
        .map_err(|_| invalid("依赖版本范围无效"))).collect::<Result<Vec<_>>>()?;
    Ok(requirements.iter().all(|requirement| requirement.matches(&version)))
}

impl Catalog {
    pub fn select(&self, id: &str, requirements: &[String]) -> Result<&CatalogEntry> {
        if !crate::package::valid_id(id) { return Err(invalid("插件标识无效")); }
        // Validate even when the directory contains no candidate for this ID.
        version_satisfies("0.0.0", requirements)?;
        self.packages.iter().filter(|entry| entry.id == id && entry.compatible())
            .filter(|entry| version_satisfies(&entry.version, requirements).unwrap_or(false))
            .max_by_key(|entry| Version::parse(&entry.version).ok())
            .ok_or_else(|| invalid(&format!("官方目录没有兼容依赖 {id} ({})", requirements.join("、"))))
    }
}

pub fn fetch_signed_catalog(url: &str, public_key_base64: &str) -> Result<Catalog> {
    if !valid_https(url) { return Err(invalid("官方目录必须使用 HTTPS")); }
    if Url::parse(url).is_ok_and(|parsed| parsed.query().is_some() || parsed.fragment().is_some()) {
        return Err(invalid("官方目录 URL 不允许查询参数或片段"));
    }
    let client = https_client(Duration::from_secs(30))?;
    let mut response = client.get(url).send()?.error_for_status()?;
    if response.url().scheme() != "https" { return Err(invalid("官方目录重定向到了非 HTTPS 地址")); }
    let mut bytes = Vec::new();
    response.by_ref().take(MAX_CATALOG + 1).read_to_end(&mut bytes)?;
    let signature_url = format!("{url}.sig");
    let mut signature = client.get(signature_url).send()?.error_for_status()?;
    if signature.url().scheme() != "https" { return Err(invalid("目录签名重定向到了非 HTTPS 地址")); }
    let mut signature_bytes = Vec::new();
    signature.by_ref().take(257).read_to_end(&mut signature_bytes)?;
    if signature_bytes.len() > 256 { return Err(invalid("目录签名超出限制")); }
    let signature = std::str::from_utf8(&signature_bytes).map_err(|_| invalid("目录签名编码无效"))?;
    verify_catalog(&bytes, signature, public_key_base64)
}

pub fn download_catalog_package(entry: &CatalogEntry, destination: &Path) -> Result<VerifiedPackage> {
    if !entry.compatible() { return Err(invalid("插件版本与当前平台或宿主 API 不兼容")); }
    if !valid_https(&entry.package_url) { return Err(invalid("插件下载地址必须使用 HTTPS")); }
    let client = https_client(Duration::from_secs(600))?;
    let mut response = client.get(&entry.package_url).send()?.error_for_status()?;
    if response.url().scheme() != "https" { return Err(invalid("插件包重定向到了非 HTTPS 地址")); }
    if let Some(parent) = destination.parent() { fs::create_dir_all(parent)?; }
    let mut file = OpenOptions::new().write(true).create_new(true).open(destination)?;
    let outcome = (|| {
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = response.read(&mut buffer)?;
            if count == 0 { break; }
            total += count as u64;
            if total > MAX_PACKAGE { return Err(invalid("插件下载超出大小限制")); }
            hash.update(&buffer[..count]);
            file.write_all(&buffer[..count])?;
        }
        file.sync_all()?;
        drop(file);
        if format!("sha256:{:x}", hash.finalize()) != entry.package_sha256 {
            return Err(invalid("下载包与签名目录中的 SHA-256 不一致"));
        }
        let package = verify_package(destination)?;
        if package.manifest.id != entry.id || package.manifest.version != entry.version
            || package.fingerprint != entry.publisher_fingerprint || package.manifest.host_api != entry.host_api {
            return Err(invalid("下载包与签名目录中的发布者或版本不一致"));
        }
        Ok(package)
    })();
    if outcome.is_err() { let _ = fs::remove_file(destination); }
    outcome
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71 && value.starts_with("sha256:") && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn https_client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder().timeout(timeout)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if !valid_https(attempt.url().as_str()) { return attempt.error("插件下载拒绝非 HTTPS 或携带凭据的重定向"); }
            if attempt.previous().len() >= 10 { return attempt.error("插件下载重定向过多"); }
            attempt.follow()
        })).build()?)
}

fn valid_https(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some() && url.username().is_empty() && url.password().is_none())
}

fn invalid(message: &str) -> PluginError { PluginError::Invalid(message.into()) }

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signed_catalog_rejects_tampering_and_http() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let catalog = serde_json::json!({"schemaVersion":1,"generatedAt":"2026-01-01T00:00:00Z","packages":[{
            "id":"org.streamscope.sample","version":"1.0.0","packageUrl":"https://example.org/sample.ssp",
            "packageSha256":format!("sha256:{}", "0".repeat(64)),
            "publisherFingerprint":format!("sha256:{}", "1".repeat(64)),
            "hostApi":"^1.0","os":"windows","arch":"x86_64"
        }]});
        let bytes = serde_json::to_vec(&catalog).unwrap();
        let signature = base64::engine::general_purpose::STANDARD.encode(key.sign(&bytes).to_bytes());
        let public = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        assert!(verify_catalog(&bytes, &signature, &public).is_ok());
        let mut changed = bytes.clone(); changed[10] ^= 1;
        assert!(verify_catalog(&changed, &signature, &public).is_err());
        assert!(!valid_https("http://example.org/unsigned.ssp"));
    }

    fn entry(version: &str, host_api: &str) -> CatalogEntry {
        CatalogEntry { id: "org.streamscope.sample".into(), version: version.into(),
            package_url: "https://example.org/sample.ssp".into(), package_sha256: format!("sha256:{}", "0".repeat(64)),
            publisher_fingerprint: format!("sha256:{}", "1".repeat(64)), host_api: host_api.into(),
            os: std::env::consts::OS.into(), arch: std::env::consts::ARCH.into() }
    }

    #[test]
    fn directory_can_contain_future_api_and_multiple_platforms() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let mut other = entry("1.0.0", "^1");
        other.arch = "other".into();
        let mut catalog = Catalog { schema_version: 1, generated_at: "2026-10-08".into(),
            packages: vec![entry("1.0.0", "^1"), other, entry("2.0.0", "^2")] };
        let verify = |catalog: &Catalog| {
            let bytes = serde_json::to_vec(catalog).unwrap();
            verify_catalog(&bytes, &base64::engine::general_purpose::STANDARD.encode(key.sign(&bytes).to_bytes()),
                &base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()))
        };
        assert!(verify(&catalog).is_ok());
        assert_eq!(catalog.packages.iter().filter(|entry| entry.compatible()).count(), 1);
        catalog.packages.push(entry("1.0.0", "^1"));
        assert!(verify(&catalog).is_err());
    }

    #[test]
    fn selection_uses_semver_and_all_dependency_constraints() {
        let catalog = Catalog { schema_version: 1, generated_at: String::new(), packages: vec![
            entry("1.2.0", "^1"), entry("1.10.0", "^1"), entry("1.11.0-beta.1", "^1"), entry("2.0.0", "^2"),
        ] };
        assert_eq!(catalog.select("org.streamscope.sample", &["^1".into()]).unwrap().version, "1.10.0");
        assert_eq!(catalog.select("org.streamscope.sample", &["^1".into(), "<1.3".into()]).unwrap().version, "1.2.0");
        assert!(catalog.select("org.streamscope.sample", &["^2".into()]).is_err());
        assert!(catalog.select("org.streamscope.sample", &["invalid".into()]).is_err());
        assert!(catalog.select("org.streamscope.sample", &[]).is_err());
    }

    #[test]
    fn catalog_hash_prefix_is_normalized_when_binding_package_confirmation() {
        let entry = entry("1.0.0", "^1");
        assert!(entry.matches_confirmation(&"0".repeat(64), &entry.publisher_fingerprint));
        assert!(!entry.matches_confirmation(&"2".repeat(64), &entry.publisher_fingerprint));
        assert!(!entry.matches_confirmation(&"0".repeat(64), "wrong publisher"));
    }
}

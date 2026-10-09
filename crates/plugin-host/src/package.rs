use crate::{HOST_API_VERSION, Manifest, PluginError, Result, UiDocument};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::{Version, VersionReq};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use zip::ZipArchive;

const MAX_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 2 * MAX_PACKAGE_BYTES;
const MAX_FILES: usize = 1000;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    pub path: PathBuf,
    pub manifest: Manifest,
    pub fingerprint: String,
    pub package_sha256: String,
    pub entry: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePreview {
    pub manifest: Manifest,
    pub fingerprint: String,
    pub package_sha256: String,
    pub native_risk: String,
}

impl From<&VerifiedPackage> for PackagePreview {
    fn from(value: &VerifiedPackage) -> Self {
        Self {
            manifest: value.manifest.clone(),
            fingerprint: value.fingerprint.clone(),
            package_sha256: value.package_sha256.clone(),
            native_risk: "此插件包含原生可执行代码，将以当前 Windows 用户权限运行；权限声明不能限制其直接访问操作系统。".into(),
        }
    }
}

pub fn verify_package(path: &Path) -> Result<VerifiedPackage> {
    let mut source = File::open(path)?;
    let compressed_bytes = source.metadata()?.len();
    if compressed_bytes == 0 || compressed_bytes > MAX_PACKAGE_BYTES {
        return Err(invalid("插件包大小超出限制"));
    }
    let package_sha256 = hash_reader(&mut source, MAX_PACKAGE_BYTES)?.0;
    let mut archive = ZipArchive::new(File::open(path)?)?;
    if archive.len() < 4 || archive.len() > MAX_FILES {
        return Err(invalid("插件包文件数量无效"));
    }
    let mut paths = HashSet::new();
    let mut folded_paths = HashSet::new();
    let mut expanded = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name();
        if !valid_relative_path(name)
            || !paths.insert(name.to_string())
            || !folded_paths.insert(name.to_ascii_lowercase())
            || entry.is_dir()
        {
            return Err(invalid("插件包包含重复路径、目录或不安全路径"));
        }
        if entry.unix_mode().is_some_and(|mode| mode & 0o170000 == 0o120000) {
            return Err(invalid("插件包不允许符号链接"));
        }
        expanded = expanded.saturating_add(entry.size());
        if expanded > MAX_EXPANDED_BYTES || entry.size() > MAX_PACKAGE_BYTES {
            return Err(invalid("插件包解压大小超出限制"));
        }
    }
    let manifest_bytes = read_small(&mut archive, "manifest.json", MAX_MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let public_key = read_small(&mut archive, "publisher.pub", 256)?;
    let signature = read_small(&mut archive, "signature.ed25519", 256)?;
    let public_key = decode_fixed::<32>(&public_key, "发布者公钥")?;
    let signature = decode_fixed::<64>(&signature, "插件签名")?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| invalid("发布者公钥无效"))?;
    key.verify_strict(&manifest_bytes, &Signature::from_bytes(&signature))
        .map_err(|_| invalid("插件签名验证失败"))?;
    let fingerprint = format!("sha256:{}", hex_digest(&public_key));
    if manifest.publisher.key_fingerprint != fingerprint {
        return Err(invalid("发布者公钥指纹与清单不一致"));
    }
    let expected = manifest
        .files
        .keys()
        .cloned()
        .chain(["manifest.json", "publisher.pub", "signature.ed25519"].map(str::to_string))
        .collect::<HashSet<_>>();
    if paths != expected {
        return Err(invalid("插件包文件与清单不一致"));
    }
    for (name, expected_hash) in &manifest.files {
        let mut entry = archive.by_name(name)?;
        let (actual, _) = hash_reader(&mut entry, MAX_PACKAGE_BYTES)?;
        if *expected_hash != format!("sha256:{actual}") {
            return Err(invalid(&format!("文件 {name} 的 SHA-256 不一致")));
        }
    }
    let ui_bytes = read_small(&mut archive, &manifest.ui.file, 256 * 1024)?;
    let ui: UiDocument = serde_json::from_slice(&ui_bytes)?;
    ui.validate()?;
    if ui.uses_file_input() && !manifest.permissions.iter().any(|permission| permission.name == "file-read") {
        return Err(invalid("文件选择组件必须声明 file-read 权限"));
    }
    for contribution in &manifest.contributions {
        if !ui.views.iter().any(|view| view.id == contribution.view) {
            return Err(invalid("功能入口引用了不存在的界面视图"));
        }
    }
    let entry = manifest
        .platforms
        .iter()
        .find(|platform| {
            platform.os == std::env::consts::OS && platform.arch == std::env::consts::ARCH
        })
        .ok_or_else(|| invalid("插件不支持当前操作系统或架构"))?
        .entry
        .clone();
    Ok(VerifiedPackage {
        path: path.to_path_buf(),
        manifest,
        fingerprint,
        package_sha256,
        entry,
    })
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema_version != 1
        || !valid_id(&manifest.id)
        || !valid_id(&manifest.publisher.id)
        || manifest.name.is_empty()
        || manifest.name.len() > 128
        || Version::parse(&manifest.version).is_err()
        || !VersionReq::parse(&manifest.host_api)
            .map_err(|_| invalid("hostApi 不是有效的版本范围"))?
            .matches(&Version::parse(HOST_API_VERSION).map_err(|_| invalid("宿主 API 版本无效"))?)
    {
        return Err(invalid("清单版本、标识或宿主 API 不兼容"));
    }
    if manifest.ui.kind != "declarative"
        || !manifest.files.contains_key(&manifest.ui.file)
        || manifest.platforms.is_empty()
        || !matches!(manifest.kind.as_str(), "feature" | "runtime")
        || (manifest.kind == "feature" && manifest.contributions.is_empty())
        || (manifest.kind == "runtime" && !manifest.contributions.is_empty())
    {
        return Err(invalid("插件缺少声明式界面、平台或功能入口"));
    }
    for platform in &manifest.platforms {
        if !valid_relative_path(&platform.entry) || !manifest.files.contains_key(&platform.entry) {
            return Err(invalid("平台可执行文件未列入文件摘要"));
        }
        if platform.os == "windows" && !platform.entry.to_ascii_lowercase().ends_with(".exe") {
            return Err(invalid("Windows 平台入口必须是 EXE"));
        }
    }
    let mut contributions = HashSet::new();
    for contribution in &manifest.contributions {
        if !valid_id(&contribution.id)
            || !contributions.insert(&contribution.id)
            || contribution.title.is_empty()
            || contribution.action.is_empty()
            || contribution.view.is_empty()
        {
            return Err(invalid("功能入口标识或动作无效"));
        }
    }
    for dependency in &manifest.dependencies {
        if !valid_id(&dependency.id)
            || dependency.id == manifest.id
            || VersionReq::parse(&dependency.version).is_err()
        {
            return Err(invalid("插件依赖无效"));
        }
    }
    for (name, hash) in &manifest.files {
        if !valid_relative_path(name)
            || name == "manifest.json"
            || name == "publisher.pub"
            || name == "signature.ed25519"
            || hash.len() != 71
            || !hash.starts_with("sha256:")
            || !hash[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("文件路径或 SHA-256 声明无效"));
        }
    }
    Ok(())
}

pub(crate) fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && !value.contains(['\\', ':', '\0'])
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with('.')
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                && !is_windows_device_name(part)
        })
}

fn is_windows_device_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

pub(crate) fn valid_id(value: &str) -> bool {
    value.len() <= 128
        && value.split('.').count() >= 2
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                })
        })
}

fn read_small<R: Read + Seek>(archive: &mut ZipArchive<R>, name: &str, limit: u64) -> Result<Vec<u8>> {
    let mut entry = archive.by_name(name)?;
    if entry.size() > limit {
        return Err(invalid("插件元数据超出大小限制"));
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn decode_fixed<const N: usize>(raw: &[u8], name: &str) -> Result<[u8; N]> {
    let value = std::str::from_utf8(raw).map_err(|_| invalid(&format!("{name}不是 UTF-8")))?;
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| invalid(&format!("{name}不是 Base64")))?
        .try_into()
        .map_err(|_| invalid(&format!("{name}长度无效")))
}

fn hash_reader(reader: &mut impl Read, limit: u64) -> Result<(String, u64)> {
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > limit {
            return Err(invalid("文件超出大小限制"));
        }
        hash.update(&buffer[..count]);
    }
    Ok((format!("{:x}", hash.finalize()), total))
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn invalid(message: &str) -> PluginError {
    PluginError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Contribution, Publisher, Ui};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn package(path: &Path, broken_signature: bool, file_picker: bool) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let executable = b"test executable";
        let ui: &[u8] = if file_picker {
            br#"{"schemaVersion":1,"views":[{"id":"main","title":"Sample","components":[{"type":"input","id":"path","label":"File","inputType":"file","required":true}]}]}"#
        } else {
            br#"{"schemaVersion":1,"views":[{"id":"main","title":"Sample","components":[{"type":"text","text":"demo"},{"type":"output","title":"Result"}]}]}"#
        };
        let mut files = BTreeMap::new();
        files.insert("bin/sample.exe".into(), format!("sha256:{}", hex_digest(executable)));
        files.insert("ui.json".into(), format!("sha256:{}", hex_digest(ui)));
        let manifest = Manifest {
            schema_version: 1,
            kind: "feature".into(),
            id: "org.streamscope.sample".into(),
            name: "Sample".into(),
            version: "1.0.0".into(),
            publisher: Publisher { id: "org.streamscope".into(), key_fingerprint: format!("sha256:{}", hex_digest(&key.verifying_key().to_bytes())) },
            host_api: "^1.0".into(),
            platforms: vec![crate::Platform { os: std::env::consts::OS.into(), arch: std::env::consts::ARCH.into(), entry: "bin/sample.exe".into() }],
            contributions: vec![Contribution { id: "org.streamscope.sample.scan".into(), title: "Scan".into(), kind: "analysis".into(), action: "scan".into(), input_types: vec!["file".into()], view: "main".into() }],
            ui: Ui { kind: "declarative".into(), file: "ui.json".into() },
            permissions: vec![], dependencies: vec![], files,
            description: None, license: None,
        };
        let manifest = serde_json::to_vec(&manifest).unwrap();
        let mut signature = key.sign(&manifest).to_bytes();
        if broken_signature { signature[0] ^= 1; }
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, bytes) in [
            ("manifest.json", manifest.as_slice()),
            ("publisher.pub", base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()).as_bytes()),
        ] {
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.start_file("signature.ed25519", SimpleFileOptions::default()).unwrap();
        zip.write_all(base64::engine::general_purpose::STANDARD.encode(signature).as_bytes()).unwrap();
        zip.start_file("bin/sample.exe", SimpleFileOptions::default()).unwrap();
        zip.write_all(executable).unwrap();
        zip.start_file("ui.json", SimpleFileOptions::default()).unwrap();
        zip.write_all(ui).unwrap();
        zip.finish().unwrap();
    }

    #[test]
    fn rejects_path_escape_and_windows_device_names() {
        for name in ["../outside", "a/../outside", "C:/outside", "a\\b", "CON.txt", "a/com1.exe", "a//b", "a/b."] {
            assert!(!valid_relative_path(name), "{name}");
        }
    }

    #[test]
    fn verifies_signature_and_installs_exact_previewed_package() {
        let root = std::env::temp_dir().join(format!("streamscope-plugin-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let good = root.join("good.ssp");
        let bad = root.join("bad.ssp");
        package(&good, false, false);
        package(&bad, true, false);
        assert!(verify_package(&bad).is_err());
        let store = crate::PluginStore::new(root.join("plugins"));
        let preview = store.preview(&good).unwrap();
        assert!(store.install(&good, "wrong", &preview.fingerprint).is_err());
        let occupied = root.join("plugins/org.streamscope.sample/1.0.0");
        std::fs::create_dir_all(&occupied).unwrap();
        assert!(store.install(&good, &preview.package_sha256, &preview.fingerprint).is_err());
        assert!(store.list().unwrap().is_empty());
        std::fs::remove_dir(&occupied).unwrap();
        let installed = store.install(&good, &preview.package_sha256, &preview.fingerprint).unwrap();
        assert_eq!(installed.manifest.id, "org.streamscope.sample");
        assert!(store.executable(&installed.manifest.id).unwrap().is_file());
        assert!(store.preview(&good).unwrap_err().to_string().contains("更高版本"));
        store.uninstall(&installed.manifest.id).unwrap();
        assert!(store.list().unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_file_picker_without_declared_file_permission() {
        let root = std::env::temp_dir().join(format!("streamscope-plugin-permission-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("file-picker.ssp");
        package(&path, false, true);
        assert!(verify_package(&path).unwrap_err().to_string().contains("file-read"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

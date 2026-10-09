use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use streamscope_plugin_host::{Manifest, verify_package};
use zip::write::SimpleFileOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("用法: plugin-pack <manifest-template.json> <payload-dir> <base64-key-file> <output.ssp>".into());
    }
    let template = PathBuf::from(&args[0]);
    let payload = PathBuf::from(&args[1]);
    let key_file = PathBuf::from(&args[2]);
    let output = PathBuf::from(&args[3]);
    let key_text = fs::read_to_string(key_file)?;
    let key_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(key_text.trim())?.try_into().map_err(|_| "签名私钥必须是 32 字节 seed 的 Base64")?;
    let key = SigningKey::from_bytes(&key_bytes);
    let mut manifest: Manifest = serde_json::from_slice(&fs::read(template)?)?;
    manifest.publisher.key_fingerprint = format!("sha256:{:x}", Sha256::digest(key.verifying_key().to_bytes()));
    manifest.files.clear();
    let mut files = Vec::new();
    collect_files(&payload, &payload, &mut files)?;
    for (name, path) in &files {
        let mut source = File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 { break; }
            hash.update(&buffer[..count]);
        }
        manifest.files.insert(name.clone(), format!("sha256:{:x}", hash.finalize()));
    }
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    let signature = key.sign(&bytes);
    if let Some(parent) = output.parent() { fs::create_dir_all(parent)?; }
    let mut writer = zip::ZipWriter::new(File::create(&output)?);
    let options = SimpleFileOptions::default();
    for (name, content) in [
        ("manifest.json", bytes),
        ("publisher.pub", base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes()).into_bytes()),
        ("signature.ed25519", base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()).into_bytes()),
    ] {
        writer.start_file(name, options)?;
        writer.write_all(&content)?;
    }
    for (name, path) in files {
        writer.start_file(name, options)?;
        std::io::copy(&mut File::open(path)?, &mut writer)?;
    }
    writer.finish()?;
    let verified = verify_package(&output)?;
    println!("包已验证：{} {} ({})", verified.manifest.id, verified.manifest.version, verified.package_sha256);
    Ok(())
}

fn collect_files(base: &Path, path: &Path, output: &mut Vec<(String, PathBuf)>) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() { return Err("payload 不允许符号链接".into()); }
        if kind.is_dir() {
            collect_files(base, &entry.path(), output)?;
        } else if kind.is_file() {
            let relative = entry.path().strip_prefix(base)?.to_string_lossy().replace('\\', "/");
            output.push((relative, entry.path()));
        }
    }
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(())
}

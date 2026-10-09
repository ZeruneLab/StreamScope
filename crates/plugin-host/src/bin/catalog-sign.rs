use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 { return Err("用法: catalog-sign <catalog.json> <base64-key-file>".into()); }
    let bytes = fs::read(&args[0])?;
    let key_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(fs::read_to_string(&args[1])?.trim())?
        .try_into().map_err(|_| "签名私钥必须是 32 字节 seed 的 Base64")?;
    let signature = SigningKey::from_bytes(&key_bytes).sign(&bytes);
    fs::write(format!("{}.sig", args[0]), base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))?;
    println!("目录签名已写入 {}.sig", args[0]);
    Ok(())
}

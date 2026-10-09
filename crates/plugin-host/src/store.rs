use crate::{Manifest, PackagePreview, PluginError, Result, UiDocument, VerifiedPackage, verify_package};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledPlugin {
    pub manifest: Manifest,
    pub fingerprint: String,
    pub enabled: bool,
}

pub struct PluginStore {
    root: PathBuf,
}

impl PluginStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn preview(&self, package: &Path) -> Result<PackagePreview> {
        let verified = verify_package(package)?;
        check_upgrade(&verified, &self.list()?)?;
        Ok(PackagePreview::from(&verified))
    }

    pub fn list(&self) -> Result<Vec<InstalledPlugin>> {
        let index = self.root.join("registry.json");
        let backup = self.root.join("registry.backup.json");
        if !index.exists() && backup.exists() {
            fs::rename(&backup, &index)?;
        }
        if !index.exists() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_reader(File::open(index)?)?)
    }

    /// Consent binds the exact previewed package and publisher key, not a mutable file name.
    pub fn install(&self, package: &Path, accepted_sha256: &str, accepted_fingerprint: &str) -> Result<InstalledPlugin> {
        let verified = verify_package(package)?;
        if verified.package_sha256 != accepted_sha256 || verified.fingerprint != accepted_fingerprint {
            return Err(invalid("插件包或发布者在确认后发生变化"));
        }
        let mut installed = self.list()?;
        check_upgrade(&verified, &installed)?;
        check_dependencies(&verified.manifest, &installed)?;
        check_cycles(&verified.manifest, &installed)?;
        fs::create_dir_all(&self.root)?;
        let stage = self.root.join(format!(".stage-{}", Uuid::new_v4()));
        fs::create_dir(&stage)?;
        let outcome = self.install_staged(&verified, &stage, &mut installed);
        if stage.exists() {
            let _ = fs::remove_dir_all(&stage);
        }
        outcome
    }

    fn install_staged(&self, verified: &VerifiedPackage, stage: &Path, installed: &mut Vec<InstalledPlugin>) -> Result<InstalledPlugin> {
        let mut archive = ZipArchive::new(File::open(&verified.path)?)?;
        for name in verified.manifest.files.keys() {
            let mut source = archive.by_name(name)?;
            let destination = stage.join(name);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut output = File::create(&destination)?;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 { break; }
                hash.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
            }
            output.flush()?;
            if format!("sha256:{:x}", hash.finalize()) != verified.manifest.files[name] {
                return Err(invalid("安装时插件包文件发生变化"));
            }
        }
        let directory = self.root.join(&verified.manifest.id).join(&verified.manifest.version);
        if directory.exists() {
            return Err(invalid("目标版本目录已经存在"));
        }
        fs::create_dir_all(directory.parent().ok_or_else(|| invalid("插件目录无效"))?)?;
        fs::rename(stage, &directory)?;
        let entry = InstalledPlugin {
            manifest: verified.manifest.clone(),
            fingerprint: verified.fingerprint.clone(),
            enabled: true,
        };
        installed.retain(|item| item.manifest.id != entry.manifest.id);
        installed.push(entry.clone());
        if let Err(error) = self.save(installed) {
            let _ = fs::remove_dir_all(&directory);
            return Err(error);
        }
        Ok(entry)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let mut installed = self.list()?;
        if !enabled && installed.iter().any(|item| item.enabled && item.manifest.dependencies.iter().any(|dependency| dependency.id == id)) {
            return Err(invalid("其他已启用插件仍依赖此插件"));
        }
        let manifest = installed.iter().find(|item| item.manifest.id == id)
            .ok_or_else(|| invalid("插件未安装"))?.manifest.clone();
        if enabled { check_dependencies(&manifest, &installed)?; }
        let item = installed.iter_mut().find(|item| item.manifest.id == id)
            .ok_or_else(|| invalid("插件未安装"))?;
        item.enabled = enabled;
        self.save(&installed)
    }

    pub fn uninstall(&self, id: &str) -> Result<()> {
        if !crate::package::valid_id(id) { return Err(invalid("插件标识无效")); }
        let mut installed = self.list()?;
        if installed.iter().any(|item| item.manifest.dependencies.iter().any(|dependency| dependency.id == id)) {
            return Err(invalid("其他插件仍依赖此插件"));
        }
        let item = installed.iter().find(|item| item.manifest.id == id)
            .ok_or_else(|| invalid("插件未安装"))?;
        Version::parse(&item.manifest.version).map_err(|_| invalid("插件版本无效"))?;
        let plugin_directory = self.root.join(id);
        let canonical_root = self.root.canonicalize()?;
        let canonical_plugin = plugin_directory.canonicalize()?;
        if canonical_plugin.parent() != Some(canonical_root.as_path()) {
            return Err(invalid("插件目录不在预期的安装根目录中"));
        }
        let tombstone = self.root.join(format!(".uninstall-{}", Uuid::new_v4()));
        fs::rename(&plugin_directory, &tombstone)?;
        installed.retain(|item| item.manifest.id != id);
        if let Err(error) = self.save(&installed) {
            let _ = fs::rename(&tombstone, &plugin_directory);
            return Err(error);
        }
        fs::remove_dir_all(tombstone)?;
        Ok(())
    }

    pub fn executable(&self, id: &str) -> Result<PathBuf> {
        let item = self.list()?.into_iter().find(|item| item.manifest.id == id && item.enabled)
            .ok_or_else(|| invalid("插件未安装或已禁用"))?;
        if item.manifest.kind != "feature" { return Err(invalid("运行时包不是可执行功能插件")); }
        let platform = item.manifest.platforms.iter().find(|platform| {
            platform.os == std::env::consts::OS && platform.arch == std::env::consts::ARCH
        }).ok_or_else(|| invalid("插件平台不匹配"))?;
        self.verified_installed_file(&item, &platform.entry)
    }

    pub fn ui_document(&self, id: &str) -> Result<UiDocument> {
        let item = self.list()?.into_iter().find(|item| item.manifest.id == id && item.enabled)
            .ok_or_else(|| invalid("插件未安装或已禁用"))?;
        if item.manifest.kind != "feature" { return Err(invalid("运行时包没有功能界面")); }
        let path = self.verified_installed_file(&item, &item.manifest.ui.file)?;
        let bytes = fs::read(path)?;
        if bytes.len() > 256 * 1024 { return Err(invalid("声明式界面超出大小限制")); }
        let ui: UiDocument = serde_json::from_slice(&bytes)?;
        ui.validate()?;
        Ok(ui)
    }

    pub fn runtime_file(&self, id: &str, name: &str) -> Result<PathBuf> {
        let item = self.list()?.into_iter().find(|item| item.manifest.id == id && item.enabled)
            .ok_or_else(|| invalid("运行时包未安装或已禁用"))?;
        if item.manifest.kind != "runtime" { return Err(invalid("依赖不是共享运行时包")); }
        self.verified_installed_file(&item, name)
    }

    fn verified_installed_file(&self, item: &InstalledPlugin, name: &str) -> Result<PathBuf> {
        if !crate::package::valid_id(&item.manifest.id)
            || Version::parse(&item.manifest.version).is_err()
            || !crate::package::valid_relative_path(name) {
            return Err(invalid("已安装插件路径无效"));
        }
        let expected = item.manifest.files.get(name).ok_or_else(|| invalid("插件文件未列入清单"))?;
        let path = self.root.join(&item.manifest.id).join(&item.manifest.version).join(name);
        let mut file = File::open(&path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            hash.update(&buffer[..count]);
        }
        if format!("sha256:{:x}", hash.finalize()) != *expected {
            return Err(invalid("已安装插件文件摘要不一致"));
        }
        Ok(path)
    }

    fn save(&self, installed: &[InstalledPlugin]) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        let temp = self.root.join(format!(".registry-{}.tmp", Uuid::new_v4()));
        let result = (|| {
            let mut file = File::create(&temp)?;
            file.write_all(&serde_json::to_vec_pretty(installed)?)?;
            file.sync_all()?;
            #[cfg(windows)]
            if self.root.join("registry.json").exists() {
                // Windows rename cannot replace an existing file. Keep the old index until
                // the new one is durable; restore it if the final rename fails.
                let backup = self.root.join("registry.backup.json");
                if backup.exists() { fs::remove_file(&backup)?; }
                fs::rename(self.root.join("registry.json"), &backup)?;
                if let Err(error) = fs::rename(&temp, self.root.join("registry.json")) {
                    let _ = fs::rename(&backup, self.root.join("registry.json"));
                    return Err(error.into());
                }
                let _ = fs::remove_file(backup);
                return Ok(());
            }
            fs::rename(&temp, self.root.join("registry.json"))?;
            Ok(())
        })();
        if temp.exists() {
            let _ = fs::remove_file(temp);
        }
        result
    }
}

fn check_upgrade(verified: &VerifiedPackage, installed: &[InstalledPlugin]) -> Result<()> {
    if let Some(previous) = installed.iter().find(|item| item.manifest.id == verified.manifest.id) {
        if previous.fingerprint != verified.fingerprint {
            return Err(invalid("发布者密钥已更换；请先手动移除旧插件并再次确认风险"));
        }
        let old = Version::parse(&previous.manifest.version).map_err(|_| invalid("已安装插件版本无效"))?;
        let new = Version::parse(&verified.manifest.version).map_err(|_| invalid("插件版本无效"))?;
        if new <= old { return Err(invalid("只能安装更高版本；降级须先卸载")); }
    }
    check_dependents(&verified.manifest, installed)
}

fn check_dependencies(manifest: &Manifest, installed: &[InstalledPlugin]) -> Result<()> {
    for dependency in &manifest.dependencies {
        let item = installed.iter().find(|item| item.manifest.id == dependency.id && item.enabled)
            .ok_or_else(|| invalid(&format!("缺少已启用依赖：{}", dependency.id)))?;
        let requirement = VersionReq::parse(&dependency.version).map_err(|_| invalid("依赖版本范围无效"))?;
        let version = Version::parse(&item.manifest.version).map_err(|_| invalid("已安装依赖版本无效"))?;
        if !requirement.matches(&version) {
            return Err(invalid(&format!("依赖版本不兼容：{}", dependency.id)));
        }
    }
    Ok(())
}

fn check_cycles(manifest: &Manifest, installed: &[InstalledPlugin]) -> Result<()> {
    fn visit(id: &str, manifest: &Manifest, installed: &[InstalledPlugin], active: &mut HashSet<String>, done: &mut HashSet<String>) -> Result<()> {
        if done.contains(id) { return Ok(()); }
        if !active.insert(id.to_owned()) { return Err(invalid("插件依赖存在循环")); }
        let dependencies = if id == manifest.id {
            &manifest.dependencies
        } else {
            &installed.iter().find(|item| item.manifest.id == id)
                .ok_or_else(|| invalid("插件依赖缺失"))?.manifest.dependencies
        };
        for dependency in dependencies {
            visit(&dependency.id, manifest, installed, active, done)?;
        }
        active.remove(id);
        done.insert(id.to_owned());
        Ok(())
    }
    visit(&manifest.id, manifest, installed, &mut HashSet::new(), &mut HashSet::new())
}

fn check_dependents(manifest: &Manifest, installed: &[InstalledPlugin]) -> Result<()> {
    for item in installed.iter().filter(|item| item.manifest.id != manifest.id) {
        for dependency in item.manifest.dependencies.iter().filter(|dependency| dependency.id == manifest.id) {
            if !crate::version_satisfies(&manifest.version, &[dependency.version.clone()])? {
                return Err(invalid(&format!("升级 {} 会使已安装的 {} 依赖不兼容 ({})", manifest.id, item.manifest.id, dependency.version)));
            }
        }
    }
    Ok(())
}

fn invalid(message: &str) -> PluginError {
    PluginError::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Contribution, Dependency, Publisher, Ui};
    use std::collections::BTreeMap;

    fn manifest(id: &str, dependency: Option<&str>) -> Manifest {
        Manifest {
            schema_version: 1, kind: "feature".into(), id: id.into(), name: id.into(), version: "1.0.0".into(),
            publisher: Publisher { id: "org.example".into(), key_fingerprint: String::new() },
            host_api: "^1".into(), platforms: vec![],
            contributions: vec![Contribution { id: format!("{id}.run"), title: "run".into(), kind: "analysis".into(), action: "run".into(), input_types: vec![], view: "main".into() }],
            ui: Ui { kind: "declarative".into(), file: "ui.json".into() },
            permissions: vec![],
            dependencies: dependency.map(|id| vec![Dependency { id: id.into(), version: "^1".into() }]).unwrap_or_default(),
            files: BTreeMap::new(), description: None, license: None,
        }
    }

    #[test]
    fn rejects_dependency_cycle_during_upgrade() {
        let a = manifest("org.example.a", Some("org.example.b"));
        let b = manifest("org.example.b", Some("org.example.a"));
        let installed = vec![InstalledPlugin { manifest: b, fingerprint: String::new(), enabled: true }];
        assert!(check_cycles(&a, &installed).is_err());
    }

    #[test]
    fn upgrade_cannot_break_existing_dependents_even_when_disabled() {
        let mut runtime = manifest("org.example.runtime", None);
        let consumer = InstalledPlugin { manifest: manifest("org.example.consumer", Some("org.example.runtime")),
            fingerprint: String::new(), enabled: false };
        runtime.version = "1.2.0".into();
        assert!(check_dependents(&runtime, &[consumer.clone()]).is_ok());
        runtime.version = "2.0.0".into();
        assert!(check_dependents(&runtime, &[consumer]).is_err());
    }

    #[test]
    fn recovers_interrupted_registry_switch() {
        let root = std::env::temp_dir().join(format!("streamscope-registry-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("registry.backup.json"), b"[]").unwrap();
        let store = PluginStore::new(root.clone());
        assert!(store.list().unwrap().is_empty());
        assert!(root.join("registry.json").exists());
        fs::remove_dir_all(root).unwrap();
    }
}

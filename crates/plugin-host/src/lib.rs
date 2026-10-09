mod ipc;
mod artifact;
mod catalog;
mod manifest;
mod package;
mod report;
mod store;
mod ui;
mod workflow;

pub use ipc::{PluginCancelHandle, PluginEvent, PluginProcess, PluginRequest, read_frame, serve, serve_with_progress, write_frame};
pub use artifact::{ArtifactStore, TaskArtifact, stage_file_inputs, stage_file_inputs_with_progress, stage_file_inputs_with_progress_and_cancel, stage_linked_file_inputs, stage_media_outputs};
pub use workflow::{WorkflowAction, attach_report_workflows, workflow_action, linked_references, validate_media_input};
pub use catalog::{Catalog, CatalogEntry, fetch_signed_catalog, download_catalog_package, verify_catalog, version_satisfies};
pub use manifest::{Contribution, Dependency, Manifest, Permission, Platform, Publisher, Ui};
pub use package::{PackagePreview, VerifiedPackage, verify_package};
pub use report::{ArtifactReference, PluginReportV2, VersionedPluginResult, list_plugin_reports, list_all_plugin_reports, load_plugin_report, save_plugin_report, save_plugin_report_with_artifacts};
pub use store::{InstalledPlugin, PluginStore};
pub use ui::{UiComponent, UiDocument, UiView};

use thiserror::Error;

pub const HOST_API_VERSION: &str = "1.2.0";

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("I/O 错误：{0}")]
    Io(#[from] std::io::Error),
    #[error("插件包格式错误：{0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("JSON 格式错误：{0}")]
    Json(#[from] serde_json::Error),
    #[error("网络错误：{0}")]
    Http(#[from] reqwest::Error),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, PluginError>;

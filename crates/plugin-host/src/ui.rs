use crate::{PluginError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiDocument {
    pub schema_version: u32,
    pub views: Vec<UiView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UiView {
    pub id: String,
    pub title: String,
    pub components: Vec<UiComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum UiComponent {
    Text { text: String },
    Input { id: String, label: String, #[serde(rename = "inputType")] input_type: String, required: bool },
    Select { id: String, label: String, options: Vec<String>, required: bool },
    Output { title: String },
}

impl UiDocument {
    pub fn uses_file_input(&self) -> bool {
        self.views.iter().flat_map(|view| &view.components).any(|component| {
            matches!(component, UiComponent::Input { input_type, .. } if input_type == "file")
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.views.is_empty() || self.views.len() > 32 {
            return Err(invalid("声明式界面版本或视图数量无效"));
        }
        let mut views = HashSet::new();
        for view in &self.views {
            if view.id.is_empty() || view.title.is_empty() || !views.insert(&view.id) || view.components.len() > 100 {
                return Err(invalid("声明式界面视图无效"));
            }
            let mut fields = HashSet::new();
            for component in &view.components {
                match component {
                    UiComponent::Text { text } if text.len() <= 8_192 => {},
                    UiComponent::Input { id, label, input_type, .. }
                        if !id.is_empty() && !label.is_empty() && fields.insert(id)
                            && matches!(input_type.as_str(), "text" | "password" | "number" | "file" | "checkbox") => {},
                    UiComponent::Output { title } if !title.is_empty() => {},
                    UiComponent::Select { id, label, options, .. }
                        if !id.is_empty() && !label.is_empty() && fields.insert(id)
                            && !options.is_empty() && options.len() <= 100
                            && options.iter().all(|value| !value.is_empty() && value.len() <= 256)
                            && options.iter().collect::<HashSet<_>>().len() == options.len() => {},
                    _ => return Err(invalid("声明式界面组件无效或不受支持")),
                }
            }
        }
        Ok(())
    }
}

fn invalid(message: &str) -> PluginError { PluginError::Invalid(message.into()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_file_picker_for_permission_check() {
        let document = UiDocument {
            schema_version: 1,
            views: vec![UiView {
                id: "main".into(),
                title: "File".into(),
                components: vec![UiComponent::Input {
                    id: "path".into(), label: "Path".into(), input_type: "file".into(), required: true,
                }],
            }],
        };
        document.validate().unwrap();
        assert!(document.uses_file_input());
    }

    #[test]
    fn select_rejects_duplicate_options_and_field_ids() {
        let mut document = UiDocument { schema_version: 1, views: vec![UiView {
            id: "main".into(), title: "Export".into(), components: vec![UiComponent::Select {
                id: "format".into(), label: "Format".into(), options: vec!["wav".into(), "mp3".into()], required: true,
            }],
        }] };
        document.validate().unwrap();
        let duplicate = document.views[0].components[0].clone();
        document.views[0].components.push(duplicate);
        assert!(document.validate().is_err());
        document.views[0].components.pop();
        if let UiComponent::Select { options, .. } = &mut document.views[0].components[0] {
            options.push("wav".into());
        }
        assert!(document.validate().is_err());
    }
}

//! The folder-choice prompt and answer format shared by the generative
//! choosers (llama.cpp and OpenAI-compatible APIs).

use crate::engine::{Choice, FolderHint, LabelHint, Labeling};

pub fn system_prompt(folders: &[FolderHint]) -> String {
    let mut text = String::from(
        "You sort email into the user's existing folders. Choose the single folder the \
         message below belongs in, or null when none clearly fits. Answer with JSON: \
         {\"folder\": <name or null>, \"confidence\": <0.0-1.0>}.\n\nFolders:\n",
    );
    for folder in folders {
        text.push_str("- ");
        text.push_str(&folder.name);
        if !folder.examples.is_empty() {
            text.push_str(" (for example: ");
            text.push_str(&quoted_examples(folder));
            text.push(')');
        }
        text.push('\n');
    }
    text
}

/// A folder's example subjects, quoted and shortened, for prompts.
pub fn quoted_examples(folder: &FolderHint) -> String {
    folder
        .examples
        .iter()
        .map(|subject| format!("\"{}\"", subject.chars().take(80).collect::<String>()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg_attr(not(feature = "local-models"), allow(dead_code))]
pub fn json_escape(text: &str) -> String {
    serde_json::to_string(text)
        .map(|quoted| quoted[1..quoted.len() - 1].to_string())
        .unwrap_or_default()
}

/// Read a `{"folder", "confidence"}` answer. Names not in `folders` are
/// ignored; code fences or prose around the JSON are tolerated.
pub fn parse_answer(raw: &str, folders: &[FolderHint]) -> Choice {
    #[derive(serde::Deserialize)]
    struct Answer {
        folder: Option<String>,
        confidence: f64,
    }
    let parsed = json_object(raw).and_then(|json| serde_json::from_str::<Answer>(json).ok());
    let folder = parsed
        .as_ref()
        .and_then(|answer| answer.folder.clone())
        .filter(|name| folders.iter().any(|folder| &folder.name == name));
    Choice {
        confidence: if folder.is_some() {
            parsed
                .map(|answer| answer.confidence.clamp(0.0, 1.0))
                .unwrap_or(0.0)
        } else {
            0.0
        },
        folder,
        raw: raw.to_string(),
    }
}

pub fn label_prompt(labels: &[LabelHint], may_propose: bool) -> String {
    let mut text = String::from(
        "You tag email with labels. List every label below that applies to the message, each \
         with how sure you are, and leave out labels that do not apply.",
    );
    if may_propose {
        text.push_str(
            " If no label fits the message well, also propose one new label in \"new_label\": \
             a general, reusable category of one to three words (never a person, company or \
             detail of this one message) with a short description. Otherwise set \
             \"new_label\" to null. Answer with JSON: {\"labels\": [{\"name\": <label>, \
             \"confidence\": <0.0-1.0>}, ...], \"new_label\": null or {\"name\": <name>, \
             \"description\": <text>}}.",
        );
    } else {
        text.push_str(
            " Answer with JSON: {\"labels\": [{\"name\": <label>, \"confidence\": \
             <0.0-1.0>}, ...]}.",
        );
    }
    text.push_str("\n\nLabels:\n");
    for label in labels {
        text.push_str("- ");
        text.push_str(&label.name);
        if !label.description.is_empty() {
            text.push_str(": ");
            text.push_str(&label.description);
        }
        text.push('\n');
    }
    text
}

/// Read a `{"labels": [{"name", "confidence"}], "new_label": ...}` answer.
/// Names not in `labels` are ignored, as are repeats; a proposal is only
/// kept when `may_propose` and it is not an existing label.
pub fn parse_labels(raw: &str, labels: &[LabelHint], may_propose: bool) -> Labeling {
    #[derive(serde::Deserialize)]
    struct Item {
        name: String,
        #[serde(default)]
        confidence: Option<f64>,
    }
    #[derive(serde::Deserialize)]
    struct Proposal {
        name: String,
        #[serde(default)]
        description: String,
    }
    #[derive(serde::Deserialize)]
    struct Answer {
        #[serde(default)]
        labels: Vec<Item>,
        #[serde(default)]
        new_label: Option<Proposal>,
    }
    let Some(answer) = json_object(raw).and_then(|json| serde_json::from_str::<Answer>(json).ok())
    else {
        return Labeling::default();
    };
    let mut out: Vec<(String, f64)> = Vec::new();
    for item in answer.labels {
        if labels.iter().any(|label| label.name == item.name)
            && !out.iter().any(|(name, _)| name == &item.name)
        {
            out.push((item.name, item.confidence.unwrap_or(1.0).clamp(0.0, 1.0)));
        }
    }
    let proposed = answer
        .new_label
        .filter(|_| may_propose)
        .filter(|p| {
            !labels
                .iter()
                .any(|label| label.name.eq_ignore_ascii_case(p.name.trim()))
        })
        .map(|p| (p.name.trim().to_string(), p.description.trim().to_string()));
    Labeling {
        labels: out,
        proposed,
    }
}

/// The outermost `{...}` in `raw`, for models that wrap JSON in prose.
fn json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (start < end).then(|| &raw[start..=end])
}

#[cfg(test)]
pub(crate) fn label_hints(names: &[&str]) -> Vec<LabelHint> {
    names
        .iter()
        .map(|name| LabelHint {
            name: name.to_string(),
            description: format!("about {name}"),
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn hints(names: &[&str]) -> Vec<FolderHint> {
    names
        .iter()
        .map(|name| FolderHint {
            name: name.to_string(),
            examples: vec![],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_outside_the_folder_list_are_ignored() {
        let folders = hints(&["Receipts", "Travel"]);
        let choice = parse_answer(r#"{"folder": "Travel", "confidence": 0.8}"#, &folders);
        assert_eq!(choice.folder.as_deref(), Some("Travel"));
        assert_eq!(choice.confidence, 0.8);
        let invented = parse_answer(r#"{"folder": "Taxes", "confidence": 0.9}"#, &folders);
        assert_eq!(invented.folder, None);
        assert_eq!(invented.confidence, 0.0);
        assert_eq!(parse_answer("garbage", &folders).folder, None);
    }

    #[test]
    fn label_answers_keep_only_known_labels_once() {
        let labels = label_hints(&["Invoices", "Urgent"]);
        let parsed = parse_labels(
            r#"{"labels": [{"name": "Urgent", "confidence": 0.9}, {"name": "Spam", "confidence": 1}, {"name": "Urgent", "confidence": 0.1}, {"name": "Invoices"}]}"#,
            &labels,
            false,
        );
        assert_eq!(
            parsed.labels,
            vec![("Urgent".to_string(), 0.9), ("Invoices".to_string(), 1.0)]
        );
        assert!(parse_labels("nope", &labels, true).labels.is_empty());
        assert!(label_prompt(&labels, false).contains("- Invoices: about Invoices"));
        assert!(!label_prompt(&labels, false).contains("new_label"));
        assert!(label_prompt(&labels, true).contains("new_label"));
    }

    #[test]
    fn proposals_are_kept_only_when_allowed_and_new() {
        let labels = label_hints(&["Invoices"]);
        let raw =
            r#"{"labels": [], "new_label": {"name": " School ", "description": "Kids' school"}}"#;
        assert_eq!(
            parse_labels(raw, &labels, true).proposed,
            Some(("School".to_string(), "Kids' school".to_string()))
        );
        assert_eq!(parse_labels(raw, &labels, false).proposed, None);
        let existing = r#"{"labels": [], "new_label": {"name": "invoices", "description": ""}}"#;
        assert_eq!(parse_labels(existing, &labels, true).proposed, None);
        let none = r#"{"labels": [{"name": "Invoices", "confidence": 0.8}], "new_label": null}"#;
        assert_eq!(parse_labels(none, &labels, true).proposed, None);
    }

    #[test]
    fn answers_wrapped_in_fences_or_prose_are_read() {
        let folders = hints(&["Receipts", "Travel"]);
        let fenced = parse_answer(
            "```json\n{\"folder\": \"Travel\", \"confidence\": 0.7}\n```",
            &folders,
        );
        assert_eq!(fenced.folder.as_deref(), Some("Travel"));
        let prose = parse_answer(
            "Sure! {\"folder\": null, \"confidence\": 0.2} Hope that helps.",
            &folders,
        );
        assert_eq!(prose.folder, None);
    }
}

//! The folder-choice prompt and answer format shared by the generative
//! choosers (llama.cpp and OpenAI-compatible APIs).

use crate::engine::{Choice, FolderHint};

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

/// The outermost `{...}` in `raw`, for models that wrap JSON in prose.
fn json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (start < end).then(|| &raw[start..=end])
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

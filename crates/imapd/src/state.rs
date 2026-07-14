use std::collections::BTreeSet;

#[derive(Default)]
pub(crate) struct SessionState {
    pub(crate) authenticated_mailbox: Option<String>,
    pub(crate) selected_mailbox: Option<String>,
    enabled_features: BTreeSet<String>,
    saved_search_uids: Vec<u64>,
}

impl SessionState {
    pub(crate) fn enable_feature(&mut self, feature: &str) -> bool {
        let feature = feature.to_ascii_uppercase();
        if supported_enable_feature(&feature) {
            if feature == "QRESYNC" {
                self.enabled_features.insert("CONDSTORE".to_string());
            }
            self.enabled_features.insert(feature);
            true
        } else {
            false
        }
    }

    pub(crate) fn feature_enabled(&self, feature: &str) -> bool {
        self.enabled_features
            .contains(&feature.to_ascii_uppercase())
    }

    pub(crate) fn utf8_enabled(&self) -> bool {
        self.feature_enabled("UTF8=ACCEPT") || self.feature_enabled("IMAP4REV2")
    }

    pub(crate) fn saved_search_uids(&self) -> &[u64] {
        &self.saved_search_uids
    }

    pub(crate) fn save_search_uids(&mut self, mut uids: Vec<u64>) {
        uids.sort_unstable();
        uids.dedup();
        self.saved_search_uids = uids;
    }
}

fn supported_enable_feature(feature: &str) -> bool {
    matches!(
        feature,
        "IMAP4REV1" | "IMAP4REV2" | "CONDSTORE" | "QRESYNC" | "UTF8=ACCEPT"
    )
}

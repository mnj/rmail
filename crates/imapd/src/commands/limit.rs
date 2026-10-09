//! RFC 9738 MESSAGELIMIT: an optional cap on the messages one command
//! touches (`security.imap_message_limit`, off by default because clients
//! that do not know the extension would see partial results).

/// Keep the `limit` highest UIDs of the ascending `uids` (the RFC processes
/// messages from highest to lowest UID). Returns the response code to send
/// when messages were left out: `MESSAGELIMIT <limit> <lowest kept UID>`.
pub(crate) fn truncate(uids: &mut Vec<u64>, limit: Option<usize>) -> Option<String> {
    truncate_by(uids, limit, |uid| *uid)
}

/// [`truncate`] for items that carry a UID; keeps them in UID order.
pub(crate) fn truncate_by<T>(
    items: &mut Vec<T>,
    limit: Option<usize>,
    uid: impl Fn(&T) -> u64,
) -> Option<String> {
    let limit = limit?;
    if items.len() <= limit {
        return None;
    }
    items.sort_unstable_by_key(&uid);
    items.drain(..items.len() - limit);
    Some(format!("MESSAGELIMIT {limit} {}", uid(&items[0])))
}

/// The code for commands that must be refused rather than cut (COPY and
/// MULTIAPPEND are atomic), or `None` within the limit.
pub(crate) fn exceeded(count: usize, limit: Option<usize>) -> Option<String> {
    limit
        .filter(|limit| count > *limit)
        .map(|limit| format!("MESSAGELIMIT {limit}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_highest_uids_and_names_the_lowest_kept() {
        let mut uids = vec![9, 3, 7, 5, 1];
        assert_eq!(
            truncate(&mut uids, Some(3)).as_deref(),
            Some("MESSAGELIMIT 3 5")
        );
        assert_eq!(uids, [5, 7, 9]);
        let mut few = vec![1, 2];
        assert_eq!(truncate(&mut few, Some(3)), None);
        assert_eq!(truncate(&mut few, None), None);
        assert_eq!(exceeded(4, Some(3)).as_deref(), Some("MESSAGELIMIT 3"));
        assert_eq!(exceeded(3, Some(3)), None);
    }
}

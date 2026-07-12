use crate::response::{Response, Status, StatusLine};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectionEffect {
    Keep,
    Clear,
}

pub(crate) struct Outcome {
    pub(crate) response: Response,
    pub(crate) selection_effect: SelectionEffect,
}

pub(crate) fn check(tag: &str) -> Outcome {
    completed(tag, "CHECK", SelectionEffect::Keep)
}

pub(crate) fn unselect(tag: &str) -> Outcome {
    completed(tag, "UNSELECT", SelectionEffect::Clear)
}

fn completed(tag: &str, command: &str, selection_effect: SelectionEffect) -> Outcome {
    Outcome {
        response: Response::new().status(StatusLine::tagged(
            tag,
            Status::Ok,
            format!("{command} completed"),
        )),
        selection_effect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_keeps_and_unselect_clears_selection() {
        let check = check("A1");
        assert_eq!(check.selection_effect, SelectionEffect::Keep);
        assert_eq!(check.response.encode(), "A1 OK CHECK completed\r\n");

        let unselect = unselect("A2");
        assert_eq!(unselect.selection_effect, SelectionEffect::Clear);
        assert_eq!(unselect.response.encode(), "A2 OK UNSELECT completed\r\n");
    }
}

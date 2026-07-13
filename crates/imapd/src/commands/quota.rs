use crate::mailbox;
use crate::parser::{self, Command};
use crate::response::{Response, Status, StatusLine};
use std::path::Path;

pub(crate) fn handle(
    tag: &str,
    command: &Command,
    args: &str,
    mail_root: &str,
    address: &str,
    utf8_accept: bool,
) -> Response {
    if matches!(command, Command::SetQuota) {
        return Response::new().status(
            StatusLine::tagged(
                tag,
                Status::No,
                "Quota changes require administrator access",
            )
            .with_code("NOPERM"),
        );
    }
    let Ok(arguments) = parser::parse_imap_args(args) else {
        return bad(tag, "Invalid quota arguments");
    };
    let [argument] = arguments.as_slice() else {
        return bad(tag, "Invalid quota arguments");
    };
    let Some(argument) = argument.as_text() else {
        return bad(tag, "Invalid quota arguments");
    };
    let Ok((local, domain)) = mailbox::address_parts(address) else {
        return unavailable(tag, "Invalid authenticated mailbox");
    };
    let quota = match rmail_common::imap_state::storage_quota(Path::new(mail_root), &domain, &local)
    {
        Ok(quota) => quota,
        Err(error) => return unavailable(tag, &error.to_string()),
    };
    let quota_line = quota_response(quota);
    match command {
        Command::GetQuota => {
            if !argument.is_empty() {
                return Response::new().status(StatusLine::tagged(
                    tag,
                    Status::No,
                    "No such quota root",
                ));
            }
            Response::new().data(quota_line).status(StatusLine::tagged(
                tag,
                Status::Ok,
                "GETQUOTA completed",
            ))
        }
        Command::GetQuotaRoot => {
            let mailbox_name = match mailbox::decode_wire_mailbox_name(argument, utf8_accept) {
                Ok(name) => name,
                Err(_) => return bad(tag, "Invalid mailbox name"),
            };
            match rmail_common::imap_state::folder_exists(
                Path::new(mail_root),
                &domain,
                &local,
                &mailbox_name,
            ) {
                Ok(true) => Response::new()
                    .data(format!(
                        "QUOTAROOT {} \"\"",
                        mailbox::quote_wire_mailbox_name(&mailbox_name, utf8_accept)
                    ))
                    .data(quota_line)
                    .status(StatusLine::tagged(
                        tag,
                        Status::Ok,
                        "GETQUOTAROOT completed",
                    )),
                Ok(false) => Response::new().status(StatusLine::tagged(
                    tag,
                    Status::No,
                    "Mailbox does not exist",
                )),
                Err(error) => unavailable(tag, &error.to_string()),
            }
        }
        _ => bad(tag, "Invalid quota command"),
    }
}

fn quota_response((used, limit): (u64, Option<u64>)) -> String {
    match limit {
        Some(limit) => format!(
            "QUOTA \"\" (STORAGE {} {})",
            used.div_ceil(1024),
            limit.div_ceil(1024)
        ),
        None => "QUOTA \"\" ()".to_string(),
    }
}

fn bad(tag: &str, message: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::Bad, message))
}

fn unavailable(tag: &str, message: &str) -> Response {
    Response::new().status(StatusLine::tagged(tag, Status::No, message).with_code("UNAVAILABLE"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_response_uses_1024_octet_units_and_reports_unlimited_roots() {
        assert_eq!(
            quota_response((1025, Some(4096))),
            "QUOTA \"\" (STORAGE 2 4)"
        );
        assert_eq!(quota_response((0, None)), "QUOTA \"\" ()");
    }
}

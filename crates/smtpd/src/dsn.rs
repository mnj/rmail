//! Delivery status notifications for local deliveries (RFC 3461 SUCCESS).

use rmail_common::tracking::new_tracking_id;

/// Queue a success DSN to the original sender when the recipient asked for one.
pub(crate) fn queue_local_success_notification(
    mail_root: &std::path::Path,
    original_sender: &str,
    final_recipient: &str,
    dsn: &rmail_common::outbound::DsnOptions,
) -> anyhow::Result<()> {
    let requested = dsn
        .notify
        .as_ref()
        .is_some_and(|notify| notify.success && !notify.never);
    if !requested {
        return Ok(());
    }
    let boundary = new_tracking_id("dsn");
    let date = chrono::Utc::now().to_rfc2822();
    let envelope_id = dsn
        .envelope_id
        .as_deref()
        .map(|value| format!("Original-Envelope-Id: {}\r\n", dsn_header_value(value)))
        .unwrap_or_default();
    let original_recipient = dsn
        .original_recipient
        .as_ref()
        .map(|(address_type, address)| {
            format!(
                "Original-Recipient: {}; {}\r\n",
                dsn_header_value(address_type),
                dsn_header_value(address)
            )
        })
        .unwrap_or_default();
    let sender = dsn_header_value(original_sender);
    let recipient = dsn_header_value(final_recipient);
    // RFC 3464 §2.2.2: the reporting MTA's own name.
    let reporting_mta = dsn_header_value(crate::server_hostname());
    let notification = format!(
        "From: Mail Delivery Subsystem <MAILER-DAEMON@{reporting_mta}>\r\n\
         To: <{sender}>\r\n\
         Subject: Delivery Status Notification (Success)\r\n\
         Date: {date}\r\n\
         Auto-Submitted: auto-replied\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         Delivery to <{recipient}> was successful.\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; {reporting_mta}\r\n\
         {envelope_id}\
         Arrival-Date: {date}\r\n\
         \r\n\
         {original_recipient}\
         Final-Recipient: rfc822; {recipient}\r\n\
         Action: delivered\r\n\
         Status: 2.0.0\r\n\
         \r\n\
         --{boundary}--\r\n"
    );
    rmail_common::outbound::queue_outbound(
        mail_root,
        original_sender,
        notification.as_bytes(),
        None,
    )?;
    Ok(())
}

fn dsn_header_value(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character == '\r' || character == '\n' || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(900)
        .collect::<String>()
        .trim()
        .to_string()
}

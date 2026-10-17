//! The Notes folder over ActiveSync (see `crate::notes`): one folder of
//! the account's notes, known to the device by their stable note ids.

use rusqlite::Connection;

use super::commands::Account;
use super::pim::email_time;
use super::state::{self, Items};
use super::wbxml::Element;
use crate::notes::{self, Note};

/// The folder's ServerId.
pub(super) const ID: &str = "notes";

pub(super) fn is_notes(id: &str) -> bool {
    id == ID
}

fn all(account: &Account) -> anyhow::Result<Vec<Note>> {
    notes::list(
        &account.state.mail_root,
        &account.user.domain,
        &account.user.localpart,
    )
}

fn note_data(note: &Note) -> Element {
    Element::new("AirSync:ApplicationData")
        .with(Element::text("Notes:Subject", note.title.clone()))
        .with(
            Element::new("AirSyncBase:Body")
                .with(Element::text("AirSyncBase:Type", "1"))
                .with(Element::text(
                    "AirSyncBase:EstimatedDataSize",
                    note.text.len().to_string(),
                ))
                .with(Element::text(
                    "AirSyncBase:Data",
                    note.text.replace('\n', "\r\n"),
                )),
        )
        .with(Element::text("Notes:MessageClass", "IPM.StickyNote"))
        .with(Element::text(
            "Notes:LastModifiedDate",
            email_time(note.modified),
        ))
}

/// A device's note as text: the body, with the subject as its first line
/// when the body does not start with it.
fn text_of(data: &Element) -> String {
    let subject = data
        .value("Notes:Subject")
        .unwrap_or_default()
        .trim()
        .to_string();
    let body = data
        .child("AirSyncBase:Body")
        .and_then(|b| b.value("AirSyncBase:Data"))
        .unwrap_or_default()
        .replace("\r\n", "\n");
    if subject.is_empty() || notes::title_of(&body) == subject {
        body
    } else if body.trim().is_empty() {
        subject
    } else {
        format!("{subject}\n{body}")
    }
}

fn save(account: &Account, id: Option<&str>, data: &Element) -> anyhow::Result<Option<Note>> {
    let text = text_of(data);
    if text.trim().is_empty() || text.chars().count() > notes::MAX_TEXT {
        return Ok(None);
    }
    notes::save(
        &account.state.mail_root,
        &account.user.address,
        &account.user.domain,
        &account.user.localpart,
        id,
        &text,
    )
    .map(Some)
}

pub(super) fn sync_collection(
    account: &Account,
    db: &Connection,
    request: &Element,
    window: Option<usize>,
) -> anyhow::Result<Element> {
    let key: i64 = request
        .value("AirSync:SyncKey")
        .and_then(|k| k.parse().ok())
        .unwrap_or(-1);
    let mut response = Element::new("AirSync:Collection");
    let status = |code: &str| Element::text("AirSync:Status", code);
    let reply = |response: Element, key: &str, code: &str| {
        response
            .with(Element::text("AirSync:SyncKey", key))
            .with(Element::text("AirSync:CollectionId", ID))
            .with(Element::text("AirSync:Status", code))
    };
    if key == 0 {
        state::save_items(db, &account.device, ID, 1, &Items::new(), None)?;
        return Ok(reply(response, "1", "1"));
    }
    let Some(known) = state::items_state(db, &account.device, ID)? else {
        return Ok(reply(response, "0", "3"));
    };
    let mut base = if key == known.0 {
        known.1.clone()
    } else if key == known.2 {
        known.3.clone()
    } else {
        return Ok(reply(response, "0", "3"));
    };
    let retry = key != known.0;
    let mut responses = Element::new("AirSync:Responses");
    if let Some(commands) = request.child("AirSync:Commands") {
        for command in &commands.children {
            let server_id = command.value("AirSync:ServerId").unwrap_or_default();
            match command.name {
                "Add" => {
                    let client = command.value("AirSync:ClientId").unwrap_or_default();
                    let mut answer =
                        Element::new("AirSync:Add").with(Element::text("AirSync:ClientId", client));
                    // A retried Sync's adds were stored by the first attempt;
                    // the device gets them back as new notes.
                    let stored = match command.child("AirSync:ApplicationData") {
                        Some(data) if !retry => save(account, None, data)?,
                        _ => None,
                    };
                    match stored {
                        Some(note) => {
                            base.insert(note.id.clone(), note.uid.to_string());
                            answer.push(Element::text("AirSync:ServerId", note.id));
                            answer.push(status("1"));
                        }
                        None => answer.push(status("6")),
                    }
                    responses.push(answer);
                }
                "Change" if retry => {}
                "Change" => {
                    let stored = match command.child("AirSync:ApplicationData") {
                        Some(data) if base.contains_key(&server_id) => {
                            save(account, Some(&server_id), data)?
                        }
                        _ => None,
                    };
                    match stored {
                        Some(note) => {
                            base.insert(server_id, note.uid.to_string());
                        }
                        None => responses.push(
                            Element::new("AirSync:Change")
                                .with(Element::text("AirSync:ServerId", server_id))
                                .with(status("6")),
                        ),
                    }
                }
                "Delete" => {
                    notes::delete(
                        &account.state.mail_root,
                        &account.user.domain,
                        &account.user.localpart,
                        &server_id,
                    )?;
                    base.remove(&server_id);
                }
                "Fetch" => {
                    let found = all(account)?.into_iter().find(|n| n.id == server_id);
                    let mut fetched = Element::new("AirSync:Fetch")
                        .with(Element::text("AirSync:ServerId", server_id));
                    match found {
                        Some(note) => {
                            fetched.push(status("1"));
                            fetched.push(note_data(&note));
                        }
                        None => fetched.push(status("8")),
                    }
                    responses.push(fetched);
                }
                _ => {}
            }
        }
    }
    let now = all(account)?;
    let limit = request
        .value("AirSync:WindowSize")
        .and_then(|w| w.parse::<usize>().ok())
        .or(window)
        .unwrap_or(100)
        .clamp(1, 512);
    let mut commands = Element::new("AirSync:Commands");
    let mut next = base.clone();
    let (mut sent, mut more) = (0, false);
    if request.value("AirSync:GetChanges").is_none_or(|v| v != "0") {
        for gone in base
            .keys()
            .filter(|id| !now.iter().any(|n| &n.id == *id))
            .cloned()
            .collect::<Vec<_>>()
        {
            if sent >= limit {
                more = true;
                break;
            }
            commands.push(
                Element::new("AirSync:Delete")
                    .with(Element::text("AirSync:ServerId", gone.clone())),
            );
            next.remove(&gone);
            sent += 1;
        }
        for note in &now {
            let version = note.uid.to_string();
            let tag = match base.get(&note.id) {
                None => "AirSync:Add",
                Some(known) if *known != version => "AirSync:Change",
                Some(_) => continue,
            };
            if sent >= limit {
                more = true;
                break;
            }
            commands.push(
                Element::new(tag)
                    .with(Element::text("AirSync:ServerId", note.id.clone()))
                    .with(note_data(note)),
            );
            next.insert(note.id.clone(), version);
            sent += 1;
        }
    }
    let new_key = if key == known.0 { known.0 + 1 } else { known.0 };
    state::save_items(db, &account.device, ID, new_key, &next, Some((key, &base)))?;
    response.push(Element::text("AirSync:SyncKey", new_key.to_string()));
    response.push(Element::text("AirSync:CollectionId", ID));
    response.push(status("1"));
    if more {
        response.push(Element::new("AirSync:MoreAvailable"));
    }
    if !commands.children.is_empty() {
        response.push(commands);
    }
    if !responses.children.is_empty() {
        response.push(responses);
    }
    Ok(response)
}

/// Changes waiting for a device.
pub(super) fn pending(account: &Account, db: &Connection) -> anyhow::Result<usize> {
    let Some(known) = state::items_state(db, &account.device, ID)? else {
        return Ok(1);
    };
    let now = all(account)?;
    let changed = now
        .iter()
        .filter(|n| known.1.get(&n.id) != Some(&n.uid.to_string()))
        .count();
    let gone = known
        .1
        .keys()
        .filter(|id| !now.iter().any(|n| &n.id == *id))
        .count();
    Ok(changed + gone)
}

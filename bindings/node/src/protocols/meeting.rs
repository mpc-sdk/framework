//! Bindings for meeting points.
use super::types::{MeetingData, MeetingItem, UserId};
use anyhow::Result;
use napi_derive::napi;
use polysig_client::{meeting, ServerOptions};
use polysig_protocol as protocol;

/// Create a meeting point used to exchange public keys.
#[napi(js_name = "createMeeting")]
pub async fn create_meeting(
    server_url: String,
    identifiers: Vec<UserId>,
    initiator: UserId,
    data: MeetingData,
) -> Result<String> {
    let options = ServerOptions {
        server_url,
        server_public_key: Default::default(),
        pattern: None,
    };

    let mut ids = Vec::with_capacity(identifiers.len());
    for id in identifiers {
        ids.push(id.try_into()?);
    }

    Ok(meeting::create(
        options,
        ids,
        initiator.try_into()?,
        data.into(),
    )
    .await?
    .to_string())
}

/// Join a meeting point used to exchange public keys.
#[napi(js_name = "joinMeeting")]
pub async fn join_meeting(
    server_url: String,
    meeting_id: String,
    user_id: Option<UserId>,
    data: MeetingData,
) -> Result<Vec<MeetingItem>> {
    let options = ServerOptions {
        server_url,
        server_public_key: Default::default(),
        pattern: None,
    };
    let meeting_id: protocol::MeetingId = meeting_id.parse()?;
    let user_id = if let Some(user_id) = user_id {
        Some(user_id.try_into()?)
    } else {
        None
    };
    let results =
        meeting::join(options, meeting_id, user_id, data.into())
            .await?;

    let mut output = Vec::with_capacity(results.len());
    for result in results {
        output.push(MeetingItem {
            user_id: result.0.into(),
            data: result.1.into(),
        })
    }

    Ok(output)
}

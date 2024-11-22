//! Bindings for meeting points.
use super::types::ServerOptions;
use anyhow::Result;
use napi_derive::napi;
use polysig_protocol::{hex, MeetingData, MeetingId, UserId};

/// Create a meeting point used to exchange public keys.
#[napi(js_name = "createMeeting")]
pub fn create_meeting(
    options: ServerOptions,
    /*
    identifiers: Vec<UserId>,
    initiator: UserId,
    data: MeetingData,
    */
) -> Result<()> {
    /*
    let options: MeetingOptions =
        serde_wasm_bindgen::from_value(options)?;
    let identifiers = parse_user_identifiers(identifiers)?;
    let initiator = parse_user_id(initiator)?;
    */

    /*
    let data: Value = serde_wasm_bindgen::from_value(data)?;
    let fut = async move {
        let meeting_id =
            meeting::create(options, identifiers, initiator, data)
                .await?;
        Ok(serde_wasm_bindgen::to_value(&meeting_id)?)
    };
    Ok(future_to_promise(fut).into())
    */

    todo!();
}

/// Join a meeting point used to exchange public keys.
#[napi(js_name = "joinMeeting")]
pub fn join_meeting(
    options: ServerOptions,
    /*
    meeting_id: MeetingId,
    user_id: UserId,
    data: MeetingData,
    */
) -> Result<()> {
    /*
    let options: MeetingOptions =
        serde_wasm_bindgen::from_value(options)?;
    let meeting_id: MeetingId =
        meeting_id.parse().map_err(JsError::from)?;
    let user_id: Option<String> =
        serde_wasm_bindgen::from_value(user_id)?;
    let user_id = if let Some(user_id) = user_id {
        Some(parse_user_id(user_id)?)
    } else {
        None
    };

    let fut = async move {
        let (public_keys, data) =
            meeting::join(options, meeting_id, user_id).await?;
        let public_keys: Vec<String> =
            public_keys.into_iter().map(|v| hex::encode(v)).collect();
        Ok(serde_wasm_bindgen::to_value(&(public_keys, data))?)
    };
    Ok(future_to_promise(fut).into())
    */

    todo!();
}

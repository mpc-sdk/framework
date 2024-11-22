//! Bindings for meeting points.
use polysig_client::meeting;
use polysig_protocol::{MeetingData, MeetingId, UserId};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// Create a meeting point used to exchange public keys.
#[wasm_bindgen(js_name = "createMeeting")]
pub fn create_meeting(
    server_url: String,
    identifiers: JsValue,
    initiator: Vec<u8>,
) -> Result<JsValue, JsError> {
    let identifiers: Vec<Vec<u8>> =
        serde_wasm_bindgen::from_value(identifiers)?;
    let identifiers = parse_user_identifiers(identifiers)?;
    let initiator = parse_user_id(initiator)?;
    let fut = async move {
        let meeting_id =
            meeting::create(&server_url, identifiers, initiator)
                .await?;
        Ok(serde_wasm_bindgen::to_value(&meeting_id)?)
    };
    Ok(future_to_promise(fut).into())
}

/// Join a meeting point used to exchange public keys.
#[wasm_bindgen(js_name = "joinMeeting")]
pub fn join_meeting(
    server_url: String,
    meeting_id: String,
    user_id: Vec<u8>,
    data: JsValue,
) -> Result<JsValue, JsError> {
    let meeting_id: MeetingId =
        meeting_id.parse().map_err(JsError::from)?;
    let user_id = parse_user_id(user_id)?;
    let data: MeetingData = serde_wasm_bindgen::from_value(data)?;

    let fut = async move {
        let results =
            meeting::join(&server_url, meeting_id, user_id, data)
                .await?;
        Ok(serde_wasm_bindgen::to_value(&results)?)
    };
    Ok(future_to_promise(fut).into())
}

/// Parse a collection of user identifiers.
fn parse_user_identifiers(
    identifiers: Vec<Vec<u8>>,
) -> Result<Vec<UserId>, JsError> {
    let mut ids = Vec::new();
    for id in identifiers {
        ids.push(parse_user_id(id)?);
    }
    Ok(ids)
}

/// Parse a single hex-encoded user identifier (SHA256 checksum).
fn parse_user_id(id: Vec<u8>) -> Result<UserId, JsError> {
    let id: [u8; 32] =
        id.as_slice().try_into().map_err(JsError::from)?;
    Ok(id.into())
}

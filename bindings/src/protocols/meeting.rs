//! Bindings for meeting points.
use mpc_driver::{meeting, MeetingOptions};
use mpc_protocol::{hex, MeetingId, UserId};
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

/// Create a meeting point used to exchange public keys.
#[wasm_bindgen(js_name = "createMeeting")]
pub fn create_meeting(
    options: JsValue,
    identifiers: JsValue,
    initiator: String,
    data: JsValue,
) -> Result<JsValue, JsError> {
    let options: MeetingOptions =
        serde_wasm_bindgen::from_value(options)?;
    let identifiers = parse_user_identifiers(identifiers)?;
    let initiator = parse_user_id(initiator)?;
    let data: Value = serde_wasm_bindgen::from_value(data)?;
    let fut = async move {
        let meeting_id =
            meeting::create(options, identifiers, initiator, data)
                .await?;
        Ok(serde_wasm_bindgen::to_value(&meeting_id)?)
    };
    Ok(future_to_promise(fut).into())
}

/// Join a meeting point used to exchange public keys.
#[wasm_bindgen(js_name = "joinMeeting")]
pub fn join_meeting(
    options: JsValue,
    meeting_id: String,
    user_id: JsValue,
) -> Result<JsValue, JsError> {
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
}

/// Parse a collection of user identifiers.
fn parse_user_identifiers(
    identifiers: JsValue,
) -> Result<Vec<UserId>, JsError> {
    let identifiers: Vec<String> =
        serde_wasm_bindgen::from_value(identifiers)?;
    let mut ids = Vec::new();
    for id in identifiers {
        ids.push(parse_user_id(id)?);
    }
    Ok(ids)
}

/// Parse a single hex-encoded user identifier (SHA256 checksum).
fn parse_user_id(id: String) -> Result<UserId, JsError> {
    let id = hex::decode(id).map_err(JsError::from)?;
    let id: [u8; 32] =
        id.as_slice().try_into().map_err(JsError::from)?;
    Ok(id.into())
}

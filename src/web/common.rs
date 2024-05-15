use std::{
	fmt::{Debug, Display},
	sync::Arc,
};

use ::serde::Serialize;
use axum::{body::Body, extract::Multipart, response::Response};
use chrono::*;
use log::*;

use super::{ActorAddress, FileData, Global, IdType};
use crate::db::{ObjectInfo, ObjectPayloadInfo};


#[derive(Debug, Serialize)]
pub struct ObjectDisplayInfo {
	hash: IdType,
	actor_address: String,
	actor_name: String,
	actor_avatar: Option<String>,
	created: String,
	time_ago: String,
	payload: ObjectPayloadInfo,
}

pub fn into_object_display_info(object: ObjectInfo) -> ObjectDisplayInfo {
	let created = Utc.timestamp_millis_opt(object.created as i64).unwrap();
	let time_ago = human_readable_duration(&Utc::now().signed_duration_since(created));

	ObjectDisplayInfo {
		hash: object.hash,
		actor_address: object.actor_address.to_string(),
		actor_name: match object.actor_name {
			None => object.actor_address.to_string(),
			Some(name) => name.clone(),
		},
		actor_avatar: object.actor_avatar.map(|id| id.to_string()),
		created: format!("{}", created.format("%Y-%m-%d %H:%M:%S")),
		time_ago,
		payload: object.payload,
	}
}

pub fn human_readable_duration(duration: &Duration) -> String {
	if duration.num_weeks() > 0 {
		let weeks = duration.num_weeks();
		if weeks > 1 {
			weeks.to_string() + " weeks"
		} else {
			weeks.to_string() + " week"
		}
	} else if duration.num_days() > 0 {
		let days = duration.num_days();
		if days > 1 {
			days.to_string() + " days"
		} else {
			days.to_string() + " day"
		}
	} else if duration.num_hours() > 0 {
		let hours = duration.num_hours();
		if hours > 1 {
			hours.to_string() + " hours"
		} else {
			hours.to_string() + " hour"
		}
	} else if duration.num_minutes() > 0 {
		let minutes = duration.num_minutes();
		if minutes > 1 {
			minutes.to_string() + " minutes"
		} else {
			minutes.to_string() + " minute"
		}
	} else {
		let seconds = duration.num_seconds();
		if seconds == 1 {
			seconds.to_string() + " second"
		} else {
			seconds.to_string() + " seconds"
		}
	}
}

pub fn json_response(json: &impl Serialize, content_type: Option<&str>) -> Response {
	Response::builder()
		.header("Content-Type", content_type.unwrap_or("application/json"))
		.body(Body::from(
			serde_json::to_string(json).expect("json serialization issue"),
		))
		.unwrap()
}

pub async fn post_message(
	g: &Arc<Global>, mut form: Multipart, in_reply_to: Option<(ActorAddress, IdType)>,
) -> Result<(), Response> {
	// Load identity + private key
	let identity = g.state.active_identity.as_ref().unwrap().1.clone();
	let private_key = match g.api.db.perform(|c| c.fetch_my_identity(&identity)) {
		Ok(r) =>
			if let Some((_, pk)) = r {
				pk
			} else {
				return Err(server_error_response2("unable to load identity"));
			},
		Err(e) => return Err(server_error_response(e, "unable to load identity")),
	};

	let mut message = String::new();
	let mut attachments = Vec::new();

	// Collect the form fields
	while let Some(field) = form.next_field().await.unwrap() {
		let name = field.name().unwrap().to_string();

		match name.as_str() {
			"message" => {
				let data = field.bytes().await.unwrap();
				message = String::from_utf8_lossy(&data).to_string();
			}
			"attachments" =>
				if let Some(content_type) = field.content_type() {
					let content_type2 = content_type.to_string();
					let data = field.bytes().await.unwrap();
					if data.len() == 0 {
						debug!("Ignoring empty attachment.");
						continue;
					}
					let attachment = FileData {
						mime_type: content_type2,
						data: data.to_vec(),
					};
					attachments.push(attachment);
				} else {
					warn!("Ignoring attachement due to missing content type.");
				},
			other => warn!("Unrecognized form field: {}", other),
		}
	}
	// TODO: Parse tags from post

	if message.len() == 0 {
		return Ok(());
	}

	if let Err(e) = g
		.api
		.publish_post(
			&identity,
			&private_key,
			&message,
			Vec::new(),
			&attachments,
			in_reply_to,
		)
		.await
	{
		return Err(server_error_response(e, "unable to publish post"));
	}
	Ok(())
}

pub fn error_response<S>(status_code: u16, message: S) -> Response
where
	S: Into<String>,
{
	let string: String = message.into();
	if status_code >= 400 {
		warn!("HTTP {} error: {}", status_code, &string);
	}
	Response::builder()
		.status(status_code)
		.header("Content-Type", "text/plain")
		.body(Body::from(string))
		.unwrap()
}

pub fn not_found_error_response(message: &str) -> Response { error_response(404, message) }

pub fn server_error_response<E>(e: E, message: &str) -> Response
where
	E: Debug + Display,
{
	error!("{}: {:?}", message, e);
	error_response(500, format!("{}: {}", message, e))
}

pub fn server_error_response2(message: &str) -> Response {
	error!("{}", message);
	error_response(500, format!("{}", message))
}

use std::{
	fmt::{self, Display},
	sync::Arc,
};

use axum::{body::Body, extract::Multipart, response::Response};
use log::*;
use serde::Serialize;

use super::IdType;
use crate::{
	core::{ActorAddress, FileData},
	web::Global,
};

pub async fn parse_post_message(mut form: Multipart) -> Result<(String, Vec<FileData>), Response> {
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
			"attachments" => {
				if let Some(content_type) = field.content_type() {
					let content_type2 = content_type.to_string();
					let data = field.bytes().await.unwrap();
					if data.len() == 0 {
						debug!("Ignoring empty attachment.");
						continue;
					}
					let attachment = FileData {
						mime_type: content_type2.into(),
						data: data.to_vec(),
					};
					attachments.push(attachment);
				} else {
					warn!("Ignoring attachement due to missing content type.");
				}
			}
			other => warn!("Unrecognized form field: {}", other),
		}
	}

	// TODO: Parse tags from post
	Ok((message, attachments))
}

pub async fn post_message(
	g: &Arc<Global>, form: Multipart, in_reply_to: Option<(ActorAddress, IdType)>,
) -> Result<IdType, Response> {
	// Parse request
	let (message, attachments) = parse_post_message(form).await?;

	// Load active identity and its private key
	let identity = match g.state.lock().await.active_identity.as_ref() {
		None => return Err(error_response(400, "No identiy selected yet.")),
		Some(i) => i.1.clone(),
	};
	let private_key = match g.api.db.perform(|c| c.fetch_my_identity(&identity)) {
		Ok(r) => {
			if let Some((_, pk)) = r {
				pk
			} else {
				return Err(server_error_response2("unable to load identity"));
			}
		}
		Err(e) => return Err(server_error_response(e, "unable to load identity")),
	};

	// Publish post
	let hash = g
		.api
		.publish_post(
			&identity,
			&private_key,
			"text/markdown",
			&message,
			Vec::new(),
			&attachments,
			in_reply_to,
		)
		.await
		.map_err(|e| server_error_response(e, "unable to publish post"))?;
	Ok(hash)
}

pub fn json_response(json: &impl Serialize, content_type: Option<&str>) -> Response {
	Response::builder()
		.header("Content-Type", content_type.unwrap_or("application/json"))
		.body(Body::from(
			serde_json::to_string(json).expect("json serialization issue"),
		))
		.unwrap()
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

pub fn not_found_error_response(message: &str) -> Response {
	error_response(404, message)
}

pub fn server_error_response<E>(e: E, message: &str) -> Response
where
	E: fmt::Debug + Display,
{
	error!("{}: {:?}", message, e);
	error_response(500, format!("{}: {}", message, e))
}

pub fn server_error_response2(message: &str) -> Response {
	error!("{}", message);
	error_response(500, format!("{}", message))
}

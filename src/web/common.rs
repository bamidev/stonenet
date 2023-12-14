use chrono::*;
use serde::Serialize;

use crate::db::*;

#[derive(Serialize)]
pub struct ObjectDisplayInfo {
	actor_id: String,
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
		actor_id: object.actor_id.to_string(),
		actor_name: match object.actor_name {
			None => object.actor_id.to_string(),
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

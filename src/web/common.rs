use chrono::*;

use crate::{
	api::{ObjectDisplayInfo, ObjectPayloadDisplayInfo},
	db::{ObjectInfo, ObjectPayloadInfo},
};


pub fn into_object_display_info(object: ObjectInfo) -> ObjectDisplayInfo {
	let created = Utc.timestamp_millis_opt(object.created as i64).unwrap();
	let time_ago = human_readable_duration(&Utc::now().signed_duration_since(created));

	ObjectDisplayInfo {
		url: format!("/actor/{}/object/{}", &object.actor_address, &object.hash),
		hash: Some(object.hash.to_string()),
		actor_url: format!("/actor/{}", &object.actor_address),
		actor_avatar_url: object
			.actor_avatar
			.map(|id| format!("/actor/{}/file/{}", &object.actor_address, id.to_string())),
		actor_name: match object.actor_name {
			None => object.actor_address.to_string(),
			Some(name) => name.clone(),
		},
		created: format!("{}", created.format("%Y-%m-%d %H:%M:%S")),
		time_ago,
		payload: match object.payload {
			ObjectPayloadInfo::Post(o) => crate::api::ObjectPayloadDisplayInfo::Post(o),
			ObjectPayloadInfo::Share(o) => crate::api::ObjectPayloadDisplayInfo::Share(o),
			ObjectPayloadInfo::Profile(o) => crate::api::ObjectPayloadDisplayInfo::Profile(o),
		},
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


impl ObjectDisplayInfo {
	pub fn type_title(&self) -> String {
		match &self.payload {
			ObjectPayloadDisplayInfo::Profile(_) => "Profile update".to_string(),
			ObjectPayloadDisplayInfo::Post(post) =>
				if let Some(irt) = &post.in_reply_to {
					if let Some(to_name) = &irt.actor_name {
						format!("Reply from {} to {}", &self.actor_name, to_name)
					} else {
						format!("Reply from {}", &self.actor_name)
					}
				} else {
					format!("Post by {}", &self.actor_name)
				},
			ObjectPayloadDisplayInfo::Share(share) => {
				if let Some(op) = &share.original_post {
					if let Some(from_name) = &op.actor_name {
						return format!("Post from {} shared by {}", from_name, &self.actor_name);
					}
				}

				format!("Post shared by {}", &self.actor_name)
			}
			ObjectPayloadDisplayInfo::Other(_) =>
				format!("ActivityPub Post from {}", self.actor_name),
		}
	}
}

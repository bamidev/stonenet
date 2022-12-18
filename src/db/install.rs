pub const QUERY: &'static str = r#"
	BEGIN;

	CREATE TABLE boost_object (
		object_id INTEGER NOT NULL,
		post_actor_address TEXT NOT NULL,
		post_index INTEGER NOT NULL,
		FOREIGN KEY(object_id) REFERENCES object(rowid)
	);

	CREATE TABLE version (
		major INTEGER NOT NULL,
		minor INTEGER NOT NULL,
		patch INTEGER NOT NULL
	);
	INSERT INTO version VALUES (0, 0, 0);

	CREATE TABLE identity (
		address TEXT,
		keypair BLOB
	);

	CREATE TABLE my_identity (
		label TEXT PRIMARY KEY,
		identity_id INTEGER UNIQUE,
		publish_trust INTEGER NOT NULL
	);

	CREATE TABLE feed_followed (
		address TEXT PRIMARY KEY,
		identity_id INTEGER NOT NULL,
		UNIQUE(address, identity_id)
	);

	CREATE TABLE feed_trusted_nodes (
		node_id INTEGER NOT NULL,
		truster_id INTEGER NOT NULL
	);

	CREATE TABLE friend (
		label TEXT PRIMARY KEY,
		address TEXT NOT NULL
	);

	CREATE TABLE remembered_nodes (
		address TEXT PRIMARY KEY,
		success_score INTEGER NOT NULL
	);

	CREATE TABLE remembered_actor_nodes (
		actor_id INTEGER NOT NULL,
		address TEXT NOT NULL,
		last_seen_contact_info TEXT NOT NULL
	);

	CREATE TABLE object (
		actor_id INTEGER NOT NULL,
		index INTEGER NOT NULL,
		signature BLOB NOT NULL,
		type INTEGER NOT NULL,
		UNIQUE(feed_id, index),
		FOREIGN KEY(actor_id) REFERENCES identity(rowid)
	);

	CREATE TABLE post_object (
		object_id INTEGER NOT NULL,
		in_reply_to_id INTEGER,
		UNIQUE(feed_id, number),
		UNIQUE(feed_id, hash),
		FOREIGN KEY(object_id) REFERENCES object(rowid),
		FOREIGN KEY(in_reply_to_id) REFERENCES post_object(rowid)
	);

	CREATE TABLE post_object_files (
		post_object_id INTEGER NOT NULL,
		file_id INTEGER NOT NULL,
		UNIQUE(post_object_id, file_id),
		FOREIGN KEY(post_object_id) REFERENCES post_object(rowid),
		FOREIGN KEY(file_id) REFERENCES file(rowid)
	);

	CREATE TABLE post_tag (
		post_id INTEGER NOT NULL,
		tag TEXT NOT NULL,
		UNIQUE(post_id, tag)
	);

	CREATE TABLE file (
		hash BLOB NOT NULL UNIQUE,
		mime_type TEXT NOT NULL,
		blocks INTEGER
	);

	CREATE TABLE block (
		file_id INTEGER NOT NULL,
		number INTEGER NOT NULL,
		hash BLOB NOT NULL,
		size INTEGER NOT NULL,
		data BLOB NOT NULL,
		UNIQUE(file_id, hash)
	);

	CREATE TABLE profile_object (
		object_id INTEGER NOT NULL,
		avatar_file_id INTEGER NOT NULL,
		wallpaper_file_id INTEGER NOT NULL,
		description_block_id INTEGER NOT NULL,
		FOREIGN KEY(object_id) REFERENCES object(rowid),
		FOREIGN KEY(avatar_file_id) REFERENCES file(rowid),
		FOREIGN KEY(wallpaper_file_id) REFERENCES file(rowid),
		FOREIGN KEY(description_block_id) REFERENCES block(rowid)
	);

	CREATE TABLE move_object (
		object_id INTEGER NOT NULL,
		new_actor_address TEXT NOT NULL,
		FOREIGN KEY(object_id) REFERENCES object(rowid)
	);

	COMMIT;
"#;

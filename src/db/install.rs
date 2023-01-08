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
		address TEXT NOT NULL UNIQUE,
		public_key BLOB NOT NULL
	);

	CREATE TABLE my_identity (
		label TEXT PRIMARY KEY,
		identity_id INTEGER NOT NULL UNIQUE,
		keypair BLOB NOT NULL
	);

	CREATE TABLE following (
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
		sequence INTEGER NOT NULL,
		signature BLOB NOT NULL,
		type INTEGER NOT NULL,
		UNIQUE(actor_id, sequence),
		FOREIGN KEY(actor_id) REFERENCES identity(rowid)
	);

	CREATE TABLE post_object (
		object_id INTEGER NOT NULL,
		in_reply_to_id INTEGER,
		FOREIGN KEY(object_id) REFERENCES object(rowid),
		FOREIGN KEY(in_reply_to_id) REFERENCES post_object(rowid)
	);

	CREATE TABLE post_files (
		post_object_id INTEGER NOT NULL,
		file_id INTEGER NOT NULL,
		UNIQUE(post_object_id, file_id),
		FOREIGN KEY(post_object_id) REFERENCES post_object(rowid),
		FOREIGN KEY(file_id) REFERENCES file(rowid)
	);

	CREATE TABLE post_tag (
		post_object_id INTEGER NOT NULL,
		tag TEXT NOT NULL,
		UNIQUE(post_object_id, tag)
	);

	CREATE TABLE file (
		hash BLOB NOT NULL UNIQUE,
		mime_type TEXT NOT NULL,
		block_count INTEGER
	);

	CREATE TABLE file_blocks (
		file_id INTEGER NOT NULL,
		block_id INTEGER NOT NULL,
		UNIQUE(file_id, block_id),
		FOREIGN KEY(file_id) REFERENCES file(rowid),
		FOREIGN KEY(block_id) REFERENCES block(rowid)
	);

	CREATE TABLE block (
		file_id INTEGER NOT NULL,
		hash BLOB NOT NULL,
		sequence INTEGER NOT NULL,
		size INTEGER NOT NULL,
		data BLOB NOT NULL,
		UNIQUE(file_id, hash),
		UNIQUE(file_id, sequence)
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

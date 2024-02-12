pub const QUERY: &'static str = r#"
	BEGIN;

	CREATE TABLE version (
		major INTEGER NOT NULL,
		minor INTEGER NOT NULL,
		patch INTEGER NOT NULL
	);
	INSERT INTO version VALUES (0, 0, 0);

	CREATE TABLE boost_object (
		object_id INTEGER NOT NULL,
		actor_address BLOB NOT NULL,
		object_hash TEXT NOT NULL,
		UNIQUE(actor_address, object_hash),
		FOREIGN KEY(object_id) REFERENCES object(rowid)
	);

	CREATE TABLE bootstrap_id (
		address TEXT NOT NULL PRIMARY KEY,
		node_id TEXT NOT NULL,
		UNIQUE(node_id)
	);

	CREATE TABLE identity (
		address BLOB NOT NULL PRIMARY KEY,
		public_key BLOB NOT NULL,
		first_object TEXT NOT NULL,
		type TEXT NOT NULL,
		UNIQUE(address),
		UNIQUE(public_key)
	);

	CREATE TABLE my_identity (
		label TEXT PRIMARY KEY,
		identity_id INTEGER NOT NULL UNIQUE,
		private_key BLOB NOT NULL
	);

	CREATE TABLE node_identity (
		address TEXT NOT NULL,
		private_key BLOB NOT NULL
	);

	CREATE TABLE following (
		identity_id INTEGER PRIMARY KEY
	);

	CREATE TABLE feed_trusted_nodes (
		node_id INTEGER NOT NULL,
		truster_id INTEGER NOT NULL
	);

	CREATE TABLE friend (
		label TEXT PRIMARY KEY,
		address TEXT NOT NULL
	);

	CREATE TABLE remembered_fingers (
		address TEXT PRIMARY KEY,
		node_id TEXT NOT NULL,
		success_score INTEGER NOT NULL,
		UNIQUE(node_id)
	);

	CREATE TABLE remembered_actor_nodes (
		actor_id INTEGER NOT NULL,
		address TEXT NOT NULL,
		last_seen_contact_info TEXT NOT NULL
	);

	CREATE TABLE object (
		hash TEXT PRIMARY KEY,
		actor_id INTEGER NOT NULL,
		sequence INTEGER NOT NULL,
		previous_hash TEXT,
		created INTEGER NOT NULL,
		found INTEGER NOT NULL,
		type INTEGER NOT NULL,
		signature BLOB NOT NULL,
		verified_from_start INTEGER NOT NULL DEFAULT 0,
		UNIQUE(actor_id, sequence),
		FOREIGN KEY(actor_id) REFERENCES identity(rowid)
	);

	CREATE TABLE post_object (
		object_id INTEGER NOT NULL,
		in_reply_to_actor_address BLOB,
		in_reply_to_object_hash TEXT,
		file_count INTEGER NOT NULL,
		FOREIGN KEY(object_id) REFERENCES object(rowid)
	);

	CREATE TABLE post_files (
		post_id INTEGER NOT NULL,
		hash TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		UNIQUE(post_id, sequence),
		FOREIGN KEY(post_id) REFERENCES post_object(rowid)
	);

	CREATE TABLE post_tag (
		post_id INTEGER NOT NULL,
		tag TEXT NOT NULL,
		UNIQUE(post_id, tag),
		FOREIGN KEY(post_id) REFERENCES post_object(rowid)
	);

	CREATE TABLE file (
		hash TEXT PRIMARY KEY,
		mime_type TEXT NOT NULL,
		block_count INTEGER NOT NULL,
		plain_hash TEXT NOT NULL,
		UNIQUE(hash)
	);

	CREATE TABLE file_blocks (
		file_id INTEGER NOT NULL,
		block_hash TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		UNIQUE(file_id, sequence),
		FOREIGN KEY(file_id) REFERENCES file(rowid)
	);

	CREATE TABLE block (
		hash TEXT PIMARY KEY,
		size INTEGER NOT NULL,
		data BLOB NOT NULL,
		UNIQUE(hash)
	);

	CREATE TABLE move_object (
		object_id INTEGER NOT NULL PRIMARY KEY,
		new_identity_hash TEXT NOT NULL,
		UNIQUE(object_id, new_identity_hash),
		FOREIGN KEY(object_id) REFERENCES object(rowid)
	);

	CREATE TABLE profile_object (
		object_id INTEGER NOT NULL PRIMARY KEY,
		name TEXT,
		avatar_file_hash TEXT,
		wallpaper_file_hash TEXT,
		description_file_hash TEXT
	);

	COMMIT;
"#;

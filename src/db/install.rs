pub const QUERY: &'static str = r#"
    BEGIN;

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

    CREATE TABLE remembered_feed_nodes (
        feed_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        last_seen_contact_info TEXT NOT NULL
    );

    CREATE TABLE post (
        feed_id INTEGER NOT NULL,
        number INTEGER NOT NULL,
        hash BLOB NOT NULL,
        signature BLOB NOT NULL,
        UNIQUE(feed_id, number),
        UNIQUE(feed_id, hash)
    );

    CREATE TABLE post_tag (
        post_id INTEGER NOT NULL,
        tag TEXT NOT NULL,
        UNIQUE(post_id, tag)
    );

    CREATE TABLE file (
        post_id INTEGER NOT NULL,
        hash BLOB NOT NULL,
        UNIQUE(post_id, hash)
    );

    CREATE TABLE block (
        file_id INTEGER NOT NULL,
        number INTEGER NOT NULL,
        hash BLOB NOT NULL,
        data BLOB,
        UNIQUE(file_id, hash)
    );

    COMMIT;
"#;

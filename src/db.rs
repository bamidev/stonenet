mod install;


use std::{
    fs,
    ops::*,
    path::*
};

use dirs;
use rusqlite::{self, Connection};
use unsafe_send_sync::*;


const DATABASE_PATH: &'static str = ".stonenet/db.sqlite";
const DATABASE_VERSION: (u8, u16, u16) = (0, 0, 0);


pub struct Database (UnsafeSendSync<Connection>);


impl Database {
    pub fn load() -> rusqlite::Result<Self> {
        let mut db_path: PathBuf = dirs::home_dir().expect("no home dir found");
        db_path.push(DATABASE_PATH);
        let db_dir = db_path.parent().unwrap();
        if !db_dir.exists() {
            fs::create_dir_all(db_dir).expect("Unable to create stonenet dir");
        }
        let connection = Connection::open(db_path)?;

        match connection.prepare("SELECT major, minor, patch FROM version") {
            Ok(mut stat) => {
                let mut rows = stat.query([])?;
                let row = rows.next()?.expect("missing version data");
                let major = row.get(0)?;
                let minor = row.get(1)?;
                let patch = row.get(2)?;

                if Self::is_outdated(major, minor, patch) {
                    Self::upgrade(&connection);
                }
            },
            Err(e) => {
                match &e {
                    rusqlite::Error::SqliteFailure(err, msg) => {
                        match msg {
                            Some(error_message) => {
                                if error_message == "no such table: version" {
                                    Self::install(&connection)?;
                                }
                                else {
                                    return Err(e);
                                }
                            },
                            None => return Err(e)
                        }
                    },
                    _ => return Err(e)
                }
            }
        }

        Ok(Self (UnsafeSendSync::new(connection)) )
    }

    /*pub async fn execute<P: rusqlite::Params + Send + 'static>(self: &Arc<Self>,
        sql: &str,
        params: P
    ) -> rusqlite::Result<usize> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();
        let sql_copy = sql.to_string();
        tokio::spawn(async move {
            let result = this.conn.execute(&sql_copy, params);
            tx.send(result);
        });
        rx.await.unwrap()
    }*/

    fn install(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        conn.execute_batch(install::QUERY)
    }

    fn is_outdated(major: u8, minor: u16, patch: u16) -> bool {
        major < DATABASE_VERSION.0 || minor < DATABASE_VERSION.1 || patch < DATABASE_VERSION.2
    }

    fn upgrade(conn: &rusqlite::Connection) {
        panic!("No database upgrade implemented yet!");
    }
}

impl Deref for Database {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

use std::{
    path::{Path, PathBuf},
    sync::*
};

use crate::{
    common::*,
    db::Database,
    global::Global,
    identity::*
};

use base58::FromBase58;
use ed25519_dalek::Keypair;
use rand_core::OsRng;
use rocket::*;
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket_dyn_templates::{Template, context};


#[get("/")]
async fn index() -> Template {
    Template::render("home", context! {
        test: "Test"
    })
}

pub async fn main(g: Global) {
    let _ = rocket::build()
        .attach(Template::fairing())
        .manage(g)
        .mount("/", routes![
            feed,
            static_,
            index,
            my_identities,
            my_identities_post,
            search
        ])
        .launch().await
        .expect("Rocket runtime failed");
}

#[get("/feed/<address>")]
async fn feed(address: &str, g: &State<Global>) -> Template {
    #[derive(rocket::serde::Serialize)]
    struct PostObject {

    }

    Template::render("feed", context! {
        address: address.to_string(),
        posts: Vec::<PostObject>::new()
    })
}

#[get("/my-identities")]
async fn my_identities(g: &State<Global>) -> Template {
    #[derive(rocket::serde::Serialize)]
    struct Object {
        id: u64,
        label: String,
        address: String
    }
    
    let mut stat = g.db.prepare(r#"
        SELECT label, identity_id, i.address FROM my_identity AS mi
        LEFT JOIN identity AS i ON mi.identity_id = i.rowid
    "#).expect("sql error");
    let mut rows = stat.query([]).expect("sql error");

    let mut identities = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        identities.push(Object {
            id: row.get(1).unwrap(),
            label: row.get(0).unwrap(),
            address: row.get(2).unwrap()
        });
    }

    Template::render("my_identities", context! {
        identities: identities
    })
}

#[derive(FromForm)]
struct MyIdentitiesPostData {
    label: String
}

#[post("/my-identities", data = "<form_data>")]
async fn my_identities_post(form_data: Form<MyIdentitiesPostData>, g: &State<Global>) -> Template {
    assert!(form_data.label.len() > 0, "Invalid label received");
    
    let mut rng = OsRng{};
    let keypair = Keypair::generate(&mut rng);
    let identity: Identity = keypair.public.into();
    let address = identity.generate_address();
    
    {
        let mut stat = g.db.prepare("INSERT INTO identity (address, keypair) VALUES(?, ?)").unwrap();
        let new_id = stat.insert(rusqlite::params![address.to_string(), keypair.to_bytes()]).unwrap();
        stat = g.db.prepare(r#"
            INSERT INTO my_identity (label, identity_id, publish_trust)
            VALUES (?, ?, FALSE)
        "#).unwrap();
        stat.insert(rusqlite::params![form_data.label, new_id]).unwrap();
    }

    my_identities(g).await
}

#[get("/static/<file..>")]
async fn static_(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/").join(file)).await.ok()
}

#[get("/search?<query>")]
async fn search(query: &str, g: &State<Global>) -> Template {
    #[derive(rocket::serde::Serialize)]
    struct SearchResult {
        
    }

    let mut error_message: Option<String> = None;
    let result = match query.from_base58() {
        Err(e) => {
            error_message = Some("not a valid base58 encoded string".into()); None
        },
        Ok(data) => {
            if data.len() < 32 {
                error_message = Some("address too short".into()); None
            }
            else if data.len() > 32 {
                error_message = Some("address too long".into()); None
            }
            else {
                let actor_id = IdType::from_slice(&data).unwrap();
                g.node.find_actor(&actor_id).await
            }
        }
    };

    Template::render("search", context! {
        query,
        posts: Vec::<SearchResult>::new(),
        error_message,
        result
    })
}
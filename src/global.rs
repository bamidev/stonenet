use std::sync::Arc;

use super::{
    net::overlay::OverlayNode,
    db::Database
};


#[derive(Clone)]
pub struct Global {
    pub node: Arc<OverlayNode>,
    pub db: Arc<Database>
}

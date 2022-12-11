use std::{
    net::{SocketAddr},
    process,
    rc::Rc
};

use stonenet::{
    net::{
        self,
        common::*,
        overlay::OverlayNode
    }
};

use env_logger;
use log::*;
use tokio::{
    self,
    net::ToSocketAddrs,
    runtime
};


async fn launch_node<A: ToSocketAddrs>(addr: A) -> Rc<OverlayNode> {
    let node = match OverlayNode::bind(IdType::random(), addr).await {
        Err(e) => {
            error!("Unable to bind to port 8337: {}", e);
            process::exit(1)
        },
        Ok(s) => Rc::new(s)
    };
    let node2 = node.clone();
    tokio::task::spawn_local(async move { node2.serve().await });
    node
}


#[test]
fn thousand_peers() {
    env_logger::init();
    let rt  = runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build().unwrap();
    rt.block_on(async {
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
            let master_addr: SocketAddr = "0.0.0.0:9999".parse().unwrap();
            let master = launch_node(master_addr).await;
            error!("MASTER NODE {}", master.node_id().to_string());

            for i in 0..1000 {
                if peer.store_actor(IdType::default(), PublicKey::default())
                let peer = launch_node("0.0.0.0:".to_string() + &(10000 + i).to_string()).await;
                peer.join_network(&master_addr).await.expect("io error");
            }

            let actor_id = IdType::default();
            let actor_info = master.find_actor(&actor_id).await.expect("actor not found");
        }).await;
    });
}
use std::fmt;

use async_trait::async_trait;
use base58::ToBase58;
use serde::{
    Serialize,
    Deserialize
};
use rand_core::{RngCore, OsRng};


#[async_trait]
pub trait AsyncIterator {
    type Item;

    async fn next(&mut self) -> Option<Self::Item>;
}


#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct IdType (pub [u8; 32]);



impl IdType {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            None
        }
        else {
            Some(Self (bytes.try_into().unwrap()))
        }
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self (bytes.into())
    }

    pub fn random() -> IdType {
        let mut rng = OsRng {};
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        IdType (buf)
    }
}

impl From<[u8; 32]> for IdType {
    fn from(other: [u8; 32]) -> Self {
        Self (other)
    }
}

impl fmt::Display for IdType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

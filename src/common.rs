use std::fmt;

use async_trait::async_trait;
use base58::*;
use serde::{
    Serialize,
    Deserialize
};
use rand_core::{RngCore, OsRng};


#[async_trait]
pub trait AsyncIterator {
    type Item;

    async fn next(&mut self) -> Option<Self::Item>;

    async fn count(&mut self) -> usize {
        let mut i = 0;
        while let Some(_) = self.next().await {
            i += 1;
        }
        i
    }
}


#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct IdType (pub [u8; 32]);

#[derive(Debug)]
pub enum IdFromBase58Error {
    FromBase58Error(FromBase58Error),
    TooLong,
    TooShort
}


impl IdType {
    pub fn from_base58(string: &str) -> Result<Self, IdFromBase58Error> {
        let buffer = string.from_base58()?;
        if buffer.len() > 32 { Err(IdFromBase58Error::TooLong) }
        else if buffer.len() < 32 { Err(IdFromBase58Error::TooShort) }
        else { Ok(Self (buffer.try_into().unwrap())) }
    }

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

impl From<FromBase58Error> for IdFromBase58Error {
    fn from(other: FromBase58Error) -> Self {
        Self::FromBase58Error(other)
    }
}

impl fmt::Display for IdFromBase58Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::FromBase58Error(e) => match e {
                FromBase58Error::InvalidBase58Character(c, s) => {
                    write!(f, "invalid base58 character {} at index {}", c, s)
                },
                FromBase58Error::InvalidBase58Length => {
                    write!(f, "invalid length for a base58 string")
                }
            },
            Self::TooLong => write!(f, "string to long"),
            Self::TooShort => write!(f, "string to short")
        }
    }
}

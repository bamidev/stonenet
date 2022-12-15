use bincode::{self, Options};
use serde::{Serialize, Deserialize};



pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> bincode::Result<T> {
    let options = bincode::options()
        .with_varint_encoding()
        .reject_trailing_bytes()
        .with_limit(65507);

    options.deserialize(bytes)
}

pub fn serialize<S: ?Sized + Serialize>(t: &S) -> bincode::Result<Vec<u8>> {
    let options = bincode::options()
        .with_varint_encoding()
        .reject_trailing_bytes()
        .with_limit(65507);

    options.serialize(t)
}
use std::{io, path::Path};

use tokio::{fs::File, io::AsyncReadExt};


/// Read all the content of a file into a string
pub async fn read_text_file(path: impl AsRef<Path>) -> io::Result<String> {
	let mut file = File::open(path).await?;
	let mut content = String::new();
	file.read_to_string(&mut content).await?;
	Ok(content)
}

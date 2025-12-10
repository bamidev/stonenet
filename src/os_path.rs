use std::{env, path::PathBuf};
#[cfg(test)]
use std::{fs, sync::Mutex};

use lazy_static::lazy_static;
#[cfg(test)]
use tempfile::TempDir;

lazy_static! {
	pub static ref HOME_DATA: PathBuf = load_data_home_path();
	pub static ref SYSTEM_DATA: PathBuf = "/var/lib/stonenet".into();
}

#[cfg(test)]
lazy_static! {
	pub static ref TEST_TEMP_DIR: Mutex<Option<TempDir>> =
		Mutex::new(Some(TempDir::new().unwrap()));
}

#[cfg(not(target_family = "windows"))]
fn load_data_home_path() -> PathBuf {
	let mut path: PathBuf = env::var_os("XDG_DATA_HOME")
		.unwrap_or("~/.local/share/".into())
		.into();
	path.push("stonenet");
	path
}

#[cfg(target_family = "windows")]
fn load_data_home_path() -> PathBuf {
	let mut install_dir = env::current_exe().unwrap();
	install_dir.pop();
	install_dir
}

/// Load the home data directory.
/// Returns None when the username could not be found.
pub fn home_data(username: &str) -> Option<PathBuf> {
	if let Ok(x) = HOME_DATA.strip_prefix("~") {
		let mut dir = homedir::home(username).expect("homedir error")?;
		dir.push(x);
		Some(dir)
	} else {
		Some(HOME_DATA.clone())
	}
}

pub fn home_data_identity(username: &str) -> Option<PathBuf> {
	home_data(username).map(|mut dir| {
		dir.push("identity");
		dir
	})
}

/// The directory to store identity private keys in, or None if the given system user did not
/// exist, but was needed to determine the folder location.
pub fn data_identity(system_user: Option<&str>) -> Option<PathBuf> {
	#[cfg(not(test))]
	if let Some(username) = &system_user {
		if let Some(dir) = home_data_identity(username) {
			Some(dir)
		} else {
			None
		}
	} else {
		Some(SYSTEM_DATA.clone())
	}
	#[cfg(test)]
	{
		let mut dir = TEST_TEMP_DIR
			.lock()
			.unwrap()
			.as_ref()
			.expect("TEST_TEMP_DIR is unset")
			.path()
			.to_path_buf();
		if let Some(username) = &system_user {
			dir.push(username);
			// Ensure the dir exists
			// TODO: Handle error and ignore directory exists errors
			let _ = fs::create_dir(&dir);
		}
		Some(dir)
	}
}

#[cfg(test)]
#[ctor::dtor]
fn uninitialize() {
	*TEST_TEMP_DIR.lock().unwrap() = None;
}

#[cfg(test)]
use std::sync::Mutex;
use std::{env, fs, path::PathBuf};

use homedir::home;
use lazy_static::lazy_static;
use log::*;
#[cfg(test)]
use tempfile::TempDir;

lazy_static! {
	pub static ref HOME_DATA: PathBuf = load_home_data_path();
	pub static ref SYSTEM_DATA: PathBuf = load_system_data_path();
}

#[cfg(test)]
lazy_static! {
	pub static ref TEST_TEMP_DIR: Mutex<Option<TempDir>> =
		Mutex::new(Some(TempDir::new().unwrap()));
}

#[cfg(not(target_family = "windows"))]
fn load_home_data_path() -> PathBuf {
	let mut path: PathBuf = env::var_os("XDG_DATA_HOME")
		.unwrap_or("~/.local/share/".into())
		.into();
	path.push("stonenet");
	path
}

#[cfg(target_family = "windows")]
fn load_home_data_path() -> PathBuf {
	"~/AppData/Local".into()
}

#[cfg(target_family = "windows")]
/// On Windows, all data is stored in the installation dir, which we can obtain by checked from
/// where the executable is run.
fn load_system_data_path() -> PathBuf {
	let mut install_dir = env::current_exe().unwrap();
	install_dir.pop();
	install_dir
}

#[cfg(not(target_family = "windows"))]
/// First check if the current process is running as user stonenet, or some other normal user.
/// If run as normal user, we store all data in the user-level directory .local/share/stonenet.
fn load_system_data_path() -> PathBuf {
	let mut checked = true;
	let s = sysinfo::System::new_all();
	match sysinfo::get_current_pid() {
		Err(e) => {
			warn!("Unable to get the current process ID: {}", e);
			checked = false;
		}
		Ok(pid) => {
			if let Some(process) = s.process(pid) {
				if let Some(uid) = process.user_id() {
					let users = sysinfo::Users::new_with_refreshed_list();
					if let Some(user) = users.get_user_by_id(uid) {
						if user.name() != "stonenet" {
							match home(user.name()) {
								Err(e) => {
									warn!("Unable to get home dir of user {}: {}", user.name(), e);
								}
								Ok(result) => {
									if let Some(mut home_dir) = result {
										home_dir.push(".local/share/stonenet");
										return home_dir;
									} else {
										warn!("No home directory found for user {}.", user.name());
									}
								}
							}
						}
					} else {
						warn!("Unable to load user of process.");
						checked = false;
					}
				} else {
					warn!("Unable to check process user ID.");
					checked = false;
				}
			} else {
				warn!("Platform doesn't support getting process info.");
				checked = false;
			}
		}
	}
	if !checked {
		warn!("Not able to check whether the process is running at system-level or user-level. Assuming system-level.");
	}
	"/var/lib/stonenet".into()
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

/// The directory to store identity private keys in, or None if the given system user did not
/// exist, but was needed to determine the folder location.
pub fn data_identity(system_user: Option<&str>) -> Option<PathBuf> {
	#[cfg(not(test))]
	{
		let mut dir = if let Some(username) = &system_user {
			if let Some(dir) = home_data(username) {
				dir
			} else {
				return None;
			}
		} else {
			SYSTEM_DATA.clone()
		};
		dir.push("identity");
		let _ = fs::create_dir(&dir);
		Some(dir)
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

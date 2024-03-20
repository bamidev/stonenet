use std::{io, process::Command};

use sysinfo::{ProcessRefreshKind, RefreshKind, System};


/// Make sure that the Stonenet daemon is actually running.
pub fn ensure_running() -> io::Result<()> {
	// If already running, do nothing
	let rk = RefreshKind::new().with_processes(ProcessRefreshKind::new());
	let s = System::new_with_specifics(rk);
	for (_, p) in s.processes() {
		if p.name().contains("stonenetd") {
			return Ok(());
		}
	}

	// Otherwise spawn the daemon
	Command::new("stonenetd").spawn()?;
	Ok(())
}

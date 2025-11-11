use std::{io, process::Command};

use sysinfo::{ProcessRefreshKind, RefreshKind, System};

/// Make sure that the Stonenet daemon is actually running.
pub fn ensure_running() -> io::Result<()> {
	// If already running, do nothing
	let rk = RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing());
	let s = System::new_with_specifics(rk);
	for (_, p) in s.processes() {
		if p.name().to_str().unwrap_or("").contains("stonenetd") {
			return Ok(());
		}
	}

	// Otherwise spawn the daemon
	Command::new("stonenetd").spawn()?;
	Ok(())
}

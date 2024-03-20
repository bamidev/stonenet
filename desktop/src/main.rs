#![windows_subsystem = "windows"]

mod daemon;

use std::process;

use browser_window::{application::*, browser::*};
use native_dialog::{MessageDialog, MessageType};

fn main() {
	let settings = ApplicationSettings::default();
	let application = Application::initialize(&settings).unwrap();
	let runtime = application.start();
	let exit_code = runtime.run_async(|handle| async move {
		if let Err(e) = daemon::ensure_running() {
			MessageDialog::new()
				.set_title("Stonenet Error")
				.set_text(&format!("Unable to spawn the Stonenet daemon: {}", e))
				.set_type(MessageType::Error)
				.show_alert()
				.expect("unable to show error dialog");
			handle.exit(1);
			return;
		}

		let source = Source::Url("http://localhost:37338".into());
		let mut bwb = BrowserWindowBuilder::new(source);
		bwb.dev_tools(true);
		bwb.title("Stonenet");
		bwb.size(1024, 768);
		let bw = bwb.build_async(&handle).await;
		bw.show();
	});

	process::exit(exit_code);
}

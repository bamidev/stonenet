#![windows_subsystem = "windows"]

mod daemon;

use std::process;

use browser_window::{application::*, browser::*};
use native_dialog::{DialogBuilder, MessageLevel};

fn main() {
	let username = "";

	let settings = ApplicationSettings::default();
	let application = Application::initialize(&settings).unwrap();
	let runtime = application.start();
	let exit_code = runtime.run_async(|handle| async move {
		if let Err(e) = daemon::ensure_running() {
			let result = DialogBuilder::message()
				.set_level(MessageLevel::Error)
				.set_title("Stonenet Error")
				.set_text(&format!(
					"The Stonenet daemon is not running and I was unable to launch it: {}",
					e
				))
				.alert()
				.show();
			if let Err(e) = result {
				println!("Unable to show error message: {}", e);
			}
			handle.exit(1);
			return;
		}

		// TODO: Read the port from the configuration file
		let source = Source::Url("http://localhost:37338".into());
		let mut bwb = BrowserWindowBuilder::new(source);
		#[cfg(debug_assertions)]
		bwb.dev_tools(true);
		bwb.title("Stonenet");
		bwb.size(1024, 768);
		let bw = bwb.build_async(&handle).await;
		bw.eval_js(&format!("document.cookie = 'system-user={}'", username))
			.await
			.expect("unable to execute JS");
		bw.show();
	});

	process::exit(exit_code);
}

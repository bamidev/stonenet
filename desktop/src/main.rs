use std::process;

use browser_window::{
    application::*,
    browser::*
};

fn main() {
	let application = Application::initialize(&ApplicationSettings::default()).unwrap();
	let runtime = application.start();

	let exit_code = runtime.run_async(|handle| async {
		
        let source = Source::Url("http://localhost:37338".into());
        let mut bwb = BrowserWindowBuilder::new(source);
        bwb.dev_tools(true);
        bwb.title("Stonenet");
        bwb.size(1024, 768);
        let bw = bwb.build(handle).await;
        bw.show();
	});

	process::exit(exit_code);
}
mod cli;
mod generator;
mod templates;
mod utils;

use cli::Cli;
use clap::Parser;

fn main() {
    let cli = Cli::parse();

    if let Err(e) = cli::handle_command(cli) {
        utils::printer::print_error(&format!("Error: {}", e));
        std::process::exit(1);
    }
}

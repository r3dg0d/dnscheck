pub mod interfaces;
pub mod mullvad;
pub mod report;
pub mod status;

use crate::cli::Cli;
use crate::output::OutputOpts;

pub fn opts_from(cli: &Cli) -> OutputOpts {
    OutputOpts {
        json: cli.json,
        quiet: cli.quiet,
        verbose: cli.verbose > 0,
    }
}

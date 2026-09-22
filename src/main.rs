//! dnscheck — DNS privacy analyzer

mod cli;
mod commands;
mod config;
mod detect;
mod exit_codes;
mod inspect;
mod output;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use tracing_subscriber::EnvFilter;

fn main() {
    let code = match real_main() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            exit_codes::GENERAL_ERROR
        }
    };
    std::process::exit(code);
}

fn real_main() -> anyhow::Result<i32> {
    let cli = Cli::parse();

    let filter = match (cli.quiet, cli.verbose) {
        (true, _) => "error",
        (false, 0) => "warn",
        (false, 1) => "info",
        (false, _) => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let flag = interrupted.clone();
        ctrlc::set_handler(move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            eprintln!("\ninterrupted");
            std::process::exit(exit_codes::INTERRUPTED);
        })?;
    }

    let (_cfg, cfg_path) = config::Config::load(cli.config.as_deref())?;
    if cli.verbose > 0 {
        if let Some(p) = cfg_path {
            tracing::info!(path = %p.display(), "loaded config");
        }
    }

    let code = match &cli.command {
        Commands::Status => commands::status::run(&cli)?,
        Commands::Interfaces => commands::interfaces::run(&cli)?,
        Commands::Mullvad => commands::mullvad::run(&cli)?,
        Commands::Report => commands::report::run(&cli)?,
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(
                clap_complete::Shell::from(*shell),
                &mut cmd,
                name,
                &mut std::io::stdout(),
            );
            exit_codes::SUCCESS
        }
    };

    let _ = interrupted;
    Ok(code)
}

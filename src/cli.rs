//! clap CLI definition.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "dnscheck",
    author = "r3dg0d",
    version,
    about = "DNS privacy analyzer — inspect local DNS for leaks and privacy issues",
    long_about = "Inspect resolv.conf, systemd-resolved, NetworkManager, and Mullvad DNS \
without active network probes by default. Use --probe for optional leak-test queries."
)]
pub struct Cli {
    /// Output machine-readable JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase logging verbosity
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Path to JSON config file (overrides XDG config)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Do not make changes (dnscheck is mostly read-only; honored for probes/completions write)
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Optional active DNS probes (queries leak-test style domains)
    #[arg(long, global = true)]
    pub probe: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Summarize current DNS configuration and notable findings
    Status,
    /// List interfaces and per-link DNS hints
    Interfaces,
    /// Show Mullvad DNS status if the mullvad CLI is present
    Mullvad,
    /// Full privacy-oriented report (findings + limitations)
    Report,
    /// Generate shell completions
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    Powershell,
    Zsh,
}

impl From<Shell> for clap_complete::Shell {
    fn from(s: Shell) -> Self {
        match s {
            Shell::Bash => Self::Bash,
            Shell::Elvish => Self::Elvish,
            Shell::Fish => Self::Fish,
            Shell::Powershell => Self::PowerShell,
            Shell::Zsh => Self::Zsh,
        }
    }
}

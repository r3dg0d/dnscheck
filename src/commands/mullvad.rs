use crate::cli::Cli;
use crate::commands::opts_from;
use crate::inspect;
use crate::output::print_json;
use anyhow::Result;

pub fn run(cli: &Cli) -> Result<i32> {
    let opts = opts_from(cli);
    let insp = inspect::inspect_all(true);
    let mv = insp.mullvad.unwrap_or(inspect::MullvadDns {
        cli_present: false,
        status_raw: None,
        dns_servers: vec![],
        notes: vec!["unavailable".into()],
    });

    if opts.json {
        print_json(opts, &mv)?;
    } else if !opts.quiet {
        println!("mullvad CLI present: {}", mv.cli_present);
        if let Some(ref s) = mv.status_raw {
            println!("status:\n{s}");
        }
        if !mv.dns_servers.is_empty() {
            println!("dns servers: {}", mv.dns_servers.join(", "));
        }
        for n in &mv.notes {
            println!("  note: {n}");
        }
    }
    Ok(0)
}

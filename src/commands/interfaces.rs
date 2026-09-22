use crate::cli::Cli;
use crate::commands::opts_from;
use crate::inspect;
use crate::output::print_json;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct IfacesOut {
    interfaces: Vec<inspect::interfaces::IfaceDns>,
    systemd_per_link: Vec<inspect::systemd_resolved::LinkDns>,
}

pub fn run(cli: &Cli) -> Result<i32> {
    let opts = opts_from(cli);
    let insp = inspect::inspect_all(false);
    let systemd_per_link = insp
        .systemd_resolved
        .as_ref()
        .map(|s| s.per_link.clone())
        .unwrap_or_default();

    let out = IfacesOut {
        interfaces: insp.interfaces,
        systemd_per_link,
    };

    if opts.json {
        print_json(opts, &out)?;
    } else if !opts.quiet {
        println!("interfaces:");
        for i in &out.interfaces {
            let vpn = if i.is_vpn_like { " vpn-like" } else { "" };
            let state = i.operstate.as_deref().unwrap_or("?");
            println!(
                "  {} [{state}]{vpn} v4={} v6={}",
                i.name,
                i.ipv4_addrs.join(","),
                i.ipv6_addrs.join(",")
            );
        }
        if !out.systemd_per_link.is_empty() {
            println!();
            println!("systemd-resolved per-link DNS:");
            for l in &out.systemd_per_link {
                println!("  {}:dns={} domains={}", l.link, l.dns.join(","), l.domains.join(","));
            }
        }
    }
    Ok(0)
}

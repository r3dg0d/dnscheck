use crate::cli::Cli;
use crate::commands::opts_from;
use crate::detect;
use crate::inspect;
use crate::output::{self, print_json};
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct StatusOut {
    inspection: inspect::DnsInspection,
    findings: Vec<detect::Finding>,
    probed: bool,
}

pub fn run(cli: &Cli) -> Result<i32> {
    let opts = opts_from(cli);
    let insp = inspect::inspect_all(true);
    let report = detect::analyze(&insp);

    if cli.probe {
        output::warn_msg(
            opts,
            "Active probes requested: performing optional dig/nslookup style checks if tools exist",
        );
        run_probes(cli.dry_run);
    }

    let out = StatusOut {
        inspection: insp,
        findings: report.findings.clone(),
        probed: cli.probe,
    };

    if opts.json {
        print_json(opts, &out)?;
    } else if !opts.quiet {
        println!("dnscheck status");
        println!();
        if let Some(ref rc) = out.inspection.resolv_conf {
            println!("resolv.conf nameservers: {}", rc.nameservers.join(", "));
            if !rc.search.is_empty() {
                println!("search domains: {}", rc.search.join(" "));
            }
            if rc.is_stub_resolved {
                println!("stub resolver: systemd-resolved (127.0.0.53) likely in use");
            }
        } else {
            println!("resolv.conf: unavailable");
        }
        if let Some(ref sr) = out.inspection.systemd_resolved {
            println!(
                "systemd-resolved: available (DoT={:?}, DNSSEC={:?})",
                sr.dns_over_tls, sr.dnssec
            );
            if !sr.fallback_dns.is_empty() {
                println!("fallback DNS: {}", sr.fallback_dns.join(", "));
            }
        }
        println!();
        println!("findings: {}", out.findings.len());
        for f in &out.findings {
            println!("  [{}] {}: {}", f.severity, f.title, f.detail);
        }
        if out.findings.is_empty() {
            println!("  (none from passive heuristics)");
        }
    }

    Ok(0)
}

fn run_probes(dry_run: bool) {
    let domains = ["whoami.akamai.net", "o-o.myaddr.l.google.com"];
    for d in domains {
        if dry_run {
            tracing::info!(domain = d, "dry-run: would probe");
            continue;
        }
        if let Ok(out) = std::process::Command::new("dig")
            .args(["+short", d])
            .output()
        {
            tracing::info!(
                domain = d,
                output = %String::from_utf8_lossy(&out.stdout).trim(),
                "probe dig"
            );
        } else if let Ok(out) = std::process::Command::new("nslookup").arg(d).output() {
            tracing::info!(
                domain = d,
                output = %String::from_utf8_lossy(&out.stdout).chars().take(200).collect::<String>(),
                "probe nslookup"
            );
        } else {
            tracing::warn!("neither dig nor nslookup available for probes");
            break;
        }
    }
}

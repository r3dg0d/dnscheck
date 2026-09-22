use crate::cli::Cli;
use crate::commands::opts_from;
use crate::detect;
use crate::inspect;
use crate::output::print_json;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
struct FullReport {
    tool: String,
    version: String,
    generated_at: String,
    inspection: inspect::DnsInspection,
    detection: detect::DetectionReport,
    honesty: Honesty,
}

#[derive(Serialize)]
struct Honesty {
    default_mode: String,
    probe_enabled: bool,
    disclaimer: String,
}

pub fn run(cli: &Cli) -> Result<i32> {
    let opts = opts_from(cli);
    let inspection = inspect::inspect_all(true);
    let detection = detect::analyze(&inspection);

    let report = FullReport {
        tool: "dnscheck".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        generated_at: Utc::now().to_rfc3339(),
        inspection,
        detection,
        honesty: Honesty {
            default_mode: "local configuration inspection only".into(),
            probe_enabled: cli.probe,
            disclaimer: "Passive findings are heuristics. They cannot prove a leak without observing actual query egress.".into(),
        },
    };

    if opts.json {
        print_json(opts, &report)?;
    } else if !opts.quiet {
        println!("dnscheck report v{}", report.version);
        println!("generated: {}", report.generated_at);
        println!();
        println!("== Findings ({}) ==", report.detection.findings.len());
        for f in &report.detection.findings {
            println!("[{}] {} — {}", f.severity, f.title, f.detail);
            println!("    confidence: {}", f.confidence);
        }
        println!();
        println!("== Resolvers ==");
        for r in &report.detection.resolver_summary {
            println!("  {} ({}) — {}", r.address, r.class, r.notes);
        }
        println!();
        println!("== What we can detect ==");
        for x in &report.detection.can_detect {
            println!("  + {x}");
        }
        println!("== What we cannot detect ==");
        for x in &report.detection.cannot_detect {
            println!("  - {x}");
        }
        println!();
        println!("{}", report.honesty.disclaimer);
    }

    let _has_warning = report
        .detection
        .findings
        .iter()
        .any(|f| f.severity == "warning" || f.severity == "critical");
    Ok(0)
}


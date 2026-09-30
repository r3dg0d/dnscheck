//! Local DNS configuration inspectors (no active probes by default).

pub mod interfaces;
pub mod networkmanager;
pub mod resolv;
pub mod systemd_resolved;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsInspection {
    pub resolv_conf: Option<resolv::ResolvConf>,
    pub systemd_resolved: Option<systemd_resolved::ResolvedStatus>,
    pub network_manager: Option<networkmanager::NmDns>,
    pub interfaces: Vec<interfaces::IfaceDns>,
    pub mullvad: Option<MullvadDns>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MullvadDns {
    pub cli_present: bool,
    pub status_raw: Option<String>,
    pub dns_servers: Vec<String>,
    pub notes: Vec<String>,
}

pub fn inspect_all(include_mullvad: bool) -> DnsInspection {
    let mut insp = DnsInspection {
        resolv_conf: resolv::parse_resolv_conf("/etc/resolv.conf").ok(),
        systemd_resolved: systemd_resolved::query_resolvectl(),
        network_manager: networkmanager::query_nmcli(),
        interfaces: interfaces::collect_iface_dns(),
        mullvad: None,
        limitations: vec![
            "Passive inspection only: cannot prove what upstream resolvers actually see without --probe.".into(),
            "DoH/DoT inside apps (browsers) is not visible from system DNS config.".into(),
            "Encrypted Client Hello / DNS over QUIC not detectable from local files.".into(),
        ],
    };

    if include_mullvad {
        insp.mullvad = Some(query_mullvad());
    }

    insp
}

fn query_mullvad() -> MullvadDns {
    use std::process::Command;

    let cli_present = which_bin("mullvad");
    if !cli_present {
        return MullvadDns {
            cli_present: false,
            status_raw: None,
            dns_servers: vec![],
            notes: vec!["mullvad CLI not found in PATH".into()],
        };
    }

    let status_raw = Command::new("mullvad")
        .args(["status"])
        .output()
        .ok()
        .map(|o| {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            } else {
                format!(
                    "exit={}: {}",
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stderr).trim()
                )
            }
        });

    let dns_out = Command::new("mullvad").args(["dns", "get"]).output().ok();

    let mut dns_servers = Vec::new();
    let mut notes = Vec::new();

    if let Some(o) = dns_out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Heuristic: collect IPv4/IPv6-looking tokens
            for tok in line.split_whitespace() {
                if looks_like_ip(tok) {
                    dns_servers.push(tok.to_string());
                }
            }
            notes.push(line.to_string());
        }
        if !o.status.success() {
            notes.push(format!(
                "mullvad dns get failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
    }

    MullvadDns {
        cli_present: true,
        status_raw,
        dns_servers,
        notes,
    }
}

fn which_bin(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(name).is_file()))
        .unwrap_or(false)
}

fn looks_like_ip(s: &str) -> bool {
    use std::net::IpAddr;
    s.parse::<IpAddr>().is_ok()
}

//! Query systemd-resolved via resolvectl when available.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResolvedStatus {
    pub available: bool,
    pub global_dns: Vec<String>,
    pub dns_over_tls: Option<String>,
    pub dnssec: Option<String>,
    pub llmnr: Option<String>,
    pub mdns: Option<String>,
    pub fallback_dns: Vec<String>,
    pub raw_excerpt: Option<String>,
    pub per_link: Vec<LinkDns>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkDns {
    pub link: String,
    pub dns: Vec<String>,
    pub domains: Vec<String>,
}

pub fn query_resolvectl() -> Option<ResolvedStatus> {
    if !command_exists("resolvectl") {
        return None;
    }

    let mut status = ResolvedStatus {
        available: true,
        ..Default::default()
    };

    if let Ok(out) = Command::new("resolvectl").arg("status").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        status.raw_excerpt = Some(text.chars().take(4000).collect());
        parse_resolvectl_status(&text, &mut status);
    }

    Some(status)
}

pub fn parse_resolvectl_status(text: &str, status: &mut ResolvedStatus) {
    let mut current_link: Option<String> = None;
    let mut current_dns: Vec<String> = Vec::new();
    let mut current_domains: Vec<String> = Vec::new();
    let mut in_global = true;

    let flush_link = |status: &mut ResolvedStatus,
                      current_link: &mut Option<String>,
                      current_dns: &mut Vec<String>,
                      current_domains: &mut Vec<String>| {
        if let Some(link) = current_link.take() {
            status.per_link.push(LinkDns {
                link,
                dns: std::mem::take(current_dns),
                domains: std::mem::take(current_domains),
            });
        }
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Link ")
            || (trimmed.starts_with("Interface ") && trimmed.contains('('))
        {
            flush_link(
                status,
                &mut current_link,
                &mut current_dns,
                &mut current_domains,
            );
            in_global = false;
            current_link = Some(trimmed.to_string());
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("DNS Servers:") {
            let servers: Vec<String> = rest.split_whitespace().map(|s| s.to_string()).collect();
            if in_global {
                status.global_dns.extend(servers);
            } else {
                current_dns.extend(servers);
            }
        } else if let Some(rest) = trimmed.strip_prefix("DNS Server:") {
            let servers: Vec<String> = rest.split_whitespace().map(|s| s.to_string()).collect();
            if in_global {
                status.global_dns.extend(servers);
            } else {
                current_dns.extend(servers);
            }
        } else if let Some(rest) = trimmed.strip_prefix("Fallback DNS Servers:") {
            status
                .fallback_dns
                .extend(rest.split_whitespace().map(|s| s.to_string()));
        } else if let Some(rest) = trimmed.strip_prefix("DNSOverTLS setting:") {
            status.dns_over_tls = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("DNSSEC setting:") {
            status.dnssec = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("LLMNR setting:") {
            status.llmnr = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("MulticastDNS setting:") {
            status.mdns = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("DNS Domain:") {
            let domains: Vec<String> = rest.split_whitespace().map(|s| s.to_string()).collect();
            if !in_global {
                current_domains.extend(domains);
            }
        } else if !trimmed.contains(':')
            && trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_digit() || c == ':')
                .unwrap_or(false)
        {
            // Continuation line with just an IP
            if looks_ipish(trimmed) {
                if in_global && status.global_dns.is_empty() {
                    // unlikely
                }
                if in_global {
                    status.global_dns.push(trimmed.to_string());
                } else {
                    current_dns.push(trimmed.to_string());
                }
            }
        }
    }

    flush_link(
        status,
        &mut current_link,
        &mut current_dns,
        &mut current_domains,
    );
}

fn looks_ipish(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(name).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sample_resolvectl() {
        let sample = r#"
Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
resolv.conf mode: stub
Fallback DNS Servers: 1.1.1.1 9.9.9.9

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1 192.168.1.2
        DNS Domain: lan
"#;
        let mut status = ResolvedStatus {
            available: true,
            ..Default::default()
        };
        parse_resolvectl_status(sample, &mut status);
        assert!(status.fallback_dns.contains(&"1.1.1.1".into()));
        assert!(!status.per_link.is_empty());
        let eth = status.per_link.iter().find(|l| l.link.contains("eth0"));
        assert!(eth.is_some());
        let eth = eth.unwrap();
        assert!(eth.dns.contains(&"192.168.1.1".into()));
    }
}

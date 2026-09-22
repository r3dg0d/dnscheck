//! Heuristic leak / privacy issue detectors (config-based).

pub mod classifiers;

use crate::inspect::DnsInspection;
use classifiers::{classify_resolver, ResolverClass};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    pub findings: Vec<Finding>,
    pub resolver_summary: Vec<ResolverSummary>,
    pub can_detect: Vec<String>,
    pub cannot_detect: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverSummary {
    pub address: String,
    pub class: String,
    pub notes: String,
}

pub fn analyze(insp: &DnsInspection) -> DetectionReport {
    let mut findings = Vec::new();
    let mut seen_resolvers: Vec<String> = Vec::new();

    if let Some(ref rc) = insp.resolv_conf {
        for ns in &rc.nameservers {
            if !seen_resolvers.contains(ns) {
                seen_resolvers.push(ns.clone());
            }
        }
        if rc.nameservers.is_empty() {
            findings.push(Finding {
                id: "no-nameservers".into(),
                severity: "warning".into(),
                title: "No nameservers in resolv.conf".into(),
                detail: "System may be relying on an unseen stub resolver or broken DNS.".into(),
                confidence: "high".into(),
            });
        }
    }

    if let Some(ref sr) = insp.systemd_resolved {
        for ns in &sr.global_dns {
            if !seen_resolvers.contains(ns) {
                seen_resolvers.push(ns.clone());
            }
        }
        for ns in &sr.fallback_dns {
            if !seen_resolvers.contains(ns) {
                seen_resolvers.push(ns.clone());
            }
        }
        for link in &sr.per_link {
            for ns in &link.dns {
                if !seen_resolvers.contains(ns) {
                    seen_resolvers.push(ns.clone());
                }
            }
        }

        if !sr.fallback_dns.is_empty() {
            findings.push(Finding {
                id: "fallback-dns".into(),
                severity: "info".into(),
                title: "Fallback DNS servers configured".into(),
                detail: format!(
                    "Fallback resolvers {:?}. These may be used if primary DNS fails — potential unexpected egress.",
                    sr.fallback_dns
                ),
                confidence: "medium".into(),
            });
        }

        match sr.dns_over_tls.as_deref() {
            Some("yes") | Some("opportunistic") => {}
            Some(other) => {
                findings.push(Finding {
                    id: "no-dot".into(),
                    severity: "info".into(),
                    title: "DNS-over-TLS not enforced".into(),
                    detail: format!("DNSOverTLS setting: {other}"),
                    confidence: "high".into(),
                });
            }
            None => {}
        }
    }

    // ISP / RFC1918 DNS while VPN iface present
    let vpn_up = insp
        .interfaces
        .iter()
        .any(|i| i.is_vpn_like && i.operstate.as_deref() == Some("up"));

    let mut resolver_summary = Vec::new();
    for addr in &seen_resolvers {
        let class = classify_resolver(addr);
        let notes = class.notes().to_string();
        let class_str = class.as_str().to_string();

        match class {
            ResolverClass::Rfc1918 | ResolverClass::LinkLocal | ResolverClass::IspLikely => {
                if vpn_up {
                    findings.push(Finding {
                        id: format!("vpn-dns-bypass-{addr}"),
                        severity: "warning".into(),
                        title: "Non-VPN resolver while VPN interface is up".into(),
                        detail: format!(
                            "Resolver {addr} ({class_str}) is visible in config while a VPN-like interface is up. \
                             This may indicate split-DNS or DNS leak — confirm traffic path with --probe or a leak test."
                        ),
                        confidence: "medium".into(),
                    });
                }
            }
            ResolverClass::LoopbackStub => {}
            ResolverClass::PublicPrivacy | ResolverClass::PublicOther | ResolverClass::Unknown => {}
        }

        // IPv6 DNS presence
        if addr.contains(':') && !addr.starts_with("127.") {
            // IPv6 literal
        }

        resolver_summary.push(ResolverSummary {
            address: addr.clone(),
            class: class_str,
            notes,
        });
    }

    let has_ipv6_dns = seen_resolvers.iter().any(|a| a.contains(':'));
    let has_ipv6_addr = insp
        .interfaces
        .iter()
        .any(|i| !i.is_loopback && i.ipv6_addrs.iter().any(|a| !a.starts_with("fe80:")));
    if has_ipv6_addr && !has_ipv6_dns {
        findings.push(Finding {
            id: "ipv6-no-dns".into(),
            severity: "info".into(),
            title: "IPv6 addresses present without IPv6 DNS servers in config".into(),
            detail: "Host has global IPv6 but no IPv6 nameserver listed. OS may still use IPv4 DNS or SLAAC RDNSS (not inspected here).".into(),
            confidence: "low".into(),
        });
    }
    if has_ipv6_dns && vpn_up {
        findings.push(Finding {
            id: "ipv6-dns-with-vpn".into(),
            severity: "info".into(),
            title: "IPv6 DNS configured alongside VPN".into(),
            detail: "Verify IPv6 DNS goes through the tunnel; IPv6 leaks are a common VPN footgun.".into(),
            confidence: "low".into(),
        });
    }

    // Split DNS: multiple distinct resolver classes across links
    if let Some(ref sr) = insp.systemd_resolved {
        if sr.per_link.len() > 1 {
            let mut classes = std::collections::BTreeSet::new();
            for link in &sr.per_link {
                for d in &link.dns {
                    classes.insert(classify_resolver(d).as_str());
                }
            }
            if classes.len() > 1 {
                findings.push(Finding {
                    id: "split-dns".into(),
                    severity: "info".into(),
                    title: "Possible split-DNS configuration".into(),
                    detail: format!(
                        "Different resolver classes across interfaces: {:?}. Expected for VPN+LAN; review domains routing.",
                        classes
                    ),
                    confidence: "medium".into(),
                });
            }
        }
    }

    if let Some(ref mv) = insp.mullvad {
        if mv.cli_present {
            if let Some(ref st) = mv.status_raw {
                if st.to_lowercase().contains("disconnected") {
                    findings.push(Finding {
                        id: "mullvad-disconnected".into(),
                        severity: "info".into(),
                        title: "Mullvad reports disconnected".into(),
                        detail: st.clone(),
                        confidence: "high".into(),
                    });
                }
            }
        }
    }

    DetectionReport {
        findings,
        resolver_summary,
        can_detect: vec![
            "Configured nameservers in resolv.conf / resolvectl / NetworkManager".into(),
            "Presence of fallback DNS and stub resolver (127.0.0.53)".into(),
            "VPN-like interfaces vs non-VPN resolvers (heuristic)".into(),
            "DoT setting from systemd-resolved when exposed".into(),
            "Search domains and split-DNS hints".into(),
        ],
        cannot_detect: vec![
            "Actual DNS query egress path without active probes".into(),
            "Browser or app-level DoH".into(),
            "Whether ISP sees SNI/ECH independently of DNS".into(),
            "RDNSS from IPv6 router advertisements (unless elsewhere exposed)".into(),
            "Guaranteed leak confirmation (use --probe + external leak tests)".into(),
        ],
    }
}

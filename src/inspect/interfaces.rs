//! Per-interface DNS hints from sysfs /proc and optional `ip` output.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfaceDns {
    pub name: String,
    pub operstate: Option<String>,
    pub ipv4_addrs: Vec<String>,
    pub ipv6_addrs: Vec<String>,
    pub is_vpn_like: bool,
    pub is_loopback: bool,
}

pub fn collect_iface_dns() -> Vec<IfaceDns> {
    let mut ifaces = Vec::new();
    let net = Path::new("/sys/class/net");
    let Ok(entries) = fs::read_dir(net) else {
        return ifaces;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let operstate = fs::read_to_string(entry.path().join("operstate"))
            .ok()
            .map(|s| s.trim().to_string());

        let (ipv4_addrs, ipv6_addrs) = read_addresses(&name);
        let is_loopback = name == "lo";
        let is_vpn_like = looks_vpn(&name);

        ifaces.push(IfaceDns {
            name,
            operstate,
            ipv4_addrs,
            ipv6_addrs,
            is_vpn_like,
            is_loopback,
        });
    }

    ifaces.sort_by(|a, b| a.name.cmp(&b.name));
    ifaces
}

fn read_addresses(iface: &str) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    // Prefer `ip -j` when available; fall back to parsing `ip addr`.
    if let Ok(out) = std::process::Command::new("ip")
        .args(["-o", "addr", "show", "dev", iface])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // format: idx iface family addr/prefix ...
                if parts.len() >= 4 {
                    match parts[2] {
                        "inet" => v4.push(parts[3].to_string()),
                        "inet6" => v6.push(parts[3].to_string()),
                        _ => {}
                    }
                }
            }
        }
    }

    (v4, v6)
}

pub fn looks_vpn(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("wg")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("mullvad")
        || n.starts_with("tailscale")
        || n.starts_with("nordlynx")
        || n.starts_with("proton")
        || n.starts_with("vpn")
        || n.contains("wireguard")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_name_detection() {
        assert!(looks_vpn("wg0"));
        assert!(looks_vpn("tun0"));
        assert!(looks_vpn("tailscale0"));
        assert!(!looks_vpn("eth0"));
        assert!(!looks_vpn("wlan0"));
    }
}

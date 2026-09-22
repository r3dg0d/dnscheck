//! NetworkManager DNS via nmcli when available.

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NmDns {
    pub available: bool,
    pub connections: Vec<NmConnectionDns>,
    pub raw_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmConnectionDns {
    pub name: String,
    pub uuid: Option<String>,
    pub device: Option<String>,
    pub ipv4_dns: Vec<String>,
    pub ipv6_dns: Vec<String>,
    pub ipv4_method: Option<String>,
    pub ipv6_method: Option<String>,
}

pub fn query_nmcli() -> Option<NmDns> {
    if !command_exists("nmcli") {
        return None;
    }

    let mut result = NmDns {
        available: true,
        ..Default::default()
    };

    let out = match Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "NAME,UUID,DEVICE,TYPE",
            "connection",
            "show",
            "--active",
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            result.raw_error = Some(e.to_string());
            return Some(result);
        }
    };

    if !out.status.success() {
        result.raw_error = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
        return Some(result);
    }

    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.is_empty() {
            continue;
        }
        let name = parts[0].to_string();
        let uuid = parts.get(1).map(|s| s.to_string());
        let device = parts
            .get(2)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let mut conn = NmConnectionDns {
            name: name.clone(),
            uuid: uuid.clone(),
            device,
            ipv4_dns: vec![],
            ipv6_dns: vec![],
            ipv4_method: None,
            ipv6_method: None,
        };

        let id = uuid.as_deref().unwrap_or(&name);
        if let Ok(detail) = Command::new("nmcli")
            .args([
                "-g",
                "IP4.DNS,IP6.DNS,ipv4.method,ipv6.method,ipv4.dns,ipv6.dns",
                "connection",
                "show",
                id,
            ])
            .output()
        {
            let dtext = String::from_utf8_lossy(&detail.stdout);
            parse_nmcli_detail(&dtext, &mut conn);
        }

        result.connections.push(conn);
    }

    Some(result)
}

/// Parse `nmcli -g` output: values are separated by `:` across fields, DNS lists by `|`.
pub fn parse_nmcli_detail(text: &str, conn: &mut NmConnectionDns) {
    // Also accept key:value lines from `nmcli -t`
    for line in text.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim();
            let val = val.trim();
            if val.is_empty() {
                continue;
            }
            match key {
                "IP4.DNS" | "ipv4.dns" => push_dns(&mut conn.ipv4_dns, val),
                "IP6.DNS" | "ipv6.dns" => push_dns(&mut conn.ipv6_dns, val),
                "ipv4.method" => conn.ipv4_method = Some(val.to_string()),
                "ipv6.method" => conn.ipv6_method = Some(val.to_string()),
                _ => {}
            }
        } else {
            // `-g` may emit a single multi-field line; best-effort skip
        }
    }
}

fn push_dns(out: &mut Vec<String>, val: &str) {
    for part in val.split(|c: char| c == ',' || c == '|' || c.is_whitespace()) {
        let part = part.trim();
        if !part.is_empty() && !out.contains(&part.to_string()) {
            out.push(part.to_string());
        }
    }
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
    fn parses_nmcli_kv() {
        let mut conn = NmConnectionDns {
            name: "test".into(),
            uuid: None,
            device: None,
            ipv4_dns: vec![],
            ipv6_dns: vec![],
            ipv4_method: None,
            ipv6_method: None,
        };
        parse_nmcli_detail(
            "IP4.DNS:1.1.1.1\nIP4.DNS:8.8.8.8\nipv4.method:auto\n",
            &mut conn,
        );
        assert_eq!(conn.ipv4_dns, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(conn.ipv4_method.as_deref(), Some("auto"));
    }
}

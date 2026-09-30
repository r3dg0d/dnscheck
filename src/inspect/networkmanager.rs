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

    Some(query_with(|args| Command::new("nmcli").args(args).output()))
}

fn query_with<R>(mut run: R) -> NmDns
where
    R: FnMut(&[&str]) -> std::io::Result<std::process::Output>,
{
    let mut result = NmDns {
        available: true,
        ..Default::default()
    };

    let out = match run(&[
        "-t",
        "-f",
        "NAME,UUID,DEVICE,TYPE",
        "connection",
        "show",
        "--active",
    ]) {
        Ok(o) => o,
        Err(e) => {
            result.raw_error = Some(e.to_string());
            return result;
        }
    };

    if !out.status.success() {
        result.raw_error = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
        return result;
    }

    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let parts = split_escaped_fields(line);
        if parts.len() != 4 || parts[1].is_empty() {
            continue;
        }
        let name = parts[0].clone();
        let uuid = Some(parts[1].clone());
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
        match run(&[
            "--mode",
            "multiline",
            "--terse",
            "--escape",
            "no",
            "--fields",
            "IP4.DNS,IP6.DNS,ipv4.method,ipv6.method,ipv4.dns,ipv6.dns",
            "connection",
            "show",
            "uuid",
            id,
        ]) {
            Ok(detail) if detail.status.success() => {
                parse_nmcli_detail(&String::from_utf8_lossy(&detail.stdout), &mut conn);
            }
            Ok(detail) => {
                result.raw_error.get_or_insert_with(|| {
                    String::from_utf8_lossy(&detail.stderr).trim().to_string()
                });
            }
            Err(error) => {
                result.raw_error.get_or_insert_with(|| error.to_string());
            }
        }

        result.connections.push(conn);
    }

    result
}

/// Parse labelled terse multiline fields. Escaping is disabled for this query.
pub fn parse_nmcli_detail(text: &str, conn: &mut NmConnectionDns) {
    // Also accept key:value lines from `nmcli -t`
    for line in text.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim();
            let key = match key.split_once('[') {
                Some((base, index))
                    if index
                        .strip_suffix(']')
                        .is_some_and(|i| i.parse::<usize>().is_ok()) =>
                {
                    base
                }
                _ => key,
            };
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
        }
    }
}

fn split_escaped_fields(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            fields.last_mut().unwrap().push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(String::new());
        } else {
            fields.last_mut().unwrap().push(character);
        }
    }
    if escaped {
        fields.last_mut().unwrap().push('\\');
    }
    fields
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

#[cfg(test)]
mod query_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn query_parses_labelled_fields_and_escaped_connection_names() {
        let mut calls = 0;
        let result = query_with(|args| {
            calls += 1;
            if calls == 1 {
                return Ok(output(
                    0,
                    "Desk\\:VPN\\\\Lab:fixture-uuid:fixture0:ethernet\n",
                    "",
                ));
            }
            assert_eq!(&args[args.len() - 2..], &["uuid", "fixture-uuid"]);
            // Values-only output lacks labels; using -g here was the old bug.
            let details = if args.contains(&"--mode")
                && args.contains(&"multiline")
                && args.contains(&"no")
            {
                "IP4.DNS[1]:1.1.1.1\nIP6.DNS[1]:2001:db8::53\nipv4.method:auto\nipv6.method:manual\nipv4.dns:1.1.1.1,8.8.8.8\n"
            } else {
                "1.1.1.1\n2001:db8::53\nauto\nmanual\n1.1.1.1,8.8.8.8\n"
            };
            Ok(output(0, details, ""))
        });
        assert_eq!(calls, 2);
        assert!(result.raw_error.is_none());
        let conn = &result.connections[0];
        assert_eq!(conn.name, "Desk:VPN\\Lab");
        assert_eq!(conn.device.as_deref(), Some("fixture0"));
        assert_eq!(conn.ipv4_dns, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(conn.ipv6_dns, vec!["2001:db8::53"]);
        assert_eq!(conn.ipv4_method.as_deref(), Some("auto"));
        assert_eq!(conn.ipv6_method.as_deref(), Some("manual"));
    }

    #[test]
    fn failed_detail_stdout_is_not_treated_as_dns_evidence() {
        let mut calls = 0;
        let result = query_with(|_| {
            calls += 1;
            Ok(match calls {
                1 => output(
                    0,
                    "first:id1:fixture0:ethernet\nsecond:id2:fixture1:ethernet\n",
                    "",
                ),
                2 => output(1, "IP4.DNS:1.1.1.1\n", "fixture detail refused"),
                _ => output(0, "IP4.DNS:8.8.8.8\n", ""),
            })
        });
        assert_eq!(result.raw_error.as_deref(), Some("fixture detail refused"));
        assert!(result.connections[0].ipv4_dns.is_empty());
        assert_eq!(result.connections[1].ipv4_dns, vec!["8.8.8.8"]);
    }

    #[test]
    fn detail_launch_error_remains_visible() {
        let mut calls = 0;
        let result = query_with(|_| {
            calls += 1;
            if calls == 1 {
                Ok(output(0, "fixture:id:fixture0:ethernet\n", ""))
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "fixture launch failure",
                ))
            }
        });
        assert!(result.raw_error.unwrap().contains("fixture launch failure"));
        assert!(result.connections[0].ipv4_dns.is_empty());
    }

    #[test]
    fn malformed_active_rows_do_not_trigger_detail_queries() {
        let mut calls = 0;
        let result = query_with(|_| {
            calls += 1;
            Ok(output(
                0,
                "bad\nmissing::fixture0:ethernet\nextra:id:fixture0:ethernet:extra\n",
                "",
            ))
        });
        assert_eq!(calls, 1);
        assert!(result.connections.is_empty());
    }

    #[test]
    fn indexed_dns_and_ipv6_colons_are_preserved() {
        let mut conn = NmConnectionDns {
            name: "fixture".into(),
            uuid: None,
            device: None,
            ipv4_dns: vec![],
            ipv6_dns: vec![],
            ipv4_method: None,
            ipv6_method: None,
        };
        parse_nmcli_detail("IP4.DNS[1]:1.1.1.1\nIP4.DNS[bogus]:9.9.9.9\nIP6.DNS[1]:2001:db8::53\nipv6.dns:2001:db8::53,2001:db8::54\n", &mut conn);
        assert_eq!(conn.ipv4_dns, vec!["1.1.1.1"]);
        assert_eq!(conn.ipv6_dns, vec!["2001:db8::53", "2001:db8::54"]);
    }
}

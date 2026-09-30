//! Classify DNS resolver addresses.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ResolverClass {
    LoopbackStub,
    Rfc1918,
    LinkLocal,
    PublicPrivacy,
    PublicOther,
    IspLikely,
    Unknown,
}

impl ResolverClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoopbackStub => "loopback-stub",
            Self::Rfc1918 => "rfc1918-local",
            Self::LinkLocal => "link-local",
            Self::PublicPrivacy => "public-privacy",
            Self::PublicOther => "public-other",
            Self::IspLikely => "isp-likely",
            Self::Unknown => "unknown",
        }
    }

    pub fn notes(self) -> &'static str {
        match self {
            Self::LoopbackStub => "Local stub (e.g. systemd-resolved); real upstream is elsewhere",
            Self::Rfc1918 => "Private LAN/router DNS — often ISP CPE",
            Self::LinkLocal => "Link-local resolver",
            Self::PublicPrivacy => "Well-known privacy-oriented public resolver",
            Self::PublicOther => "Well-known public resolver",
            Self::IspLikely => "Address pattern often used by ISP recursive resolvers",
            Self::Unknown => "Unrecognized — inspect manually",
        }
    }
}

pub fn classify_resolver(addr: &str) -> ResolverClass {
    let addr = addr.trim();
    // Strip zone id / port if present
    let host = addr.split('%').next().unwrap_or(addr);
    let host = host
        .split(']')
        .next()
        .unwrap_or(host)
        .trim_start_matches('[');
    let host = if let Some((h, port)) = host.rsplit_once(':') {
        // IPv4:port vs IPv6
        if host.matches(':').count() == 1 && port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host
        }
    } else {
        host
    };

    if host == "127.0.0.53" || host == "127.0.0.54" || host == "::1" || host.starts_with("127.") {
        return ResolverClass::LoopbackStub;
    }

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        let o = ip.octets();
        if o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        {
            return ResolverClass::Rfc1918;
        }
        if o[0] == 169 && o[1] == 254 {
            return ResolverClass::LinkLocal;
        }

        // Well-known
        let s = host.to_string();
        const PRIVACY: &[&str] = &[
            "1.1.1.1",
            "1.0.0.1",
            "9.9.9.9",
            "149.112.112.112",
            "94.140.14.14",
            "94.140.15.15",
            "194.242.2.2",
            "194.242.2.3",
            "64.6.64.6",
            "64.6.65.6",
        ];
        const PUBLIC: &[&str] = &[
            "8.8.8.8",
            "8.8.4.4",
            "208.67.222.222",
            "208.67.220.220",
            "4.2.2.1",
            "4.2.2.2",
        ];
        if PRIVACY.contains(&s.as_str()) {
            return ResolverClass::PublicPrivacy;
        }
        if PUBLIC.contains(&s.as_str()) {
            return ResolverClass::PublicOther;
        }

        // Heuristic: many ISP resolvers sit in less-famous unicast space — mark unknown,
        // but flag common CPE gateway .1 as isp-likely when RFC1918 (already handled).
        return ResolverClass::Unknown;
    }

    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        if ip.is_loopback() {
            return ResolverClass::LoopbackStub;
        }
        let s = host.to_lowercase();
        if s.starts_with("fe80:") {
            return ResolverClass::LinkLocal;
        }
        if s.starts_with("fc") || s.starts_with("fd") {
            return ResolverClass::Rfc1918; // ULA
        }
        const PRIVACY6: &[&str] = &[
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
            "2620:fe::fe",
            "2620:fe::9",
            "2a0d:2a00:1::",
            "2a0d:2a00:2::",
        ];
        if PRIVACY6.iter().any(|p| s.starts_with(p) || s == *p) {
            return ResolverClass::PublicPrivacy;
        }
        if s == "2001:4860:4860::8888" || s == "2001:4860:4860::8844" {
            return ResolverClass::PublicOther;
        }
        return ResolverClass::Unknown;
    }

    ResolverClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common() {
        assert_eq!(classify_resolver("127.0.0.53"), ResolverClass::LoopbackStub);
        assert_eq!(classify_resolver("192.168.1.1"), ResolverClass::Rfc1918);
        assert_eq!(classify_resolver("1.1.1.1"), ResolverClass::PublicPrivacy);
        assert_eq!(classify_resolver("8.8.8.8"), ResolverClass::PublicOther);
        assert_eq!(classify_resolver("10.0.0.53"), ResolverClass::Rfc1918);
    }
}

# dnscheck

**DNS privacy analyzer** — inspect local DNS configuration for likely leaks, fallback resolvers, VPN DNS bypass, and split-DNS. Built for honesty: passive by default, optional probes, and clear statements about what cannot be detected.

Owner: **r3dg0d** · License: **MIT**

## Install

### Cargo

```bash
cargo install --path .
# or from a checkout:
cargo build --release
sudo install -Dm755 target/release/dnscheck /usr/local/bin/dnscheck
```

### Nix

```bash
nix build
./result/bin/dnscheck status
# or
nix run . -- report
```

### Shell completions

```bash
dnscheck completions bash > ~/.local/share/bash-completion/completions/dnscheck
dnscheck completions zsh  > ~/.zsh/completions/_dnscheck
dnscheck completions fish > ~/.config/fish/completions/dnscheck.fish
```

## Usage

```bash
dnscheck status              # summary + findings
dnscheck interfaces          # per-iface / per-link DNS
dnscheck mullvad             # Mullvad CLI DNS if present
dnscheck report              # full report + limitations
dnscheck report --json
dnscheck status --probe      # optional active dig/nslookup
dnscheck status --dry-run --probe
```

### Global flags

| Flag | Meaning |
|------|---------|
| `--help` / `--version` | Standard |
| `--json` | Machine-readable output |
| `--verbose` / `-v` | Tracing to stderr |
| `--quiet` / `-q` | Minimal output |
| `--config PATH` | JSON config (else XDG `~/.config/dnscheck/config.json`) |
| `--dry-run` | Do not perform optional probes/writes |
| `--probe` | Active DNS queries (optional) |

Exit codes: `0` success, `1` error, `2` usage, `130` Ctrl+C.

## What it inspects

- `/etc/resolv.conf` (nameservers, search, stub hints)
- `resolvectl status` (DoT/DNSSEC/fallback/per-link)
- NetworkManager via `nmcli` when available
- Mullvad via `mullvad` CLI when available
- Interfaces (`/sys/class/net` + `ip addr`) for VPN-like names

## Detection (heuristic)

Likely flags for: ISP/LAN DNS with VPN up, fallback DNS, IPv6 DNS footguns, unexpected split-DNS, DoT off.

### Can detect (config)

Configured resolvers, stub vs upstream hints, NM/resolved settings, VPN iface presence.

### Cannot detect (without probes / out of scope)

Actual query egress, browser DoH, ECH/SNI, RDNSS-only IPv6 DNS, guaranteed leak proof.

## Architecture

```
src/
  inspect/   # resolv, resolved, NM, interfaces, mullvad
  detect/    # classifiers + findings
  commands/  # status, interfaces, mullvad, report
```

## Config (optional)

`~/.config/dnscheck/config.json`:

```json
{
  "probe_domains": ["whoami.akamai.net"],
  "known_isp_resolvers": [],
  "notes": null
}
```

## License

MIT © r3dg0d

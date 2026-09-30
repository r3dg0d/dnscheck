# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Request labelled NetworkManager detail fields instead of parsing values-only output as keys.
- Parse escaped active-connection names and indexed IPv4/IPv6 DNS fields; query details by UUID.
- Preserve detail failures as inspection errors and add fixture-based query/parser regressions.

## [0.1.0] - 2026-09-21

### Added
- Initial release: `status`, `interfaces`, `mullvad`, `report`, `completions`
- Passive inspection of `/etc/resolv.conf`, systemd-resolved, NetworkManager
- Heuristic leak / split-DNS / fallback DNS findings
- Optional `--probe` for dig/nslookup style checks
- Global flags: `--json --verbose --quiet --config --dry-run`
- XDG config under `~/.config/dnscheck/`
- Nix flake and GitHub Actions CI

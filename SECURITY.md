# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Email or open a private advisory for **r3dg0d/dnscheck**. Please include:

- Description and impact
- Reproduction steps
- Affected version / commit

Do **not** file public issues for undisclosed vulnerabilities.

## Scope notes

dnscheck reads local network configuration. It does not require root for most
operations. Optional `--probe` sends DNS queries — treat that as intentional
network activity. Never paste secrets into config files.

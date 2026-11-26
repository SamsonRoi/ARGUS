# Changelog

All notable changes to ARGUS are listed here. ARGUS uses [semantic versioning](https://semver.org).

## [1.0.0] - 2026-11-26

The first release of ARGUS, a network attack surface mapper.

### Scanning

- Interactive command-line interface with sessions.
- Target parsing for single IPs, lists and CIDR ranges, with validation and scope warnings.
- Host discovery using ARP, ICMP, TCP SYN, TCP ACK and UDP. ARGUS picks methods that suit your privileges.
- TCP port scans:
  - Quick: top 100 ports.
  - Standard: top 1,000 ports.
  - Full: all 65,535 ports.
  - Custom ports.
- Optional extras:
  - UDP scanning.
  - Service and version detection.
  - OS estimation.
  - Traceroute.
- Safe use of Nmap:
  - Targets and options are validated before anything runs.
  - Dangerous options (`--script`, `-A`, `-iL`, `-iR`) are refused.
  - Scans have time limits and can be cancelled with Ctrl+C.

### Scan history

- Every scan is saved automatically in a local SQLite database, together with Nmap's raw XML as evidence.
- Coverage-aware comparison: a port is only reported as closed if both scans checked it.
- Hosts are matched across scans by MAC address, so a device that changes IP is recognised.
- Baselines, to see what changed since a reference scan.
- Engagements, to record who authorized the work, the scope and the dates.

### Asset classification and network map

- Every host gets its likely roles, such as router, domain controller, printer, camera or database server.
- Each role has a confidence level and the evidence behind it, and each host gets a criticality level.
- The classification rules are in an editable file, `argus/data/asset_rules.toml`.
- Network map: hosts grouped by subnet under their gateway. Each link is marked observed (seen by traceroute) or inferred (from addresses only).

### Risk analysis

- 36 risk rules covering:
  - cleartext protocols
  - remote access
  - exposed databases
  - services that usually have no login
  - management interfaces
  - end-of-life software
- Severity is raised when the context makes a risk worse, for example Telnet on a router or camera, or RDP on a public address.
- Scores from 0 to 10, with every factor shown: severity, asset criticality, exposure, confidence and persistence.
- Network-level findings: critical assets that share a subnet with weak devices, and management interfaces on the general network.
- Possible attack paths, a fix-first plan, and a letter grade for the network.
- History for each finding: first seen, streak and new since baseline. A finding is only "resolved" when a newer scan checked it again.
- Accepted risks, with a reason and an expiry date.

### Reports

- HTML: one self-contained file with an interactive network map, and findings you can filter and search.
- PDF: printed from the HTML report by Edge or Chrome, with a basic layout as a fallback.
- JSON (with a published schema) and CSV.
- Optional redaction of addresses, hostnames and names, for sharing.
- SHA-256 tamper evidence, checked from the menus or with `argus verify`.
- Every report includes its authorization and scope, what changed since the last scan, and an honest limitations section.

### Command line

- `argus scans`, `argus report` and `argus verify`, for automation.

### Quality

- 530 automated tests.
- Tested on Python 3.10 and 3.13 by GitHub Actions on every push.

[1.0.0]: https://github.com/SamsonRoi/ARGUS/releases/tag/v1.0.0

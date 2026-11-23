# ARGUS

**Network Attack Surface Mapper**

_See everything. Miss nothing._

ARGUS is a Python command-line tool for network reconnaissance and attack surface assessment. Given a CIDR range or one or more IP addresses, it aims to discover hosts, open ports and services, analyze possible exposure, and produce structured reports.

> **Authorized use only.** ARGUS is meant for defensive security assessments on networks you own or have explicit written permission to test. Scan results show potential exposure. They do not prove that something is exploitable.

## Status

ARGUS is in early development. Right now only the startup banner works. The planned features below are **not built yet**.

## Planned features

- Interactive menu-driven CLI
- Host discovery and TCP/UDP port scanning
- Service and version detection
- Asset classification and network mapping
- Evidence-based risk analysis
- Reports in HTML, JSON, CSV and PDF
- Scan history and comparison using SQLite

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/SamsonRoi/ARGUS.git
cd ARGUS
python -m venv venv
```

Activate the virtual environment:

```bash
# Windows (PowerShell)
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

Then install ARGUS:

```bash
pip install -e .
```

## Usage

```bash
argus
```

## License

MIT License. See the [LICENSE](LICENSE) file.

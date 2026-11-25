# ARGUS

**Network Attack Surface Mapper**

_See everything. Miss nothing._

ARGUS is a Python-based command-line tool for network reconnaissance and attack surface assessment.

It helps security professionals discover network hosts, identify open ports, detect running services, estimate operating systems, and understand potential exposure points.

> **Authorized use only.** ARGUS is intended for defensive security assessments on networks you own or have explicit permission to test. Scan results indicate potential exposure; they do not prove that a system is vulnerable or exploitable.

---

## Current Status

ARGUS is under active development.

### Implemented Features

- Interactive, menu-driven command-line interface.
- Target input supporting:
  - Single IPv4 addresses.
  - Multiple IPv4 addresses.
  - CIDR network ranges.
- Target validation and duplicate removal.
- Session management and target replacement confirmation.
- Host discovery using multiple discovery methods:
  - ARP discovery.
  - ICMP Echo discovery.
  - TCP SYN discovery.
  - TCP ACK discovery.
  - UDP discovery.
- TCP port scanning:
  - Quick scan – top 100 common TCP ports.
  - Standard scan – top 1,000 common TCP ports.
  - Full scan – all 65,535 TCP ports.
  - Custom port selection.
- Optional UDP port scanning.
- Service and version detection.
- Operating system estimation.
- Structured scan results and warnings.
- Nmap execution and XML result parsing.

### Planned Features

- Improved service enumeration.
- Asset classification.
- Network topology mapping.
- Evidence-based risk analysis and prioritization.
- Report generation in JSON, CSV, HTML, and PDF.
- Scan history and comparison using SQLite.

---

## Requirements

- Python 3.10 or newer.
- Nmap.
- Git.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/SamsonRoi/ARGUS.git
cd ARGUS
```

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux / Kali:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install ARGUS

```bash
pip install -e .
```

For development and testing:

```bash
pip install -e ".[dev]"
```

---

## Usage

Start ARGUS:

```bash
argus
```

ARGUS opens an interactive command-line interface.

### Basic Workflow

1. Start ARGUS.
2. Select target configuration.
3. Enter an IP address, multiple IP addresses, or a CIDR range.
4. Review the target information.
5. Choose a scanning operation.
6. Configure additional scan options when available.
7. Review the scan results.

---

## Scanning Options

ARGUS currently provides the following scanning operations:

| Scan              | Description                                               |
| ----------------- | --------------------------------------------------------- |
| Host Discovery    | Identifies active hosts using selected discovery methods. |
| Quick TCP Scan    | Scans the top 100 common TCP ports.                       |
| Standard TCP Scan | Scans the top 1,000 common TCP ports.                     |
| Full TCP Scan     | Scans all 65,535 TCP ports.                               |
| Custom TCP Scan   | Scans user-defined ports or port ranges.                  |

Additional scan options include:

- UDP scanning.
- Service and version detection.
- Operating system estimation.
- Discovery method selection.

Some discovery methods and scan types may require elevated privileges.

---

## Project Structure

```text
ARGUS/
│
├── argus/
│   ├── __init__.py
│   ├── main.py
│   ├── banner.py
│   ├── menus.py
│   ├── scan_menu.py
│   ├── results_display.py
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── discovery.py
│   │   ├── models.py
│   │   ├── nmap_parser.py
│   │   ├── nmap_runner.py
│   │   ├── port_scan.py
│   │   ├── scan_manager.py
│   │   ├── service_detect.py
│   │   └── os_detect.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── helpers.py
│       ├── prompts.py
│       ├── session.py
│       ├── target_parser.py
│       └── validators.py
│
├── tests/
├── README.md
├── requirements.txt
├── pyproject.toml
└── LICENSE
```

---

## Running Tests

ARGUS uses `pytest` for testing.

Run the complete test suite:

```bash
python -m pytest -v
```

---

## Limitations

- Host discovery may miss systems that block or ignore discovery probes.
- CIDR-based port scanning depends on discovered hosts. Hosts that do not respond to discovery may be missed.
- UDP scan results can be inconclusive because filtered and open UDP ports may be difficult to distinguish.
- Service and operating system detection are estimates and may not always be accurate.
- Some scanning methods require elevated privileges.
- Scan results do not establish that a vulnerability exists.
- Vulnerability exploitation and NSE-based vulnerability scanning are not currently part of ARGUS.
- Scan history and report generation are planned features.

---

## Development Roadmap

ARGUS is being developed in stages:

1. Core CLI and session management.
2. Target parsing and validation.
3. Nmap integration.
4. Host discovery.
5. TCP and UDP port scanning.
6. Service and operating system detection.
7. Asset classification and network mapping.
8. Risk analysis and prioritization.
9. Report generation.
10. Scan history and comparison.

---

## License

ARGUS is released under the MIT License. See [LICENSE](LICENSE) for details.

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
- Scan history in a local SQLite database:
  - Every scan is saved automatically, with Nmap's raw XML as evidence.
  - Records exactly which ports each scan checked.
  - Coverage-aware comparison of any two scans.
  - Baselines, to answer "what changed since then?".
  - Engagements, to record who authorized the work and what is in scope.

### Planned Features

- Improved service enumeration.
- Asset classification.
- Network topology mapping.
- Evidence-based risk analysis and prioritization.
- Report generation in JSON, CSV, HTML, and PDF.

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

## Scan History

Every scan is saved automatically. Open **Scan History** from the main menu to:

- View any saved scan.
- Compare two scans.
- Compare the newest scan with its baseline.
- Mark a scan as the baseline.
- Delete a scan.
- Record engagements, and choose which one new scans are filed under.

### How comparison works

ARGUS records exactly which ports each scan checked, and only reports what it can actually tell:

| Result                   | Meaning                                                                 |
| ------------------------ | ----------------------------------------------------------------------- |
| Port opened              | Both scans checked the port; it is open now and was not before.         |
| Port no longer open      | Both scans checked the port; it was open before and is not now.         |
| Open, not checked before | The port is open now, but the older scan never checked it.              |
| Not re-checked           | The port was open before, but the newer scan did not check it.          |
| New host / Host not seen | Only reported for addresses inside both scans' targets.                 |
| Address changed          | Same MAC address, new IP: the same device moved.                        |
| Service changed          | The service or version on an open port changed.                         |
| OS estimate changed      | The operating system estimate changed.                                  |

Hosts are matched by MAC address when both scans saw one, and by IP address otherwise.

### Where the history is stored

- Default: `~/.argus/argus.db`.
- Under `sudo` on Linux/macOS, ARGUS uses the real user's home folder, so the history is not split between root and your account.
- Set the `ARGUS_DB` environment variable to use another file.

### Engagements

An engagement records who authorized the work, the authorized scope, and the dates. Scans are filed under the current engagement. ARGUS stores this information but does not enforce the scope yet.

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
│   ├── history_menu.py
│   ├── results_display.py
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── compare.py
│   │   ├── discovery.py
│   │   ├── evidence.py
│   │   ├── models.py
│   │   ├── nmap_parser.py
│   │   ├── nmap_runner.py
│   │   ├── port_scan.py
│   │   ├── scan_manager.py
│   │   ├── service_detect.py
│   │   └── os_detect.py
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py
│   │   └── repository.py
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
- Comparisons can only report changes in ports that both scans checked.
- Engagement scope is recorded but not yet enforced.
- Report generation is a planned feature.

---

## Development Roadmap

ARGUS is being developed in stages:

1. Project foundation and interactive CLI. **Done**
2. Session management. **Done**
3. Target parsing, validation, and scope checks. **Done**
4. Nmap engine: host discovery, port scanning, service and OS detection. **Done**
5. SQLite database, scan history, and comparing scans. **Done**
6. Asset classification and a network graph.
7. The risk analysis engine.
8. Reports: JSON and CSV first, then HTML and PDF.

Next version: enforcing the authorized scope recorded in engagements.

---

## License

ARGUS is released under the MIT License. See [LICENSE](LICENSE) for details.
